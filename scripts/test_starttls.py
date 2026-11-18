"""STARTTLS regression tests. Run after cargo build; requires openssl."""

import contextlib
import json
from pathlib import Path
import queue
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest

from test_agent import BINARY
from test_tls import tls_server


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"

# Even indices: server sends. Odd indices: exact client bytes.
EXCHANGES = {
    "smtp": [b"220-mail.test ESMTP\r\n220 ready\r\n", b"EHLO [127.0.0.1]\r\n",
             b"250-mail.test\r\n250 STARTTLS\r\n", b"STARTTLS\r\n", b"220 2.0.0 Ready to start TLS\r\n"],
    "lmtp": [b"220 lmtp ready\r\n", b"LHLO [127.0.0.1]\r\n", b"250 STARTTLS\r\n", b"STARTTLS\r\n", b"220 go\r\n"],
    "imap": [b"* OK IMAP4rev1 ready\r\n", b"a1 STARTTLS\r\n", b"* CAPABILITY IMAP4rev1\r\na1 OK Begin TLS\r\n"],
    "pop3": [b"+OK POP3 ready\r\n", b"STLS\r\n", b"+OK Begin TLS\r\n"],
    "ftp": [b"220-Welcome\r\n text without a code\r\n220 FTP ready\r\n", b"AUTH TLS\r\n", b"234 AUTH TLS OK\r\n"],
    "nntp": [b"201 news ready\r\n", b"STARTTLS\r\n", b"382 Continue with TLS\r\n"],
    "sieve": [b'"IMPLEMENTATION" "test"\r\n"STARTTLS"\r\nOK "ready"\r\n', b"STARTTLS\r\n", b'OK "Begin TLS"\r\n'],
    "postgres": [b"", POSTGRES_SSL_REQUEST, b"S"],
}


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size and (chunk := sock.recv(size - len(data))):
        data.extend(chunk)
    return bytes(data)


def greet_and_close(stream):
    stream.sendall(b"ready\r\n")
    stream.recv(4096)


@contextlib.contextmanager
def starttls_server(cert, key, steps, action=greet_and_close, log=None):
    """Runs `steps` in plaintext; wraps the socket in TLS if all client bytes match."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                for index, item in enumerate(steps):
                    if index % 2 == 0:
                        self.request.sendall(item)
                        continue
                    data = read_exact(self.request, len(item))
                    if log is not None:
                        log.put(data)
                    if data != item:
                        return
                if action is not None:
                    with context.wrap_socket(self.request, server_side=True) as stream:
                        action(stream)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01))
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="telnetz-starttls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.cert = cls.directory / "server.crt"
        cls.key = cls.directory / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE", "-out", str(cls.cert), "-keyout", str(cls.key),
        ], check=True, capture_output=True)

    def client(self, port, *options, trust=True):
        names = ("--cacert", self.cert, "--server-name", "localhost") if trust else ()
        return subprocess.run(
            [str(BINARY), "127.0.0.1", str(port), "-q", "--max-time", "3", "--connect-timeout", "2",
             *map(str, names), *map(str, options)],
            input=b"", capture_output=True, timeout=5,
        )

    def report(self, result):
        self.assertEqual(result.stderr, b"", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["exit_code"], result.returncode)
        return report


class StartTlsTests(Fixture):
    def test_protocols(self):
        for protocol, steps in EXCHANGES.items():
            with self.subTest(protocol=protocol):
                log = queue.Queue()
                with starttls_server(self.cert, self.key, steps, log=log) as port:
                    result = self.client(port, "--starttls", protocol, "--expect", "ready", "-w", "2")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"ready\r\n")
                self.assertEqual([log.get(timeout=1) for _ in steps[1::2]], steps[1::2])

    def test_json_excludes_negotiation_bytes(self):
        with starttls_server(self.cert, self.key, EXCHANGES["smtp"]) as port:
            report = self.report(self.client(port, "--starttls", "SMTP", "--expect", "ready", "--json"))
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual((report["bytes_sent"], report["bytes_received"]), (0, 7))
        self.assertEqual(report["output_utf8"], "ready\r\n")
        self.assertEqual(report["server_name"], "localhost")
        self.assertEqual(report["tls"]["verification"], "verified")

    def test_commands_follow_the_handshake(self):
        received = queue.Queue()
        def action(stream):
            received.put(stream.recv(4096))
            stream.sendall(b"250 secure\r\n")
        with starttls_server(self.cert, self.key, EXCHANGES["smtp"], action=action) as port:
            result = self.client(port, "--starttls", "smtp", "-c", "EHLO client", "--expect", "250 ")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received.get(timeout=1), b"EHLO client\r\n")

    def test_rejections(self):
        cases = {
            "smtp": (EXCHANGES["smtp"][:4] + [b"454 4.7.0 TLS not available\r\n"], "454 4.7.0"),
            "ftp": ([b"421 Service not available\r\n"], "421 Service"),
            "imap": ([b"* OK ready\r\n", b"a1 STARTTLS\r\n", b"a1 NO disabled\r\n"], "a1 NO"),
            "pop3": ([b"+OK ready\r\n", b"STLS\r\n", b"-ERR no TLS\r\n"], "-ERR"),
            "sieve": ([b'OK "ready"\r\n', b"STARTTLS\r\n", b'NO "no TLS"\r\n'], "NO"),
            "postgres": (EXCHANGES["postgres"][:2] + [b"N"], "SSLRequest rejected: N"),
        }
        for protocol, (steps, text) in cases.items():
            with self.subTest(protocol=protocol):
                with starttls_server(self.cert, self.key, steps, action=None) as port:
                    report = self.report(self.client(port, "--starttls", protocol, "--json"))
                self.assertEqual(report["exit_code"], 1, report)
                self.assertEqual((report["phase"], report["reason"]), ("starttls", "starttls_rejected"))
                self.assertIn(text, report["error"])
                self.assertIsNone(report["tls"])

    def test_plaintext_after_reply_is_rejected(self):
        for protocol, steps in (
            ("smtp", EXCHANGES["smtp"][:4] + [b"220 go\r\n250 injected\r\n"]),
            ("postgres", EXCHANGES["postgres"][:2] + [b"Sinjected"]),
        ):
            with self.subTest(protocol=protocol):
                with starttls_server(self.cert, self.key, steps) as port:
                    report = self.report(self.client(port, "--starttls", protocol, "--json"))
                self.assertEqual(report["exit_code"], 1, report)
                self.assertEqual(report["reason"], "starttls_unexpected_data")
                self.assertIsNone(report["tls"])

    def test_protocol_errors(self):
        for steps, text in (
            ([b"220 ready\r\n"], "connection closed"),
            ([b"hello\r\n"], "malformed reply"),
            ([b"220-" + b"x" * (70 * 1024)], "exceeds 64 KiB"),
        ):
            with self.subTest(text=text):
                with starttls_server(self.cert, self.key, steps, action=None) as port:
                    report = self.report(self.client(port, "--starttls", "smtp", "--json"))
                self.assertEqual(report["exit_code"], 1, report)
                self.assertEqual(report["reason"], "starttls_protocol_error")
                self.assertIn(text, report["error"])

    def test_negotiation_is_bounded_by_connect_timeout(self):
        with starttls_server(self.cert, self.key, [b"", b"never"], action=None) as port:
            report = self.report(self.client(port, "--starttls", "smtp", "--json", "--connect-timeout", "0.1"))
        self.assertEqual(report["exit_code"], 1, report)
        self.assertEqual((report["phase"], report["reason"]), ("starttls", "connect_timeout"))

    def test_certificate_is_verified(self):
        with starttls_server(self.cert, self.key, EXCHANGES["imap"]) as port:
            report = self.report(self.client(port, "--starttls", "imap", "--json", trust=False))
        self.assertEqual(report["exit_code"], 1, report)
        self.assertEqual((report["phase"], report["reason"]), ("tls", "unknown_issuer"))

    def test_tls_info_and_dump_cert(self):
        with starttls_server(self.cert, self.key, EXCHANGES["pop3"], action=lambda s: s.recv(1)) as port:
            report = self.report(self.client(port, "--starttls", "pop3", "--tls-info", "--json"))
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["reason"], "tls_info")
        self.assertEqual(report["bytes_sent"], 0)
        self.assertEqual(report["tls"]["verification"], "verified")
        with starttls_server(self.cert, self.key, EXCHANGES["pop3"], action=lambda s: s.recv(1)) as port:
            result = self.client(port, "--starttls", "pop3", "--dump-cert", "-", trust=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(ssl.PEM_cert_to_DER_cert(result.stdout.decode()),
                         ssl.PEM_cert_to_DER_cert(self.cert.read_text()))

    def test_usage_errors(self):
        for options, text in (
            (("--starttls", "smtp", "--tls"), b"--starttls cannot be used with --tls"),
            (("--starttls", "xmpp"), b"unknown protocol 'xmpp'"),
            (("--starttls",), b"--starttls requires a value"),
        ):
            with self.subTest(options=options):
                result = subprocess.run([str(BINARY), "127.0.0.1", "1", *options], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 2)
                self.assertIn(text, result.stderr)


class ScriptStartTlsTests(Fixture):
    def run_script(self, port, document, *options, trust=True):
        path = self.directory / "conversation.json"
        path.write_text(json.dumps(document))
        return self.report(self.client(port, "--script", path, "--json", *options, trust=trust))

    @staticmethod
    def smtp_action(stream):
        with stream.makefile("rb") as lines:
            if lines.readline() == b"EHLO agent.example\r\n":
                stream.sendall(b"250-secure\r\n250 SIZE\r\n")
            if lines.readline() == b"QUIT\r\n":
                stream.sendall(b"221 bye\r\n")

    def test_smtp_example(self):
        steps = [b"220 mail.test\r\n", b"EHLO agent.example\r\n", b"250-mail.test\r\n250 STARTTLS\r\n",
                 b"STARTTLS\r\n", b"220 2.0.0 Ready to start TLS\r\n"]
        with starttls_server(self.cert, self.key, steps, action=self.smtp_action) as port:
            result = self.client(port, "--script", ROOT / "examples/smtp-starttls.toml", "--json")
        report = self.report(result)
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["tls"]["verification"], "verified")
        self.assertTrue(report["output_utf8"].startswith(steps[0].decode()))
        self.assertTrue(report["output_utf8"].endswith("250 SIZE\r\n221 bye\r\n"))
        upgrade = [step for step in report["script"]["steps"] if step["action"] == "starttls"]
        self.assertEqual([(step["path"], step["reason"]) for step in upgrade], [("steps[8]", "tls_upgraded")])
        self.assertEqual(report["bytes_sent"], 2 * len(b"EHLO agent.example\r\n") + len(b"STARTTLS\r\nQUIT\r\n"))

    def test_unconsumed_plaintext_is_rejected(self):
        steps = [b"220 ready\r\n", b"STARTTLS\r\n", b"220 go\r\n"]
        with starttls_server(self.cert, self.key, steps) as port:
            report = self.run_script(port, {"steps": [
                {"expect": "220 "}, {"expect": "\r\n"}, {"send_line": "STARTTLS"},
                {"expect": "220 "}, {"starttls": True},
            ]})
        self.assertEqual(report["exit_code"], 1, report)
        self.assertEqual((report["phase"], report["reason"]), ("starttls", "starttls_unexpected_data"))
        self.assertIn("4 unconsumed plaintext bytes", report["error"])
        self.assertEqual(report["script"]["current_step"], "steps[4]")
        self.assertIsNone(report["tls"])

    def test_upgrade_is_terminal_and_single(self):
        with tls_server(self.cert, self.key) as port:
            report = self.run_script(port, {"steps": [{"starttls": True}, {"expect": "ready\r\n"}, {"starttls": True}]})
        self.assertEqual(report["exit_code"], 1, report)
        self.assertEqual(report["reason"], "starttls_error")
        self.assertIn("already active", report["error"])
        with starttls_server(self.cert, self.key, [b""]) as port:
            report = self.run_script(port, {"steps": [{"starttls": True}]}, trust=False)
        self.assertEqual((report["exit_code"], report["phase"], report["reason"]), (1, "tls", "unknown_issuer"))

    def test_cli_starttls_runs_script_over_tls(self):
        with starttls_server(self.cert, self.key, EXCHANGES["nntp"]) as port:
            report = self.run_script(port, {"steps": [{"expect": "ready\r\n"}]}, "--starttls", "nntp")
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["tls"]["verification"], "verified")

    def test_usage_errors(self):
        path = self.directory / "upgrade.json"
        path.write_text(json.dumps({"steps": [{"starttls": True}]}))
        plain = self.directory / "plain.json"
        plain.write_text(json.dumps({"steps": [{"send": "x"}]}))
        for script, options, text in (
            (path, ("--tls",), "cannot be used with --tls"),
            (path, ("--starttls", "smtp"), "cannot be used with --tls or --starttls"),
            (plain, ("--cacert", self.cert), "--cacert requires --tls, --starttls, or a script starttls step"),
            (plain, ("--insecure",), "--insecure requires"),
        ):
            with self.subTest(options=options):
                report = self.report(subprocess.run(
                    [str(BINARY), "127.0.0.1", "1", "--json", "--script", str(script), *map(str, options)],
                    capture_output=True, timeout=5,
                ))
                self.assertEqual((report["exit_code"], report["reason"]), (2, "invalid_arguments"))
                self.assertIn(text, report["error"])
                self.assertIsNone(report["peer_addr"])
        path.write_text(json.dumps({"steps": [{"starttls": False}]}))
        report = self.report(subprocess.run([str(BINARY), "127.0.0.1", "1", "--json", "--script", str(path)],
                                            capture_output=True, timeout=5))
        self.assertEqual(report["reason"], "invalid_script")


if __name__ == "__main__":
    unittest.main(verbosity=2)
