"""Run after cargo build. Requires Python 3 and openssl; TELNETZ_BIN overrides the binary."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import queue
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TELNETZ_BIN", ROOT / "target/debug/telnetz")).resolve()


@contextlib.contextmanager
def tls_server(cert, key, received=None, send_banner=True, server_names=None, action=None, tls_version=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    if tls_version is not None:
        context.minimum_version = context.maximum_version = tls_version
    if server_names is not None:
        context.set_servername_callback(lambda connection, name, context: server_names.put(name))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                with context.wrap_socket(self.request, server_side=True) as stream:
                    if action is not None:
                        action(stream)
                        return
                    if send_banner:
                        stream.sendall(b"ready\r\n")
                    if received is not None:
                        received.put(stream.recv(4096))
            except (ssl.SSLError, ConnectionError):
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = contextlib.ExitStack()
        cls.addClassCleanup(stack.close)
        cls.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="telnetz-tls-")))
        for name in ("server", "other", "inspect"):
            names = "DNS:localhost"
            if name == "inspect":
                names += ",IP:127.0.0.1,IP:2001:db8::1,URI:spiffe://local/service,email:agent@example.test"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                    "-subj", f"/CN={name}", "-addext", f"subjectAltName={names}",
                    "-addext", "basicConstraints=critical,CA:FALSE",
                    "-keyout", str(cls.directory / f"{name}.key"),
                    "-out", str(cls.directory / f"{name}.crt"),
                ],
                check=True, capture_output=True,
            )
        cls.cert = cls.directory / "server.crt"
        cls.key = cls.directory / "server.key"
        cls.other = cls.directory / "other.crt"
        cls.der = cls.directory / "server.der"
        cls.der.write_bytes(ssl.PEM_cert_to_DER_cert(cls.cert.read_text()))
        cls.bundle = cls.directory / "bundle.pem"
        cls.bundle.write_bytes(cls.other.read_bytes() + cls.cert.read_bytes())
        cls.port = stack.enter_context(tls_server(cls.cert, cls.key))

    def client(self, *options, host="localhost", port=None, expect="ready"):
        return subprocess.run(
            [
                str(BINARY), host, str(self.port if port is None else port),
                "-q", "-w", "2", "--connect-timeout", "2",
                *(["--expect", expect] if expect is not None else []),
                *map(str, options),
            ],
            input=b"", capture_output=True, timeout=5,
        )

    def assert_connected(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"ready\r\n")
        self.assertEqual(result.stderr, b"")

    def test_pem_der_and_bundle(self):
        for options in ((), ("--no-default-ca",)):
            for path in (self.cert, self.der, self.bundle):
                with self.subTest(path=path.name, options=options):
                    self.assert_connected(self.client("--tls", *options, "--cacert", path))

    def test_repeated_files(self):
        for options in ((), ("--no-default-ca",)):
            for paths in ((self.cert, self.other), (self.other, self.cert)):
                with self.subTest(paths=paths, options=options):
                    self.assert_connected(
                        self.client("--tls", *options, "--cacert", paths[0], "--cacert", paths[1])
                    )

    def test_untrusted_certificate(self):
        for options in (
            (), ("--cacert", self.other),
            ("--no-default-ca",), ("--no-default-ca", "--cacert", self.other),
        ):
            with self.subTest(options=options):
                result = self.client("--tls", *options)
                self.assertEqual(result.returncode, 1, result.stderr.decode())
                self.assertIn(b"UnknownIssuer", result.stderr)

    def test_hostname_mismatch(self):
        for options in ((), ("--no-default-ca",)):
            with self.subTest(options=options):
                result = self.client("--tls", *options, "--cacert", self.cert, host="127.0.0.1")
                self.assertEqual(result.returncode, 1, result.stderr.decode())
                self.assertIn(b"certificate not valid for name", result.stderr)

    def test_server_name_override(self):
        names = queue.Queue()
        with tls_server(self.cert, self.key, server_names=names) as port:
            result = self.client(
                "--tls", "--cacert", self.cert, "--server-name", "localhost", "--json",
                host="127.0.0.1", port=port,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["server_name"], "localhost")
            self.assertEqual(report["reason"], "expect_matched")
            self.assertEqual(names.get(timeout=1), "localhost")
            wrong = self.client(
                "--tls", "--cacert", self.cert, "--server-name", "wrong.example", "--json",
                host="127.0.0.1", port=port,
            )
            self.assertEqual(wrong.returncode, 1)
            self.assertEqual(json.loads(wrong.stdout)["reason"], "hostname_mismatch")
            self.assertEqual(names.get(timeout=1), "wrong.example")
            dumped = self.client(
                "--tls", "--dump-cert", "-", "--server-name", "localhost",
                host="127.0.0.1", port=port, expect=None,
            )
            self.assertEqual(dumped.returncode, 0, dumped.stderr)
            self.assertEqual(ssl.PEM_cert_to_DER_cert(dumped.stdout.decode()), self.der.read_bytes())
            self.assertEqual(names.get(timeout=1), "localhost")

    def test_expired_certificate(self):
        config = self.directory / "ca.cnf"
        config.write_text(
            "[ca]\ndefault_ca = local\n"
            "[local]\ndatabase = index.txt\nserial = serial\n"
            "default_md = sha256\npolicy = policy\nx509_extensions = server\n"
            "[policy]\ncommonName = supplied\n"
            "[server]\nbasicConstraints = critical,CA:FALSE\nsubjectAltName = DNS:localhost\n"
        )
        (self.directory / "index.txt").write_text("")
        (self.directory / "serial").write_text("01\n")
        csr = self.directory / "expired.csr"
        expired = self.directory / "expired.crt"
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(self.key), "-subj", "/CN=expired", "-out", str(csr)],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "openssl", "ca", "-batch", "-selfsign", "-config", str(config),
                "-in", str(csr), "-keyfile", str(self.key), "-cert", str(self.cert),
                "-out", str(expired), "-outdir", str(self.directory), "-notext",
                "-startdate", "20200101000000Z", "-enddate", "20210101000000Z",
            ],
            cwd=self.directory, check=True, capture_output=True,
        )
        with tls_server(expired, self.key) as port:
            for options in ((), ("--no-default-ca",)):
                with self.subTest(options=options):
                    result = self.client("--tls", *options, "--cacert", expired, port=port)
                    self.assertEqual(result.returncode, 1, result.stderr.decode())
                    self.assertIn(b"certificate expired", result.stderr)
            dumped = self.client("--tls", "--dump-cert", "-", port=port, expect=None)
            verified_info = self.client(
                "--tls", "--tls-info", "--cacert", expired, "--json", port=port, expect=None,
            )
            self.assertEqual(verified_info.returncode, 1)
            self.assertEqual(json.loads(verified_info.stdout)["reason"], "certificate_expired")
            skipped_info = self.client(
                "--tls", "--tls-info", "--insecure", "--json", port=port, expect=None,
            )
            self.assertEqual(skipped_info.returncode, 0, skipped_info.stderr)
            info = json.loads(skipped_info.stdout)["tls"]
            self.assertEqual(info["verification"], "skipped")
            self.assertTrue(info["certificates"][0]["expired"])
            self.assertEqual(info["certificates"][0]["not_after_unix"], 1609459200)
        self.assertEqual(dumped.returncode, 0, dumped.stderr.decode())
        self.assertEqual(
            ssl.PEM_cert_to_DER_cert(dumped.stdout.decode()),
            ssl.PEM_cert_to_DER_cert(expired.read_text()),
        )

    def test_dump_and_import(self):
        path = self.directory / "dumped.crt"
        result = self.client("--tls", "--dump-cert", path, expect=None)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(ssl.PEM_cert_to_DER_cert(path.read_text()), self.der.read_bytes())
        self.assert_connected(self.client("--tls", "--cacert", path))

    def test_dump_stdout_and_hostname_mismatch(self):
        result = self.client("--tls", "--dump-cert", "-", host="127.0.0.1", expect=None)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        self.assertEqual(ssl.PEM_cert_to_DER_cert(result.stdout.decode()), self.der.read_bytes())
        self.assertEqual(result.stdout.count(b"-----BEGIN CERTIFICATE-----"), 1)
        self.assertTrue(all(len(line) <= 64 for line in result.stdout.splitlines()[1:-1]))

    def test_dump_does_not_read_stdin_or_send_application_data(self):
        received = queue.Queue()
        with tls_server(self.cert, self.key, received=received, send_banner=False) as port:
            with subprocess.Popen(
                [str(BINARY), "localhost", str(port), "--tls", "--dump-cert", "-", "-q"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    process.stdin.write(b"unsent input\n")
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=5), 0)
                    self.assertEqual(
                        ssl.PEM_cert_to_DER_cert(process.stdout.read().decode()), self.der.read_bytes()
                    )
                    self.assertEqual(process.stderr.read(), b"")
                    self.assertEqual(received.get(timeout=3), b"")
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_tls_info_does_not_read_stdin_or_send_application_data(self):
        received = queue.Queue()
        with tls_server(self.cert, self.key, received=received, send_banner=False) as port:
            with subprocess.Popen(
                [str(BINARY), "localhost", str(port), "--tls", "--tls-info", "--cacert", str(self.cert)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    process.stdin.write(b"unsent input\n")
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=5), 0)
                    info = json.loads(process.stdout.read())
                    self.assertEqual(info["verification"], "verified")
                    self.assertEqual(process.stderr.read(), b"")
                    self.assertEqual(received.get(timeout=3), b"")
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_tls_info_metadata(self):
        cert = self.directory / "inspect.crt"
        key = self.directory / "inspect.key"
        der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        fingerprint = ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())
        dates = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-startdate", "-enddate"],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        before, after = (int(ssl.cert_time_to_seconds(line.split("=", 1)[1])) for line in dates)
        for version, expected in ((ssl.TLSVersion.TLSv1_2, "TLSv1_2"), (ssl.TLSVersion.TLSv1_3, "TLSv1_3")):
            with self.subTest(version=expected):
                with tls_server(cert, key, tls_version=version) as port:
                    result = self.client("--tls", "--tls-info", "--cacert", cert, "--json", port=port, expect=None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                report = json.loads(result.stdout)
                self.assertEqual(report["reason"], "tls_info")
                self.assertEqual(report["bytes_received"], 0)
                self.assertEqual(report["bytes_sent"], 0)
                info = report["tls"]
                self.assertEqual(info["protocol_version"], expected)
                self.assertTrue(info["cipher_suite"])
                self.assertEqual(info["verification"], "verified")
                leaf = info["certificates"][0]
                self.assertIsNone(leaf["parse_error"])
                self.assertEqual(leaf["sha256_fingerprint"], fingerprint)
                self.assertEqual(leaf["subject"], "CN=inspect")
                self.assertEqual(leaf["issuer"], "CN=inspect")
                self.assertEqual(leaf["not_before_unix"], before)
                self.assertEqual(leaf["not_after_unix"], after)
                self.assertFalse(leaf["expired"])
                self.assertFalse(leaf["not_yet_valid"])
                names = {(entry["type"], entry["value"]) for entry in leaf["subject_alt_names"]}
                self.assertEqual(names, {
                    ("DNS", "localhost"), ("IP", "127.0.0.1"), ("IP", "2001:db8::1"),
                    ("URI", "spiffe://local/service"), ("email", "agent@example.test"),
                })

    def test_tls_info_verification_and_chain(self):
        untrusted = self.client("--tls", "--tls-info", "--json", expect=None)
        self.assertEqual(untrusted.returncode, 1)
        self.assertEqual(json.loads(untrusted.stdout)["reason"], "unknown_issuer")
        skipped = self.client("--tls", "--tls-info", "--insecure", "--json", expect=None)
        self.assertEqual(skipped.returncode, 0)
        self.assertEqual(json.loads(skipped.stdout)["tls"]["verification"], "skipped")
        chain = self.directory / "server-chain.pem"
        chain.write_bytes(self.cert.read_bytes() + self.other.read_bytes())
        with tls_server(chain, self.key) as port:
            result = self.client("--tls", "--tls-info", "--cacert", self.cert, "--json", port=port, expect=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        certificates = json.loads(result.stdout)["tls"]["certificates"]
        self.assertEqual([entry["subject"] for entry in certificates], ["CN=server", "CN=other"])

    def test_dump_write_errors(self):
        existing = self.directory / "existing.crt"
        existing.write_bytes(b"existing trusted certificate\n")
        for path in (existing, self.directory, self.directory / "absent" / "server.crt"):
            with self.subTest(path=path):
                result = self.client("--tls", "--dump-cert", path, expect=None)
                self.assertEqual(result.returncode, 1, result.stderr.decode())
                self.assertEqual(result.stdout, b"")
                self.assertIn(str(path).encode(), result.stderr)
        self.assertEqual(existing.read_bytes(), b"existing trusted certificate\n")

    def test_dump_connection_failure_does_not_create_file(self):
        path = self.directory / "failed.crt"
        result = self.client("--tls", "--dump-cert", path, port=0, expect=None)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertFalse(path.exists())

    def test_invalid_files(self):
        invalid_pem = b"-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n"
        invalid_der = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        files = {
            "empty.crt": b"",
            "invalid.pem": invalid_pem,
            "invalid.der": b"not a certificate",
            "invalid-cert.pem": invalid_der,
            "key-only.pem": self.key.read_bytes(),
            "invalid-bundle.pem": self.cert.read_bytes() + invalid_pem,
            "invalid-cert-bundle.pem": self.cert.read_bytes() + invalid_der,
            "missing.crt": None,
        }
        for name, contents in files.items():
            with self.subTest(name=name):
                path = self.directory / name
                if contents is not None:
                    path.write_bytes(contents)
                result = self.client("--tls", "--cacert", path, port=0)
                self.assertEqual(result.returncode, 1, result.stderr.decode())
                self.assertIn(str(path).encode(), result.stderr)

    def test_invalid_options(self):
        cases = (
            (("--tls-info",), b"--tls-info requires --tls"),
            (("--tls", "--tls-info", "--dump-cert", "-"), b"--tls-info cannot be used with"),
            (("--tls", "--tls-info", "-c", "PING"), b"--tls-info cannot be used with"),
            (("--tls", "--tls-info", "--expect", "ready"), b"--tls-info cannot be used with"),
            (("--server-name", "localhost"), b"--server-name requires --tls"),
            (("--tls", "--server-name"), b"--server-name requires a value"),
            (("--tls", "--server-name", "bad name"), b"--server-name requires a valid"),
            (("--no-default-ca",), b"--no-default-ca requires --tls"),
            (("--cacert", self.cert), b"--cacert requires --tls"),
            (("--tls", "--cacert", self.cert, "--insecure"), b"--cacert cannot be used with --insecure"),
            (("--tls", "--cacert"), b"--cacert requires a value"),
            (("--dump-cert", "-"), b"--dump-cert requires --tls"),
            (("--tls", "--dump-cert"), b"--dump-cert requires a value"),
            (("--tls", "--dump-cert", "-", "--cacert", self.cert), b"--dump-cert cannot be used with"),
            (("--tls", "--dump-cert", "-", "-c", "PING"), b"--dump-cert cannot be used with"),
            (("--tls", "--dump-cert", "-", "--expect", "ready"), b"--dump-cert cannot be used with"),
        )
        for options, message in cases:
            with self.subTest(options=options):
                result = self.client(*options, port=0, expect=None)
                self.assertEqual(result.returncode, 2, result.stderr.decode())
                self.assertIn(message, result.stderr)

    def test_insecure(self):
        self.assert_connected(self.client("--tls", "--insecure"))

    def test_tls_shutdown_write(self):
        received = queue.Queue()
        def reply(stream):
            data = bytearray()
            while chunk := stream.recv(4096):
                data.extend(chunk)
            received.put(bytes(data))
            stream.sendall(b"reply:" + data)

        with tls_server(self.cert, self.key, action=reply) as port:
            result = self.client(
                "--tls", "--cacert", self.cert, "--shutdown-write", "--json", "-c", "PING",
                port=port, expect="reply:",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["reason"], "expect_matched")
            self.assertEqual(report["bytes_sent"], 6)
            self.assertEqual(report["output_utf8"], "reply:PING\r\n")
            self.assertEqual(received.get(timeout=1), b"PING\r\n")

    def test_json_tls_errors(self):
        for options, host, reason in (
            ((), "localhost", "unknown_issuer"),
            (("--cacert", self.cert), "127.0.0.1", "hostname_mismatch"),
        ):
            with self.subTest(reason=reason):
                result = self.client("--json", "--tls", *options, host=host)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, b"")
                report = json.loads(result.stdout)
                self.assertEqual(report["phase"], "tls")
                self.assertEqual(report["reason"], reason)

    def test_json_deadline_loading_certificate(self):
        fifo = self.directory / "blocked.crt"
        os.mkfifo(fifo)
        result = self.client("--json", "--tls", "--cacert", fifo, "--max-time", "0.1", expect=None)
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 4)
        self.assertEqual(report["phase"], "certificate")
        self.assertEqual(report["reason"], "max_time")

    def test_json_dump(self):
        path = self.directory / "json-dump.crt"
        result = self.client("--json", "--tls", "--dump-cert", path, expect=None)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["reason"], "certificate_dumped")
        self.assertEqual(json.loads(result.stdout)["tls"]["verification"], "skipped")
        self.assertEqual(ssl.PEM_cert_to_DER_cert(path.read_text()), self.der.read_bytes())
        invalid = self.client("--json", "--tls", "--dump-cert", "-", expect=None)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(json.loads(invalid.stdout)["phase"], "usage")


if __name__ == "__main__":
    unittest.main(verbosity=2)
