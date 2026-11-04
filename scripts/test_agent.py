"""Local CLI regression tests. Run after cargo build; TELNETZ_BIN overrides the binary."""

import contextlib
import base64
import json
import os
from pathlib import Path
import socketserver
import subprocess
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TELNETZ_BIN", ROOT / "target/debug/telnetz")).resolve()


@contextlib.contextmanager
def tcp_server(action):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                action(self.request)
            except (ConnectionError, TimeoutError):
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


def client(port, *options, data=b""):
    return subprocess.run(
        [str(BINARY), "127.0.0.1", str(port), "-q", *map(str, options)],
        input=data, capture_output=True, timeout=4,
    )


class AgentTests(unittest.TestCase):
    def test_shutdown_write_preserves_replies(self):
        def reply(stream):
            received = bytearray()
            while chunk := stream.recv(4096):
                received.extend(chunk)
            stream.sendall(b"reply:" + received)

        for options, data, expected in (
            (("-c", "PING"), b"", b"PING\r\n"),
            ((), b"one\ntwo\n", b"one\r\ntwo\r\n"),
            (("--raw",), b"\x00\xffhello", b"\x00\xffhello"),
            ((), b"", b""),
        ):
            with self.subTest(options=options, data=data):
                with tcp_server(reply) as port:
                    result = client(port, "--shutdown-write", "--max-time", "1", *options, data=data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"reply:" + expected)

    def test_shutdown_write_is_opt_in(self):
        def reply(stream):
            while stream.recv(4096):
                pass
            stream.sendall(b"reply")

        with tcp_server(reply) as port:
            result = client(port, "--max-time", "0.05", "-c", "PING")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(result.stdout, b"")

    def result_json(self, result):
        self.assertEqual(result.stderr, b"")
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["exit_code"], result.returncode)
        self.assertEqual(report["ok"], result.returncode == 0)
        self.assertGreaterEqual(report["elapsed_ms"], 0)
        return report

    def test_json_binary_and_sent_counts(self):
        def reply(stream):
            self.assertEqual(stream.recv(1024), b"PING\r\n")
            stream.sendall(b"\x00\xffhello")

        with tcp_server(reply) as port:
            report = self.result_json(client(port, "--json", "-c", "PING", "--max-time", "1"))
        self.assertEqual(report["reason"], "eof")
        self.assertEqual(report["phase"], "read")
        self.assertEqual(report["bytes_sent"], 6)
        self.assertEqual(report["bytes_received"], 7)
        self.assertEqual(base64.b64decode(report["output_base64"]), b"\x00\xffhello")
        self.assertIsNone(report["output_utf8"])
        self.assertTrue(report["peer_addr"].startswith("127.0.0.1:"))

    def test_json_termination_conditions(self):
        cases = (
            (("--expect", "ready"), "expect_matched", 0),
            (("-w", "0.05"), "idle_timeout", 0),
            (("-w", "0.05", "--expect", "absent"), "idle_timeout", 3),
            (("--max-time", "0.05"), "max_time", 4),
            (("--max-bytes", "3"), "max_bytes", 4),
        )
        def reply(stream):
            stream.sendall(b"ready")
            stream.recv(1)

        for options, reason, code in cases:
            with self.subTest(reason=reason, options=options):
                with tcp_server(reply) as port:
                    result = client(port, "--json", "--max-time", "1", *options)
                report = self.result_json(result)
                self.assertEqual(result.returncode, code)
                self.assertEqual(report["reason"], reason)
                self.assertEqual(report["matched"], reason == "expect_matched")

    def test_json_usage_and_connection_errors(self):
        for options in (("--json", "--unknown"), ("--unknown", "--json")):
            report = self.result_json(client(0, *options))
            self.assertEqual(report["phase"], "usage")
            self.assertEqual(report["reason"], "invalid_arguments")
            self.assertIsNotNone(report["error"])
        report = self.result_json(client(0, "--json"))
        self.assertEqual(report["phase"], "connect")
        self.assertEqual(report["reason"], "connection_refused")
        plain = client(0, "-c", "--json")
        self.assertEqual(plain.stdout, b"")
        self.assertIn(b"Error:", plain.stderr)

    def test_json_default_capture_cap(self):
        with tcp_server(lambda stream: stream.sendall(b"x" * (1024 * 1024 + 10))) as port:
            report = self.result_json(client(port, "--json", "--max-time", "2"))
        self.assertEqual(report["reason"], "max_bytes")
        self.assertEqual(report["bytes_received"], 1024 * 1024)
        self.assertEqual(len(base64.b64decode(report["output_base64"])), 1024 * 1024)

    def test_json_deadline_with_blocked_stdout(self):
        with tcp_server(lambda stream: stream.sendall(b"x" * 100000)) as port:
            with subprocess.Popen(
                [str(BINARY), "127.0.0.1", str(port), "--json", "--max-time", "0.1"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    self.assertEqual(process.wait(timeout=2), 4)
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_deadline_with_continuous_traffic(self):
        def flood(stream):
            while True:
                stream.sendall(b"x")
                time.sleep(0.01)

        with tcp_server(flood) as port:
            result = client(port, "-w", "1", "--max-time", "0.15")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertTrue(result.stdout)

    def test_deadline_with_open_stdin(self):
        with tcp_server(lambda stream: stream.recv(1)) as port:
            with subprocess.Popen(
                [str(BINARY), "127.0.0.1", str(port), "-q", "--max-time", "0.1"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    self.assertEqual(process.wait(timeout=2), 4)
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_deadline_during_tls_handshake(self):
        with tcp_server(lambda stream: time.sleep(0.5)) as port:
            result = client(port, "--tls", "--max-time", "0.1", "--connect-timeout", "2")
        self.assertEqual(result.returncode, 4, result.stderr)

    def test_deadline_during_blocked_write(self):
        for options in ((), ("--json",)):
            with self.subTest(options=options):
                with tcp_server(lambda stream: time.sleep(1)) as port:
                    result = client(port, *options, "--raw", "--max-time", "0.1", data=b"x" * (8 * 1024 * 1024))
                self.assertEqual(result.returncode, 4, result.stderr)
                if options:
                    report = self.result_json(result)
                    self.assertEqual(report["phase"], "write")
                    self.assertGreater(report["bytes_sent"], 0)
                    self.assertLess(report["bytes_sent"], 8 * 1024 * 1024)

    def test_receive_limit_and_expect_boundary(self):
        for limit, expected_exit, expected_output in ((4, 4, b"abcd"), (6, 0, b"abcdef")):
            with self.subTest(limit=limit):
                with tcp_server(lambda stream: stream.sendall(b"abcdefmore")) as port:
                    result = client(port, "--max-bytes", limit, "--expect", "abcdef", "--max-time", "1")
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertEqual(result.stdout, expected_output)

    def test_receive_limit_across_reads(self):
        def chunks(stream):
            for _ in range(10):
                stream.sendall(b"abc")
                time.sleep(0.01)

        with tcp_server(chunks) as port:
            result = client(port, "--max-bytes", "7", "--max-time", "1")
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(result.stdout, b"abcabca")

    def test_invalid_limits(self):
        for options in (
            ("--max-time", "nan"), ("--max-time", "-1"), ("--max-time", "inf"),
            ("--max-bytes", "0"), ("--max-bytes", "-1"), ("--max-bytes", "1.5"),
            ("--max-bytes", str(2**64)), ("--max-time",), ("--max-bytes",),
        ):
            with self.subTest(options=options):
                self.assertEqual(client(0, *options).returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
