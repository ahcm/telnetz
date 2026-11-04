"""Local CLI regression tests. Run after cargo build; TELNETZ_BIN overrides the binary."""

import contextlib
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
        with tcp_server(lambda stream: time.sleep(1)) as port:
            result = client(port, "--raw", "--max-time", "0.1", data=b"x" * (8 * 1024 * 1024))
        self.assertEqual(result.returncode, 4, result.stderr)

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
