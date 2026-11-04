"""Conversation script regression tests. Run after cargo build."""

import base64
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import unittest

from test_agent import BINARY, client, tcp_server
from test_tls import tls_server


class ScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="telnetz-scripts-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.cert = cls.directory / "server.crt"
        cls.key = cls.directory / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            "-addext", "basicConstraints=critical,CA:FALSE", "-out", str(cls.cert), "-keyout", str(cls.key),
        ], check=True, capture_output=True)

    def script_file(self, document, extension="json"):
        path = self.directory / f"conversation.{extension}"
        path.write_text(json.dumps(document) if not isinstance(document, str) else document)
        return path

    def run_script(self, port, document, *options, extension="json", plain=False):
        path = self.script_file(document, extension)
        result = client(port, "--script", path, "--max-time", "2", *([] if plain else ["--json"]), *options)
        if plain:
            return result
        self.assertEqual(result.stderr, b"", result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["exit_code"], result.returncode)
        return report

    def test_json_and_toml_conversations(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        document = json.loads((examples / "smtp.json").read_text())
        toml = (examples / "smtp.toml").read_text()
        received = queue.Queue()
        def smtp(stream):
            stream.sendall(b"220 hello\r\n")
            lines = stream.makefile("rb")
            first = lines.readline()
            stream.sendall(b"250-first\r\n250 ready\r\n")
            second = lines.readline()
            received.put((first, second))
            stream.sendall(b"221 bye\r\n")
            lines.close()

        reports = []
        for extension, source in (("json", document), ("toml", toml)):
            with self.subTest(extension=extension):
                with tcp_server(smtp) as port:
                    report = self.run_script(port, source, extension=extension)
                self.assertEqual(report["exit_code"], 0, report)
                self.assertEqual(report["reason"], "script_completed")
                self.assertEqual(received.get(timeout=1), (b"EHLO agent.example\r\n", b"QUIT\r\n"))
                self.assertEqual(report["bytes_sent"], 26)
                reports.append(report)
        self.assertEqual(reports[0]["output_base64"], reports[1]["output_base64"])
        paths = [[(step["path"], step["reason"]) for step in report["script"]["steps"]] for report in reports]
        self.assertEqual(paths[0], paths[1])
        self.assertIn(("steps[3]", "sent"), paths[0])

    def test_fragmented_and_buffered_matches(self):
        for chunks in ((b"one|two|three",), tuple(bytes([byte]) for byte in b"one|two|three")):
            with self.subTest(chunks=chunks):
                def reply(stream):
                    for chunk in chunks:
                        stream.sendall(chunk)
                with tcp_server(reply) as port:
                    report = self.run_script(port, {"steps": [
                        {"expect": "one"}, {"expect": "two"}, {"expect": "three"},
                    ]}, "--max-bytes", "13")
                self.assertEqual(report["exit_code"], 0, report)
                self.assertEqual(report["output_utf8"], "one|two|three")
                ranges = [(step["match_start"], step["match_end"]) for step in report["script"]["steps"]]
                self.assertEqual(ranges, [(0, 3), (4, 7), (8, 13)])

    def test_case_then_precedes_common_then(self):
        received = queue.Queue()
        def reply(stream):
            stream.sendall(b"ready")
            reader = stream.makefile("rb")
            received.put((reader.readline(), reader.readline()))
            stream.sendall(b"done")
            reader.close()

        with tcp_server(reply) as port:
            report = self.run_script(port, {"steps": [
                {"expect": [{"text": "ready", "then": [{"send_line": "branch"}]}],
                 "then": [{"send_line": "common"}]}, {"expect": "done"},
            ]})
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(received.get(timeout=1), (b"branch\r\n", b"common\r\n"))

    def test_toml_tables_and_else(self):
        source = '''# Array-of-table steps and nested branches
version = 1
[[steps]]
expect = 'ready'
[[steps.then]]
send_line = 'GO'
[[steps]]
expect = 'done'
'''
        def reply(stream):
            stream.sendall(b"ready")
            if stream.recv(4096) == b"GO\r\n":
                stream.sendall(b"done")
        with tcp_server(reply) as port:
            report = self.run_script(port, source, extension="toml")
        self.assertEqual(report["exit_code"], 0, report)
        with tcp_server(lambda stream: None) as port:
            failed = self.run_script(port, '''[[steps]]
expect = '+OK'
else = [{ fail = 'expected greeting' }]
''', extension="toml")
        self.assertEqual(failed["exit_code"], 3)
        self.assertIn("expected greeting", failed["error"])

    def test_case_selection_is_independent_of_reads(self):
        for chunks in ((b"abcd",), (b"abc", b"d")):
            with self.subTest(chunks=chunks):
                def reply(stream):
                    for chunk in chunks:
                        stream.sendall(chunk)
                with tcp_server(reply) as port:
                    report = self.run_script(port, {"steps": [{"expect": [
                        {"text": "abcd", "then": [{"fail": "longer case should lose"}]},
                        {"text": "bc"},
                    ]}]})
                self.assertEqual(report["exit_code"], 0, report)
                self.assertEqual(report["script"]["steps"][0]["matched_case"], 1)
        with tcp_server(lambda stream: stream.sendall(b"OK")) as port:
            tied = self.run_script(port, {"steps": [{"expect": [
                {"text": "OK"}, {"text": "OK", "then": [{"fail": "second case should lose"}]},
            ]}]})
        self.assertEqual(tied["exit_code"], 0, tied)
        self.assertEqual(tied["script"]["steps"][0]["matched_case"], 0)

    def test_send_types_line_endings_and_write_shutdown(self):
        received = queue.Queue()
        def reply(stream):
            data = bytearray()
            while chunk := stream.recv(4096):
                data.extend(chunk)
            received.put(bytes(data))
            stream.sendall(b"\x00\xff" + data)

        for options, eol in (((), b"\r\n"), (("--lf",), b"\n")):
            with self.subTest(options=options):
                with tcp_server(reply) as port:
                    report = self.run_script(port, {"steps": [
                        {"send_base64": "AP8="}, {"send": "exact\n"}, {"send_line": "line"},
                        {"shutdown_write": True}, {"expect_eof": True},
                    ]}, *options)
                expected = b"\x00\xffexact\nline" + eol
                self.assertEqual(received.get(timeout=1), expected)
                self.assertEqual(report["exit_code"], 0, report)
                self.assertEqual(base64.b64decode(report["output_base64"]), b"\x00\xff" + expected)
                self.assertIsNone(report["output_utf8"])
                self.assertEqual(report["bytes_sent"], len(expected))

    def test_known_negative_reply_and_explicit_failure(self):
        with tcp_server(lambda stream: stream.sendall(b"-ERR rejected\r\n")) as port:
            report = self.run_script(port, {"steps": [{"expect": [
                {"text": "+OK"}, {"text": "-ERR", "then": [{"fail": "server rejected request"}]},
            ]}, {"send_line": "must not run"}]})
        self.assertEqual(report["exit_code"], 3, report)
        self.assertEqual(report["reason"], "script_failure")
        self.assertIn("server rejected request", report["error"])
        self.assertEqual(report["script"]["current_step"], "steps[0].expect[1].then[0]")
        self.assertEqual(len(report["script"]["steps"]), 2)
        self.assertEqual(report["bytes_sent"], 0)

    def test_timeout_handler_precedence_and_continuation(self):
        for handler in ("else", "on_timeout"):
            with self.subTest(handler=handler):
                def reply(stream):
                    if stream.recv(4096) == b"fallback\r\n":
                        stream.sendall(b"ready")
                step = {"expect": "absent", "timeout": 0.03, "then": [{"fail": "wrong success branch"}]}
                if handler == "on_timeout":
                    step["else"] = [{"fail": "specific handler should win"}]
                step[handler] = [{"send_line": "fallback"}]
                with tcp_server(reply) as port:
                    report = self.run_script(port, {"steps": [step, {"expect": "ready"}]})
                self.assertEqual(report["exit_code"], 0, report)
                self.assertIsNone(report["error"])
                first = report["script"]["steps"][0]
                self.assertEqual(first["reason"], "step_timeout")
                self.assertTrue(first["handled"])
                self.assertEqual(report["script"]["steps"][1]["path"], f"steps[0].{handler}[0]")

    def test_eof_handler_and_buffer_preservation(self):
        for handler in ("else", "on_eof"):
            with self.subTest(handler=handler):
                step = {"expect": "absent", handler: []}
                if handler == "on_eof":
                    step["else"] = [{"fail": "specific handler should win"}]
                with tcp_server(lambda stream: stream.sendall(b"partial")) as port:
                    report = self.run_script(port, {"steps": [step, {"expect": "partial"}, {"expect_eof": True}]})
                self.assertEqual(report["exit_code"], 0, report)
                first = report["script"]["steps"][0]
                self.assertEqual(first["reason"], "eof")
                self.assertTrue(first["handled"])

    def test_unhandled_timeout_and_eof(self):
        for action, reason in ((lambda stream: stream.recv(1), "step_timeout"), (lambda stream: None, "eof")):
            with self.subTest(reason=reason):
                with tcp_server(action) as port:
                    report = self.run_script(port, {"step_timeout": 0.03, "steps": [{"name": "greeting", "expect": "ready"}]})
                self.assertEqual(report["exit_code"], 3, report)
                self.assertEqual(report["reason"], reason)
                self.assertEqual(report["script"]["steps"][0]["name"], "greeting")
                self.assertFalse(report["script"]["steps"][0]["handled"])

    def test_hard_limits_cannot_be_handled(self):
        for options, action, reason in (
            (("--max-time", "0.03"), lambda stream: stream.recv(1), "max_time"),
            (("--max-bytes", "3"), lambda stream: stream.sendall(b"abcdef"), "max_bytes"),
        ):
            with self.subTest(reason=reason):
                with tcp_server(action) as port:
                    report = self.run_script(port, {"steps": [{
                        "expect": "ready", "timeout": 1, "else": [{"fail": "must not run"}],
                        "on_timeout": [{"fail": "must not run"}], "on_eof": [{"fail": "must not run"}],
                    }]}, *options)
                self.assertEqual(report["exit_code"], 4, report)
                self.assertEqual(report["reason"], reason)
                self.assertEqual(len(report["script"]["steps"]), 1)
                self.assertEqual(report["script"]["steps"][0]["reason"], reason)
                self.assertEqual(report["script"]["steps"][0]["exit_code"], 4)

    def test_idle_timeout_can_be_handled(self):
        with tcp_server(lambda stream: stream.recv(1)) as port:
            report = self.run_script(port, {"steps": [{"expect": "ready", "timeout": 1, "on_timeout": []}]}, "-w", "0.02")
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["script"]["steps"][0]["reason"], "idle_timeout")

    def test_send_after_shutdown_is_a_transport_error(self):
        with tcp_server(lambda stream: stream.recv(1)) as port:
            report = self.run_script(port, {"steps": [{"shutdown_write": True}, {"send_line": "invalid"}]})
        self.assertEqual(report["exit_code"], 1, report)
        self.assertEqual(report["phase"], "write")
        self.assertEqual(report["reason"], "broken_pipe")
        self.assertEqual(report["script"]["current_step"], "steps[1]")
        self.assertEqual(report["script"]["steps"][1]["reason"], "broken_pipe")

    def test_invalid_scripts_fail_before_connecting(self):
        cases = [
            "{", {"steps": []}, {"version": 2, "steps": [{"send": "x"}]},
            '{"steps": [{"send":"x"}], "steps": [{"send":"y"}]}',
            {"unknown": 1, "steps": [{"send": "x"}]}, {"steps": [{"unknown": True}]},
            {"steps": [{"send": "x", "send_line": "x"}]}, {"steps": [{"expect": ""}]},
            {"steps": [{"expect": []}]}, {"steps": [{"send_base64": "!bad!"}]},
            {"steps": [{"send": "x", "else": []}]}, {"steps": [{"expect_eof": False}]},
            {"steps": [{"shutdown_write": False}]}, {"step_timeout": -1, "steps": [{"send": "x"}]},
            {"steps": [{"expect": "x", "timeout": 0}]},
            {"steps": [{"expect": [{"text": "x", "unknown": 1}]}]},
            {"steps": [{"expect": "ready", "then": [{"invalid": True}]}]},
        ]
        for document in cases:
            with self.subTest(document=document):
                report = self.run_script(0, document)
                self.assertEqual(report["exit_code"], 2, report)
                self.assertEqual(report["reason"], "invalid_script")
                self.assertIsNone(report["peer_addr"])
        for source in ("steps = [", 'step_timeout = nan\nsteps = [{ expect = "x" }]',
                       'steps = [{ send = "x", send = "y" }]'):
            with self.subTest(toml=source):
                self.assertEqual(self.run_script(0, source, extension="toml")["exit_code"], 2)

    def test_script_resource_bounds(self):
        nested = {"expect": "x"}
        for _ in range(20):
            nested = {"expect": "x", "then": [nested]}
        for document in (
            {"steps": [nested]}, {"steps": [{"send": ""}] * 4097},
            {"steps": [{"expect": [{"text": "x"}] * 129}]}, " " * (1024 * 1024 + 1),
        ):
            with self.subTest(kind=type(document)):
                self.assertEqual(self.run_script(0, document)["exit_code"], 2)

    def test_file_and_cli_errors(self):
        result = client(0, "--json", "--script", self.directory / "missing.json")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["reason"], "script_error")
        self.assertEqual(self.run_script(0, {"steps": [{"send": "x"}]}, extension="txt")["exit_code"], 2)
        path = self.script_file({"steps": [{"send": "x"}]})
        for options in (("-c", "x"), ("--expect", "x"), ("--raw",), ("--shutdown-write",),
                        ("--tls-info",), ("--dump-cert", "-")):
            with self.subTest(options=options):
                invalid = client(0, "--json", "--script", path, *options)
                self.assertEqual(invalid.returncode, 2)
                self.assertEqual(json.loads(invalid.stdout)["reason"], "invalid_arguments")
        self.assertEqual(client(0, "--json", "--script").returncode, 2)

    def test_script_does_not_read_stdin(self):
        path = self.script_file({"steps": [{"expect": "ready"}]})
        with tcp_server(lambda stream: stream.sendall(b"ready")) as port:
            with subprocess.Popen(
                [str(BINARY), "127.0.0.1", str(port), "--json", "--script", str(path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    self.assertEqual(process.wait(timeout=2), 0)
                    self.assertEqual(json.loads(process.stdout.read())["reason"], "script_completed")
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_deadline_while_loading_script(self):
        path = self.directory / "blocked.json"
        os.mkfifo(path)
        result = client(0, "--json", "--script", path, "--max-time", "0.03")
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 4, report)
        self.assertEqual(report["phase"], "script")
        self.assertEqual(report["reason"], "max_time")

    def test_plain_output(self):
        with tcp_server(lambda stream: stream.sendall(b"ready\r\n")) as port:
            result = self.run_script(port, {"steps": [{"expect": "ready"}]}, plain=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"ready\r\n")
        with tcp_server(lambda stream: None) as port:
            failed = self.run_script(port, {"steps": [{"fail": "explicit failure"}]}, plain=True)
        self.assertEqual(failed.returncode, 3)
        self.assertIn(b"steps[0]: explicit failure", failed.stderr)

    def test_default_receive_cap_without_json(self):
        with tcp_server(lambda stream: stream.sendall(b"x" * (1024 * 1024 + 1))) as port:
            result = self.run_script(port, {"steps": [{"expect": "absent"}]}, plain=True)
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(len(result.stdout), 1024 * 1024)

    def test_step_deadline_during_blocked_output_is_terminal(self):
        path = self.script_file({"steps": [{"expect": "absent", "timeout": 0.03, "else": []}]})
        with tcp_server(lambda stream: stream.sendall(b"x" * 100000)) as port:
            with subprocess.Popen(
                [str(BINARY), "127.0.0.1", str(port), "--script", str(path), "--max-time", "1"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) as process:
                try:
                    self.assertEqual(process.wait(timeout=2), 1)
                    self.assertIn(b"step_timeout during output", process.stderr.read())
                finally:
                    if process.poll() is None:
                        process.kill()

    def test_tls_conversation(self):
        def reply(stream):
            stream.sendall(b"ready\r\n")
            request = stream.makefile("rb").readline()
            if request == b"PING\r\n":
                stream.sendall(b"PONG\r\n")
            stream.unwrap()

        with tls_server(self.cert, self.key, action=reply) as port:
            report = self.run_script(port, {"steps": [
                {"expect": "ready\r\n"}, {"send_line": "PING"},
                {"expect": "PONG\r\n"}, {"expect_eof": True},
            ]}, "--tls", "--cacert", self.cert, "--server-name", "localhost")
        self.assertEqual(report["exit_code"], 0, report)
        self.assertEqual(report["tls"]["verification"], "verified")
        self.assertEqual(report["output_utf8"], "ready\r\nPONG\r\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
