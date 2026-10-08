import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "trace_duckdb_syscalls.py"
SPEC = importlib.util.spec_from_file_location("trace_duckdb_syscalls", SCRIPT)
TRACE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(TRACE)


FAKE_DUCKDB = r"""#!/usr/bin/env python3
import json
import os
import signal
import sys
import time

if "--version" in sys.argv:
    print("DuckDB fake-version")
    raise SystemExit(0)

pid_capture = os.environ.get("FAKE_PID_CAPTURE")
if pid_capture:
    with open(pid_capture, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))

sql = sys.stdin.buffer.read()
with open(os.environ["FAKE_SQL_CAPTURE"], "wb") as handle:
    handle.write(sql)
with open(os.environ["FAKE_ARGV_CAPTURE"], "w", encoding="utf-8") as handle:
    json.dump(sys.argv[1:], handle)

if b"IGNORE_TERM_QUERY" in sql:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if b"SLOW_QUERY" in sql:
    time.sleep(10)

sys.stdout.buffer.write(b"duckdb-output\n")
sys.stdout.buffer.write(sql)
sys.stdout.buffer.flush()
if b"PERMISSION_DENIED_QUERY" in sql:
    sys.stderr.write("IO Error: Permission denied while opening database\n")
    raise SystemExit(7)
if b"TRACER_NAME_QUERY" in sql:
    sys.stderr.write("strace: failed because this is target-owned text\n")
    raise SystemExit(7)
if b"FAIL_QUERY" in sql:
    sys.stderr.write("duckdb-error: representative failure\n")
    raise SystemExit(7)
"""


FAKE_STRACE = r"""#!/usr/bin/env python3
import os
import sys

if sys.argv[1:] == ["-V"]:
    print("strace -- fake-version")
    raise SystemExit(0)

raw_path = None
target = None
index = 1
while index < len(sys.argv):
    argument = sys.argv[index]
    if argument == "-o":
        raw_path = sys.argv[index + 1]
        index += 2
    elif argument in ("-s",):
        index += 2
    elif argument == "--":
        target = sys.argv[index + 1:]
        break
    else:
        index += 1

if raw_path is None or not target:
    sys.stderr.write("strace: invalid fake invocation\n")
    raise SystemExit(2)

with open(raw_path, "w", encoding="utf-8") as handle:
    handle.write(
        '431  1700000000.000001 read(0</dev/stdin>, "SELECT", 4096) = 6 '
        '<0.000120>\n'
    )
    handle.write(
        '432  1700000000.000200 openat(AT_FDCWD</tmp>, "/missing", '
        'O_RDONLY) = -1 ENOENT (No such file or directory) <0.000030>\n'
    )

os.execv(target[0], target)
"""


FAKE_DTRACE = r"""#!/usr/bin/env python3
import json
import shlex
import subprocess
import sys

if sys.argv[1:] == ["-V"]:
    print("dtrace: fake-version")
    raise SystemExit(0)

raw_path = sys.argv[sys.argv.index("-o") + 1]
program_path = sys.argv[sys.argv.index("-s") + 1]
target_text = sys.argv[sys.argv.index("-c") + 1]
sql = sys.stdin.buffer.read()
completed = subprocess.run(shlex.split(target_text), input=sql, check=False)
program = open(program_path, encoding="utf-8").read()
if "_fake_execute_sql" in program:
    scope = "query"
elif "_fake_connection_query" in program:
    scope = "engine"
else:
    scope = "process"
events = [
    {"type": "trace_start", "scope": scope, "ts_ns": 1, "target_pid": 100},
]
if scope != "process" and b"NO_BOUNDARY" not in sql:
    events.append(
        {
            "type": "boundary",
            "phase": "entry",
            "scope": scope,
            "ts_ns": 2,
            "pid": 100,
            "tid": 101,
            "depth": 1,
        }
    )
events.extend([
    {
        "type": "call",
        "phase": "return",
        "provider": "syscall",
        "call": "read",
        "ts_ns": 3,
        "pid": 100,
        "tid": 101,
        "return": len(sql),
        "error": 0,
        "duration_ns": 1000,
    },
    {
        "type": "process_exit",
        "ts_ns": 4,
        "pid": 100,
        "status": completed.returncode,
    },
])
if scope != "process" and b"NO_BOUNDARY" not in sql:
    events.append(
        {
            "type": "boundary",
            "phase": "return",
            "scope": scope,
            "ts_ns": 5,
            "pid": 100,
            "tid": 101,
            "depth": 1,
        }
    )
events.append(
    {"type": "trace_end", "scope": scope, "ts_ns": 6, "target_pid": 100}
)
with open(raw_path, "w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event) + "\n")
raise SystemExit(0)
"""

FAKE_NM = r"""#!/usr/bin/env python3
print("0000000000001000 T _fake_execute_sql")
print("0000000000002000 T _fake_connection_query")
"""


FAKE_CXXFILT = r"""#!/usr/bin/env python3
import sys

for symbol in sys.stdin.read().splitlines():
    if symbol == "_fake_execute_sql":
        print("duckdb_shell::ShellState::ExecuteSQL(std::string const&)")
    elif symbol == "_fake_connection_query":
        print("duckdb::Connection::Query(std::string const&)")
    else:
        print(symbol)
"""


class InputTests(unittest.TestCase):
    def test_sql_argument_is_utf8_without_rewriting(self):
        sql = "SELECT 'snowman ☃';\nSELECT 2;"
        args = TRACE.parse_args(["--sql", sql])
        self.assertEqual(TRACE.read_sql(args), sql.encode("utf-8"))

    def test_sql_file_is_read_as_unmodified_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "query.sql"
            expected = b"SELECT 'a';\r\nSELECT '\\xff';\n"
            path.write_bytes(expected)
            args = TRACE.parse_args(["--sql-file", str(path)])
            self.assertEqual(TRACE.read_sql(args), expected)

    def test_stdin_is_read_as_unmodified_bytes(self):
        expected = b"SELECT 1;\nSELECT 2;\n"
        args = TRACE.parse_args(["--stdin"])
        self.assertEqual(TRACE.read_sql(args, io.BytesIO(expected)), expected)

    def test_tty_without_an_input_option_is_rejected(self):
        class Tty(io.BytesIO):
            def isatty(self):
                return True

        args = TRACE.parse_args([])
        with self.assertRaisesRegex(TRACE.TraceError, "no SQL supplied"):
            TRACE.read_sql(args, Tty())

    def test_invalid_limits_are_rejected(self):
        with self.assertRaisesRegex(TRACE.TraceError, "buffer-size"):
            TRACE.parse_args(["--buffer-size", "not-a-size"])
        with self.assertRaisesRegex(TRACE.TraceError, "string-limit"):
            TRACE.parse_args(["--string-limit", "0"])

    def test_database_connection_strings_are_redacted_for_metadata(self):
        connection = "md:demo?motherduck_token=review-secret-token"
        self.assertEqual(
            TRACE.database_metadata_value(connection),
            "md:<redacted-connection-string>",
        )
        self.assertEqual(
            TRACE.database_metadata_value("/tmp/local.db"), "/tmp/local.db"
        )

    def test_existing_artifacts_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = pathlib.Path(temporary) / "trace"
            args = TRACE.parse_args(["--output-dir", str(output_dir)])
            paths = TRACE.make_artifact_paths(
                args,
                "strace",
                TRACE.utc_now(),
            )
            paths["raw"].write_text("existing", encoding="utf-8")
            with self.assertRaisesRegex(TRACE.TraceError, "refusing to overwrite"):
                TRACE.make_artifact_paths(args, "strace", TRACE.utc_now())


class BoundaryTests(unittest.TestCase):
    def test_nm_output_is_parsed_without_undefined_symbols(self):
        output = textwrap.dedent(
            """\
            0000000100001000 T __ZN12duckdb_shell10ShellState11RenderQueryEv
                             U _malloc
            0000000100002000 T __ZN6duckdb10Connection5QueryEv
            """
        )
        self.assertEqual(
            TRACE.parse_nm_symbols(output),
            [
                "__ZN12duckdb_shell10ShellState11RenderQueryEv",
                "__ZN6duckdb10Connection5QueryEv",
            ],
        )

    def test_query_program_uses_process_state_for_all_threads(self):
        symbol = "__ZN12duckdb_shell10ShellState10ExecuteSQLEv"
        program = TRACE.build_dtrace_program("query", [symbol], True)
        self.assertIn("pid$target::{}:entry".format(symbol), program)
        self.assertIn("pid$target::{}:return".format(symbol), program)
        self.assertIn("active[$target]", program)
        self.assertIn("pid == $target || progenyof($target)", program)
        self.assertIn("syscall:::entry", program)
        self.assertIn("syscall:::return", program)
        self.assertIn("mach_trap:::entry", program)
        self.assertIn("mach_trap:::return", program)
        self.assertIn('"type\\":\\"boundary', program)
        self.assertNotIn("self->active", program)

    def test_process_program_starts_active_and_has_no_boundary_probe(self):
        program = TRACE.build_dtrace_program("process", [], False)
        self.assertIn("active[$target] = 1;", program)
        self.assertIn("/active[$target] && (pid == $target)/", program)
        self.assertNotIn("pid$target::", program)

    def test_dtrace_target_command_contains_no_sql(self):
        target = [
            "/tmp/duck db",
            "--no-init",
            "--batch",
            "--bail",
            "/tmp/db; touch /tmp/not-run",
        ]
        command = TRACE.build_dtrace_command(
            "/usr/sbin/dtrace",
            pathlib.Path("/tmp/program.d"),
            pathlib.Path("/tmp/raw.jsonl"),
            "16m",
            target,
        )
        self.assertEqual(command[-2], "-c")
        self.assertEqual(shlex.split(command[-1]), target)
        self.assertNotIn("SELECT", command[-1])
        self.assertIn("dynvarsize=16m", command)

    def test_strace_always_follows_workers_and_descendants(self):
        command = TRACE.build_strace_command(
            "/usr/bin/strace",
            pathlib.Path("/tmp/raw.strace"),
            8192,
            ["/tmp/duckdb", ":memory:"],
        )
        self.assertIn("-f", command)
        self.assertIn("-ttt", command)
        self.assertIn("-T", command)
        self.assertIn("-yy", command)
        self.assertEqual(command[-3:], ["--", "/tmp/duckdb", ":memory:"])

class SummaryTests(unittest.TestCase):
    def test_dtrace_summary_groups_calls_and_extracts_exit_status(self):
        events = [
            {
                "type": "boundary",
                "phase": "entry",
                "scope": "query",
                "ts_ns": 1,
                "pid": 10,
                "tid": 20,
                "depth": 1,
            },
            {
                "type": "call",
                "phase": "entry",
                "provider": "syscall",
                "call": "read",
                "ts_ns": 2,
                "pid": 10,
                "tid": 21,
                "args": [0, 1, 2, 3, 4, 5],
            },
            {
                "type": "call",
                "phase": "return",
                "provider": "syscall",
                "call": "read",
                "ts_ns": 3,
                "pid": 10,
                "tid": 21,
                "return": -1,
                "error": 5,
                "duration_ns": 2000,
            },
            {
                "type": "call",
                "phase": "return",
                "provider": "mach_trap",
                "call": "mach_msg_trap",
                "ts_ns": 4,
                "pid": 10,
                "tid": 22,
                "return": 0,
                "error": None,
                "duration_ns": 3000,
            },
            {
                "type": "boundary",
                "phase": "return",
                "scope": "query",
                "ts_ns": 5,
                "pid": 10,
                "tid": 20,
                "depth": 1,
            },
            {"type": "process_exit", "ts_ns": 6, "pid": 10, "status": 7},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            raw = pathlib.Path(temporary) / "raw.jsonl"
            raw.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            stats = TRACE.summarize_dtrace(raw)
            self.assertEqual(stats["complete_calls"], 2)
            self.assertEqual(stats["boundary_entries"], 1)
            self.assertEqual(stats["boundary_returns"], 1)
            self.assertEqual(stats["target_exit_status"], 7)
            self.assertEqual(stats["calls"]["syscall:read"]["errors"], 1)
            self.assertEqual(
                stats["calls"]["mach_trap:mach_msg_trap"]["total_ns"], 3000
            )
            summary = TRACE.render_summary(stats, "query", "dtrace", raw, 0)
            self.assertIn("syscall:read", summary)
            self.assertIn("mach_trap:mach_msg_trap", summary)

    def test_strace_summary_handles_errors_and_resumed_calls(self):
        raw_text = textwrap.dedent(
            """\
            100  1700000000.000001 read(3</tmp/a>, "x", 1) = 1 <0.000010>
            101  1700000000.000002 openat(AT_FDCWD</tmp>, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000020>
            102  1700000000.000003 poll([{fd=3}], 1, -1 <unfinished ...>
            102  1700000000.000004 <... poll resumed>) = 1 <0.000030>
            102  1700000000.000005 +++ exited with 0 +++
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            raw = pathlib.Path(temporary) / "raw.strace"
            raw.write_text(raw_text, encoding="utf-8")
            stats = TRACE.summarize_strace(raw)
            self.assertEqual(stats["complete_calls"], 3)
            self.assertEqual(stats["calls"]["syscall:openat"]["errors"], 1)
            self.assertEqual(stats["calls"]["syscall:poll"]["count"], 1)
            self.assertEqual(stats["calls"]["syscall:read"]["total_ns"], 10_000)

    def test_dropped_events_are_detected(self):
        self.assertEqual(
            TRACE.dropped_event_count("dtrace: 42 dynamic variable drops"), 42
        )
        self.assertEqual(
            TRACE.dropped_event_count("dtrace: 3 principal buffer drops"), 3
        )
        self.assertEqual(
            TRACE.dropped_event_count("dtrace: drops were detected"), -1
        )
        self.assertEqual(TRACE.dropped_event_count("all good"), 0)

    def test_dtrace_permission_error_is_actionable(self):
        diagnostic = TRACE.dtrace_permission_diagnostic(
            "dtrace: failed to initialize dtrace: Operation not permitted"
        )
        self.assertIn("SIP", diagnostic)
        self.assertIn("sudo", diagnostic)

    def test_strace_permission_error_is_actionable(self):
        diagnostic = TRACE.tracer_failure_diagnostic(
            "strace",
            "strace: PTRACE_TRACEME: Operation not permitted",
        )
        self.assertIn("could not trace DuckDB", diagnostic)


class CommandIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.duckdb = self.root / "fake duckdb"
        self.strace = self.root / "fake strace"
        self.dtrace = self.root / "fake dtrace"
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.duckdb.write_text(FAKE_DUCKDB, encoding="utf-8")
        self.strace.write_text(FAKE_STRACE, encoding="utf-8")
        self.dtrace.write_text(FAKE_DTRACE, encoding="utf-8")
        (self.fake_bin / "nm").write_text(FAKE_NM, encoding="utf-8")
        (self.fake_bin / "c++filt").write_text(FAKE_CXXFILT, encoding="utf-8")
        self.duckdb.chmod(0o755)
        self.strace.chmod(0o755)
        self.dtrace.chmod(0o755)
        (self.fake_bin / "nm").chmod(0o755)
        (self.fake_bin / "c++filt").chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def run_tool(self, sql, form="argument", extra=None):
        run_number = len(list(self.root.glob("run-*")))
        run_dir = self.root / "run-{}".format(run_number)
        capture = self.root / "sql-{}.bin".format(run_number)
        argv_capture = self.root / "argv-{}.json".format(run_number)
        command = [
            sys.executable,
            str(SCRIPT),
            "--backend",
            "strace",
            "--scope",
            "process",
            "--duckdb",
            str(self.duckdb),
            "--tracer",
            str(self.strace),
            "--database",
            str(self.root / "database with spaces.db"),
            "--output-dir",
            str(run_dir),
        ]
        input_bytes = None
        if form == "argument":
            command.extend(["--sql", sql.decode("utf-8")])
        elif form == "file":
            sql_file = self.root / "query-{}.sql".format(run_number)
            sql_file.write_bytes(sql)
            command.extend(["--sql-file", str(sql_file)])
        elif form == "stdin":
            command.append("--stdin")
            input_bytes = sql
        else:
            raise AssertionError("unknown form")
        if extra:
            command.extend(extra)
        env = os.environ.copy()
        env["FAKE_SQL_CAPTURE"] = str(capture)
        env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=15,
        )
        return completed, run_dir, capture, argv_capture

    def run_dtrace_tool(self, query, scope="process", run_name="dtrace-run"):
        run_dir = self.root / run_name
        capture = self.root / "{}-sql.bin".format(run_name)
        argv_capture = self.root / "{}-argv.json".format(run_name)
        env = os.environ.copy()
        env["FAKE_SQL_CAPTURE"] = str(capture)
        env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
        env["PATH"] = "{}{}{}".format(
            self.fake_bin, os.pathsep, env.get("PATH", "")
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backend",
                "dtrace",
                "--scope",
                scope,
                "--duckdb",
                str(self.duckdb),
                "--tracer",
                str(self.dtrace),
                "--output-dir",
                str(run_dir),
                "--sql",
                query.decode("utf-8"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        return completed, run_dir, capture, argv_capture

    def test_all_sql_input_forms_preserve_multistatement_text(self):
        query = (
            b"CREATE SECRET s (TYPE aws, SECRET 'not-in-metadata');\n"
            b"SELECT '; $(touch should-not-run)';\n"
            b"SHOW ALL TABLES;\n"
        )
        for form in ("argument", "file", "stdin"):
            with self.subTest(form=form):
                completed, run_dir, capture, argv_capture = self.run_tool(
                    query, form=form
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(capture.read_bytes(), query)
                self.assertEqual(completed.stdout, b"duckdb-output\n" + query)
                argv = json.loads(argv_capture.read_text(encoding="utf-8"))
                self.assertEqual(
                    argv[:3], ["--no-init", "--batch", "--bail"]
                )
                self.assertEqual(
                    argv[3], str(self.root / "database with spaces.db")
                )
                metadata_text = (run_dir / "metadata.json").read_text(
                    encoding="utf-8"
                )
                metadata = json.loads(metadata_text)
                self.assertNotIn("not-in-metadata", metadata_text)
                self.assertNotIn("touch should-not-run", metadata_text)
                self.assertEqual(
                    metadata["query_sha256"], hashlib.sha256(query).hexdigest()
                )
                self.assertEqual(metadata["query_bytes"], len(query))
                self.assertEqual(metadata["duckdb_exit_status"], 0)
                self.assertTrue((run_dir / "raw.strace").stat().st_size)
                summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
                self.assertIn("syscall:read", summary)
                self.assertIn("syscall:openat", summary)

    def test_failing_query_preserves_status_errors_and_raw_trace(self):
        query = b"SELECT FAIL_QUERY;\n"
        completed, run_dir, capture, _ = self.run_tool(query)
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(capture.read_bytes(), query)
        self.assertIn(b"representative failure", completed.stderr)
        self.assertTrue((run_dir / "raw.strace").stat().st_size)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["duckdb_exit_status"], 7)
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_target_strace_text_is_not_misclassified_as_tracer_failure(self):
        completed, run_dir, _, _ = self.run_tool(
            b"SELECT TRACER_NAME_QUERY;\n"
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_database_credentials_are_not_written_to_metadata(self):
        connection = "md:demo?motherduck_token=review-secret-token"
        completed, run_dir, _, argv_capture = self.run_tool(
            b"SELECT 1;\n", extra=["--database", connection]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        metadata_text = (run_dir / "metadata.json").read_text(encoding="utf-8")
        self.assertNotIn("review-secret-token", metadata_text)
        metadata = json.loads(metadata_text)
        self.assertEqual(
            metadata["database_path"], "md:<redacted-connection-string>"
        )
        argv = json.loads(argv_capture.read_text(encoding="utf-8"))
        self.assertEqual(argv[-1], connection)

    def test_query_stdout_can_be_suppressed(self):
        completed, run_dir, _, _ = self.run_tool(
            b"SELECT 1;\n", extra=["--no-results"]
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"")
        self.assertTrue((run_dir / "raw.strace").exists())

    def test_timeout_returns_124_and_keeps_artifacts(self):
        completed, run_dir, _, _ = self.run_tool(
            b"SELECT SLOW_QUERY;\n", extra=["--timeout", "0.1"]
        )
        self.assertEqual(completed.returncode, 124)
        self.assertTrue((run_dir / "raw.strace").stat().st_size)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertTrue(metadata["timed_out"])
        self.assertEqual(metadata["effective_exit_status"], 124)

    def test_interrupt_and_termination_kill_the_traced_process_group(self):
        for signum, expected_status in (
            (signal.SIGINT, 130),
            (signal.SIGTERM, 143),
        ):
            with self.subTest(signum=signum):
                run_dir = self.root / "signal-{}".format(signum)
                capture = self.root / "signal-{}-sql.bin".format(signum)
                argv_capture = self.root / "signal-{}-argv.json".format(signum)
                pid_capture = self.root / "signal-{}-pid.txt".format(signum)
                env = os.environ.copy()
                env["FAKE_SQL_CAPTURE"] = str(capture)
                env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
                env["FAKE_PID_CAPTURE"] = str(pid_capture)
                process = subprocess.Popen(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "--backend",
                        "strace",
                        "--scope",
                        "process",
                        "--duckdb",
                        str(self.duckdb),
                        "--tracer",
                        str(self.strace),
                        "--output-dir",
                        str(run_dir),
                        "--sql",
                        "SELECT SLOW_QUERY{};".format(
                            " IGNORE_TERM_QUERY"
                            if signum == signal.SIGTERM
                            else ""
                        ),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                deadline = time.monotonic() + 5
                while not pid_capture.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(pid_capture.exists(), "fake DuckDB did not start")
                target_pid = int(pid_capture.read_text(encoding="utf-8"))
                process.send_signal(signum)
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, expected_status, stderr)
                with self.assertRaises(ProcessLookupError):
                    os.kill(target_pid, 0)

    def test_dtrace_process_scope_extracts_duckdb_exit_status(self):
        query = b"SELECT FAIL_QUERY;\n"
        completed, run_dir, capture, _ = self.run_dtrace_tool(
            query, scope="process"
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(capture.read_bytes(), query)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["tracer_exit_status"], 0)
        self.assertEqual(metadata["duckdb_exit_status"], 7)
        self.assertEqual(metadata["effective_exit_status"], 7)
        self.assertTrue((run_dir / "dtrace-program.d").exists())

    def test_query_scope_observes_execute_sql_boundary(self):
        completed, run_dir, _, _ = self.run_dtrace_tool(
            b"SELECT 1;\n", scope="query", run_name="dtrace-query"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["boundary_entries"], 1)
        self.assertEqual(metadata["boundary_returns"], 1)
        self.assertIn(
            "ShellState::ExecuteSQL",
            metadata["boundary_symbols"][0]["demangled"],
        )

    def test_dtrace_target_permission_error_preserves_query_status(self):
        completed, run_dir, _, _ = self.run_dtrace_tool(
            b"SELECT PERMISSION_DENIED_QUERY;\n",
            scope="process",
            run_name="dtrace-permission-target",
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_pre_engine_failure_without_boundary_preserves_query_status(self):
        completed, run_dir, _, _ = self.run_dtrace_tool(
            b"SELECT NO_BOUNDARY FAIL_QUERY;\n",
            scope="engine",
            run_name="dtrace-engine-pre-boundary",
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertIn("never observed", metadata["boundary_warning"])
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_strace_query_scope_is_rejected_without_running_query(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backend",
                "strace",
                "--scope",
                "query",
                "--sql",
                "SELECT 1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"cannot observe DuckDB C++ function boundaries", completed.stderr)

    def test_missing_binary_has_an_actionable_error(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backend",
                "strace",
                "--scope",
                "process",
                "--duckdb",
                str(self.root / "missing-duckdb"),
                "--tracer",
                str(self.strace),
                "--sql",
                "SELECT 1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(b"DuckDB executable not found", completed.stderr)


if __name__ == "__main__":
    unittest.main()
