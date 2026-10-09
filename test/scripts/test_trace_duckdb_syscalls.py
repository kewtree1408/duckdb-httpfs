import csv
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


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


FAKE_XCTRACE = r'''#!/usr/bin/env python3
import os
import pathlib
import sys
import time

argv = sys.argv[1:]

if argv == ["version"]:
    print("xctrace version fake")
    raise SystemExit(0)

if argv[:2] == ["list", "templates"]:
    print("== Standard Templates ==")
    print("File Activity")
    print("Network")
    raise SystemExit(0)

if argv and argv[0] == "record":
    output = pathlib.Path(argv[argv.index("--output") + 1])
    target_pid = int(argv[argv.index("--attach") + 1])
    if argv[argv.index("--template") + 1] != "File Activity":
        print("Cannot find template matching name: unknown")
        raise SystemExit(1)
    print("Attaching to: fake ({})".format(target_pid), flush=True)
    print("Ctrl-C to stop the recording", flush=True)
    output.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            os.kill(target_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    print("Target app exited, ending recording...", flush=True)
    raise SystemExit(0)

if argv and argv[0] == "export":
    bundle = pathlib.Path(argv[argv.index("--input") + 1])
    xpath = argv[argv.index("--xpath") + 1]
    if "FsSyscall" not in xpath:
        sys.stderr.write("fake xctrace: unexpected xpath {}\n".format(xpath))
        raise SystemExit(2)
    begin_path = "/absent-begin-marker"
    end_path = "/absent-end-marker"
    if os.environ.get("FAKE_XCTRACE_NO_MARKERS") != "1":
        begin = sorted(bundle.parent.glob("marker-begin-*.csv"))
        end = sorted(bundle.parent.glob("marker-end-*.csv"))
        if begin:
            begin_path = str(begin[0])
        if end:
            end_path = str(end[0])
    rows = []
    if os.environ.get("FAKE_XCTRACE_EMPTY") != "1":
        rows = [
            # Startup call, outside any marker window.
            '<row><start-time id="1" fmt="00:00.000.100">100</start-time>'
            '<duration id="2" fmt="10 ns">10</duration><sentinel/>'
            '<syscall id="3" fmt="open">BSC_open</syscall>'
            '<syscall-return id="4" fmt="0x3">3</syscall-return>'
            '<process id="5" fmt="duckdb (4242)">'
            '<pid id="6" fmt="4242">4242</pid></process>'
            '<thread id="7" fmt="Main Thread">'
            '<tid id="8" fmt="0x1">1</tid></thread>'
            '<file-path id="9" fmt="/startup/library">/startup/library'
            "</file-path></row>",
            (
                '<row><start-time id="10" fmt="00:00.000.200">200</start-time>'
                '<duration ref="2"/><sentinel/>'
                '<syscall id="11" fmt="stat64">BSC_stat64</syscall>'
                '<syscall-return ref="4"/>'
                '<process ref="5"/><thread ref="7"/>'
                '<file-path id="12" fmt="{begin}">{begin}</file-path></row>'
            ).format(begin=begin_path),
            '<row><start-time id="13" fmt="00:00.000.300">300</start-time>'
            '<duration id="14" fmt="1 us">1000</duration><sentinel/>'
            '<syscall id="15" fmt="recvfrom">BSC_recvfrom</syscall>'
            '<syscall-return id="16" fmt="0x400">1024</syscall-return>'
            '<process ref="5"/>'
            '<thread id="17" fmt="Worker"><tid id="18" fmt="0x2">2</tid>'
            "</thread><sentinel/></row>",
            # Only refs plus a negative return: exercises the catalogue and
            # the errno-free error heuristic.
            '<row><start-time id="19" fmt="00:00.000.400">400</start-time>'
            '<duration ref="14"/><sentinel/><syscall ref="15"/>'
            '<syscall-return id="20" fmt="0xffffffff">-1</syscall-return>'
            '<process ref="5"/><thread ref="17"/><sentinel/></row>',
            (
                '<row><start-time id="21" fmt="00:00.000.500">500</start-time>'
                '<duration ref="2"/><sentinel/><syscall ref="11"/>'
                '<syscall-return ref="4"/><process ref="5"/><thread ref="7"/>'
                '<file-path id="22" fmt="{end}">{end}</file-path></row>'
            ).format(end=end_path),
            # Shutdown call, outside any marker window.
            '<row><start-time id="23" fmt="00:00.000.600">600</start-time>'
            '<duration ref="2"/><sentinel/>'
            '<syscall id="24" fmt="sys_close">BSC_close</syscall>'
            '<syscall-return ref="4"/>'
            '<process ref="5"/><thread ref="7"/><sentinel/></row>',
        ]
    print('<?xml version="1.0"?>')
    print("<trace-query-result>")
    print('<node xpath="//trace-toc[1]/run[1]/data[1]/table[2]">')
    print('<schema name="FsSyscall"/>')
    for row in rows:
        print(row)
    print("</node>")
    print("</trace-query-result>")
    raise SystemExit(0)

sys.stderr.write("fake xctrace: unsupported invocation {}\n".format(argv))
raise SystemExit(2)
'''

FAKE_BPFTRACE = r"""#!/usr/bin/env python3
import json
import os
import sys
import time

if sys.argv[1:] == ["-V"]:
    print("bpftrace v0.fake")
    raise SystemExit(0)

target_pid = int(sys.argv[sys.argv.index("-p") + 1])
program_path = sys.argv[-1]
program = open(program_path, encoding="utf-8").read()
scope = "engine" if "_fake_connection_query" in program else "query"
no_boundary = os.environ.get("FAKE_BPFTRACE_NO_BOUNDARY") == "1"

def emit(event):
    print(json.dumps(event), flush=True)

emit({"type": "trace_start", "scope": scope, "ts_ns": 1, "target_pid": target_pid})
if not no_boundary:
    emit({
        "type": "boundary",
        "phase": "entry",
        "scope": scope,
        "ts_ns": 2,
        "pid": target_pid,
        "tid": target_pid,
        "depth": 1,
    })
    emit({
        "type": "call",
        "phase": "entry",
        "provider": "syscall",
        "call": "tracepoint:syscalls:sys_enter_read",
        "ts_ns": 3,
        "pid": target_pid,
        "tid": target_pid,
    })
    emit({
        "type": "call",
        "phase": "return",
        "provider": "syscall",
        "call": "tracepoint:syscalls:sys_exit_read",
        "ts_ns": 4,
        "pid": target_pid,
        "tid": target_pid,
        "return": 1,
        "error": 0,
        "duration_ns": 1000,
    })

deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        os.kill(target_pid, 0)
    except ProcessLookupError:
        break
    time.sleep(0.01)

if not no_boundary:
    emit({
        "type": "boundary",
        "phase": "return",
        "scope": scope,
        "ts_ns": 5,
        "pid": target_pid,
        "tid": target_pid,
        "depth": 1,
    })
emit({"type": "trace_end", "scope": scope, "ts_ns": 6, "target_pid": target_pid})
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
        with self.assertRaisesRegex(TRACE.TraceError, "string-limit"):
            TRACE.parse_args(["--string-limit", "0"])
        with self.assertRaisesRegex(TRACE.TraceError, "timeout"):
            TRACE.parse_args(["--timeout", "0"])
        with self.assertRaisesRegex(TRACE.TraceError, "template"):
            TRACE.parse_args(["--template", "   "])

    def test_database_connection_strings_are_redacted_for_metadata(self):
        connection = "md:demo?motherduck_token=review-secret-token"
        self.assertEqual(
            TRACE.database_metadata_value(connection),
            "md:<redacted-connection-string>",
        )
        self.assertEqual(
            TRACE.database_metadata_value("/tmp/local.db"), "/tmp/local.db"
        )

    def test_duckdb_args_are_appended_after_the_fixed_flags(self):
        for argv in (
            ["--duckdb-arg=-unsigned", "--duckdb-arg=-readonly"],
            ["--", "-unsigned", "-readonly"],
            ["--duckdb-arg=-unsigned", "--", "-readonly"],
        ):
            with self.subTest(argv=argv):
                args = TRACE.parse_args(argv)
                self.assertEqual(args.duckdb_args, ["-unsigned", "-readonly"])
                self.assertEqual(
                    TRACE.duckdb_command("/bin/duckdb", ":memory:", args.duckdb_args),
                    [
                        "/bin/duckdb",
                        ":memory:",
                        "--no-init",
                        "--batch",
                        "--bail",
                        "-unsigned",
                        "-readonly",
                    ],
                )

    def test_duckdb_command_without_extra_args_is_unchanged(self):
        self.assertEqual(
            TRACE.duckdb_command("/bin/duckdb", ":memory:"),
            ["/bin/duckdb", ":memory:", "--no-init", "--batch", "--bail"],
        )
        self.assertEqual(TRACE.parse_args([]).duckdb_args, [])

    def test_sql_bearing_duckdb_args_are_rejected(self):
        for argv in (
            ["--duckdb-arg=-c", "--duckdb-arg=SELECT 1;"],
            ["--duckdb-arg=-c=SELECT 1;"],
            ["--", "-cmd", "SELECT 1;"],
            ["--", "-s", "SELECT 1;"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(
                    TRACE.TraceError, "puts SQL on the DuckDB command line"
                ):
                    TRACE.parse_args(argv)

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

    def test_classification_paths_are_protected(self):
        for filename in ("syscall-categories.md", "syscall-categories.csv"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                output_dir = pathlib.Path(temporary)
                artifact = output_dir / filename
                args = TRACE.parse_args(["--output-dir", str(output_dir)])
                artifact.write_text("existing report", encoding="utf-8")
                with self.assertRaisesRegex(TRACE.TraceError, "refusing to overwrite"):
                    TRACE.make_artifact_paths(args, "strace", TRACE.utc_now())
                self.assertEqual(artifact.read_text(encoding="utf-8"), "existing report")
                collision_args = TRACE.parse_args(
                    ["--output-dir", str(output_dir), "--raw-trace", str(artifact)]
                )
                with self.assertRaisesRegex(TRACE.TraceError, "paths must differ"):
                    TRACE.make_artifact_paths(collision_args, "strace", TRACE.utc_now())


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

    def test_boundary_lookup_tries_full_table_after_unrelated_exports(self):
        readable_symbols = {
            "_fake_execute_sql": "duckdb_shell::ShellState::ExecuteSQL(std::string const&)",
            "_fake_connection_query": "duckdb::Connection::Query(std::string const&)",
        }

        def run_symbol_command(command, **kwargs):
            if command[0] == "/mock/nm":
                if "-D" in command or "-gU" in command:
                    output = b"0000000000001000 B stderr\n"
                else:
                    output = (
                        b"0000000000002000 T _fake_execute_sql\n"
                        b"0000000000003000 T _fake_connection_query\n"
                    )
            else:
                output = (
                    "\n".join(
                        readable_symbols.get(symbol, symbol)
                        for symbol in kwargs["input"].decode().splitlines()
                    ) + "\n"
                ).encode()
            return subprocess.CompletedProcess(
                command, 0, stdout=output, stderr=b""
            )

        for system_name, first_options, full_options in (
            ("Linux", ["-D", "--defined-only"], ["--defined-only"]),
            ("Darwin", ["-gU"], ["-U"]),
        ):
            for scope, symbol in (
                ("query", "_fake_execute_sql"),
                ("engine", "_fake_connection_query"),
            ):
                with self.subTest(system=system_name, scope=scope):
                    with (
                        mock.patch.object(
                            TRACE.platform, "system", return_value=system_name
                        ),
                        mock.patch.object(
                            TRACE.shutil, "which",
                            side_effect=lambda name: "/mock/" + name,
                        ),
                        mock.patch.object(
                            TRACE.subprocess, "run", side_effect=run_symbol_command
                        ) as runner,
                    ):
                        matches = TRACE.resolve_boundary_symbols(
                            "/mock/duckdb", scope
                        )
                    self.assertEqual(
                        matches, [(symbol, readable_symbols[symbol])]
                    )
                    nm_commands = [
                        call.args[0]
                        for call in runner.call_args_list
                        if call.args[0][0] == "/mock/nm"
                    ]
                    self.assertEqual(
                        nm_commands,
                        [
                            ["/mock/nm", *first_options, "/mock/duckdb"],
                            ["/mock/nm", *full_options, "/mock/duckdb"],
                        ],
                    )

    def test_boundary_lookup_reports_missing_symbol_after_all_tables(self):
        with (
            mock.patch.object(TRACE.platform, "system", return_value="Linux"),
            mock.patch.object(TRACE.shutil, "which", return_value="/mock/nm"),
            mock.patch.object(
                TRACE.subprocess, "run",
                return_value=subprocess.CompletedProcess(
                    [], 0, stdout=b"0000000000001000 B stderr\n", stderr=b""
                ),
            ) as runner,
            mock.patch.object(
                TRACE, "demangle_symbols", side_effect=lambda symbols: list(symbols)
            ),
        ):
            with self.assertRaisesRegex(
                TRACE.TraceError, "does not contain a symbol"
            ):
                TRACE.resolve_boundary_symbols("/mock/duckdb", "query")
        self.assertEqual(runner.call_count, 3)

    def test_macos_auto_selects_xctrace_with_query_scope(self):
        self.assertEqual(
            TRACE.select_backend("auto", system_name="Darwin"), "xctrace"
        )
        self.assertEqual(TRACE.select_scope(None, "xctrace"), "query")

    def test_xctrace_record_command_attaches_and_carries_no_sql(self):
        command = TRACE.build_xctrace_record_command(
            "/usr/bin/xctrace",
            "File Activity",
            pathlib.Path("/tmp/out/recording.trace"),
            4242,
        )
        self.assertEqual(command[1], "record")
        self.assertEqual(command[command.index("--attach") + 1], "4242")
        self.assertEqual(
            command[command.index("--template") + 1], "File Activity"
        )
        self.assertIn("--no-prompt", command)
        self.assertNotIn("--launch", command)
        for argument in command:
            self.assertNotIn("SELECT", argument)

    def test_xctrace_export_command_selects_the_syscall_table(self):
        command = TRACE.build_xctrace_export_command(
            "/usr/bin/xctrace", pathlib.Path("/tmp/out/recording.trace")
        )
        self.assertEqual(command[1], "export")
        xpath = command[command.index("--xpath") + 1]
        self.assertIn('run[@number="1"]', xpath)
        self.assertIn('table[@schema="FsSyscall"]', xpath)

    def test_fssyscall_export_resolves_back_references(self):
        payload = (
            '<?xml version="1.0"?><trace-query-result><node>'
            '<row><start-time id="1">100</start-time>'
            '<duration id="2">10</duration>'
            '<syscall id="3" fmt="recvfrom">BSC_recvfrom</syscall>'
            '<syscall-return id="4">1024</syscall-return>'
            '<process id="5"><pid id="6">4242</pid></process>'
            '<thread id="7"><tid id="8">11</tid></thread>'
            '<file-path id="9" fmt="/data">/data</file-path></row>'
            '<row><start-time id="10">200</start-time>'
            '<duration ref="2"/><syscall ref="3"/>'
            '<syscall-return id="11">-1</syscall-return>'
            '<process ref="5"/><thread ref="7"/></row>'
            "</node></trace-query-result>"
        ).encode("utf-8")
        rows = TRACE.parse_fssyscall_xml(payload)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["path"], "/data")
        # Every column of the second row arrives as a ref, so these values can
        # only come from following the back-references.
        self.assertEqual(rows[1]["call"], "recvfrom")
        self.assertEqual(rows[1]["duration_ns"], 10)
        self.assertEqual(rows[1]["pid"], 4242)
        self.assertEqual(rows[1]["tid"], 11)
        self.assertEqual(rows[1]["return"], -1)
        self.assertIsNone(rows[1]["path"])

    def test_marker_window_covers_only_the_bracketed_rows(self):
        nonce = "0a1b2c3d4e5f"
        rows = [
            {"start_ns": 10, "path": "/startup"},
            {"start_ns": 20, "path": "/out/marker-begin-{}.csv".format(nonce)},
            {"start_ns": 30, "path": None},
            {"start_ns": 40, "path": "/out/marker-end-{}.csv".format(nonce)},
            {"start_ns": 50, "path": "/shutdown"},
        ]
        self.assertEqual(TRACE.find_marker_window(rows, nonce), (20, 40))
        self.assertIsNone(TRACE.find_marker_window(rows, "ffffffffffff"))

    def test_marker_sql_quotes_paths_and_keeps_user_sql_intact(self):
        begin = pathlib.Path("/tmp/owner's dir/marker-begin-1.csv")
        end = pathlib.Path("/tmp/marker-end-1.csv")
        sql = b"SELECT 'quoted';"
        wrapped = TRACE.wrap_sql_with_markers(sql, begin, end)
        self.assertIn(sql, wrapped)
        self.assertIn(b"/tmp/owner''s dir/marker-begin-1.csv", wrapped)
        self.assertTrue(wrapped.startswith(b"SELECT * FROM read_csv('"))
        self.assertTrue(wrapped.rstrip().endswith(b"');"))
        # SQL without a trailing newline must not run into the end marker.
        self.assertIn(b"SELECT 'quoted';\nSELECT * FROM read_csv", wrapped)

    def test_xctrace_never_follows_descendants(self):
        self.assertFalse(TRACE.select_children(None, "xctrace"))
        self.assertFalse(TRACE.select_children(False, "xctrace"))
        with self.assertRaisesRegex(
            TRACE.TraceError, "--children is not available"
        ):
            TRACE.select_children(True, "xctrace")
        self.assertTrue(TRACE.select_children(None, "strace"))
        self.assertTrue(TRACE.select_children(None, "bpftrace"))
        self.assertFalse(TRACE.select_children(False, "bpftrace"))

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

    def test_linux_query_scope_auto_selects_bpftrace(self):
        self.assertEqual(
            TRACE.select_backend("auto", system_name="Linux", scope="query"),
            "bpftrace",
        )
        self.assertEqual(
            TRACE.select_backend("auto", system_name="Linux", scope="process"),
            "strace",
        )

    def test_bpftrace_program_gates_all_threads_to_query_boundary(self):
        program = TRACE.build_bpftrace_program(
            "query",
            "/tmp/duck db",
            ["_fake_execute_sql"],
            1234,
            True,
        )
        self.assertIn('uprobe:"/tmp/duck db":_fake_execute_sql', program)
        self.assertIn('uretprobe:"/tmp/duck db":_fake_execute_sql', program)
        self.assertIn("tracepoint:raw_syscalls:sys_enter", program)
        self.assertIn("tracepoint:raw_syscalls:sys_exit", program)
        self.assertIn('"syscall_nr\\":%d', program)
        self.assertIn("@boundary_depth > 0 && (@tracked[pid])", program)
        self.assertIn("tracepoint:sched:sched_process_fork", program)
        self.assertIn('"type\\":\\"boundary', program)

    def test_bpftrace_no_children_keeps_worker_threads(self):
        program = TRACE.build_bpftrace_program(
            "engine",
            "/tmp/duckdb",
            ["_fake_connection_query"],
            1234,
            False,
        )
        self.assertIn("@boundary_depth > 0 && (pid == 1234)", program)
        self.assertNotIn("sched_process_fork", program)

    def test_bpftrace_command_attaches_to_paused_target(self):
        command = TRACE.build_bpftrace_command(
            "/usr/bin/bpftrace",
            pathlib.Path("/tmp/program.bt"),
            1234,
        )
        self.assertEqual(
            command,
            [
                "/usr/bin/bpftrace",
                "-q",
                "-B",
                "line",
                "-p",
                "1234",
                "/tmp/program.bt",
            ],
        )

class SummaryTests(unittest.TestCase):
    def test_syscall_names_are_freed_and_cached(self):
        name_buffer = ctypes.create_string_buffer(b"write")
        name_pointer = ctypes.addressof(name_buffer)
        seccomp = mock.Mock()
        seccomp.seccomp_arch_native.return_value = 123
        seccomp.seccomp_syscall_resolve_num_arch.side_effect = [
            name_pointer, None
        ]
        libc = mock.Mock()
        with (
            mock.patch.multiple(
                TRACE,
                _SYSCALL_NAME_RESOLVER=None,
                _SYSCALL_NAME_RESOLVER_INITIALIZED=False,
            ),
            mock.patch.object(
                TRACE.ctypes.util, "find_library", return_value="libseccomp.so.2"
            ),
            mock.patch.object(TRACE.ctypes, "CDLL", side_effect=[seccomp, libc]),
        ):
            self.assertEqual(TRACE.resolve_linux_syscall_name(1), "write")
            self.assertEqual(TRACE.resolve_linux_syscall_name(1), "write")
            self.assertEqual(TRACE.resolve_linux_syscall_name(99999), "nr_99999")
            self.assertEqual(TRACE.resolve_linux_syscall_name(99999), "nr_99999")
        self.assertIs(
            seccomp.seccomp_syscall_resolve_num_arch.restype, ctypes.c_void_p
        )
        self.assertEqual(
            seccomp.seccomp_syscall_resolve_num_arch.call_args_list,
            [mock.call(123, 1), mock.call(123, 99999)],
        )
        libc.free.assert_called_once_with(name_pointer)

    def test_syscall_name_is_freed_when_copying_fails(self):
        seccomp = mock.Mock()
        seccomp.seccomp_arch_native.return_value = 123
        seccomp.seccomp_syscall_resolve_num_arch.return_value = 456
        libc = mock.Mock()
        with (
            mock.patch.multiple(
                TRACE,
                _SYSCALL_NAME_RESOLVER=None,
                _SYSCALL_NAME_RESOLVER_INITIALIZED=False,
            ),
            mock.patch.object(
                TRACE.ctypes.util, "find_library", return_value="libseccomp.so.2"
            ),
            mock.patch.object(TRACE.ctypes, "CDLL", side_effect=[seccomp, libc]),
            mock.patch.object(
                TRACE.ctypes, "string_at", side_effect=MemoryError
            ),
        ):
            with self.assertRaises(MemoryError):
                TRACE.resolve_linux_syscall_name(1)
        libc.free.assert_called_once_with(456)

    def test_summary_groups_calls_by_provider_and_extracts_exit_status(self):
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
            stats = TRACE.summarize_events(raw)
            self.assertEqual(stats["complete_calls"], 2)
            self.assertEqual(stats["boundary_entries"], 1)
            self.assertEqual(stats["boundary_returns"], 1)
            self.assertEqual(stats["target_exit_status"], 7)
            self.assertEqual(stats["calls"]["syscall:read"]["errors"], 1)
            self.assertEqual(
                stats["calls"]["mach_trap:mach_msg_trap"]["total_ns"], 3000
            )
            summary = TRACE.render_summary(stats, "query", "xctrace", raw, 0)
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

    def test_bpftrace_summary_resolves_raw_syscall_numbers(self):
        event = {
            "type": "call",
            "phase": "return",
            "provider": "syscall",
            "syscall_nr": 1,
            "return": 5,
            "error": 0,
            "duration_ns": 3000,
        }
        previous_resolver = TRACE._SYSCALL_NAME_RESOLVER
        previous_initialized = TRACE._SYSCALL_NAME_RESOLVER_INITIALIZED
        try:
            TRACE._SYSCALL_NAME_RESOLVER_INITIALIZED = True
            TRACE._SYSCALL_NAME_RESOLVER = lambda number: (
                b"write" if number == 1 else None
            )
            with tempfile.TemporaryDirectory() as temporary:
                raw = pathlib.Path(temporary) / "raw.bpftrace.jsonl"
                raw.write_text(json.dumps(event) + "\n", encoding="utf-8")
                stats = TRACE.summarize_events(raw)
            self.assertEqual(stats["calls"]["syscall:write"]["count"], 1)
            self.assertEqual(stats["calls"]["syscall:write"]["total_ns"], 3000)
        finally:
            TRACE._SYSCALL_NAME_RESOLVER = previous_resolver
            TRACE._SYSCALL_NAME_RESOLVER_INITIALIZED = previous_initialized

    def test_dropped_events_are_detected(self):
        self.assertEqual(TRACE.dropped_event_count("Lost 42 events"), 42)
        self.assertEqual(TRACE.dropped_event_count("bpftrace: 3 drops"), 3)
        self.assertEqual(
            TRACE.dropped_event_count("lost events were detected"), -1
        )
        self.assertEqual(TRACE.dropped_event_count("all good"), 0)

    def test_xctrace_failure_diagnostics_are_actionable(self):
        sandbox = TRACE.tracer_failure_diagnostic(
            "xctrace",
            "Assertion failed: file XRAugmentationManager.m, line 90.",
        )
        self.assertIn("sandbox", sandbox)
        template = TRACE.tracer_failure_diagnostic(
            "xctrace", "Cannot find template matching name: System Trace"
        )
        self.assertIn("Xcode", template)
        self.assertIsNone(
            TRACE.tracer_failure_diagnostic("xctrace", "recording complete")
        )

    def test_strace_permission_error_is_actionable(self):
        diagnostic = TRACE.tracer_failure_diagnostic(
            "strace",
            "strace: PTRACE_TRACEME: Operation not permitted",
        )
        self.assertIn("could not trace DuckDB", diagnostic)

    def test_bpftrace_permission_error_is_actionable(self):
        diagnostic = TRACE.tracer_failure_diagnostic(
            "bpftrace",
            "ERROR: failed to load BPF program: Operation not permitted",
        )
        self.assertIn("sudo", diagnostic)
        self.assertIn("eBPF", diagnostic)


class ClassificationTests(unittest.TestCase):
    def test_categories_have_no_duplicate_names(self):
        names = [
            name for category in TRACE.SYSCALL_CATEGORIES.values() for name in category
        ]
        self.assertEqual(len(names), len(set(names)))

    def test_classification_handles_macos_linux_and_unknown_names(self):
        expected = {
            "recvfrom_nocancel": "Network and sockets",
            "accept4": "Network and sockets",
            "sys_close_nocancel": "File and descriptor I/O",
            "pread64": "File and descriptor I/O",
            "psynch_cvwait": "Thread synchronization",
            "sys_ulock_wait2": "Thread synchronization",
            "futex": "Thread synchronization",
            "epoll_pwait2": "I/O readiness and event notification",
            "poll": "I/O readiness and event notification",
            "mach_vm_map_trap": "Virtual and shared memory",
            "brk": "Virtual and shared memory",
            "bsdthread_create": "Thread lifecycle and workqueues",
            "mach_msg2_trap": "IPC, Mach ports and activity context",
            "pipe2": "IPC, Mach ports and activity context",
            "sys_fstat64": "Filesystem metadata and discovery",
            "newfstatat": "Filesystem metadata and discovery",
            "getrlimit": "Process identity, system information and signals",
            "sys_crossarch_trap": "Security, tracing and platform support",
            "getrandom": "Security, tracing and platform support",
            "clock_gettime": "Time and clock information",
            "clone3": "Process lifecycle",
            "tracepoint:syscalls:sys_enter_read": "File and descriptor I/O",
            "tracepoint:syscalls:sys_exit_futex": "Thread synchronization",
            "nr_999999": "Other / unclassified",
            "future_syscall": "Other / unclassified",
            "unknown": "Other / unclassified",
        }
        for name, category in expected.items():
            with self.subTest(name=name):
                self.assertEqual(TRACE.syscall_category(name), category)

    def test_reports_preserve_counts_providers_errors_and_durations(self):
        stats = TRACE.new_stats()
        stats["complete_calls"] = 6
        stats["calls"].update({
            "syscall:recvfrom": {
                "count": 2, "errors": 1, "total_ns": 30_000, "max_ns": 20_000,
            },
            "syscall:read": {
                "count": 1, "errors": 0, "total_ns": 10_000, "max_ns": 10_000,
            },
            "mach_trap:mach_msg_trap": {
                "count": 1, "errors": 0, "total_ns": 5_000, "max_ns": 5_000,
            },
            "syscall:mach_msg_trap": {
                "count": 1, "errors": 0, "total_ns": 7_000, "max_ns": 7_000,
            },
            "syscall:nr_999999": {
                "count": 1, "errors": 1, "total_ns": 3_000, "max_ns": 3_000,
            },
        })
        metadata = {
            "started_at": "2026-10-09T08:16:07Z",
            "backend": "xctrace",
            "scope": "process",
        }
        rows = list(csv.DictReader(io.StringIO(TRACE.render_classification_csv(stats))))
        self.assertEqual(sum(int(row["count"]) for row in rows), 6)
        self.assertEqual(len(rows), 5)
        received = next(row for row in rows if row["syscall"] == "recvfrom")
        self.assertEqual(
            (received["category"], received["errors"], received["total_ns"], received["max_ns"]),
            ("Network and sockets", "1", "30000", "20000"),
        )
        self.assertEqual(
            {row["provider"] for row in rows if row["syscall"] == "mach_msg_trap"},
            {"syscall", "mach_trap"},
        )
        report = TRACE.render_classification_report(stats, metadata)
        self.assertIn("6 completed calls, 5 distinct provider/name pairs", report)
        self.assertIn("| Network and sockets | 2 | 33.33% | 1 |", report)
        self.assertIn("| IPC, Mach ports and activity context | 2 | 33.33% | 2 |", report)
        self.assertIn("| Other / unclassified | 1 | 16.67% | 1 |", report)
        self.assertIn("| `syscall` | `recvfrom` | 2 | 1 | 0.030 | 0.020 |", report)
        self.assertIn("not necessarily disk I/O", report)
        self.assertIn("not process wall time", report)
        self.assertNotIn("## Capture notes", report)

    def test_empty_partial_capture_reports_uncertainty(self):
        stats = TRACE.new_stats()
        stats["malformed_lines"] = 2
        metadata = {
            "started_at": "2026-10-09T08:16:07Z",
            "backend": "bpftrace",
            "scope": "query",
            "timed_out": True,
            "dropped_events": -1,
            "duckdb_exit_status": 7,
            "infrastructure_error": "No trace-start event.",
            "boundary_warning": "Boundary events are unbalanced.",
        }
        report = TRACE.render_classification_report(stats, metadata)
        self.assertIn("No complete calls recorded.", report)
        self.assertIn("run timed out", report)
        self.assertIn("an unknown number of lost events", report)
        self.assertIn("2 raw lines could not be parsed", report)
        self.assertIn("DuckDB exited with status 7", report)
        self.assertIn("No trace-start event.", report)
        self.assertIn("Boundary events are unbalanced.", report)
        self.assertEqual(
            list(csv.DictReader(io.StringIO(TRACE.render_classification_csv(stats)))), []
        )


class CommandIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.duckdb = self.root / "fake duckdb"
        self.strace = self.root / "fake strace"
        self.xctrace = self.root / "fake xctrace"
        self.bpftrace = self.root / "fake bpftrace"
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.duckdb.write_text(FAKE_DUCKDB, encoding="utf-8")
        self.strace.write_text(FAKE_STRACE, encoding="utf-8")
        self.xctrace.write_text(FAKE_XCTRACE, encoding="utf-8")
        self.bpftrace.write_text(FAKE_BPFTRACE, encoding="utf-8")
        (self.fake_bin / "nm").write_text(FAKE_NM, encoding="utf-8")
        (self.fake_bin / "c++filt").write_text(FAKE_CXXFILT, encoding="utf-8")
        self.duckdb.chmod(0o755)
        self.strace.chmod(0o755)
        self.xctrace.chmod(0o755)
        self.bpftrace.chmod(0o755)
        (self.fake_bin / "nm").chmod(0o755)
        (self.fake_bin / "c++filt").chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def assert_classification(self, run_dir, expected_counts):
        report_path = run_dir / "syscall-categories.md"
        csv_path = run_dir / "syscall-categories.csv"
        metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["classification_report"], str(report_path))
        self.assertEqual(metadata["classification_csv"], str(csv_path))
        with csv_path.open(encoding="utf-8", newline="") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(
            {row["syscall"]: int(row["count"]) for row in rows}, expected_counts
        )
        self.assertEqual(sum(int(row["count"]) for row in rows), metadata["complete_calls"])
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("{:,} completed calls".format(metadata["complete_calls"]), report)
        self.assertIn("Scope: {}".format(metadata["scope"]), report)
        return report

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

    def run_xctrace_tool(
        self,
        query,
        scope="process",
        run_name="xctrace-run",
        extra=None,
        extra_env=None,
    ):
        run_dir = self.root / run_name
        capture = self.root / "{}-sql.bin".format(run_name)
        argv_capture = self.root / "{}-argv.json".format(run_name)
        env = os.environ.copy()
        env["FAKE_SQL_CAPTURE"] = str(capture)
        env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
        if extra_env:
            env.update(extra_env)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--backend",
                "xctrace",
                "--scope",
                scope,
                "--duckdb",
                str(self.duckdb),
                "--tracer",
                str(self.xctrace),
                "--output-dir",
                str(run_dir),
                "--sql",
                query.decode("utf-8"),
                *(extra or []),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=90,
        )
        return completed, run_dir, capture, argv_capture

    def run_bpftrace_tool(
        self,
        query,
        scope="query",
        run_name="bpftrace-run",
        extra_env=None,
        extra=None,
    ):
        run_dir = self.root / run_name
        capture = self.root / "{}-sql.bin".format(run_name)
        argv_capture = self.root / "{}-argv.json".format(run_name)
        env = os.environ.copy()
        env["FAKE_SQL_CAPTURE"] = str(capture)
        env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
        env["PATH"] = "{}{}{}".format(
            self.fake_bin, os.pathsep, env.get("PATH", "")
        )
        if extra_env:
            env.update(extra_env)
        command = [
            sys.executable,
            str(SCRIPT),
            "--backend",
            "bpftrace",
            "--scope",
            scope,
            "--duckdb",
            str(self.duckdb),
            "--tracer",
            str(self.bpftrace),
            "--output-dir",
            str(run_dir),
            "--sql",
            query.decode("utf-8"),
        ]
        if extra:
            command.extend(extra)
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=15,
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
                    argv[1:], ["--no-init", "--batch", "--bail"]
                )
                self.assertEqual(
                    argv[0], str(self.root / "database with spaces.db")
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
                self.assert_classification(run_dir, {"read": 1, "openat": 1})

    def test_classification_is_generated_without_summary(self):
        completed, run_dir, _, _ = self.run_tool(
            b"SELECT 1;\n", extra=["--no-summary"]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((run_dir / "summary.txt").exists())
        self.assert_classification(run_dir, {"read": 1, "openat": 1})
        self.assertIn(b"Classification report:", completed.stderr)
        self.assertIn(b"Classification CSV:", completed.stderr)

    def test_duckdb_args_reach_duckdb_and_metadata(self):
        query = b"SELECT 1;\n"
        for form, extra in (
            ("equals", ["--duckdb-arg=-unsigned"]),
            ("separator", ["--", "-unsigned"]),
        ):
            with self.subTest(form=form):
                completed, run_dir, capture, argv_capture = self.run_tool(
                    query, extra=extra
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(capture.read_bytes(), query)
                argv = json.loads(argv_capture.read_text(encoding="utf-8"))
                self.assertEqual(
                    argv[1:], ["--no-init", "--batch", "--bail", "-unsigned"]
                )
                metadata = json.loads(
                    (run_dir / "metadata.json").read_text(encoding="utf-8")
                )
                self.assertEqual(metadata["duckdb_args"], ["-unsigned"])

    def test_sql_bearing_duckdb_arg_is_rejected_before_duckdb_starts(self):
        completed, run_dir, capture, _ = self.run_tool(
            b"SELECT 1;\n",
            extra=["--duckdb-arg=-c", "--duckdb-arg=SELECT 'leaked';"],
        )
        self.assertEqual(completed.returncode, TRACE.TOOL_ERROR_STATUS)
        self.assertIn(b"puts SQL on the DuckDB command line", completed.stderr)
        self.assertNotIn(b"leaked", completed.stdout)
        self.assertFalse(capture.exists())
        self.assertFalse(run_dir.exists())

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
        report = self.assert_classification(run_dir, {"read": 1, "openat": 1})
        self.assertIn("DuckDB exited with status 7", report)

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
        self.assertEqual(argv[0], connection)

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
        report = self.assert_classification(run_dir, {"read": 1, "openat": 1})
        self.assertIn("run timed out", report)

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

    def test_xctrace_process_scope_preserves_duckdb_exit_status(self):
        query = b"SELECT FAIL_QUERY;\n"
        completed, run_dir, capture, _ = self.run_xctrace_tool(
            query, scope="process", run_name="xctrace-exit"
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        self.assertEqual(capture.read_bytes(), query)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["backend"], "xctrace")
        self.assertEqual(metadata["template"], "File Activity")
        self.assertEqual(metadata["tracer_exit_status"], 0)
        self.assertEqual(metadata["duckdb_exit_status"], 7)
        self.assertEqual(metadata["effective_exit_status"], 7)
        self.assertFalse(metadata["markers_injected"])
        self.assertFalse(metadata["children"])
        self.assertIsNone(metadata["query_window_ns"])
        self.assertEqual(metadata["exported_rows"], 6)
        self.assertEqual(metadata["complete_calls"], 6)
        self.assertTrue((run_dir / "recording.trace").exists())
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("syscall:recvfrom", summary)
        self.assertIn("syscall:stat64", summary)

    def test_xctrace_query_scope_brackets_the_trace_with_markers(self):
        query = b"SELECT 1;\n"
        completed, run_dir, capture, _ = self.run_xctrace_tool(
            query, scope="query", run_name="xctrace-query"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertTrue(metadata["markers_injected"])
        self.assertEqual(len(metadata["marker_files"]), 2)
        self.assertEqual(metadata["boundary_entries"], 1)
        self.assertEqual(metadata["boundary_returns"], 1)
        self.assertEqual(metadata["query_window_ns"], 300)
        self.assertEqual(metadata["exported_rows"], 6)
        # Only the four rows between the markers are summarised; the startup
        # and shutdown rows fall outside the window.
        self.assertEqual(metadata["complete_calls"], 4)
        self.assertIsNone(metadata["infrastructure_error"])
        # The recorded hash describes the caller's SQL, not the wrapped copy.
        self.assertEqual(
            metadata["query_sha256"], hashlib.sha256(query).hexdigest()
        )
        self.assertEqual(metadata["query_bytes"], len(query))
        received = capture.read_bytes()
        self.assertIn(query, received)
        self.assertIn(b"marker-begin-", received)
        self.assertIn(b"marker-end-", received)
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("Boundary events: 1 entry, 1 return", summary)
        # The negative return inside the window is the only error signal
        # FsSyscall offers.
        self.assertRegex(summary, r"syscall:recvfrom\s+2\s+1\s")
        self.assert_classification(run_dir, {"stat64": 2, "recvfrom": 2})

    def test_xctrace_preserves_database_paths_and_connection_strings(self):
        for run_number, database in enumerate(
            (
                str(self.root / "owner's \"database\" with spaces.db"),
                str(self.root / "database\\"),
                str(self.root / "database "),
                "md:demo?motherduck_token=example&option=value",
            )
        ):
            with self.subTest(database=database):
                completed, _, _, argv_capture = self.run_xctrace_tool(
                    b"SELECT 1;\n",
                    run_name="xctrace-database-{}".format(run_number),
                    extra=["--database", database],
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(
                    json.loads(argv_capture.read_text(encoding="utf-8")),
                    [database, "--no-init", "--batch", "--bail"],
                )

    def test_xctrace_engine_scope_is_rejected_before_duckdb_starts(self):
        completed, run_dir, capture, _ = self.run_xctrace_tool(
            b"SELECT 1;\n", scope="engine", run_name="xctrace-engine"
        )
        self.assertEqual(completed.returncode, TRACE.TOOL_ERROR_STATUS)
        self.assertIn(
            b"engine scope is not available with xctrace", completed.stderr
        )
        self.assertFalse(capture.exists())
        self.assertFalse(run_dir.exists())

    def test_xctrace_children_flag_is_rejected(self):
        completed, _, capture, _ = self.run_xctrace_tool(
            b"SELECT 1;\n",
            run_name="xctrace-children",
            extra=["--children"],
        )
        self.assertEqual(completed.returncode, TRACE.TOOL_ERROR_STATUS)
        self.assertIn(b"--children is not available", completed.stderr)
        self.assertFalse(capture.exists())

    def test_xctrace_recording_without_rows_is_an_infrastructure_error(self):
        completed, run_dir, _, _ = self.run_xctrace_tool(
            b"SELECT 1;\n",
            run_name="xctrace-empty",
            extra_env={"FAKE_XCTRACE_EMPTY": "1"},
        )
        self.assertEqual(completed.returncode, TRACE.TOOL_ERROR_STATUS)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["exported_rows"], 0)
        self.assertIn("recorded no", metadata["infrastructure_error"])
        report = self.assert_classification(run_dir, {})
        self.assertIn("No complete calls recorded.", report)
        self.assertIn("recorded no", report)

    def test_xctrace_target_permission_error_preserves_query_status(self):
        completed, run_dir, _, _ = self.run_xctrace_tool(
            b"SELECT PERMISSION_DENIED_QUERY;\n",
            scope="process",
            run_name="xctrace-permission-target",
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_unobserved_markers_warn_and_preserve_query_status(self):
        completed, run_dir, _, _ = self.run_xctrace_tool(
            b"SELECT FAIL_QUERY;\n",
            scope="query",
            run_name="xctrace-no-markers",
            extra_env={"FAKE_XCTRACE_NO_MARKERS": "1"},
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertIn("never observed", metadata["boundary_warning"])
        self.assertEqual(metadata["query_window_ns"], None)
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_bpftrace_query_scope_preserves_sql_output_and_exit_status(self):
        query = b"SELECT 1;\nSELECT 2;\n"
        completed, run_dir, capture, argv_capture = self.run_bpftrace_tool(
            query
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(capture.read_bytes(), query)
        self.assertEqual(completed.stdout, b"duckdb-output\n" + query)
        argv = json.loads(argv_capture.read_text(encoding="utf-8"))
        self.assertEqual(argv[1:], ["--no-init", "--batch", "--bail"])
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["backend"], "bpftrace")
        self.assertEqual(metadata["duckdb_exit_status"], 0)
        self.assertEqual(metadata["boundary_entries"], 1)
        self.assertEqual(metadata["boundary_returns"], 1)
        self.assertEqual(metadata["complete_calls"], 1)
        self.assertTrue((run_dir / "bpftrace-program.bt").exists())
        raw = (run_dir / "raw.bpftrace.jsonl").read_text(encoding="utf-8")
        self.assertIn('"trace_start"', raw)
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("syscall:read", summary)
        self.assert_classification(run_dir, {"read": 1})

    def test_bpftrace_preserves_failing_duckdb_status(self):
        completed, run_dir, _, _ = self.run_bpftrace_tool(
            b"SELECT FAIL_QUERY;\n",
            run_name="bpftrace-failure",
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["tracer_exit_status"], 0)
        self.assertEqual(metadata["duckdb_exit_status"], 7)
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_bpftrace_pre_boundary_failure_preserves_duckdb_status(self):
        completed, run_dir, _, _ = self.run_bpftrace_tool(
            b"SELECT FAIL_QUERY;\n",
            run_name="bpftrace-pre-boundary",
            extra_env={"FAKE_BPFTRACE_NO_BOUNDARY": "1"},
        )
        self.assertEqual(completed.returncode, 7, completed.stderr)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertIsNone(metadata["infrastructure_error"])
        self.assertIn("never observed", metadata["boundary_warning"])
        self.assertEqual(metadata["effective_exit_status"], 7)

    def test_bpftrace_timeout_returns_124_and_keeps_artifacts(self):
        completed, run_dir, _, _ = self.run_bpftrace_tool(
            b"SELECT SLOW_QUERY;\n",
            run_name="bpftrace-timeout",
            extra=["--timeout", "0.1"],
        )
        self.assertEqual(completed.returncode, 124, completed.stderr)
        self.assertTrue((run_dir / "raw.bpftrace.jsonl").stat().st_size)
        metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        self.assertTrue(metadata["timed_out"])
        self.assertEqual(metadata["effective_exit_status"], 124)

    def test_interrupt_kills_bpftrace_target_process_group(self):
        run_dir = self.root / "bpftrace-interrupt"
        capture = self.root / "bpftrace-interrupt-sql.bin"
        argv_capture = self.root / "bpftrace-interrupt-argv.json"
        pid_capture = self.root / "bpftrace-interrupt-pid.txt"
        env = os.environ.copy()
        env["FAKE_SQL_CAPTURE"] = str(capture)
        env["FAKE_ARGV_CAPTURE"] = str(argv_capture)
        env["FAKE_PID_CAPTURE"] = str(pid_capture)
        env["PATH"] = "{}{}{}".format(
            self.fake_bin, os.pathsep, env.get("PATH", "")
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT),
                "--backend",
                "bpftrace",
                "--scope",
                "query",
                "--duckdb",
                str(self.duckdb),
                "--tracer",
                str(self.bpftrace),
                "--output-dir",
                str(run_dir),
                "--sql",
                "SELECT SLOW_QUERY;",
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
        process.send_signal(signal.SIGINT)
        _, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 130, stderr)
        with self.assertRaises(ProcessLookupError):
            os.kill(target_pid, 0)

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
