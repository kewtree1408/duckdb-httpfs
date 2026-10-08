#!/usr/bin/env python3
"""Trace operating-system calls made by DuckDB while executing SQL."""

from __future__ import annotations

import argparse
import collections
import ctypes
import ctypes.util
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple


TOOL_VERSION = "1.1"
DEFAULT_DUCKDB = "build/release/duckdb"
DEFAULT_DATABASE = ":memory:"
DEFAULT_BUFFER_SIZE = "16m"
DEFAULT_STRING_LIMIT = 4096
TIMEOUT_EXIT_STATUS = 124
TOOL_ERROR_STATUS = 2

BUFFER_SIZE_RE = re.compile(r"^[1-9][0-9]*[kmgtKMGT]?$")
STRACE_COMPLETE_RE = re.compile(
    r"^(?:(?:\[pid\s+)?(?P<pid>[0-9]+)\]?\s+)?"
    r"(?P<timestamp>[0-9]+\.[0-9]+)\s+"
    r"(?P<call>[A-Za-z_][A-Za-z0-9_]*)\(.*\)\s+=\s+"
    r"(?P<result>.*?)\s+<(?P<duration>[0-9]+\.[0-9]+)>$"
)
STRACE_RESUMED_RE = re.compile(
    r"^(?:(?:\[pid\s+)?(?P<pid>[0-9]+)\]?\s+)?"
    r"(?P<timestamp>[0-9]+\.[0-9]+)\s+"
    r"<\.\.\.\s+(?P<call>[A-Za-z_][A-Za-z0-9_]*)\s+resumed>.*\s+=\s+"
    r"(?P<result>.*?)\s+<(?P<duration>[0-9]+\.[0-9]+)>$"
)


class TraceError(Exception):
    """An expected command-line or tracing error."""


class TraceSignal(Exception):
    """A termination signal received while a tracer process is active."""

    def __init__(self, signum: int):
        super().__init__("received signal {}".format(signum))
        self.signum = signum


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def isoformat(value: datetime.datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run DuckDB with SQL from an argument, file, or stdin and write a "
            "syscall trace, summary, and metadata."
        )
    )
    parser.add_argument(
        "--duckdb",
        default=DEFAULT_DUCKDB,
        help="DuckDB executable (default: %(default)s)",
    )
    parser.add_argument(
        "--database",
        default=DEFAULT_DATABASE,
        help="database path or DuckDB connection string (default: %(default)s)",
    )
    sql_group = parser.add_mutually_exclusive_group()
    sql_group.add_argument("--sql", help="SQL text; passed to DuckDB over stdin")
    sql_group.add_argument("--sql-file", help="read SQL bytes from this file")
    sql_group.add_argument(
        "--stdin",
        action="store_true",
        help="read SQL from stdin (also the default when stdin is not a terminal)",
    )
    parser.add_argument(
        "--scope",
        choices=("query", "engine", "process"),
        help=(
            "trace boundary; defaults to query with DTrace/bpftrace and process "
            "with strace"
        ),
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "dtrace", "strace", "bpftrace"),
        default="auto",
        help=(
            "tracing backend (default: DTrace on macOS; strace for Linux process "
            "scope and bpftrace for explicit Linux query/engine scope)"
        ),
    )
    parser.add_argument(
        "--tracer",
        help=(
            "path to dtrace, strace, or bpftrace "
            "(mainly useful for nonstandard installs)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        help="artifact directory (default: timestamped directory in the current directory)",
    )
    parser.add_argument("--raw-trace", help="raw trace path")
    parser.add_argument("--summary", help="human-readable summary path")
    parser.add_argument("--metadata", help="execution metadata path")
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="do not write a human-readable summary",
    )
    parser.add_argument(
        "--children",
        dest="children",
        action="store_true",
        default=True,
        help="include descendant processes (default)",
    )
    parser.add_argument(
        "--no-children",
        dest="children",
        action="store_false",
        help="exclude descendant processes (DTrace only; threads remain included)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="terminate the trace after this many seconds",
    )
    parser.add_argument(
        "--buffer-size",
        default=DEFAULT_BUFFER_SIZE,
        help="DTrace principal/dynamic buffer size (default: %(default)s)",
    )
    parser.add_argument(
        "--string-limit",
        type=int,
        default=DEFAULT_STRING_LIMIT,
        help="maximum strace string argument length (default: %(default)s)",
    )
    parser.add_argument(
        "--no-results",
        action="store_true",
        help="suppress DuckDB stdout; DuckDB and tracer errors remain visible",
    )
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    args = build_parser().parse_args(argv)
    if args.timeout is not None and args.timeout <= 0:
        raise TraceError("--timeout must be greater than zero")
    if not BUFFER_SIZE_RE.fullmatch(args.buffer_size):
        raise TraceError(
            "--buffer-size must be a positive integer with an optional k, m, g, or t suffix"
        )
    if args.string_limit <= 0:
        raise TraceError("--string-limit must be greater than zero")
    if args.no_summary and args.summary:
        raise TraceError("--summary and --no-summary cannot be used together")
    return args


def resolve_executable(value: str, description: str) -> str:
    if os.path.sep in value or (os.path.altsep and os.path.altsep in value):
        candidate = os.path.abspath(os.path.expanduser(value))
    else:
        found = shutil.which(value)
        candidate = found if found else value
    if not os.path.isfile(candidate):
        raise TraceError("{} not found: {}".format(description, value))
    if not os.access(candidate, os.X_OK):
        raise TraceError("{} is not executable: {}".format(description, candidate))
    return os.path.realpath(candidate)


def normalize_database(value: str) -> str:
    if value == ":memory:" or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value):
        return value
    return os.path.abspath(os.path.expanduser(value))


def database_metadata_value(value: str) -> str:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    if value != ":memory:" and match:
        return "{}:<redacted-connection-string>".format(match.group(1))
    return value


def read_sql(args: argparse.Namespace, stdin: Any = None) -> bytes:
    if args.sql is not None:
        return args.sql.encode("utf-8")
    if args.sql_file is not None:
        path = pathlib.Path(args.sql_file)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise TraceError("cannot read SQL file {}: {}".format(path, exc)) from exc

    source = stdin if stdin is not None else sys.stdin.buffer
    if not args.stdin and hasattr(source, "isatty") and source.isatty():
        raise TraceError("no SQL supplied; use --sql, --sql-file, or pipe SQL on stdin")
    try:
        data = source.read()
    except OSError as exc:
        raise TraceError("cannot read SQL from stdin: {}".format(exc)) from exc
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def select_backend(
    requested: str,
    system_name: Optional[str] = None,
    scope: Optional[str] = None,
) -> str:
    if requested != "auto":
        return requested
    host = system_name if system_name is not None else platform.system()
    if host == "Darwin":
        return "dtrace"
    if host == "Linux":
        if scope in ("query", "engine"):
            return "bpftrace"
        return "strace"
    raise TraceError(
        "unsupported platform {}; supported platforms are macOS and Linux".format(host)
    )


def select_scope(requested: Optional[str], backend: str) -> str:
    if requested:
        return requested
    return "query" if backend in ("dtrace", "bpftrace") else "process"


def make_artifact_paths(
    args: argparse.Namespace, backend: str, started: datetime.datetime
) -> Dict[str, Optional[pathlib.Path]]:
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    if args.output_dir:
        output_dir = pathlib.Path(args.output_dir).expanduser().absolute()
    else:
        base = pathlib.Path(
            "duckdb-syscall-trace-{}".format(stamp)
        ).absolute()
        output_dir = base
        suffix = 1
        while output_dir.exists():
            output_dir = pathlib.Path("{}-{}".format(base, suffix))
            suffix += 1
    if backend == "dtrace":
        raw_name = "raw.dtrace.jsonl"
    elif backend == "bpftrace":
        raw_name = "raw.bpftrace.jsonl"
    else:
        raw_name = "raw.strace"
    paths: Dict[str, Optional[pathlib.Path]] = {
        "output_dir": output_dir,
        "raw": pathlib.Path(args.raw_trace).expanduser().absolute()
        if args.raw_trace
        else output_dir / raw_name,
        "summary": None
        if args.no_summary
        else (
            pathlib.Path(args.summary).expanduser().absolute()
            if args.summary
            else output_dir / "summary.txt"
        ),
        "metadata": pathlib.Path(args.metadata).expanduser().absolute()
        if args.metadata
        else output_dir / "metadata.json",
        "program": (
            output_dir / "dtrace-program.d"
            if backend == "dtrace"
            else (
                output_dir / "bpftrace-program.bt"
                if backend == "bpftrace"
                else None
            )
        ),
    }
    artifacts = [
        path
        for name, path in paths.items()
        if name != "output_dir" and path is not None
    ]
    if len({str(path) for path in artifacts}) != len(artifacts):
        raise TraceError(
            "raw trace, summary, metadata, and tracer program paths must differ"
        )
    for path in artifacts:
        if path.exists():
            raise TraceError("refusing to overwrite existing artifact: {}".format(path))
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in artifacts:
        path.parent.mkdir(parents=True, exist_ok=True)
    return paths


def command_version(command: Sequence[str]) -> Optional[str]:
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout.decode("utf-8", "replace").strip()
    return output.splitlines()[0] if output else None


def duckdb_command(binary: str, database: str) -> List[str]:
    return [binary, "--no-init", "--batch", "--bail", database]


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_tracer(
    command: Sequence[str],
    sql: bytes,
    timeout: Optional[float],
    suppress_stdout: bool,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, bytes, bool]:
    stdout = subprocess.DEVNULL if suppress_stdout else None
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        raise TraceError("cannot start tracer: {}".format(exc)) from exc

    previous_signal_handlers: Dict[int, Any] = {}

    def handle_termination_signal(signum: int, _frame: Any) -> None:
        raise TraceSignal(signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        try:
            previous_signal_handlers[signum] = signal.signal(
                signum, handle_termination_signal
            )
        except (OSError, ValueError):
            pass

    timed_out = False
    stderr = b""
    try:
        try:
            _, stderr = process.communicate(input=sql, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(process)
            _, stderr = process.communicate()
        except BaseException:
            terminate_process_group(process)
            _, stderr = process.communicate()
            if stderr:
                sys.stderr.buffer.write(stderr)
                sys.stderr.buffer.flush()
            raise
    finally:
        for signum, previous_handler in previous_signal_handlers.items():
            signal.signal(signum, previous_handler)

    if stderr:
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()
    return process.returncode, stderr, timed_out


PAUSED_EXEC_CODE = (
    "import os, signal, sys\n"
    "os.kill(os.getpid(), signal.SIGSTOP)\n"
    "os.execv(sys.argv[1], sys.argv[1:])\n"
)


def wait_for_process_stop(
    process: subprocess.Popen[bytes], timeout: float = 5.0
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited_pid, status = os.waitpid(
            process.pid, os.WNOHANG | os.WUNTRACED
        )
        if waited_pid == 0:
            time.sleep(0.01)
            continue
        if os.WIFSTOPPED(status):
            return
        process.returncode = os.waitstatus_to_exitcode(status)
        stderr = process.stderr.read() if process.stderr is not None else b""
        detail = stderr.decode("utf-8", "replace").strip()
        raise TraceError(
            "DuckDB launcher exited before bpftrace could attach{}".format(
                ": {}".format(detail) if detail else ""
            )
        )
    terminate_process_group(process)
    raise TraceError("timed out waiting for the DuckDB launcher to pause")


def pump_bpftrace_output(
    stream: Any,
    raw_path: pathlib.Path,
    ready: threading.Event,
) -> None:
    with raw_path.open("wb") as handle:
        for line in iter(stream.readline, b""):
            handle.write(line)
            if not ready.is_set():
                try:
                    event = json.loads(line.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    event = {}
                if event.get("type") == "trace_start":
                    handle.flush()
                    ready.set()
    stream.close()


def pump_stream(stream: Any, chunks: List[bytes]) -> None:
    for chunk in iter(lambda: stream.read(65536), b""):
        chunks.append(chunk)
    stream.close()


def write_stderr(data: bytes) -> None:
    if data:
        sys.stderr.buffer.write(data)
        sys.stderr.buffer.flush()


def run_bpftrace(
    tracer: str,
    program_path: pathlib.Path,
    raw_path: pathlib.Path,
    binary: str,
    symbols: Sequence[str],
    scope: str,
    include_children: bool,
    target: Sequence[str],
    sql: bytes,
    timeout: Optional[float],
    suppress_stdout: bool,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, Optional[int], bytes, bool]:
    stdout = subprocess.DEVNULL if suppress_stdout else None
    launcher = [sys.executable, "-c", PAUSED_EXEC_CODE, *target]
    try:
        target_process = subprocess.Popen(
            launcher,
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        raise TraceError("cannot start DuckDB launcher: {}".format(exc)) from exc

    tracer_process: Optional[subprocess.Popen[bytes]] = None
    target_stderr = b""
    tracer_stderr_chunks: List[bytes] = []
    output_thread: Optional[threading.Thread] = None
    error_thread: Optional[threading.Thread] = None
    previous_signal_handlers: Dict[int, Any] = {}

    def handle_termination_signal(signum: int, _frame: Any) -> None:
        raise TraceSignal(signum)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        try:
            previous_signal_handlers[signum] = signal.signal(
                signum, handle_termination_signal
            )
        except (OSError, ValueError):
            pass

    try:
        wait_for_process_stop(target_process)
        program = build_bpftrace_program(
            scope,
            binary,
            symbols,
            target_process.pid,
            include_children,
        )
        atomic_write_text(program_path, program)
        command = build_bpftrace_command(
            tracer,
            program_path,
            target_process.pid,
        )
        try:
            tracer_process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
        except OSError as exc:
            terminate_process_group(target_process)
            target_process.communicate()
            raise TraceError("cannot start bpftrace: {}".format(exc)) from exc

        assert tracer_process.stdout is not None
        assert tracer_process.stderr is not None
        ready = threading.Event()
        output_thread = threading.Thread(
            target=pump_bpftrace_output,
            args=(tracer_process.stdout, raw_path, ready),
            daemon=True,
        )
        error_thread = threading.Thread(
            target=pump_stream,
            args=(tracer_process.stderr, tracer_stderr_chunks),
            daemon=True,
        )
        output_thread.start()
        error_thread.start()

        attach_deadline = time.monotonic() + 10.0
        while not ready.wait(0.05):
            if tracer_process.poll() is not None:
                break
            if time.monotonic() >= attach_deadline:
                break

        if not ready.is_set():
            attach_timed_out = tracer_process.poll() is None
            terminate_process_group(target_process)
            _, target_stderr = target_process.communicate()
            if tracer_process.poll() is None:
                terminate_process_group(tracer_process)
            tracer_process.wait()
            output_thread.join(timeout=2)
            error_thread.join(timeout=2)
            if attach_timed_out:
                tracer_stderr_chunks.append(
                    b"bpftrace: timed out waiting for probes to attach\n"
                )
            tracer_stderr = b"".join(tracer_stderr_chunks)
            write_stderr(target_stderr)
            write_stderr(tracer_stderr)
            return tracer_process.returncode, None, tracer_stderr, False

        os.killpg(target_process.pid, signal.SIGCONT)
        timed_out = False
        try:
            _, target_stderr = target_process.communicate(
                input=sql,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(target_process)
            _, target_stderr = target_process.communicate()

        target_returncode = None if timed_out else target_process.returncode
        try:
            tracer_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            terminate_process_group(tracer_process)
            tracer_process.wait()
        output_thread.join(timeout=2)
        error_thread.join(timeout=2)
        tracer_stderr = b"".join(tracer_stderr_chunks)
        write_stderr(target_stderr)
        write_stderr(tracer_stderr)
        return (
            tracer_process.returncode,
            target_returncode,
            tracer_stderr,
            timed_out,
        )
    except BaseException:
        if target_process.poll() is None:
            terminate_process_group(target_process)
        try:
            _, remaining_target_stderr = target_process.communicate()
            target_stderr += remaining_target_stderr
        except (OSError, ValueError):
            pass
        if tracer_process is not None and tracer_process.poll() is None:
            terminate_process_group(tracer_process)
        if tracer_process is not None:
            try:
                tracer_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        if output_thread is not None:
            output_thread.join(timeout=2)
        if error_thread is not None:
            error_thread.join(timeout=2)
        write_stderr(target_stderr)
        write_stderr(b"".join(tracer_stderr_chunks))
        raise
    finally:
        for signum, previous_handler in previous_signal_handlers.items():
            signal.signal(signum, previous_handler)


def parse_nm_symbols(output: str) -> List[str]:
    symbols: List[str] = []
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol = fields[-1]
        symbol_type = fields[-2] if len(fields) >= 2 else ""
        if symbol_type.upper() == "U":
            continue
        if symbol not in seen:
            seen.add(symbol)
            symbols.append(symbol)
    return symbols


def run_nm(binary: str) -> List[str]:
    nm = shutil.which("nm")
    if not nm:
        raise TraceError("nm is required to resolve DuckDB query-boundary symbols")
    commands: List[List[str]]
    if platform.system() == "Darwin":
        commands = [[nm, "-gU", binary], [nm, "-U", binary], [nm, binary]]
    else:
        commands = [
            [nm, "-D", "--defined-only", binary],
            [nm, "--defined-only", binary],
            [nm, binary],
        ]
    diagnostics: List[str] = []
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            diagnostics.append("{} timed out".format(" ".join(command[:2])))
            continue
        if completed.returncode == 0:
            symbols = parse_nm_symbols(completed.stdout.decode("utf-8", "replace"))
            if symbols:
                return symbols
        diagnostic = completed.stderr.decode("utf-8", "replace").strip()
        if diagnostic:
            diagnostics.append(diagnostic)
    detail = "; ".join(diagnostics[-2:]) if diagnostics else "no symbols found"
    raise TraceError("could not read symbols from {}: {}".format(binary, detail))


def demangle_symbols(symbols: Sequence[str]) -> List[str]:
    cxxfilt = shutil.which("c++filt")
    if not cxxfilt:
        raise TraceError("c++filt is required to resolve C++ query-boundary symbols")
    if not symbols:
        return []
    try:
        completed = subprocess.run(
            [cxxfilt],
            input=("\n".join(symbols) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TraceError("c++filt timed out while resolving symbols") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise TraceError("c++filt failed while resolving symbols: {}".format(detail))
    demangled = completed.stdout.decode("utf-8", "replace").splitlines()
    if len(demangled) != len(symbols):
        raise TraceError("c++filt returned an unexpected number of symbols")
    return demangled


def boundary_marker(scope: str) -> str:
    if scope == "query":
        return "duckdb_shell::ShellState::ExecuteSQL("
    if scope == "engine":
        return "duckdb::Connection::Query("
    raise TraceError("process scope does not use a C++ query-boundary symbol")


def resolve_boundary_symbols(binary: str, scope: str) -> List[Tuple[str, str]]:
    symbols = run_nm(binary)
    demangled = demangle_symbols(symbols)
    marker = boundary_marker(scope)
    matches = [
        (symbol, readable)
        for symbol, readable in zip(symbols, demangled)
        if marker in readable
    ]
    if not matches:
        raise TraceError(
            "DuckDB binary does not export a symbol matching {!r}; "
            "use --scope process or build an unstripped shell with that symbol".format(
                marker[:-1]
            )
        )
    return matches


def dtrace_probe_list(symbols: Sequence[str], probe: str) -> str:
    return ",\n".join(
        "pid$target::{}:{}".format(symbol, probe) for symbol in symbols
    )


def build_dtrace_program(
    scope: str, symbols: Sequence[str], include_children: bool
) -> str:
    subject = (
        "(pid == $target || progenyof($target))"
        if include_children
        else "pid == $target"
    )
    boundary = ""
    initial_active = 1 if scope == "process" else 0
    if scope != "process":
        entry_probes = dtrace_probe_list(symbols, "entry")
        return_probes = dtrace_probe_list(symbols, "return")
        boundary = """
{entry_probes}
{{
    boundary_depth[$target] = boundary_depth[$target] + 1;
    active[$target] = 1;
    printf("{{\\\"type\\\":\\\"boundary\\\",\\\"phase\\\":\\\"entry\\\",\\\"scope\\\":\\\"{scope}\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"depth\\\":%d}}\\n",
        walltimestamp, pid, tid, boundary_depth[$target]);
}}

{return_probes}
/boundary_depth[$target] > 0/
{{
    printf("{{\\\"type\\\":\\\"boundary\\\",\\\"phase\\\":\\\"return\\\",\\\"scope\\\":\\\"{scope}\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"depth\\\":%d}}\\n",
        walltimestamp, pid, tid, boundary_depth[$target]);
    boundary_depth[$target] = boundary_depth[$target] - 1;
    active[$target] = boundary_depth[$target] > 0;
}}
""".format(
            entry_probes=entry_probes,
            return_probes=return_probes,
            scope=scope,
        )

    return """#pragma D option quiet

dtrace:::BEGIN
{{
    active[$target] = {initial_active};
    boundary_depth[$target] = 0;
    printf("{{\\\"type\\\":\\\"trace_start\\\",\\\"scope\\\":\\\"{scope}\\\",\\\"ts_ns\\\":%lld,\\\"target_pid\\\":%d}}\\n",
        walltimestamp, $target);
}}

{boundary}

syscall:::entry
/active[$target] && ({subject})/
{{
    self->syscall_started = timestamp;
    self->syscall_arg0 = arg0;
    self->syscall_arg1 = arg1;
    self->syscall_arg2 = arg2;
    self->syscall_arg3 = arg3;
    self->syscall_arg4 = arg4;
    self->syscall_arg5 = arg5;
    printf("{{\\\"type\\\":\\\"call\\\",\\\"phase\\\":\\\"entry\\\",\\\"provider\\\":\\\"syscall\\\",\\\"call\\\":\\\"%s\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"args\\\":[%lld,%lld,%lld,%lld,%lld,%lld]}}\\n",
        probefunc, walltimestamp, pid, tid,
        self->syscall_arg0, self->syscall_arg1, self->syscall_arg2,
        self->syscall_arg3, self->syscall_arg4, self->syscall_arg5);
}}

syscall:::return
/self->syscall_started/
{{
    this->elapsed = timestamp - self->syscall_started;
    printf("{{\\\"type\\\":\\\"call\\\",\\\"phase\\\":\\\"return\\\",\\\"provider\\\":\\\"syscall\\\",\\\"call\\\":\\\"%s\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"return\\\":%lld,\\\"error\\\":%d,\\\"duration_ns\\\":%llu}}\\n",
        probefunc, walltimestamp, pid, tid, arg0, errno, this->elapsed);
    self->syscall_started = 0;
}}

mach_trap:::entry
/active[$target] && ({subject})/
{{
    self->mach_started = timestamp;
    self->mach_arg0 = arg0;
    self->mach_arg1 = arg1;
    self->mach_arg2 = arg2;
    self->mach_arg3 = arg3;
    self->mach_arg4 = arg4;
    self->mach_arg5 = arg5;
    printf("{{\\\"type\\\":\\\"call\\\",\\\"phase\\\":\\\"entry\\\",\\\"provider\\\":\\\"mach_trap\\\",\\\"call\\\":\\\"%s\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"args\\\":[%lld,%lld,%lld,%lld,%lld,%lld]}}\\n",
        probefunc, walltimestamp, pid, tid,
        self->mach_arg0, self->mach_arg1, self->mach_arg2,
        self->mach_arg3, self->mach_arg4, self->mach_arg5);
}}

mach_trap:::return
/self->mach_started/
{{
    this->elapsed = timestamp - self->mach_started;
    printf("{{\\\"type\\\":\\\"call\\\",\\\"phase\\\":\\\"return\\\",\\\"provider\\\":\\\"mach_trap\\\",\\\"call\\\":\\\"%s\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"tid\\\":%llu,\\\"return\\\":%lld,\\\"error\\\":null,\\\"duration_ns\\\":%llu}}\\n",
        probefunc, walltimestamp, pid, tid, arg0, this->elapsed);
    self->mach_started = 0;
}}

syscall::exit:entry
/pid == $target/
{{
    printf("{{\\\"type\\\":\\\"process_exit\\\",\\\"ts_ns\\\":%lld,\\\"pid\\\":%d,\\\"status\\\":%d}}\\n",
        walltimestamp, pid, arg0);
}}

dtrace:::ERROR
{{
    printf("{{\\\"type\\\":\\\"dtrace_error\\\",\\\"ts_ns\\\":%lld}}\\n",
        walltimestamp);
}}

dtrace:::END
{{
    printf("{{\\\"type\\\":\\\"trace_end\\\",\\\"scope\\\":\\\"{scope}\\\",\\\"ts_ns\\\":%lld,\\\"target_pid\\\":%d}}\\n",
        walltimestamp, $target);
}}
""".format(
        initial_active=initial_active,
        scope=scope,
        boundary=boundary,
        subject=subject,
    )


def bpftrace_probe_list(
    binary: str,
    symbols: Sequence[str],
    probe: str,
) -> str:
    binary_literal = json.dumps(binary)
    return ",\n".join(
        "{}:{}:{}".format(probe, binary_literal, symbol)
        for symbol in symbols
    )


def build_bpftrace_program(
    scope: str,
    binary: str,
    symbols: Sequence[str],
    target_pid: int,
    include_children: bool,
) -> str:
    if scope == "process":
        raise TraceError(
            "bpftrace process scope is not supported; use the strace backend"
        )
    if not symbols:
        raise TraceError("bpftrace query scope requires a boundary symbol")

    entry_probes = bpftrace_probe_list(binary, symbols, "uprobe")
    return_probes = bpftrace_probe_list(binary, symbols, "uretprobe")
    subject = "@tracked[pid]" if include_children else "pid == {}".format(target_pid)
    descendant_tracking = ""
    if include_children:
        descendant_tracking = r"""
tracepoint:sched:sched_process_fork
/@tracked[pid]/
{
    @tracked[args->child_pid] = 1;
}

tracepoint:sched:sched_process_exit
/pid == tid && @tracked[pid]/
{
    delete(@tracked[pid]);
}
"""

    return r"""
BEGIN
{{
    @tracked[{target_pid}] = 1;
    printf("{{\"type\":\"trace_start\",\"scope\":\"{scope}\",\"ts_ns\":%llu,\"target_pid\":%d}}\n",
        nsecs, {target_pid});
}}

{descendant_tracking}

{entry_probes}
/pid == {target_pid}/
{{
    @boundary_depth = @boundary_depth + 1;
    printf("{{\"type\":\"boundary\",\"phase\":\"entry\",\"scope\":\"{scope}\",\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d,\"depth\":%d}}\n",
        nsecs, pid, tid, @boundary_depth);
}}

{return_probes}
/pid == {target_pid} && @boundary_depth > 0/
{{
    printf("{{\"type\":\"boundary\",\"phase\":\"return\",\"scope\":\"{scope}\",\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d,\"depth\":%d}}\n",
        nsecs, pid, tid, @boundary_depth);
    @boundary_depth = @boundary_depth - 1;
}}

tracepoint:raw_syscalls:sys_enter
/@boundary_depth > 0 && ({subject})/
{{
    @syscall_started[tid] = nsecs;
    @syscall_number[tid] = args->id;
    printf("{{\"type\":\"call\",\"phase\":\"entry\",\"provider\":\"syscall\",\"syscall_nr\":%d,\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d}}\n",
        args->id, nsecs, pid, tid);
}}

tracepoint:raw_syscalls:sys_exit
/@syscall_started[tid]/
{{
    $return_value = args->ret;
    $duration = nsecs - @syscall_started[tid];
    if ($return_value < 0 && $return_value >= -4095) {{
        printf("{{\"type\":\"call\",\"phase\":\"return\",\"provider\":\"syscall\",\"syscall_nr\":%d,\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d,\"return\":%lld,\"error\":%lld,\"duration_ns\":%llu}}\n",
            @syscall_number[tid], nsecs, pid, tid, $return_value,
            0 - $return_value, $duration);
    }} else {{
        printf("{{\"type\":\"call\",\"phase\":\"return\",\"provider\":\"syscall\",\"syscall_nr\":%d,\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d,\"return\":%lld,\"error\":0,\"duration_ns\":%llu}}\n",
            @syscall_number[tid], nsecs, pid, tid, $return_value, $duration);
    }}
    delete(@syscall_started[tid]);
    delete(@syscall_number[tid]);
}}

END
{{
    printf("{{\"type\":\"trace_end\",\"scope\":\"{scope}\",\"ts_ns\":%llu,\"target_pid\":%d}}\n",
        nsecs, {target_pid});
    clear(@tracked);
    clear(@boundary_depth);
    clear(@syscall_started);
    clear(@syscall_number);
}}
""".format(
        target_pid=target_pid,
        scope=scope,
        descendant_tracking=descendant_tracking,
        entry_probes=entry_probes,
        return_probes=return_probes,
        subject=subject,
    )


def build_dtrace_command(
    tracer: str,
    program_path: pathlib.Path,
    raw_path: pathlib.Path,
    buffer_size: str,
    target: Sequence[str],
) -> List[str]:
    # DTrace accepts its -c target as one command string. SQL is not included:
    # it is written verbatim to stdin. shlex.join protects executable/database
    # path characters from the command parser.
    target_command = shlex.join(list(target))
    return [
        tracer,
        "-q",
        "-xmangled",
        "-b",
        buffer_size,
        "-x",
        "dynvarsize={}".format(buffer_size),
        "-o",
        str(raw_path),
        "-s",
        str(program_path),
        "-c",
        target_command,
    ]


def build_bpftrace_command(
    tracer: str,
    program_path: pathlib.Path,
    target_pid: int,
) -> List[str]:
    return [
        tracer,
        "-q",
        "-B",
        "line",
        "-p",
        str(target_pid),
        str(program_path),
    ]


def build_strace_command(
    tracer: str,
    raw_path: pathlib.Path,
    string_limit: int,
    target: Sequence[str],
) -> List[str]:
    return [
        tracer,
        "-f",
        "-qq",
        "-ttt",
        "-T",
        "-yy",
        "-s",
        str(string_limit),
        "-o",
        str(raw_path),
        "--",
        *target,
    ]


def dtrace_permission_diagnostic(stderr: str) -> Optional[str]:
    lowered = stderr.lower()
    patterns = (
        "operation not permitted",
        "permission denied",
        "failed to initialize dtrace",
        "requires root",
        "not permitted by system integrity protection",
    )
    if any(pattern in lowered for pattern in patterns):
        return (
            "DTrace could not start. Run the command with the privileges required "
            "by this macOS installation (commonly sudo). If it still fails, SIP "
            "or a restricted execution environment may prohibit DTrace."
        )
    return None


def tracer_failure_diagnostic(backend: str, stderr: str) -> Optional[str]:
    lowered = stderr.lower()
    if backend == "dtrace":
        permission = dtrace_permission_diagnostic(stderr)
        if permission:
            return permission
        if "failed to match" in lowered or "invalid probe specifier" in lowered:
            return (
                "DTrace could not enable the resolved DuckDB boundary probe. "
                "Inspect dtrace-program.d and retry with --scope process."
            )
        if "dtrace:" in lowered and ("failed" in lowered or "error" in lowered):
            return "DTrace reported an instrumentation error; see stderr and dtrace-program.d."
    elif backend == "bpftrace":
        permission_patterns = (
            "operation not permitted",
            "permission denied",
            "failed to load bpf",
            "could not open bpf map",
            "requires root",
        )
        if any(pattern in lowered for pattern in permission_patterns):
            return (
                "bpftrace could not load tracing programs. Run the command with "
                "sudo and verify that the EC2 kernel permits eBPF tracing."
            )
        probe_patterns = (
            "no probes to attach",
            "failed to attach",
            "could not attach",
            "tracepoint not found",
            "invalid probe",
            "uprobe",
        )
        if any(pattern in lowered for pattern in probe_patterns):
            return (
                "bpftrace could not attach the DuckDB boundary or syscall probes; "
                "inspect bpftrace-program.bt and verify the selected binary is "
                "unstripped."
            )
        if "bpftrace:" in lowered or "error:" in lowered:
            return "bpftrace reported an instrumentation error; see stderr."
    else:
        patterns = (
            "strace: can't stat",
            "strace: ptrace",
            "strace: invalid",
            "strace: unrecognized",
            "strace: option requires",
            "strace: command not found",
        )
        strace_error = "strace:" in lowered and any(
            marker in lowered
            for marker in (
                "operation not permitted",
                "permission denied",
                "failed",
                "error",
            )
        )
        if strace_error or any(pattern in lowered for pattern in patterns):
            return "strace could not trace DuckDB; see the preceding strace diagnostic."
    return None


def dropped_event_count(stderr: str) -> int:
    total = 0
    for line in stderr.splitlines():
        match = re.search(
            r"\b([0-9]+)\s+(?:(?:dynamic\s+variable|principal\s+buffer|"
            r"aggregation|speculation)\s+)?drops?\b",
            line,
            re.IGNORECASE,
        )
        if not match:
            match = re.search(
                r"\b(?:dropped|lost)\s+([0-9]+)\s+(?:records?|events?)\b",
                line,
                re.IGNORECASE,
            )
        if match:
            total += int(match.group(1))
    if total == 0 and re.search(
        r"\b(?:drop(?:ped|s)?|lost)\b", stderr, re.IGNORECASE
    ):
        return -1
    return total


def new_stats() -> Dict[str, Any]:
    return {
        "calls": collections.defaultdict(
            lambda: {"count": 0, "errors": 0, "total_ns": 0, "max_ns": 0}
        ),
        "complete_calls": 0,
        "entry_calls": 0,
        "boundary_entries": 0,
        "boundary_returns": 0,
        "malformed_lines": 0,
        "target_exit_status": None,
        "dtrace_errors": 0,
        "trace_starts": 0,
        "trace_ends": 0,
    }


def normalized_syscall_name(value: str) -> str:
    return re.sub(
        r"^tracepoint:syscalls:sys_(?:enter|exit)_",
        "",
        value,
    )


_SYSCALL_NAME_RESOLVER: Any = None
_SYSCALL_NAME_RESOLVER_INITIALIZED = False


def resolve_linux_syscall_name(number: int) -> str:
    global _SYSCALL_NAME_RESOLVER
    global _SYSCALL_NAME_RESOLVER_INITIALIZED

    if not _SYSCALL_NAME_RESOLVER_INITIALIZED:
        _SYSCALL_NAME_RESOLVER_INITIALIZED = True
        library_name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
        try:
            library = ctypes.CDLL(library_name)
            arch_native = library.seccomp_arch_native
            arch_native.argtypes = []
            arch_native.restype = ctypes.c_uint32
            resolve_number = library.seccomp_syscall_resolve_num_arch
            resolve_number.argtypes = [ctypes.c_uint32, ctypes.c_int]
            resolve_number.restype = ctypes.c_char_p
            architecture = arch_native()

            def resolver(value: int) -> Optional[bytes]:
                return resolve_number(architecture, value)

            _SYSCALL_NAME_RESOLVER = resolver
        except (AttributeError, OSError):
            _SYSCALL_NAME_RESOLVER = None

    if _SYSCALL_NAME_RESOLVER is not None:
        resolved = _SYSCALL_NAME_RESOLVER(number)
        if resolved:
            return resolved.decode("ascii", "replace")
    return "nr_{}".format(number)


def summarize_dtrace(path: pathlib.Path) -> Dict[str, Any]:
    stats = new_stats()
    if not path.exists():
        return stats
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                stats["malformed_lines"] += 1
                continue
            event_type = event.get("type")
            if event_type == "trace_start":
                stats["trace_starts"] += 1
            elif event_type == "trace_end":
                stats["trace_ends"] += 1
            elif event_type == "boundary":
                if event.get("phase") == "entry":
                    stats["boundary_entries"] += 1
                elif event.get("phase") == "return":
                    stats["boundary_returns"] += 1
            elif event_type == "process_exit":
                stats["target_exit_status"] = event.get("status")
            elif event_type == "dtrace_error":
                stats["dtrace_errors"] += 1
            elif event_type == "call" and event.get("phase") == "entry":
                stats["entry_calls"] += 1
            elif event_type == "call" and event.get("phase") == "return":
                provider = event.get("provider", "unknown")
                call_value = event.get("call")
                syscall_number = event.get("syscall_nr")
                if call_value is not None:
                    call = normalized_syscall_name(str(call_value))
                elif syscall_number is not None:
                    call = resolve_linux_syscall_name(int(syscall_number))
                else:
                    call = "unknown"
                key = "{}:{}".format(provider, call)
                duration = max(0, int(event.get("duration_ns", 0)))
                item = stats["calls"][key]
                item["count"] += 1
                item["total_ns"] += duration
                item["max_ns"] = max(item["max_ns"], duration)
                error = event.get("error")
                if error not in (None, 0):
                    item["errors"] += 1
                stats["complete_calls"] += 1
    return stats


def summarize_bpftrace(path: pathlib.Path) -> Dict[str, Any]:
    return summarize_dtrace(path)


def strace_line_match(line: str) -> Optional[re.Match[str]]:
    return STRACE_COMPLETE_RE.match(line) or STRACE_RESUMED_RE.match(line)


def summarize_strace(path: pathlib.Path) -> Dict[str, Any]:
    stats = new_stats()
    if not path.exists():
        return stats
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line or "<unfinished ...>" in line:
                continue
            match = strace_line_match(line)
            if not match:
                if not (
                    "+++ exited" in line
                    or "--- SIG" in line
                    or line.lstrip().startswith("strace:")
                    or "resumed>" in line
                ):
                    stats["malformed_lines"] += 1
                continue
            call = match.group("call")
            result = match.group("result").strip()
            duration = int(float(match.group("duration")) * 1_000_000_000)
            item = stats["calls"]["syscall:{}".format(call)]
            item["count"] += 1
            item["total_ns"] += duration
            item["max_ns"] = max(item["max_ns"], duration)
            if result.startswith("-1 "):
                item["errors"] += 1
            stats["complete_calls"] += 1
    return stats


def format_duration_ns(value: int) -> str:
    return "{:.3f}".format(value / 1_000_000)


def render_summary(
    stats: Dict[str, Any],
    scope: str,
    backend: str,
    raw_path: pathlib.Path,
    dropped: int,
) -> str:
    lines = [
        "DuckDB syscall trace summary",
        "Backend: {}".format(backend),
        "Scope: {}".format(scope),
        "Raw trace: {}".format(raw_path),
        "Complete calls: {}".format(stats["complete_calls"]),
    ]
    if backend in ("dtrace", "bpftrace"):
        lines.append(
            "Boundary events: {} entry, {} return".format(
                stats["boundary_entries"], stats["boundary_returns"]
            )
        )
    if backend == "dtrace":
        lines.append("DTrace error events: {}".format(stats["dtrace_errors"]))
    if backend in ("dtrace", "bpftrace"):
        if dropped == -1:
            lines.append(
                "Dropped events: reported by {} (count unavailable)".format(
                    backend
                )
            )
        else:
            lines.append("Dropped events: {}".format(dropped))
    if stats["malformed_lines"]:
        lines.append("Unparsed raw lines: {}".format(stats["malformed_lines"]))
    lines.extend(
        [
            "",
            "{:<42} {:>10} {:>10} {:>14} {:>14}".format(
                "Call", "Count", "Errors", "Total ms", "Maximum ms"
            ),
            "-" * 94,
        ]
    )
    ordered = sorted(
        stats["calls"].items(),
        key=lambda item: (-item[1]["total_ns"], item[0]),
    )
    for call, item in ordered:
        lines.append(
            "{:<42} {:>10} {:>10} {:>14} {:>14}".format(
                call[:42],
                item["count"],
                item["errors"],
                format_duration_ns(item["total_ns"]),
                format_duration_ns(item["max_ns"]),
            )
        )
    if not ordered:
        lines.append("(no complete calls recorded)")
    return "\n".join(lines) + "\n"


def atomic_write_text(path: pathlib.Path, text: str) -> None:
    temporary = path.with_name(".{}.tmp-{}".format(path.name, os.getpid()))
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def atomic_write_json(path: pathlib.Path, value: Dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def normalize_exit_status(returncode: int) -> int:
    if returncode < 0:
        return 128 + (-returncode)
    return returncode


def metadata_scope_description(scope: str, backend: str) -> str:
    if scope == "query":
        return (
            "ShellState::ExecuteSQL entry through return; includes SQL parsing, "
            "execution, result rendering, and all active DuckDB threads"
        )
    if scope == "engine":
        return (
            "Connection::Query entry through return; includes all active DuckDB "
            "threads but excludes shell rendering"
        )
    if backend == "strace":
        return "entire DuckDB process; strace follows threads and descendants"
    return "entire DuckDB process from startup through shutdown"


def main(argv: Optional[Sequence[str]] = None) -> int:
    started = utc_now()
    try:
        args = parse_args(argv)
        backend = select_backend(args.backend, scope=args.scope)
        scope = select_scope(args.scope, backend)
        if backend == "strace" and scope != "process":
            raise TraceError(
                "{} scope is not available with baseline strace because strace "
                "cannot observe DuckDB C++ function boundaries; use --scope process "
                "or use the bpftrace backend on Linux".format(scope)
            )
        if backend == "strace" and not args.children:
            raise TraceError(
                "--no-children is not supported by the strace backend: -f is "
                "required for DuckDB worker threads and also follows descendants"
            )
        if backend == "bpftrace" and scope == "process":
            raise TraceError(
                "process scope is not supported by the bpftrace backend; "
                "use --backend strace --scope process"
            )

        sql = read_sql(args)
        binary = resolve_executable(args.duckdb, "DuckDB executable")
        tracer_name = args.tracer or backend
        tracer = resolve_executable(tracer_name, "{} executable".format(backend))
        database = normalize_database(args.database)
        paths = make_artifact_paths(args, backend, started)
        raw_path = paths["raw"]
        assert raw_path is not None
        with raw_path.open("x"):
            pass

        symbols: List[Tuple[str, str]] = []
        if backend in ("dtrace", "bpftrace") and scope != "process":
            symbols = resolve_boundary_symbols(binary, scope)

        target = duckdb_command(binary, database)
        if backend == "dtrace":
            program_path = paths["program"]
            assert program_path is not None
            program = build_dtrace_program(
                scope, [symbol for symbol, _ in symbols], args.children
            )
            atomic_write_text(program_path, program)
            command = build_dtrace_command(
                tracer, program_path, raw_path, args.buffer_size, target
            )
        elif backend == "strace":
            command = build_strace_command(
                tracer, raw_path, args.string_limit, target
            )
        else:
            command = []

        duckdb_version = command_version([binary, "--version"])
        tracer_version = command_version([tracer, "-V"])

        bpftrace_target_returncode: Optional[int] = None
        if backend == "bpftrace":
            program_path = paths["program"]
            assert program_path is not None
            (
                tracer_returncode,
                bpftrace_target_returncode,
                stderr_bytes,
                timed_out,
            ) = run_bpftrace(
                tracer,
                program_path,
                raw_path,
                binary,
                [symbol for symbol, _ in symbols],
                scope,
                args.children,
                target,
                sql,
                args.timeout,
                args.no_results,
            )
        else:
            tracer_returncode, stderr_bytes, timed_out = run_tracer(
                command, sql, args.timeout, args.no_results
            )
        stderr_text = stderr_bytes.decode("utf-8", "replace")
        ended = utc_now()
        dropped = (
            dropped_event_count(stderr_text)
            if backend in ("dtrace", "bpftrace")
            else 0
        )
        if backend == "dtrace":
            stats = summarize_dtrace(raw_path)
        elif backend == "bpftrace":
            stats = summarize_bpftrace(raw_path)
        else:
            stats = summarize_strace(raw_path)

        infrastructure_error: Optional[str] = None
        boundary_warning: Optional[str] = None
        if timed_out:
            process_status: Optional[int] = None
            effective_status = TIMEOUT_EXIT_STATUS
        elif backend in ("dtrace", "bpftrace"):
            if backend == "dtrace":
                target_status = stats.get("target_exit_status")
                process_status = (
                    int(target_status) if target_status is not None else None
                )
            else:
                process_status = (
                    normalize_exit_status(bpftrace_target_returncode)
                    if bpftrace_target_returncode is not None
                    else None
                )
            if stats["trace_starts"] == 0:
                infrastructure_error = tracer_failure_diagnostic(
                    backend, stderr_text
                ) or "{} did not record a trace-start event.".format(backend)
            elif tracer_returncode != 0:
                infrastructure_error = tracer_failure_diagnostic(
                    backend, stderr_text
                ) or (
                    "{} exited with status {}.".format(
                        backend,
                        normalize_exit_status(tracer_returncode)
                    )
                )
            elif backend == "dtrace" and stats["dtrace_errors"]:
                infrastructure_error = (
                    "DTrace reported {} runtime error event(s).".format(
                        stats["dtrace_errors"]
                    )
                )
            elif process_status is None:
                infrastructure_error = (
                    "{} did not preserve DuckDB's exit status.".format(backend)
                )
            if (
                scope != "process"
                and stats["boundary_entries"] == 0
                and infrastructure_error is None
            ):
                boundary_message = (
                    "The resolved {} boundary was never observed; the trace is not "
                    "query-scoped.".format(scope)
                )
                if process_status:
                    boundary_warning = (
                        "{} DuckDB exited before entering the selected boundary; "
                        "preserving its exit status.".format(boundary_message)
                    )
                else:
                    infrastructure_error = boundary_message
            elif (
                scope != "process"
                and stats["boundary_entries"] != stats["boundary_returns"]
                and infrastructure_error is None
            ):
                boundary_message = (
                    "The {} boundary events are unbalanced ({} entry, {} return); "
                    "the trace may be incomplete.".format(
                        scope,
                        stats["boundary_entries"],
                        stats["boundary_returns"],
                    )
                )
                if process_status:
                    boundary_warning = (
                        "{} Preserving DuckDB's nonzero exit status.".format(
                            boundary_message
                        )
                    )
                else:
                    infrastructure_error = boundary_message
            effective_status = (
                TOOL_ERROR_STATUS
                if infrastructure_error
                else int(process_status if process_status is not None else TOOL_ERROR_STATUS)
            )
        else:
            process_status = normalize_exit_status(tracer_returncode)
            if raw_path.stat().st_size == 0:
                infrastructure_error = tracer_failure_diagnostic(
                    backend, stderr_text
                ) or "strace produced an empty raw trace."
            effective_status = TOOL_ERROR_STATUS if infrastructure_error else process_status

        summary_path = paths["summary"]
        if summary_path is not None:
            atomic_write_text(
                summary_path,
                render_summary(stats, scope, backend, raw_path, dropped),
            )

        metadata: Dict[str, Any] = {
            "tool": "trace_duckdb_syscalls",
            "tool_version": TOOL_VERSION,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "backend": backend,
            "tracer": {"path": tracer, "version": tracer_version},
            "duckdb": {"path": binary, "version": duckdb_version},
            "database_path": database_metadata_value(database),
            "scope": scope,
            "scope_description": metadata_scope_description(scope, backend),
            "children": args.children,
            "query_sha256": hashlib.sha256(sql).hexdigest(),
            "query_bytes": len(sql),
            "started_at": isoformat(started),
            "ended_at": isoformat(ended),
            "elapsed_seconds": round((ended - started).total_seconds(), 6),
            "timeout_seconds": args.timeout,
            "buffer_size": args.buffer_size if backend == "dtrace" else None,
            "string_limit": args.string_limit if backend == "strace" else None,
            "timed_out": timed_out,
            "duckdb_exit_status": process_status,
            "tracer_exit_status": normalize_exit_status(tracer_returncode),
            "effective_exit_status": effective_status,
            "raw_trace": str(raw_path),
            "summary": str(summary_path) if summary_path else None,
            "dropped_events": (
                dropped if backend in ("dtrace", "bpftrace") else None
            ),
            "complete_calls": stats["complete_calls"],
            "boundary_entries": stats["boundary_entries"]
            if backend in ("dtrace", "bpftrace")
            else None,
            "boundary_returns": stats["boundary_returns"]
            if backend in ("dtrace", "bpftrace")
            else None,
            "boundary_warning": boundary_warning,
            "dtrace_error_events": stats["dtrace_errors"]
            if backend == "dtrace"
            else None,
            "boundary_symbols": [
                {"mangled": symbol, "demangled": readable}
                for symbol, readable in symbols
            ],
            "infrastructure_error": infrastructure_error,
        }
        metadata_path = paths["metadata"]
        assert metadata_path is not None
        atomic_write_json(metadata_path, metadata)

        eprint("Raw trace: {}".format(raw_path))
        if summary_path is not None:
            eprint("Summary: {}".format(summary_path))
        eprint("Metadata: {}".format(metadata_path))
        if dropped:
            count_text = "an unknown number of" if dropped == -1 else str(dropped)
            if backend == "dtrace":
                eprint(
                    "warning: DTrace reported {} dropped events; "
                    "increase --buffer-size".format(count_text)
                )
            else:
                eprint(
                    "warning: bpftrace reported {} lost events; "
                    "the trace may be incomplete".format(count_text)
                )
        if infrastructure_error:
            eprint("trace error: {}".format(infrastructure_error))
        if boundary_warning:
            eprint("warning: {}".format(boundary_warning))
        return effective_status
    except TraceError as exc:
        eprint("trace_duckdb_syscalls: error: {}".format(exc))
        return TOOL_ERROR_STATUS
    except OSError as exc:
        eprint("trace_duckdb_syscalls: operating-system error: {}".format(exc))
        return TOOL_ERROR_STATUS
    except KeyboardInterrupt:
        eprint("trace_duckdb_syscalls: interrupted")
        return 130
    except TraceSignal as exc:
        eprint("trace_duckdb_syscalls: terminated by signal {}".format(exc.signum))
        return 128 + exc.signum


if __name__ == "__main__":
    sys.exit(main())
