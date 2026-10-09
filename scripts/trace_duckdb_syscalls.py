#!/usr/bin/env python3
"""Trace operating-system calls made by DuckDB while executing SQL."""

from __future__ import annotations

import argparse
import collections
import csv
import ctypes
import ctypes.util
import datetime
import functools
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple
from xml.etree import ElementTree


TOOL_VERSION = "2.1"
DEFAULT_DUCKDB = "build/release/duckdb"
DEFAULT_DATABASE = ":memory:"
DEFAULT_STRING_LIMIT = 4096
DEFAULT_TEMPLATE = "File Activity"
# Xcode 27 dropped the System Trace template, so File Activity is the only
# stock template that records BSD syscalls. Despite the name it also covers the
# socket calls (socket/connect/sendto/recvfrom) that httpfs work depends on.
FSSYSCALL_SCHEMA = "FsSyscall"
XCTRACE_ATTACH_TIMEOUT = 120.0
XCTRACE_SAVE_TIMEOUT = 180.0
TIMEOUT_EXIT_STATUS = 124
TOOL_ERROR_STATUS = 2
# DuckDB flags that carry SQL text in argv. Accepting them would put the query
# in the process table and leave query_sha256 describing only part of what ran.
SQL_BEARING_DUCKDB_FLAGS = frozenset(("-c", "-cmd", "-s"))
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
SYSCALL_CATEGORIES = {
    "Network and sockets": (
        "accept accept4 bind connect getsockname getpeername getsockopt "
        "listen necp_client_action necp_open recv recvfrom recvmsg recvmmsg "
        "send sendmsg sendmmsg sendto setsockopt shutdown socket"
    ).split(),
    "File and descriptor I/O": (
        "change_fdguard_np close close_range dup dup2 dup3 fcntl fdatasync "
        "flock fsync ftruncate ftruncate64 ioctl lseek open openat openat2 "
        "creat pread pread64 preadv preadv2 pwrite pwrite64 pwritev pwritev2 "
        "read readv write writev sendfile sendfile64 copy_file_range "
        "splice tee vmsplice fallocate truncate truncate64"
    ).split(),
    "Thread synchronization": (
        "psynch_cvbroad psynch_cvsignal psynch_cvwait psynch_mutexdrop "
        "psynch_mutexwait psynch_rw_rdlock psynch_rw_unlock psynch_rw_wrlock "
        "semaphore_signal_trap semaphore_wait_trap semaphore_timedwait_trap "
        "semaphore_wait_signal_trap semaphore_timedwait_signal_trap "
        "ulock_wait ulock_wait2 ulock_wake futex futex_time64 futex_waitv "
        "futex_wait futex_wake futex_requeue set_robust_list get_robust_list"
    ).split(),
    "I/O readiness and event notification": (
        "kevent kevent_id kevent_qos kqueue poll ppoll ppoll_time64 select "
        "pselect6 pselect6_time64 epoll_create epoll_create1 epoll_ctl "
        "epoll_wait epoll_pwait epoll_pwait2 eventfd eventfd2 "
        "io_uring_setup io_uring_enter io_uring_register "
        "io_setup io_destroy io_submit io_cancel io_getevents io_pgetevents"
    ).split(),
    "Virtual and shared memory": (
        "mach_vm_allocate_trap mach_vm_deallocate_trap mach_vm_map_trap "
        "mach_vm_protect_trap map_with_linking_np shared_region_check_np "
        "mmap mmap2 mprotect munmap mremap brk madvise msync mincore "
        "mlock mlock2 munlock mlockall munlockall "
        "shm_open shm_unlink shmget shmat shmdt shmctl memfd_create "
        "memfd_secret process_madvise"
    ).split(),
    "Thread lifecycle and workqueues": (
        "bsdthread_create bsdthread_ctl bsdthread_register disable_threadsignal "
        "gettid thread_selfid workq_kernreturn workq_open set_tid_address rseq "
        "sched_yield sched_getaffinity sched_setaffinity sched_getparam "
        "sched_setparam sched_getscheduler sched_setscheduler"
    ).split(),
    "IPC, Mach ports and activity context": (
        "host_create_mach_voucher_trap host_self_trap mach_generate_activity_id "
        "mach_msg_trap mach_msg_overwrite_trap mach_msg2_trap "
        "mach_port_construct_trap mach_port_deallocate_trap mach_port_destruct_trap "
        "mach_port_mod_refs_trap mach_port_request_notification_trap "
        "mach_reply_port task_self_trap thread_get_special_reply_port "
        "pipe pipe2 socketpair msgget msgsnd msgrcv msgctl "
        "semget semop semtimedop semctl"
    ).split(),
    "Filesystem metadata and discovery": (
        "access faccessat faccessat2 fgetattrlist fsgetpath fstatat64 "
        "fstatfs64 getattrlist getdirentries64 getfsstat64 stat64 fstat64 "
        "lstat64 stat fstat lstat newfstatat statx statfs fstatfs "
        "getdents getdents64 getcwd chdir fchdir readlink readlinkat "
        "getxattr fgetxattr lgetxattr listxattr flistxattr llistxattr "
        "mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2 "
        "link linkat symlink symlinkat chmod fchmod fchmodat "
        "chown fchown lchown fchownat utime utimes utimensat"
    ).split(),
    "Process identity, system information and signals": (
        "getegid geteuid getgid getpid getppid getpgrp getpgid getsid getrlimit "
        "getuid getresuid getresgid getgroups prlimit64 setrlimit getrusage "
        "proc_info sysctl sysinfo uname sigaction rt_sigaction sigprocmask "
        "rt_sigprocmask rt_sigreturn sigaltstack kill tkill tgkill"
    ).split(),
    "Security, tracing and platform support": (
        "csops csops_audittoken csrctl getentropy getrandom issetugid "
        "kdebug_typefilter mac_syscall crossarch_trap arch_prctl prctl "
        "seccomp capget capset ptrace"
    ).split(),
    "Time and clock information": (
        "gettimeofday mach_timebase_info clock_gettime clock_gettime64 "
        "clock_getres clock_getres_time64 nanosleep clock_nanosleep "
        "clock_nanosleep_time64 time times getitimer setitimer alarm "
        "timerfd_create timerfd_settime timerfd_gettime"
    ).split(),
    "Process lifecycle": (
        "clone clone3 fork vfork execve execveat exit exit_group wait4 waitid "
        "pidfd_open pidfd_getfd pidfd_send_signal"
    ).split(),
}
SYSCALL_CATEGORY_BY_NAME = {
    name: category
    for category, names in SYSCALL_CATEGORIES.items()
    for name in names
}
UNCLASSIFIED_CATEGORY = "Other / unclassified"


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
            "syscall trace, summary, classification reports, and metadata."
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
    parser.add_argument(
        "--duckdb-arg",
        dest="duckdb_args",
        action="append",
        default=[],
        metavar="ARG",
        help=(
            "extra DuckDB command-line argument, repeated once per argument; "
            "use the equals form for values that start with a dash "
            "(--duckdb-arg=-unsigned), or pass them after a -- separator"
        ),
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
            "trace boundary; defaults to query with xctrace/bpftrace and "
            "process with strace"
        ),
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "xctrace", "strace", "bpftrace"),
        default="auto",
        help=(
            "tracing backend (default: xctrace on macOS; strace for Linux "
            "process scope and bpftrace for explicit Linux query/engine scope)"
        ),
    )
    parser.add_argument(
        "--tracer",
        help=(
            "path to xctrace, strace, or bpftrace "
            "(mainly useful for nonstandard installs)"
        ),
    )
    parser.add_argument(
        "--template",
        default=DEFAULT_TEMPLATE,
        help="xctrace recording template (default: %(default)s)",
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
        help="omit summary.txt (classification reports are still written)",
    )
    parser.add_argument(
        "--children",
        dest="children",
        action="store_true",
        default=None,
        help="include descendant processes (default on strace and bpftrace)",
    )
    parser.add_argument(
        "--no-children",
        dest="children",
        action="store_false",
        help="exclude descendant processes (threads remain included)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="terminate the trace after this many seconds",
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


def split_passthrough(
    argv: Sequence[str],
) -> Tuple[List[str], List[str]]:
    values = list(argv)
    if "--" not in values:
        return values, []
    separator = values.index("--")
    return values[:separator], values[separator + 1 :]


def validate_duckdb_args(values: Sequence[str]) -> None:
    for value in values:
        if value.split("=", 1)[0] in SQL_BEARING_DUCKDB_FLAGS:
            raise TraceError(
                "{} puts SQL on the DuckDB command line, where it is visible to "
                "other processes and absent from query_sha256; supply SQL with "
                "--sql, --sql-file, or stdin".format(value.split("=", 1)[0])
            )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    options, passthrough = split_passthrough(
        sys.argv[1:] if argv is None else argv
    )
    args = build_parser().parse_args(options)
    args.duckdb_args = list(args.duckdb_args) + passthrough
    validate_duckdb_args(args.duckdb_args)
    if args.timeout is not None and args.timeout <= 0:
        raise TraceError("--timeout must be greater than zero")
    if not args.template.strip():
        raise TraceError("--template must not be empty")
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
        return "xctrace"
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
    return "query" if backend in ("xctrace", "bpftrace") else "process"


def select_children(requested: Optional[bool], backend: str) -> bool:
    if backend == "xctrace":
        if requested:
            raise TraceError(
                "--children is not available with xctrace: the recording "
                "attaches to one process and does not follow descendants; "
                "every thread of that process is always included"
            )
        return False
    return True if requested is None else requested


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
    if backend == "xctrace":
        raw_name = "raw.xctrace.jsonl"
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
            output_dir / "bpftrace-program.bt" if backend == "bpftrace" else None
        ),
        "bundle": output_dir / "recording.trace" if backend == "xctrace" else None,
        "classification_report": output_dir / "syscall-categories.md",
        "classification_csv": output_dir / "syscall-categories.csv",
    }
    artifacts = [
        path
        for name, path in paths.items()
        if name != "output_dir" and path is not None
    ]
    if len({str(path) for path in artifacts}) != len(artifacts):
        raise TraceError(
            "artifact paths must differ"
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


def duckdb_command(
    binary: str, database: str, extra_args: Sequence[str] = ()
) -> List[str]:
    return [binary, database, "--no-init", "--batch", "--bail", *extra_args]


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


def run_nm(binary: str) -> Iterator[List[str]]:
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
    found_symbols = False
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
                found_symbols = True
                yield symbols
        diagnostic = completed.stderr.decode("utf-8", "replace").strip()
        if diagnostic:
            diagnostics.append(diagnostic)
    if found_symbols:
        return
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
    marker = boundary_marker(scope)
    for symbols in run_nm(binary):
        demangled = demangle_symbols(symbols)
        matches = [
            (symbol, readable)
            for symbol, readable in zip(symbols, demangled)
            if marker in readable
        ]
        if matches:
            return matches
    raise TraceError(
        "DuckDB binary does not contain a symbol matching {!r}; "
        "use --scope process or build an unstripped shell with that symbol".format(
            marker[:-1]
        )
    )


def xctrace_templates(tracer: str) -> List[str]:
    try:
        completed = subprocess.run(
            [tracer, "list", "templates"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TraceError("cannot list xctrace templates: {}".format(exc)) from exc
    output = completed.stdout.decode("utf-8", "replace")
    if completed.returncode != 0:
        raise TraceError(
            "xctrace could not list templates: {}".format(output.strip())
        )
    names = []
    for line in output.splitlines():
        name = line.strip()
        if name and not name.startswith("=="):
            names.append(name)
    return names


def ensure_xctrace_template(tracer: str, template: str) -> None:
    available = xctrace_templates(tracer)
    if template in available:
        return
    raise TraceError(
        "xctrace template {!r} is unavailable. Recording needs a full Xcode "
        "installation rather than the Command Line Tools alone. Available "
        "templates: {}".format(template, ", ".join(available) or "none")
    )


def build_xctrace_record_command(
    tracer: str,
    template: str,
    bundle_path: pathlib.Path,
    target_pid: int,
) -> List[str]:
    return [
        tracer,
        "record",
        "--template",
        template,
        "--output",
        str(bundle_path),
        "--no-prompt",
        "--attach",
        str(target_pid),
    ]


def build_xctrace_export_command(
    tracer: str, bundle_path: pathlib.Path, schema: str = FSSYSCALL_SCHEMA
) -> List[str]:
    return [
        tracer,
        "export",
        "--input",
        str(bundle_path),
        "--xpath",
        '/trace-toc/run[@number="1"]/data/table[@schema="{}"]'.format(schema),
    ]


def sql_string_literal(value: str) -> str:
    return "'{}'".format(value.replace("'", "''"))


def marker_paths(
    output_dir: pathlib.Path, nonce: str
) -> Tuple[pathlib.Path, pathlib.Path]:
    return (
        output_dir / "marker-begin-{}.csv".format(nonce),
        output_dir / "marker-end-{}.csv".format(nonce),
    )


def write_marker_files(begin: pathlib.Path, end: pathlib.Path) -> None:
    for path in (begin, end):
        path.write_bytes(b"duckdb_trace_marker\n1\n")


def wrap_sql_with_markers(
    sql: bytes, begin: pathlib.Path, end: pathlib.Path
) -> bytes:
    def read_marker(path: pathlib.Path) -> bytes:
        return "SELECT * FROM read_csv({});\n".format(
            sql_string_literal(str(path))
        ).encode("utf-8")

    separator = b"" if not sql or sql.endswith(b"\n") else b"\n"
    return read_marker(begin) + sql + separator + read_marker(end)


def find_marker_window(
    rows: Sequence[Dict[str, Any]], nonce: str
) -> Optional[Tuple[int, int]]:
    def timestamps(prefix: str) -> List[int]:
        needle = "marker-{}-{}".format(prefix, nonce)
        return [
            row["start_ns"]
            for row in rows
            if row["path"] and needle in row["path"]
        ]

    begins = timestamps("begin")
    ends = timestamps("end")
    if not begins or not ends:
        return None
    return min(begins), max(ends)


def parse_fssyscall_xml(payload: bytes) -> List[Dict[str, Any]]:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise TraceError(
            "could not parse the xctrace export: {}".format(exc)
        ) from exc

    # The exporter writes each distinct value once with an id attribute and
    # refers to every later occurrence by ref, so reading a column means
    # following those back-references.
    catalogue = {
        element.get("id"): element for element in root.iter() if element.get("id")
    }

    def resolve(element: Any) -> Any:
        if element is None:
            return None
        reference = element.get("ref")
        return catalogue.get(reference) if reference else element

    def column(parent: Any, tag: str) -> Any:
        return resolve(parent.find(tag)) if parent is not None else None

    def number(element: Any) -> Optional[int]:
        if element is None or not element.text:
            return None
        try:
            return int(element.text)
        except ValueError:
            return None

    rows: List[Dict[str, Any]] = []
    for row in root.findall(".//row"):
        start = number(column(row, "start-time"))
        if start is None:
            continue
        syscall = column(row, "syscall")
        path = column(row, "file-path")
        rows.append(
            {
                "start_ns": start,
                "duration_ns": number(column(row, "duration")) or 0,
                "call": syscall.get("fmt") if syscall is not None else "unknown",
                "return": number(column(row, "syscall-return")),
                "pid": number(column(column(row, "process"), "pid")),
                "tid": number(column(column(row, "thread"), "tid")),
                "path": path.get("fmt") if path is not None else None,
            }
        )
    rows.sort(key=lambda row: row["start_ns"])
    return rows


def export_fssyscall_rows(
    tracer: str, bundle_path: pathlib.Path
) -> List[Dict[str, Any]]:
    command = build_xctrace_export_command(tracer, bundle_path)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TraceError(
            "cannot export the xctrace recording: {}".format(exc)
        ) from exc
    if completed.returncode != 0:
        raise TraceError(
            "xctrace export failed: {}".format(
                completed.stderr.decode("utf-8", "replace").strip()
            )
        )
    return parse_fssyscall_xml(completed.stdout)


def write_xctrace_jsonl(
    rows: Sequence[Dict[str, Any]],
    raw_path: pathlib.Path,
    scope: str,
    window: Optional[Tuple[int, int]],
    target_pid: Optional[int],
) -> None:
    first = rows[0]["start_ns"] if rows else 0
    last = rows[-1]["start_ns"] if rows else 0
    with raw_path.open("w", encoding="utf-8") as handle:
        def emit(event: Dict[str, Any]) -> None:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

        def boundary(phase: str, timestamp: int) -> None:
            emit(
                {
                    "type": "boundary",
                    "phase": phase,
                    "scope": scope,
                    "ts_ns": timestamp,
                    "pid": target_pid,
                    "tid": None,
                    "depth": 1,
                }
            )

        emit(
            {
                "type": "trace_start",
                "scope": scope,
                "ts_ns": first,
                "target_pid": target_pid,
            }
        )
        if window is not None:
            boundary("entry", window[0])
        for row in rows:
            if window is not None and not window[0] <= row["start_ns"] <= window[1]:
                continue
            shared = {
                "type": "call",
                "provider": "syscall",
                "call": row["call"],
                "pid": row["pid"],
                "tid": row["tid"],
            }
            emit(dict(shared, phase="entry", ts_ns=row["start_ns"], path=row["path"]))
            returned = row["return"]
            emit(
                dict(
                    shared,
                    phase="return",
                    ts_ns=row["start_ns"] + row["duration_ns"],
                    duration_ns=row["duration_ns"],
                    # FsSyscall has no errno column, so a negative return is
                    # the only available error signal.
                    error=1 if returned is not None and returned < 0 else 0,
                    **{"return": returned},
                )
            )
        if window is not None:
            boundary("return", window[1])
        emit(
            {
                "type": "trace_end",
                "scope": scope,
                "ts_ns": last,
                "target_pid": target_pid,
            }
        )


def pump_xctrace_output(
    stream: Any, chunks: List[bytes], ready: threading.Event
) -> None:
    for line in iter(stream.readline, b""):
        chunks.append(line)
        if b"Ctrl-C to stop" in line:
            ready.set()
    stream.close()


def run_xctrace(
    tracer: str,
    template: str,
    bundle_path: pathlib.Path,
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
    tracer_chunks: List[bytes] = []
    output_thread: Optional[threading.Thread] = None
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
        command = build_xctrace_record_command(
            tracer, template, bundle_path, target_process.pid
        )
        try:
            tracer_process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
            )
        except OSError as exc:
            terminate_process_group(target_process)
            target_process.communicate()
            raise TraceError("cannot start xctrace: {}".format(exc)) from exc

        assert tracer_process.stdout is not None
        ready = threading.Event()
        output_thread = threading.Thread(
            target=pump_xctrace_output,
            args=(tracer_process.stdout, tracer_chunks, ready),
            daemon=True,
        )
        output_thread.start()

        attach_deadline = time.monotonic() + XCTRACE_ATTACH_TIMEOUT
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
            if attach_timed_out:
                tracer_chunks.append(
                    b"xctrace: timed out waiting for the recording to start\n"
                )
            tracer_stderr = b"".join(tracer_chunks)
            write_stderr(target_stderr)
            write_stderr(tracer_stderr)
            return tracer_process.returncode, None, tracer_stderr, False

        os.killpg(target_process.pid, signal.SIGCONT)
        timed_out = False
        try:
            _, target_stderr = target_process.communicate(
                input=sql, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(target_process)
            _, target_stderr = target_process.communicate()

        target_returncode = None if timed_out else target_process.returncode
        # xctrace normally notices the target exiting and saves by itself; the
        # interrupt is the fallback for a timeout or a missed exit.
        try:
            tracer_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            tracer_process.send_signal(signal.SIGINT)
            try:
                tracer_process.wait(timeout=XCTRACE_SAVE_TIMEOUT)
            except subprocess.TimeoutExpired:
                terminate_process_group(tracer_process)
                tracer_process.wait()
        output_thread.join(timeout=2)
        tracer_stderr = b"".join(tracer_chunks)
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
        write_stderr(target_stderr)
        write_stderr(b"".join(tracer_chunks))
        raise
    finally:
        for signum, previous_handler in previous_signal_handlers.items():
            signal.signal(signum, previous_handler)


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


def tracer_failure_diagnostic(backend: str, stderr: str) -> Optional[str]:
    lowered = stderr.lower()
    if backend == "xctrace":
        if "xraugmentationmanager" in lowered or "mac policy error" in lowered:
            return (
                "xctrace aborted before recording. This happens inside an OS "
                "sandbox such as Seatbelt; run the command outside the sandbox."
            )
        if "cannot find template" in lowered:
            return (
                "xctrace does not have the requested template. A full Xcode "
                "installation is required, and Xcode 27 removed System Trace; "
                "File Activity is the template that records syscalls."
            )
        if "failed to attach" in lowered or "unable to attach" in lowered:
            return (
                "xctrace could not attach to DuckDB. Verify that the selected "
                "binary runs and that no other recording holds the process."
            )
        if "error" in lowered or "failed" in lowered:
            return "xctrace reported a recording error; see the output above."
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
        match = re.search(r"\b([0-9]+)\s+drops?\b", line, re.IGNORECASE)
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
            resolve_number.restype = ctypes.c_void_p
            free = ctypes.CDLL(None).free
            free.argtypes = [ctypes.c_void_p]
            free.restype = None
            architecture = arch_native()

            @functools.lru_cache(maxsize=1024)
            def resolver(value: int) -> Optional[bytes]:
                pointer = resolve_number(architecture, value)
                if not pointer:
                    return None
                try:
                    return ctypes.string_at(pointer)
                finally:
                    free(pointer)

            _SYSCALL_NAME_RESOLVER = resolver
        except (AttributeError, OSError):
            _SYSCALL_NAME_RESOLVER = None

    if _SYSCALL_NAME_RESOLVER is not None:
        resolved = _SYSCALL_NAME_RESOLVER(number)
        if resolved:
            return resolved.decode("ascii", "replace")
    return "nr_{}".format(number)


def summarize_events(path: pathlib.Path) -> Dict[str, Any]:
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
    if backend in ("xctrace", "bpftrace"):
        lines.append(
            "Boundary events: {} entry, {} return".format(
                stats["boundary_entries"], stats["boundary_returns"]
            )
        )
    if backend == "bpftrace":
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


def syscall_category(name: str) -> str:
    name = normalized_syscall_name(name)
    if name.startswith("sys_"):
        name = name[4:]
    if name.endswith("_nocancel"):
        name = name[: -len("_nocancel")]
    return SYSCALL_CATEGORY_BY_NAME.get(name, UNCLASSIFIED_CATEGORY)


def classified_syscalls(stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for qualified_name, item in stats["calls"].items():
        provider, _, name = qualified_name.partition(":")
        rows.append(
            dict(
                category=syscall_category(name),
                provider=provider,
                syscall=name,
                **item,
            )
        )
    return sorted(
        rows, key=lambda row: (row["category"], row["provider"], row["syscall"])
    )


def render_classification_csv(stats: Dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=(
            "category", "provider", "syscall", "count", "errors",
            "total_ns", "max_ns",
        ),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(classified_syscalls(stats))
    return output.getvalue()


def render_classification_report(
    stats: Dict[str, Any], metadata: Dict[str, Any]
) -> str:
    groups: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in classified_syscalls(stats):
        groups[row["category"]].append(row)
    counts = {
        category: sum(row["count"] for row in rows)
        for category, rows in groups.items()
    }
    ordered = sorted(groups, key=lambda category: (-counts[category], category))
    total = stats["complete_calls"]
    lines = [
        "# DuckDB syscall classification",
        "",
        "Run: {} · Backend: {} · Scope: {}".format(
            metadata["started_at"], metadata["backend"], metadata["scope"]
        ),
        "",
        "**{:,} completed calls, {} distinct provider/name pairs, "
        "{} observed categories.**".format(total, len(stats["calls"]), len(groups)),
        "",
        "Each completed call is classified exactly once by its API purpose. "
        "Unknown names and unresolved syscall numbers remain in "
        "**Other / unclassified**.",
        "",
        "[Download per-syscall counts and timings](syscall-categories.csv).",
        "",
        "Counts measure frequency, not time spent. Descriptor operations such "
        "as `read`, `write`, `ioctl`, and `fcntl` may act on files, pipes, sockets, "
        "or terminals; they are not necessarily disk I/O. Synchronization may "
        "include waiting for HTTP workers or idle workers. Summed syscall "
        "durations overlap across threads and are not process wall time.",
        "",
        "Only completed calls captured by the selected backend and scope are "
        "included. An absent category does not prove those operations never "
        "occurred. Error counts inherit the backend's detection limits.",
    ]
    warnings = []
    if metadata.get("timed_out"):
        warnings.append("The run timed out; this report contains partial data.")
    if metadata.get("infrastructure_error"):
        warnings.append(metadata["infrastructure_error"])
    if metadata.get("boundary_warning"):
        warnings.append(metadata["boundary_warning"])
    if metadata.get("duckdb_exit_status") not in (None, 0):
        warnings.append(
            "DuckDB exited with status {}.".format(metadata["duckdb_exit_status"])
        )
    dropped = metadata.get("dropped_events")
    if dropped:
        warnings.append(
            "The tracer reported {} lost events; this report is incomplete.".format(
                "an unknown number of" if dropped == -1 else dropped
            )
        )
    if stats["malformed_lines"]:
        warnings.append(
            "{} raw lines could not be parsed.".format(stats["malformed_lines"])
        )
    if warnings:
        lines.extend(["", "## Capture notes", ""])
        lines.extend("- {}".format(warning) for warning in warnings)
    lines.extend(
        [
            "",
            "## Category totals",
            "",
            "| Category | Calls | Share | Provider/name pairs |",
            "|---|---:|---:|---:|",
        ]
    )
    for category in ordered:
        count = counts[category]
        lines.append(
            "| {} | {:,} | {:.2f}% | {} |".format(
                category, count, 100 * count / total if total else 0, len(groups[category])
            )
        )
    if not ordered:
        lines.extend(["", "No complete calls recorded."])
    for category in ordered:
        lines.extend(
            [
                "",
                "## {}".format(category),
                "",
                "| Provider | Syscall | Calls | Errors | Total ms | Maximum ms |",
                "|---|---|---:|---:|---:|---:|",
            ]
        )
        for row in groups[category]:
            lines.append(
                "| `{provider}` | `{syscall}` | {count:,} | {errors:,} | "
                "{total_ms} | {maximum_ms} |".format(
                    **row,
                    total_ms=format_duration_ns(row["total_ns"]),
                    maximum_ms=format_duration_ns(row["max_ns"]),
                )
            )
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
    if scope == "query" and backend == "xctrace":
        return (
            "first marker read through last marker read; includes the supplied "
            "SQL, its DuckDB threads, and the two injected marker statements, "
            "but excludes startup, extension loading, and shutdown"
        )
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
        children = select_children(args.children, backend)
        if backend == "strace" and scope != "process":
            raise TraceError(
                "{} scope is not available with baseline strace because strace "
                "cannot observe DuckDB C++ function boundaries; use --scope process "
                "or use the bpftrace backend on Linux".format(scope)
            )
        if backend == "strace" and not children:
            raise TraceError(
                "--no-children is not supported by the strace backend: -f is "
                "required for DuckDB worker threads and also follows descendants"
            )
        if backend == "bpftrace" and scope == "process":
            raise TraceError(
                "process scope is not supported by the bpftrace backend; "
                "use --backend strace --scope process"
            )
        if backend == "xctrace" and scope == "engine":
            raise TraceError(
                "engine scope is not available with xctrace: Connection::Query "
                "has no observable side effect to mark, and xctrace cannot "
                "probe C++ function boundaries; use --scope query or "
                "--scope process"
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
        if backend == "bpftrace" and scope != "process":
            symbols = resolve_boundary_symbols(binary, scope)

        # query_sha256 and query_bytes describe the SQL the caller supplied, so
        # the marker-wrapped copy stays separate.
        traced_sql = sql
        markers: Optional[Tuple[pathlib.Path, pathlib.Path]] = None
        nonce = ""
        if backend == "xctrace":
            ensure_xctrace_template(tracer, args.template)
            if scope == "query":
                nonce = uuid.uuid4().hex[:12]
                output_dir = paths["output_dir"]
                assert output_dir is not None
                markers = marker_paths(output_dir, nonce)
                write_marker_files(*markers)
                traced_sql = wrap_sql_with_markers(sql, *markers)

        target = duckdb_command(binary, database, args.duckdb_args)
        if backend == "strace":
            command = build_strace_command(
                tracer, raw_path, args.string_limit, target
            )
        else:
            command = []

        duckdb_version = command_version([binary, "--version"])
        tracer_version = command_version(
            [tracer, "version"] if backend == "xctrace" else [tracer, "-V"]
        )

        attached_target_returncode: Optional[int] = None
        window: Optional[Tuple[int, int]] = None
        exported_rows = 0
        if backend == "bpftrace":
            program_path = paths["program"]
            assert program_path is not None
            (
                tracer_returncode,
                attached_target_returncode,
                stderr_bytes,
                timed_out,
            ) = run_bpftrace(
                tracer,
                program_path,
                raw_path,
                binary,
                [symbol for symbol, _ in symbols],
                scope,
                children,
                target,
                traced_sql,
                args.timeout,
                args.no_results,
            )
        elif backend == "xctrace":
            bundle_path = paths["bundle"]
            assert bundle_path is not None
            (
                tracer_returncode,
                attached_target_returncode,
                stderr_bytes,
                timed_out,
            ) = run_xctrace(
                tracer,
                args.template,
                bundle_path,
                target,
                traced_sql,
                args.timeout,
                args.no_results,
            )
            if bundle_path.exists():
                rows = export_fssyscall_rows(tracer, bundle_path)
                exported_rows = len(rows)
                if scope == "query":
                    window = find_marker_window(rows, nonce)
                write_xctrace_jsonl(
                    rows, raw_path, scope, window, rows[0]["pid"] if rows else None
                )
        else:
            tracer_returncode, stderr_bytes, timed_out = run_tracer(
                command, traced_sql, args.timeout, args.no_results
            )
        stderr_text = stderr_bytes.decode("utf-8", "replace")
        ended = utc_now()
        dropped = dropped_event_count(stderr_text) if backend == "bpftrace" else 0
        if backend in ("xctrace", "bpftrace"):
            stats = summarize_events(raw_path)
        else:
            stats = summarize_strace(raw_path)

        infrastructure_error: Optional[str] = None
        boundary_warning: Optional[str] = None
        if timed_out:
            process_status: Optional[int] = None
            effective_status = TIMEOUT_EXIT_STATUS
        elif backend in ("xctrace", "bpftrace"):
            process_status = (
                normalize_exit_status(attached_target_returncode)
                if attached_target_returncode is not None
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
            elif backend == "xctrace" and exported_rows == 0:
                infrastructure_error = (
                    "xctrace recorded no {} rows; the template captured no "
                    "syscalls for DuckDB.".format(FSSYSCALL_SCHEMA)
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
                    "The injected {} markers were never observed; the trace is "
                    "not query-scoped.".format(scope)
                    if backend == "xctrace"
                    else "The resolved {} boundary was never observed; the "
                    "trace is not query-scoped.".format(scope)
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
            "duckdb_args": list(args.duckdb_args),
            "database_path": database_metadata_value(database),
            "scope": scope,
            "scope_description": metadata_scope_description(scope, backend),
            "children": children,
            "query_sha256": hashlib.sha256(sql).hexdigest(),
            "query_bytes": len(sql),
            "started_at": isoformat(started),
            "ended_at": isoformat(ended),
            "elapsed_seconds": round((ended - started).total_seconds(), 6),
            "timeout_seconds": args.timeout,
            "template": args.template if backend == "xctrace" else None,
            "trace_bundle": str(paths["bundle"]) if paths["bundle"] else None,
            "markers_injected": markers is not None,
            "marker_files": [str(path) for path in markers] if markers else [],
            "query_window_ns": (window[1] - window[0]) if window else None,
            "exported_rows": exported_rows if backend == "xctrace" else None,
            "string_limit": args.string_limit if backend == "strace" else None,
            "timed_out": timed_out,
            "duckdb_exit_status": process_status,
            "tracer_exit_status": normalize_exit_status(tracer_returncode),
            "effective_exit_status": effective_status,
            "raw_trace": str(raw_path),
            "summary": str(summary_path) if summary_path else None,
            "classification_report": str(paths["classification_report"]),
            "classification_csv": str(paths["classification_csv"]),
            "dropped_events": dropped if backend == "bpftrace" else None,
            "complete_calls": stats["complete_calls"],
            "boundary_entries": stats["boundary_entries"]
            if backend in ("xctrace", "bpftrace")
            else None,
            "boundary_returns": stats["boundary_returns"]
            if backend in ("xctrace", "bpftrace")
            else None,
            "boundary_warning": boundary_warning,
            "boundary_symbols": [
                {"mangled": symbol, "demangled": readable}
                for symbol, readable in symbols
            ],
            "infrastructure_error": infrastructure_error,
        }
        classification_report = paths["classification_report"]
        classification_csv = paths["classification_csv"]
        assert classification_report is not None and classification_csv is not None
        atomic_write_text(
            classification_report, render_classification_report(stats, metadata)
        )
        atomic_write_text(classification_csv, render_classification_csv(stats))
        metadata_path = paths["metadata"]
        assert metadata_path is not None
        atomic_write_json(metadata_path, metadata)

        eprint("Raw trace: {}".format(raw_path))
        if summary_path is not None:
            eprint("Summary: {}".format(summary_path))
        eprint("Classification report: {}".format(classification_report))
        eprint("Classification CSV: {}".format(classification_csv))
        eprint("Metadata: {}".format(metadata_path))
        if dropped:
            count_text = "an unknown number of" if dropped == -1 else str(dropped)
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
