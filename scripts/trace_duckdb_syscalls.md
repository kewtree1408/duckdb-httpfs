# Tracing DuckDB system calls

`trace_duckdb_syscalls.py` runs the repository's DuckDB shell with SQL supplied
over standard input and writes native trace data, a grouped summary, and
execution metadata.

The SQL is never placed in a shell command or metadata. SQL supplied with
`--sql`, `--sql-file`, or stdin is passed byte-for-byte to DuckDB's stdin.
DuckDB is launched with `--no-init`, `--batch`, and `--bail`.

## Examples

Trace one query on macOS:

```console
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --database :memory: \
  --scope query \
  --sql 'SELECT count(*) FROM range(1000000);'
```

Trace only the query boundary on Linux:

```console
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --database :memory: \
  --scope query \
  --sql 'SELECT count(*) FROM range(1000000);'
```

Read a multi-statement query from a file:

```console
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --database trace.db \
  --sql-file /path/to/query.sql \
  --output-dir duckdb-trace
```

Read SQL from stdin without evaluating it in a shell:

```console
python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope process \
  --stdin < /path/to/query.sql
```

The default scope is `query` on macOS and `process` on Linux. On Linux, an
explicit `--scope query` or `--scope engine` automatically selects bpftrace;
the default process scope continues to use strace. Run
`python3 scripts/trace_duckdb_syscalls.py --help` for backend/path overrides,
timeout, buffer sizing, child-process control, and output suppression.

## Scopes

| Scope | Boundary | Includes | Limitations |
| --- | --- | --- | --- |
| `query` | `duckdb_shell::ShellState::ExecuteSQL` entry/return | SQL parsing, query execution, DuckDB worker threads, and shell result rendering | DTrace on macOS or bpftrace on Linux; each complete SQL batch read by the shell has its own boundary |
| `engine` | Every matching `duckdb::Connection::Query` entry/return | Engine execution and all DuckDB worker threads | DTrace on macOS or bpftrace on Linux; excludes shell rendering and may include other `Connection::Query` calls made by the shell |
| `process` | Process startup through shutdown | Startup, extension loading, queries, formatting, and shutdown | Cannot attribute calls to one SQL statement |

The macOS backend resolves mangled symbols from the selected DuckDB binary with
`nm` and `c++filt`; it does not hardcode addresses or version-specific mangled
names. A process-wide active flag is toggled by the boundary probes, so syscall
events from every worker thread in the DuckDB process are included. Descendant
processes are included by default and can be excluded with `--no-children`.

The custom DTrace program subscribes to both `syscall` and `mach_trap` entry and
return probes. `syscall` return events contain `errno`; Mach trap return values
are recorded, but they are not generically interpreted as error codes. This is
why the tool uses a custom program rather than stock `dtruss`, which traces the
`syscall` provider but not `mach_trap`.

On Linux, process scope uses `strace -f`; baseline strace cannot see C++
function entry/return boundaries. Query and engine scopes use a generated
bpftrace program with uprobes/uretprobes on the same resolved DuckDB symbols.
The tool starts DuckDB paused, attaches bpftrace to that exact PID, resumes it,
and then passes SQL directly to DuckDB's stdin. SQL is never passed through
the bpftrace command line.

The bpftrace boundary depth is process-wide rather than thread-local. Syscall
events from every DuckDB worker thread are therefore captured while any
selected boundary is active. With the default `--children`, scheduler fork
events track descendant processes and include their syscalls only while the
root DuckDB boundary remains active. `--no-children` still includes every
thread in the DuckDB process.

To stay within bpftrace's default probe safety limits, the generated program
uses the two `raw_syscalls` entry/exit tracepoints rather than expanding one
probe per syscall name. Raw JSONL records contain the syscall number, PID,
thread ID, return value, errno, and duration. The summary resolves syscall
numbers through the host's libseccomp; numbers unknown to that library are
shown as `nr_<number>`. Unlike strace, this backend does not decode syscall
argument buffers, paths, or descriptors.

## Artifacts

Unless paths are overridden, a timestamped directory contains:

- `raw.dtrace.jsonl`, `raw.bpftrace.jsonl`, or `raw.strace`: the native
  tracer output;
- `summary.txt`: calls grouped by provider/name with count, errors, total time,
  and maximum time;
- `metadata.json`: platform, tracer and DuckDB versions, paths, scope,
  timestamps, SHA-256 query hash, byte count, exit statuses, boundary counts,
  and drop information;
- `dtrace-program.d` or `bpftrace-program.bt`: the exact generated tracer
  program for a boundary-scoped run.

The tool refuses to overwrite existing artifact files. `--no-results`
suppresses DuckDB stdout only; DuckDB errors and tracer diagnostics remain
visible. A normal query exit status is returned unchanged. A timeout returns
124, and a tracing/setup error returns 2. Raw trace and metadata artifacts are
retained for query failures and tracer failures whenever an output directory
was created.

Full SQL and credentials are not copied into metadata. Local database paths
are recorded, but DuckDB connection strings are represented only by their
scheme (for example, `md:<redacted-connection-string>`), so URI userinfo,
tokens, and other connection options are omitted. Traces are still sensitive:
`strace` decodes string buffers, file paths, descriptors, and network
endpoints, and DTrace arguments can expose addresses and other process state.
The bpftrace raw output does not decode argument buffers, but syscall patterns
and return data may still be sensitive. Store and share trace directories
accordingly. Supplying credentials in `--sql` can also expose them through
shell history; prefer a protected SQL file or stdin.

## macOS permissions and event drops

DTrace commonly requires `sudo`. System Integrity Protection, hardened runtime
restrictions, containers, and managed development environments can still make
it unavailable. The tool reports permission/SIP failures without attempting
to change system security settings.

DTrace drop messages are copied to stderr, recorded in metadata, and called out
in the summary. `--buffer-size` configures both the principal and dynamic
variable buffers. Increase it (for example, `--buffer-size 64m`) and repeat the
trace if events are dropped.

## Linux bpftrace permissions and losses

bpftrace normally requires root or equivalent BPF/perf capabilities. Run
query/engine scope with `sudo`. The selected DuckDB executable must retain the
boundary symbol; if it has been stripped, use a non-stripped or debug build.
The tool emits an actionable error when bpftrace cannot load or attach the
generated program.

bpftrace lost-event messages are copied to stderr, recorded in metadata, and
called out in the summary. A lost-event warning means the raw query trace is
incomplete.

## Tests

The non-privileged suite uses fake DuckDB and tracer executables:

```console
python3 -m unittest discover -v -s test/scripts -p 'test_*.py'
```

It covers all SQL input forms, exact multi-statement transport, DTrace program
generation, boundary-event parsing, summary generation, output separation,
timeouts, failure traces, and exit-code preservation.

Privileged integration checks are intentionally explicit:

```console
# macOS: query boundary plus syscall and mach_trap providers
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope query \
  --sql 'SELECT sum(i) FROM range(1000000) t(i);'

# macOS: startup-through-shutdown
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope process \
  --sql 'SELECT 42;'

# Linux: strace process scope
python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope process \
  --sql 'SELECT 42;'

# Linux: bpftrace query boundary
sudo python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope query \
  --sql 'SELECT sum(i) FROM range(1000000) t(i);'
```

After a macOS run, verify that `raw.dtrace.jsonl` contains balanced `boundary`
records plus `call` records from both `syscall` and `mach_trap` where the query
uses those providers. A highly CPU-bound query might legitimately produce no
Mach trap records inside a short boundary.

After a Linux query/engine run, verify that `raw.bpftrace.jsonl` contains
balanced `boundary` records and `call` records only between those boundaries.
