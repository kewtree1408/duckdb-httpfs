# Tracing DuckDB system calls

`trace_duckdb_syscalls.py` runs the repository's DuckDB shell with SQL supplied
over standard input and writes native trace data, a grouped summary, and
syscall classification reports alongside execution metadata.

The SQL is never placed in a shell command or metadata. SQL supplied with
`--sql`, `--sql-file`, or stdin is passed byte-for-byte to DuckDB's stdin.
DuckDB is launched with `--no-init`, `--batch`, and `--bail`.

## Examples

Trace one query on macOS. No `sudo`:

```console
python3 scripts/trace_duckdb_syscalls.py \
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
python3 scripts/trace_duckdb_syscalls.py \
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

Pass extra DuckDB flags, for example to allow unsigned extensions:

```console
python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope process \
  --duckdb-arg=-unsigned \
  --sql "FROM 'https://blobs.duckdb.org/nl-railway/services-2023.parquet' LIMIT 3;"
```

`--duckdb-arg` is repeatable and appends to the DuckDB command line after the
fixed `--no-init --batch --bail` flags. Values that begin with a dash need the
equals form (`--duckdb-arg=-unsigned`), because argparse otherwise reads the
value as another option; alternatively, put them after a `--` separator, which
passes every remaining argument straight to DuckDB:

```console
python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb --stdin -- -unsigned < /path/to/query.sql
```

The SQL-bearing DuckDB flags `-c`, `-cmd`, and `-s` are refused. They would put
the query in the process table where other users can read it, and
`query_sha256` would then describe only the SQL that arrived over stdin rather
than everything DuckDB executed. Supply SQL with `--sql`, `--sql-file`, or
stdin instead. Accepted arguments are recorded in metadata as `duckdb_args`.

The default scope is `query` on macOS and `process` on Linux. On Linux, an
explicit `--scope query` or `--scope engine` automatically selects bpftrace;
the default process scope continues to use strace. Run
`python3 scripts/trace_duckdb_syscalls.py --help` for backend/path overrides,
timeout, template selection, child-process control, and output suppression.

## Scopes

| Scope | Boundary | Includes | Limitations |
| --- | --- | --- | --- |
| `query` | macOS: first through last injected marker read. Linux: `duckdb_shell::ShellState::ExecuteSQL` entry/return | The supplied SQL, its DuckDB worker threads, and (on macOS) the two marker statements | macOS gives one window per run and cannot nest; Linux gives one boundary per SQL batch |
| `engine` | Every matching `duckdb::Connection::Query` entry/return | Engine execution and all DuckDB worker threads | Linux bpftrace only; excludes shell rendering and may include other `Connection::Query` calls made by the shell |
| `process` | Process startup through shutdown | Startup, extension loading, queries, formatting, and shutdown | Cannot attribute calls to one SQL statement |

## macOS: xctrace

The macOS backend records with `xctrace`, which needs no elevated privileges
and works with System Integrity Protection enabled. It requires a full Xcode
installation rather than the Command Line Tools alone.

The template is `File Activity`. Xcode 27 removed `System Trace`, which was the
only template that recorded every syscall. Despite its name, `File Activity`
records the socket calls as well, so `socket`, `connect`, `sendto`, and
`recvfrom` appear alongside the filesystem calls. It does not record
`mach_trap`, memory calls such as `mmap`, or thread primitives.

The tool starts DuckDB paused, attaches xctrace to that exact PID, waits for
the recording to start, resumes DuckDB, and then writes SQL to its stdin. SQL
is never placed on a command line. After DuckDB exits, the `.trace` bundle is
exported with `xctrace export --xpath`, and the rows are converted to the same
JSONL schema the Linux backends emit. The exporter writes each repeated value
once and refers to later occurrences by `ref`, so reading any column means
following those back-references.

Two capabilities are weaker than a kernel-probe tracer such as bpftrace:

- There is no `errno`. `FsSyscall` records only a return value, so a call is
  counted as failed when that value is negative. Expect the error column to
  undercount compared with `strace`.
- There is no function-boundary probe. Query scope is produced by writing two
  one-row marker CSV files into the output directory and wrapping the supplied
  SQL in `read_csv` statements that read them. Their paths appear in the trace,
  which gives the window. This means the SQL DuckDB executes is not quite the
  SQL supplied: two statements are added. `query_sha256` and `query_bytes`
  still describe the supplied bytes only, and `markers_injected` records that
  the wrapping happened. If the query fails under `--bail` before the end
  marker runs, the markers are unbalanced and the tool warns while preserving
  DuckDB's exit status.

`--scope engine` is unavailable on macOS: `Connection::Query` has no
path-observable side effect to mark. Use `--scope query` or `--scope process`.
`--children` is also unavailable, because the recording attaches to a single
process; every thread of that process is always included.

xctrace aborts with an `XRAugmentationManager` assertion when run inside an OS
sandbox such as Seatbelt. Run it outside the sandbox.

On Linux, process scope uses `strace -f`; baseline strace cannot see C++
function entry/return boundaries. Query and engine scopes use a generated
bpftrace program with uprobes/uretprobes on DuckDB symbols resolved from the
selected binary with `nm` and `c++filt`, so no addresses or version-specific
mangled names are hardcoded. The tool starts DuckDB paused, attaches bpftrace
to that exact PID, resumes it, and then passes SQL directly to DuckDB's stdin.
SQL is never passed through the bpftrace command line.

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

- `raw.xctrace.jsonl`, `raw.bpftrace.jsonl`, or `raw.strace`: the tracer output,
  normalised to one JSONL schema;
- `recording.trace`: on macOS, the xctrace bundle the JSONL was derived from,
  which Instruments can open directly;
- `marker-begin-<nonce>.csv` and `marker-end-<nonce>.csv`: on macOS query
  scope, the files whose reads delimit the window;
- `summary.txt`: calls grouped by provider/name with count, errors, total time,
  and maximum time;
- `syscall-categories.md`: category totals, percentages of completed calls,
  and the complete per-category syscall breakdown with counts, errors, and
  timings;
- `syscall-categories.csv`: one row per provider/syscall pair, with category,
  count, errors, total duration in nanoseconds, and maximum duration in
  nanoseconds;
- `metadata.json`: platform, tracer and DuckDB versions, paths, extra DuckDB
  arguments, scope, template, timestamps, SHA-256 query hash, byte count, exit
  statuses, boundary counts, query window width, exported row count, and drop
  information;
- `bpftrace-program.bt`: on Linux, the exact generated tracer program for a
  boundary-scoped run.

The tool refuses to overwrite existing artifact files. `--no-results`
suppresses DuckDB stdout only; DuckDB errors and tracer diagnostics remain
visible. A normal query exit status is returned unchanged. A timeout returns
124, and a tracing/setup error returns 2. Raw trace and metadata artifacts are
retained for query failures and tracer failures whenever an output directory
was created.

### Automatic syscall classification

Every run that reaches trace summarization writes both classification files
into its output directory, without extra flags. Their absolute paths appear
in stderr and in the metadata fields `classification_report` and
`classification_csv`. `--no-summary` suppresses only `summary.txt`; it does
not suppress classification reports. Existing classification files are
protected by the same no-overwrite checks as other artifacts.

The classification uses the same completed calls as `summary.txt`, across
xctrace, strace, and bpftrace. Each call belongs to exactly one category:
network and sockets; file and descriptor I/O; thread synchronization; I/O
readiness and event notification; virtual and shared memory; thread lifecycle
and workqueues; IPC and Mach ports; filesystem metadata; process identity,
system information and signals; security and platform support; time and
clocks; or process lifecycle. Only observed categories appear in the report.

The built-in mapping covers the macOS calls and common Linux counterparts.
Darwin `sys_` prefixes and `_nocancel` suffixes are normalized for
classification while the original names remain in the report. Unknown names
and unresolved bpftrace numbers such as `nr_1234` are retained under
`Other / unclassified`, so they still contribute to the totals and percentages.

Counts describe frequency, not elapsed time. `read`, `write`, `ioctl`, and
`fcntl` can operate on sockets, pipes, or terminals as well as files, so
descriptor I/O must not be interpreted as physical disk I/O. Synchronization
can include waits for HTTP workers or idle workers. Durations summed across
threads overlap and are not process wall time.

Reports inherit the selected scope, backend coverage, and error-detection
limits. On macOS query scope, the marker calls inside the selected window
are included. Query failures and timeouts still produce reports when trace
summarization is reached; empty captures produce a zero-call report and a
header-only CSV. Capture notes identify timeouts, reported dropped events,
unparsed lines, nonzero DuckDB exits, and boundary or infrastructure problems.
Failures before trace summarization do not produce classification reports.

Full SQL and credentials are not copied into metadata. Local database paths
are recorded, but DuckDB connection strings are represented only by their
scheme (for example, `md:<redacted-connection-string>`), so URI userinfo,
tokens, and other connection options are omitted. Traces are still sensitive:
`strace` decodes string buffers, file paths, descriptors, and network
endpoints, and the xctrace rows carry file paths and symbolised backtraces.
The bpftrace raw output does not decode argument buffers, but syscall patterns
and return data may still be sensitive. The `recording.trace` bundle holds more
than the exported JSONL. Store and share trace directories accordingly.
Supplying credentials in `--sql` can also expose them through shell history;
prefer a protected SQL file or stdin.

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

It covers all SQL input forms, exact multi-statement transport, xctrace command
construction, `ref` back-reference resolution in the export, marker-window
derivation, boundary-event parsing, summary generation, output separation,
timeouts, failure traces, and exit-code preservation. Classification checks
cover platform aliases, unknown names, count conservation, report paths,
query-window filtering, empty captures, partial captures, and `--no-summary`.

End-to-end checks against a real tracer are intentionally explicit. The macOS
ones need no `sudo` but must run outside any OS sandbox:

```console
# macOS: marker-bracketed query window
python3 scripts/trace_duckdb_syscalls.py \
  --duckdb build/release/duckdb \
  --scope query \
  --sql 'SELECT sum(i) FROM range(1000000) t(i);'

# macOS: startup-through-shutdown
python3 scripts/trace_duckdb_syscalls.py \
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

After a macOS query run, verify that `raw.xctrace.jsonl` holds one balanced
pair of `boundary` records and that `metadata.json` reports a non-null
`query_window_ns` with `exported_rows` larger than `complete_calls`, which is
what shows that startup and shutdown were excluded.

After a Linux query/engine run, verify that `raw.bpftrace.jsonl` contains
balanced `boundary` records and `call` records only between those boundaries.
