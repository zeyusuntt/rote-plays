"""Probe ONE MCP server discovered by discover.py -- a for_each fan-out item,
so each server gets its own timeout budget.

argv[1]  the discovered server as JSON (this is exactly one element of
         discover.py's "servers" array, arriving as $item -- rote passes an
         object fan-out element to a script as one compact-JSON argv string)
argv[2]  item_index (this server's 0-based position in discover.py's
         "servers" array, bound by rote's fan-out as $item_index)
argv[3]  per_server_timeout_s (seconds to wait for the whole handshake)
argv[4]  max_servers (probe at most this many servers, by item_index; the
         rest are "capped" -- listed unprobed, never spawned)

The fan-out always runs over every discovered server regardless of
max_servers (slicing the fan-out set itself via `.servers[0:$max_servers]`
turns out to fail the whole step on max_servers=0: a zero-width slice reads
to the runner as "no results", not an empty-but-successful fan-out). Capping
is therefore enforced HERE, per item, by comparing item_index to max_servers
-- the first max_servers servers (by discovery order) are actually probed;
every later one returns "capped" immediately, before even the remote/stdio
branch, without spawning anything.

Remote servers (transport == "remote") are NEVER contacted -- this script
makes zero network calls, full stop; it does not enforce that a spawned
LOCAL stdio server won't reach the network on its own (a launcher like npx
can download packages) -- this script's own no-network promise covers only
the calls it makes directly.

A local stdio server's real command + args are looked up from discover.py's
private exec store (item.exec_store, keyed by item.id -- see discover.py's
module docstring) and spawned with start_new_session=True (its own process
group) and a minimal ALLOWLISTED environment -- PATH plus a handful of
locale/timezone variables, never this script's full ambient environment,
so this play cannot and does not hand any ambient credential (API keys,
tokens, ...) it happens to be running with to arbitrary local code it did
not configure. It is sent the standard MCP handshake over newline-delimited
JSON-RPC 2.0 on stdio (no Content-Length headers): initialize,
notifications/initialized, then tools/list, resources/list, prompts/list (a
method-not-found error on any of those three is treated as an empty list,
not a failure). A reply is only accepted once it is jsonrpc: "2.0", carries
the matching id, and has exactly one of a well-shaped result/error -- a
stray JSON-formatted log line on stdout that happens to reuse an id can
never spoof a response. Every list's advertised JSON is sized in
bytes/chars and converted to an ESTIMATED token count (chars/4, rounded) --
never a real tokenizer count.

Classification (exactly one of):
  healthy             handshake + all three lists completed within budget
  slow                handshake ok, but more than half the timeout elapsed
  needs-auth          handshake failed and stderr/the JSON-RPC error's own
                       message carried an auth-shaped signal (401,
                       unauthorized, api key, token, login) -- detected
                       internally, never echoed into any output
  unresponsive         the deadline was hit waiting for a response, with no
                       auth signal
  config-error        the process could not be spawned at all, exited
                       before ever responding, or the item/argv was
                       malformed
  remote-not-probed   transport was remote; never contacted
  capped               item_index >= max_servers; never contacted

"error", when present, is always one of a small set of FIXED reason codes
(e.g. "spawn-failed:FileNotFoundError", "handshake-timeout",
"process-exited-early:code=1", "handshake-rpc-error:code=-32001") -- never
raw child stderr, a raw JSON-RPC error message, or any other
child-controlled text, so a server error that happens to echo back a
credential (e.g. "invalid API key sk-...") can never leak into this
script's output.

However this classifies, the process GROUP this script itself started is
ALWAYS terminated in a finally block: SIGTERM to the group, a grace period,
then SIGKILL to the group if anything in it is still alive -- driven by the
process group id captured at spawn time (not by polling the direct child),
so a leader that exits early while a same-group descendant is still running
never short-circuits escalation. Nothing outside that group is signaled.
Caveat this script cannot close: start_new_session=True only guarantees
control over the process group THIS script created; nothing in userspace
stops a spawned server (or a descendant of it) from calling setsid() or
double-forking into an unrelated process group, at which point it is no
longer reachable through this mechanism at all. This script does not claim
otherwise -- it guarantees only that the group it owns is fully terminated,
not that every process a misbehaving server may have detached is gone.

Emits one JSON object on stdout and always exits 0, EXCEPT when argv[1]
itself is missing -- a fundamental contract violation, not a probeable
server's failure -- which fails closed: stderr + exit 1.
"""

import json
import os
import select
import signal
import subprocess
import sys
import time

PROTOCOL_VERSION = "2024-11-05"
CLIENT_INFO = {"name": "mcp-context-tax", "version": "0.1.0"}

DEFAULT_TIMEOUT_S = 10
MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 60

DEFAULT_MAX_SERVERS = 20

GRACE_S = 0.5
KILL_GRACE_S = 1.0
STDERR_PEEK_S = 0.3
STDERR_PEEK_MAX_CHARS = 4000
ERROR_MAX_CHARS = 120
ARGS_MAX_COUNT = 40
READ_CHUNK_BYTES = 65536

AUTH_SIGNALS = (
    "401", "unauthorized", "api key", "api_key", "apikey",
    "access token", "auth token", "invalid token", "token expired",
    "missing token", "login", "authentication failed", "credential",
)  # no bare "token": Node's "Unexpected token" is a crash, not auth

# Minimal allowlisted environment for spawned servers: PATH so the
# configured command can be found, plus locale/timezone variables that
# affect encoding/formatting but are never secret-shaped. Deliberately
# excludes everything else, including this script's own credentials.
_SAFE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ")
_FALLBACK_PATH = "/usr/bin:/bin:/usr/local/bin"


def spawn_env():
    """A minimal allowlisted environment for the spawned server process --
    never this script's full ambient environment. See _SAFE_ENV_KEYS."""
    env = {}
    for key in _SAFE_ENV_KEYS:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.setdefault("PATH", _FALLBACK_PATH)
    return env


def parse_timeout(raw):
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        return DEFAULT_TIMEOUT_S
    return max(MIN_TIMEOUT_S, min(MAX_TIMEOUT_S, value))


def parse_int(raw, fallback):
    try:
        return int(str(raw).strip())
    except (ValueError, TypeError):
        return fallback


def parse_item_index(raw):
    # A missing/malformed index can only come from a contract violation
    # upstream, not from anything a server itself controls; 0 (never capped
    # by itself) is the safest fallback so a parse hiccup here degrades to
    # "probe it" rather than silently capping every server.
    return parse_int(raw, 0)


def resolve_exec_args(item):
    """The REAL command + args to spawn, resolved from discover.py's
    private exec store (item["exec_store"], keyed by item["id"] -- see
    discover.py's module docstring). item["args"] itself is a structural
    display summary only (flag names and length placeholders, no values)
    and was never meant to be executed. Falls back to item["command"] with
    NO args (never a guessed-wrong argv) if the store is absent,
    unreadable, or malformed for this id -- a degrade, never a crash."""
    command = item.get("command")
    store_path = item.get("exec_store")
    server_id = item.get("id")
    if isinstance(store_path, str) and store_path and server_id is not None:
        try:
            with open(store_path, "r", encoding="utf-8") as fh:
                store = json.load(fh)
            record = store.get(str(server_id)) if isinstance(store, dict) else None
            if isinstance(record, dict) and isinstance(record.get("args"), list):
                real_command = record.get("command")
                if isinstance(real_command, str) and real_command:
                    command = real_command
                return command, [str(a) for a in record["args"][:ARGS_MAX_COUNT]]
        except (OSError, ValueError):
            pass
    return command, []


def empty_list_measure(note=None):
    m = {"count": 0, "bytes": 0, "est_tokens": 0}
    if note:
        m["note"] = note
    return m


def measure_list(value):
    """value is whatever JSON list the server advertised (tools/resources/
    prompts); size it as compact JSON and estimate tokens as chars/4."""
    if not isinstance(value, list):
        value = []
    raw = json.dumps(value, separators=(",", ":"))
    chars = len(raw)
    return {
        "count": len(value),
        "bytes": len(raw.encode("utf-8")),
        "est_tokens": round(chars / 4),
    }


def base_row(item, transport=None):
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "harness": item.get("harness"),
        "transport": transport if transport is not None else item.get("transport"),
    }


def emit(row):
    print(json.dumps(row))


class LineReader:
    """Buffers bytes read non-blockingly from a pipe via select() +
    os.read(), and yields decoded NDJSON lines against an absolute
    monotonic deadline. Once select() reports the fd readable, only a
    single bounded os.read() is issued -- never a blocking text-mode
    readline() -- so a slow/partial line (bytes ready but no newline yet)
    can never stall past the caller's deadline; the caller just comes back
    and waits again for more bytes or for the deadline."""

    def __init__(self, stream):
        self._stream = stream
        self._buf = bytearray()
        self._eof = False

    def _fill(self, deadline):
        if self._eof:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        try:
            ready, _, _ = select.select([self._stream], [], [], remaining)
        except (OSError, ValueError):
            self._eof = True
            return
        if not ready:
            return
        try:
            chunk = os.read(self._stream.fileno(), READ_CHUNK_BYTES)
        except OSError:
            self._eof = True
            return
        if chunk == b"":
            self._eof = True
            return
        self._buf.extend(chunk)

    def readline(self, deadline):
        """Returns (line_or_None, timed_out). A returned line never
        includes its trailing newline. (None, False) means EOF with no
        further complete line ever coming."""
        while True:
            nl = self._buf.find(b"\n")
            if nl != -1:
                raw = bytes(self._buf[:nl])
                del self._buf[: nl + 1]
                return raw.decode("utf-8", errors="replace"), False
            if self._eof:
                if self._buf:
                    raw = bytes(self._buf)
                    self._buf.clear()
                    return raw.decode("utf-8", errors="replace"), False
                return None, False
            if deadline - time.monotonic() <= 0:
                return None, True
            self._fill(deadline)


def is_valid_rpc_response(obj):
    """A reply is only accepted when it is a well-shaped JSON-RPC 2.0
    response: jsonrpc == "2.0", and exactly one of a dict result or a
    dict error carrying code+message. This is what stops a JSON-formatted
    log line that happens to reuse an id from spoofing a response."""
    if obj.get("jsonrpc") != "2.0":
        return False
    has_result = "result" in obj
    has_error = "error" in obj
    if has_result == has_error:  # neither, or both -- not a valid reply
        return False
    if has_error:
        err = obj.get("error")
        return isinstance(err, dict) and "code" in err and "message" in err
    return isinstance(obj.get("result"), dict)


def read_response(reader, deadline, expected_id):
    """Read NDJSON lines until one is a well-shaped JSON-RPC 2.0 response
    whose "id" matches expected_id, or the deadline is hit. Non-JSON,
    mismatched-id, or spoof-shaped lines are skipped, not fatal."""
    while True:
        if deadline - time.monotonic() <= 0:
            return None, True
        line, timed_out = reader.readline(deadline)
        if timed_out:
            return None, True
        if line is None:
            return None, False  # EOF before a matching response arrived
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("id") != expected_id:
            continue  # notification, mismatched id, or non-object line
        if not is_valid_rpc_response(obj):
            continue  # id matched but shape doesn't -- spoof-shaped, skip
        return obj, False


def peek_stderr(proc):
    """Best-effort, bounded, non-blocking-ish peek at whatever the child has
    already written to stderr -- used ONLY internally to detect an
    auth-shaped signal after a failed handshake (a boolean outcome); the
    text itself is never echoed into this script's output."""
    try:
        ready, _, _ = select.select([proc.stderr], [], [], STDERR_PEEK_S)
    except (OSError, ValueError):
        return ""
    if not ready:
        return ""
    try:
        chunk = os.read(proc.stderr.fileno(), STDERR_PEEK_MAX_CHARS)
    except OSError:
        return ""
    try:
        return chunk.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _group_pids(pgid):
    """Enumerate LIVE (non-zombie) pids currently in process group `pgid`
    by asking `ps` directly, rather than inferring liveness from a signal's
    success/failure. This sidesteps a macOS/BSD kernel quirk (reproduced
    while hardening this script): killpg()/kill(pid, 0) can return EPERM
    -- not ESRCH -- for a group that still has a genuinely live member
    alongside an unreaped zombie (e.g. a launcher that already exited,
    still un-waited-for, next to the worker process it spawned), which
    would otherwise be misread as "group already gone" and end escalation
    early exactly like the leader-polling bug this rewrite fixes. Returns
    None (treated as "unknown, assume alive" by callers) if `ps` itself
    could not be run."""
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=,stat=", "-g", str(pgid)],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        # ps failed or -g unsupported: group state UNKNOWN, not empty --
        # None makes the caller escalate SIGKILL instead of skipping it
        return None
    pids = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        pid_str, stat = parts[0], parts[1]
        if stat.startswith("Z"):
            continue  # zombie: already exited, nothing left to signal
        try:
            pids.append(int(pid_str))
        except ValueError:
            continue
    return pids


def _group_alive(pgid):
    survivors = _group_pids(pgid)
    return True if survivors is None else bool(survivors)


def _signal_group(pgid, sig):
    """Best-effort delivery of `sig` to every member of process group
    `pgid`: one killpg() (the fast path, reaches everyone in one syscall
    when it works) PLUS an individual kill() to every live pid _group_pids()
    finds there. The second part is not redundant belt-and-suspenders --
    reproduced directly while hardening this script: killpg() can return
    EPERM (not ESRCH) for a group whose DIRECT-CHILD LEADER has already
    exited into an unreaped zombie, even though a live descendant (a
    process the leader itself forked, e.g. a launcher and the server it
    started) is still running in that same group -- the exact "leader
    exits early, descendant survives" case this whole rewrite exists to
    close. Individual kill(pid, sig) is checked against that specific
    pid's own credentials, not the (possibly zombie) group leader's, so it
    is not subject to the same quirk. Never raises."""
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass
    for pid in _group_pids(pgid) or ():
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass


def terminate_process_group(proc, pgid):
    """Always run: terminate the process group THIS script started
    (SIGTERM, brief grace, SIGKILL), driven by the pgid captured at spawn
    time -- never by polling the direct child alone, and never by trusting
    killpg()'s own success/failure alone (see _signal_group). start_new_session=True
    made this child its own group leader, so pgid == the child's own pid
    from the moment Popen returned; escalation is therefore keyed off
    whether the GROUP is still alive (verified via `ps`, see _group_pids),
    so a leader that exits early while a same-group descendant is still
    running can never short-circuit the SIGKILL step (see module docstring
    for the setsid/double-fork caveat this cannot close)."""
    if pgid is not None:
        _signal_group(pgid, signal.SIGTERM)
        deadline = time.monotonic() + GRACE_S
        while time.monotonic() < deadline and _group_alive(pgid):
            time.sleep(0.05)
        if _group_alive(pgid):
            _signal_group(pgid, signal.SIGKILL)
            kill_deadline = time.monotonic() + KILL_GRACE_S
            while time.monotonic() < kill_deadline and _group_alive(pgid):
                time.sleep(0.05)
    if proc is not None:
        if proc.poll() is None:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        _close_pipes(proc)


def _close_pipes(proc):
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream:
                stream.close()
        except OSError:
            pass


def send(proc, obj):
    line = (json.dumps(obj) + "\n").encode("utf-8")
    proc.stdin.write(line)
    proc.stdin.flush()


def probe_stdio(item, timeout_s):
    row = base_row(item, transport="stdio")
    command, args = resolve_exec_args(item)

    if not command:
        row.update({"state": "config-error", "error": "no-command-configured",
                    "tools": empty_list_measure(), "resources": empty_list_measure(),
                    "prompts": empty_list_measure(), "total_bytes": 0, "total_est_tokens": 0,
                    "elapsed_ms": 0, "timeout_s": timeout_s})
        return row

    argv = [command] + args
    start = time.monotonic()
    deadline = start + timeout_s
    proc = None
    pgid = None
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
            env=spawn_env(),
            start_new_session=True,
        )
        pgid = proc.pid  # start_new_session=True: this child is its own group leader
    except (OSError, ValueError) as exc:
        row.update({"state": "config-error", "error": ("spawn-failed:%s" % type(exc).__name__)[:ERROR_MAX_CHARS],
                    "tools": empty_list_measure(), "resources": empty_list_measure(),
                    "prompts": empty_list_measure(), "total_bytes": 0, "total_est_tokens": 0,
                    "elapsed_ms": round((time.monotonic() - start) * 1000), "timeout_s": timeout_s})
        return row

    reader = LineReader(proc.stdout)
    try:
        init_response = None
        init_timed_out = False
        early_exit_code = None
        send_error_kind = None
        try:
            send(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": CLIENT_INFO,
                    },
                },
            )
            init_response, init_timed_out = read_response(reader, deadline, expected_id=1)
        except (BrokenPipeError, OSError, ValueError) as exc:
            send_error_kind = type(exc).__name__

        if init_response is None:
            if proc.poll() is not None and not init_timed_out:
                early_exit_code = proc.poll()
            stderr_text = peek_stderr(proc)
            has_auth_signal = any(sig in stderr_text.lower() for sig in AUTH_SIGNALS)
            elapsed_ms = round((time.monotonic() - start) * 1000)
            if has_auth_signal:
                state = "needs-auth"
                reason = "auth-signal-detected"
            elif init_timed_out:
                state = "unresponsive"
                reason = "handshake-timeout"
            elif early_exit_code is not None:
                state = "config-error"
                reason = "process-exited-early:code=%s" % early_exit_code
            elif send_error_kind is not None:
                state = "config-error"
                reason = "stdin-write-failed:%s" % send_error_kind
            else:
                state = "config-error"
                reason = "handshake-no-response"
            row.update(
                {
                    "state": state,
                    "error": reason[:ERROR_MAX_CHARS],
                    "tools": empty_list_measure(),
                    "resources": empty_list_measure(),
                    "prompts": empty_list_measure(),
                    "total_bytes": 0,
                    "total_est_tokens": 0,
                    "elapsed_ms": elapsed_ms,
                    "timeout_s": timeout_s,
                }
            )
            return row

        if "error" in init_response:
            # read_response() only ever returns a well-shaped JSON-RPC 2.0
            # reply (see is_valid_rpc_response), so reaching here means the
            # server itself replied with a real JSON-RPC error object.
            stderr_text = peek_stderr(proc)
            err_obj = init_response.get("error") if isinstance(init_response.get("error"), dict) else {}
            err_message = str(err_obj.get("message") or "")
            has_auth_signal = any(sig in stderr_text.lower() for sig in AUTH_SIGNALS) or any(
                sig in err_message.lower() for sig in AUTH_SIGNALS
            )
            elapsed_ms = round((time.monotonic() - start) * 1000)
            err_code = err_obj.get("code")
            reason = "handshake-rpc-error"
            if isinstance(err_code, int):
                reason += ":code=%d" % err_code
            row.update(
                {
                    "state": "needs-auth" if has_auth_signal else "config-error",
                    "error": reason[:ERROR_MAX_CHARS],
                    "tools": empty_list_measure(),
                    "resources": empty_list_measure(),
                    "prompts": empty_list_measure(),
                    "total_bytes": 0,
                    "total_est_tokens": 0,
                    "elapsed_ms": elapsed_ms,
                    "timeout_s": timeout_s,
                }
            )
            return row

        # Handshake ok. Best-effort notification; never fatal if it fails.
        try:
            send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except (BrokenPipeError, OSError, ValueError):
            pass

        overall_timed_out = False
        measures = {}
        for next_id, method, result_key in (
            (2, "tools/list", "tools"),
            (3, "resources/list", "resources"),
            (4, "prompts/list", "prompts"),
        ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                overall_timed_out = True
                measures[result_key] = empty_list_measure("timed out")
                continue
            try:
                send(proc, {"jsonrpc": "2.0", "id": next_id, "method": method, "params": {}})
                resp, timed_out = read_response(reader, deadline, expected_id=next_id)
            except (BrokenPipeError, OSError, ValueError):
                resp, timed_out = None, False
            if timed_out:
                overall_timed_out = True
                measures[result_key] = empty_list_measure("timed out")
                continue
            if resp is None or "error" in resp:
                # Method-not-found (or any error, or EOF) reads as empty.
                measures[result_key] = empty_list_measure()
                continue
            payload = resp.get("result") if isinstance(resp, dict) else None
            items = payload.get(result_key) if isinstance(payload, dict) else None
            measures[result_key] = measure_list(items)

        elapsed = time.monotonic() - start
        elapsed_ms = round(elapsed * 1000)
        total_bytes = sum(m["bytes"] for m in measures.values())
        total_est_tokens = sum(m["est_tokens"] for m in measures.values())

        if overall_timed_out:
            state = "unresponsive"
        elif elapsed > timeout_s / 2:
            state = "slow"
        else:
            state = "healthy"

        row.update(
            {
                "state": state,
                "error": None,
                "tools": measures["tools"],
                "resources": measures["resources"],
                "prompts": measures["prompts"],
                "total_bytes": total_bytes,
                "total_est_tokens": total_est_tokens,
                "elapsed_ms": elapsed_ms,
                "timeout_s": timeout_s,
            }
        )
        return row
    finally:
        terminate_process_group(proc, pgid)


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        sys.stderr.write("probe: missing server item argv\n")
        raise SystemExit(1)

    item_index = parse_item_index(sys.argv[2] if len(sys.argv) > 2 else "")
    timeout_s = parse_timeout(sys.argv[3] if len(sys.argv) > 3 else "")
    max_servers = parse_int(sys.argv[4] if len(sys.argv) > 4 else "", DEFAULT_MAX_SERVERS)

    try:
        item = json.loads(sys.argv[1])
        if not isinstance(item, dict):
            raise ValueError("item is not a JSON object")
    except (ValueError, TypeError) as exc:
        emit(
            {
                "id": None,
                "name": None,
                "harness": None,
                "transport": None,
                "state": "config-error",
                "error": ("malformed-item:%s" % type(exc).__name__)[:ERROR_MAX_CHARS],
                "tools": empty_list_measure(),
                "resources": empty_list_measure(),
                "prompts": empty_list_measure(),
                "total_bytes": 0,
                "total_est_tokens": 0,
                "elapsed_ms": 0,
                "timeout_s": timeout_s,
            }
        )
        return

    if item_index >= max_servers:
        # Beyond the max_servers cap: never contacted, local or remote alike.
        row = base_row(item)
        row.update(
            {
                "state": "capped",
                "error": None,
                "tools": empty_list_measure(),
                "resources": empty_list_measure(),
                "prompts": empty_list_measure(),
                "total_bytes": 0,
                "total_est_tokens": 0,
                "elapsed_ms": 0,
                "timeout_s": timeout_s,
            }
        )
        emit(row)
        return

    try:
        if item.get("transport") == "remote":
            row = base_row(item, transport="remote")
            row.update(
                {
                    "state": "remote-not-probed",
                    "error": None,
                    "tools": empty_list_measure(),
                    "resources": empty_list_measure(),
                    "prompts": empty_list_measure(),
                    "total_bytes": 0,
                    "total_est_tokens": 0,
                    "elapsed_ms": 0,
                    "timeout_s": timeout_s,
                }
            )
            emit(row)
            return
        emit(probe_stdio(item, timeout_s))
    except Exception as exc:  # pragma: no cover -- last-resort degrade, never a crash
        row = base_row(item)
        row.update(
            {
                "state": "config-error",
                "error": ("internal-exception:%s" % type(exc).__name__)[:ERROR_MAX_CHARS],
                "tools": empty_list_measure(),
                "resources": empty_list_measure(),
                "prompts": empty_list_measure(),
                "total_bytes": 0,
                "total_est_tokens": 0,
                "elapsed_ms": 0,
                "timeout_s": timeout_s,
            }
        )
        emit(row)


main()
