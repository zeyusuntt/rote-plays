"""Classify and rank the processes enumerate.py found, joined against total RAM
and against the on-disk sessions sessions.py found.

Read-only: pure computation over its five inputs. Never touches a process.

argv[1]  packed process rows from enumerate_processes (chr(31)/chr(30) — see
         enumerate.py; 7 fields per row as of v0.2.0: pid, ppid, rss_kb,
         pcpu, etime, session_id, args); empty string is a valid "nothing
         matched" input
argv[2]  packed total-RAM bytes from system_memory, or the literal string
         "unknown" when that step degraded
argv[3]  top — how many ranked processes to show (clamped to 1..100)
argv[4]  min_rss_mb — only rows holding at least this much RSS are reported
         (clamped to 0..4096)
argv[5]  packed session rows from scan_sessions (chr(31)/chr(30) — see
         sessions.py); empty string is a valid "no sessions found" input
argv[6]  idle_minutes — a joined session with no transcript activity for
         longer than this counts as running-idle rather than running-active
         (clamped to 1..1440)
argv[3], argv[4], and argv[6] must int-parse; a non-integer is a hard fault
(this is bad wiring between steps, not an expected absence) — message on
stderr, exit 2.

SESSIONS — joining a session file to a live process, honestly:
Each enumerated process row already carries a session_id field
enumerate_processes extracted from that row's own FULL args (see
enumerate.py's extract_session_id()/is_claude_exec()) — not re-derived here
from the row's (200-character-truncated) args, because a long invocation's
join flag can fall past that truncation boundary (verified live: the VS
Code extension's `--resume=<uuid>` shape routinely does) and re-deriving it
from truncated text would silently break the join. Two argv shapes feed
that field, both verified live on the machine this play was built on: a
forked/new session's own `--session-id <uuid>`, and the VS Code extension's
in-place `--resume=<uuid>` (bare uuid, not the fork-shape's path form of
`--resume`) — see enumerate.py for the full reasoning. Codex's process argv
carries no equivalent clean key (also verified live), so a codex process
can never be joined to a specific session row here; see
codex_process_detected below for the honest substitute.
  - claude session, uuid found among joined processes: state is
    running-active if the session file's mtime is within idle_minutes of
    now, else running-idle. The matching process's pid/rss/pcpu are
    attached.
  - claude session, uuid not found among joined processes: state is
    resumable — no process, no pid/rss/pcpu attached, no certainty this
    session is not itself still running under a process this heuristic
    missed (e.g. a form the join regex does not recognize); "resumable" is
    the conservative label for "no process was found", not a claim that
    none exists.
  - codex session: always resumable, for the same conservative reason
    (never a false "running").
If any enumerated process's own executable identity resolves to "codex" (the
same tier-1 path-component-root check enumerate.py performs; duplicated here
because each resource script in this play is self-contained rather than
importing a sibling), codex_process_detected is reported true regardless of
whether any codex session file matched anything — the honest substitute for
"this codex process exists, but this play cannot say which session it
belongs to, if any".

Category assignment, most specific signal wins (a Cursor "Helper" process
matches the desktop-app path pattern AND the generic "cursor" substring;
the structural path signal is the more honest label, so it is checked
first). known-daemon is checked ahead of companion/harness-cli specifically
so that a command matching BOTH a companion/harness pattern AND the word
"daemon" (e.g. a rote companion invoked as "... daemon ...") lands on the
category that is never orphan-eligible, rather than the one that is:
  1. desktop-app    — args mention ".app/" or (case-sensitive) "Helper"
                       (macOS app bundles and their "AppName Helper"
                       subprocesses)
  2. mcp-server      — mcp-server / modelcontextprotocol / mcp_ markers, or
                       an npx/uvx launch whose args also mention mcp
  3. known-daemon    — args mention "daemon" (covers generic daemons and
                       rote's own daemon paths, which contain the word too)
  4. companion       — codex-companion, or a rote play/proc child process
  5. harness-cli     — args mention claude/codex/aider/opencode and nothing
                       more specific claimed the row first (real installs
                       are often versioned binaries like
                       ~/.local/share/claude/versions/2.1.251, so this
                       checks the full command line, not just argv[0])
  6. helper          — everything else that still matched enumerate.py's
                       agent signatures (e.g. windsurf, gemini-cli, copilot)

Orphan-suspect rule, deliberately conservative — never a certainty, just a
suspicion worth a look: ppid == 1 (reparented to launchd/init) AND category
in (harness-cli, mcp-server, companion) AND etime > 10 minutes. known-daemon
and desktop-app are NEVER orphan-suspects, by category exclusion alone —
those are expected to live under launchd for their whole life. This is a
heuristic, not proof of abandonment (a properly registered launchd/systemd
service also has ppid 1); querying launchctl/systemctl to disambiguate
would need a capability beyond this play's declared "python3, ps, sysctl/
/proc/meminfo, read-only" surface, so every rendering of this label is
worded as a suspicion, never a certainty.

orphan_suspects is computed from every enriched row, before the
min_rss_mb/top display filters are applied — a suspect below the memory
floor or outside the top N must still be surfaced, or the report could
claim "none" while one silently exists below the fold. It is therefore not
a strict subset of `processes`, which IS filtered/truncated for display.

Rows shown in `processes` are filtered to rss_mb >= min_rss_mb, ranked by
rss_mb descending, and truncated to the top N; totals report what was
filtered so nothing is silently dropped from the count.

Malformed packed records (wrong field count, non-integer pid/ppid/rss) are
tolerated rather than crashing the whole audit, but are no longer silently
invisible: if any are dropped, a top-level `warning` is emitted alongside
`ok: true` so the caller can render this stage as degraded instead of
quietly under-reporting.

Malformed packed session records (wrong field count, non-float epochs) are
tolerated the same way — dropped, counted, folded into the same `warning`
rather than crashing the sessions section of the report.

The resumable bucket of `sessions.rows` is capped at RESUMABLE_SHOWN_MAX
(display-only, not a parameter — see its own comment) so this step's stdout
cannot grow past the runner's output ceiling on a machine with a large
on-disk session history; running sessions are never capped. This is exactly
the same shape as `processes`/`totals.matched`/`totals.shown` above:
`sessions.totals.resumable` is always the true on-disk count, computed
before the cap, and `sessions.totals.resumable_shown` records how many of
those actually made it into `rows` — the declared count gotcha 12 requires
before any collection may be truncated.

Emits one canonical JSON object on stdout, always exit 0 once inputs parse:
    {"ok": true,
     "warning": "<optional — N malformed row(s) dropped>",
     "totals": {"matched": n, "shown": n, "filtered_below_min": n,
                "agent_rss_mb": total, "system_ram_gb": x-or-null},
     "processes": [{pid, ppid, category, rss_mb, pcpu, age, cmd_short,
                     orphan_suspect}, ...],
     "orphan_suspects": [...every matched suspect, independent of the
                          top/min_rss_mb display filters...],
     "kill_hints": ["ps -p <pid> ... # verify before: kill <pid>  #
                     <cmd_short>", ...],
     "sessions": {
       "totals": {"running": n, "running_idle": n, "resumable": n,
                  "resumable_shown": n, "running_rss_mb": total,
                  "claude_listed": n, "codex_listed": n},
       "rows": [{harness, session_id, id_short, project, started,
                  started_approx, last_active, idle_minutes, state,
                  pid, rss_mb, pcpu, advisory}, ...],
       "codex_process_detected": bool,
       "codex_running_unmatched_note": "<text, only when the above is true>"
     }}
"""

import json
import re
import sys
import time
from datetime import datetime

FS, RS = chr(31), chr(30)

TOP_MIN, TOP_MAX, TOP_DEFAULT = 1, 100, 15
MIN_RSS_MIN, MIN_RSS_MAX, MIN_RSS_DEFAULT = 0, 4096, 25
ORPHAN_AGE_MINUTES = 10
CMD_SHORT_MAX = 100
PROCESS_FIELDS = 7  # pid, ppid, rss_kb, pcpu, etime, session_id, args -- see enumerate.py

IDLE_MINUTES_MIN, IDLE_MINUTES_MAX, IDLE_MINUTES_DEFAULT = 1, 1440, 20
SESSION_FIELDS = 6  # harness, session_id, project, started_epoch, mtime_epoch, started_approx
# Not a parameter: a display cap on the resumable bucket only (never on
# running sessions, which are always few) so this step's own stdout cannot
# grow past the runner's output ceiling on a machine with a large on-disk
# session history. totals.resumable is always the true on-disk count,
# computed before this cap is applied -- see main() for the reconciliation.
RESUMABLE_SHOWN_MAX = 50

CODEX_RUNNING_UNMATCHED_NOTE = (
    "a codex process is running on this machine right now, but its session cannot be "
    "matched to a specific file -- codex's process arguments carry no session id to join "
    "against. Run `codex resume` yourself to choose from its picker, or `codex resume "
    "--last` for the most recent (both verified real subcommands of the codex CLI on this "
    "machine)."
)


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def parse_int_arg(index, name, default):
    raw = arg(index, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        sys.stderr.write(name + " must be an integer, got: " + raw + "\n")
        sys.exit(2)


def clamp(value, lo, hi):
    return max(lo, min(hi, value))


def unpack_rows(packed):
    """Returns (rows, raw_record_count). raw_record_count is every non-empty
    record the RS split produced, regardless of whether it went on to parse
    successfully — comparing it against len(rows) is what lets main() tell
    a clean "nothing matched" input apart from one that silently lost rows
    to a malformed-record path."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != PROCESS_FIELDS:
            continue  # tolerate a malformed row rather than crash the whole audit
        pid_s, ppid_s, rss_kb_s, pcpu_s, etime_s, session_id, args = fields
        try:
            pid = int(pid_s)
            ppid = int(ppid_s)
            rss_kb = float(rss_kb_s)
        except ValueError:
            continue
        try:
            pcpu = float(pcpu_s)
        except ValueError:
            pcpu = 0.0
        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "rss_kb": rss_kb,
                "pcpu": pcpu,
                "etime": etime_s,
                "session_id": session_id,
                "args": args,
            }
        )
    return rows, raw_record_count


def etime_to_minutes(etime):
    """ps etime reads like '[[dd-]hh:]mm:ss'; return minutes, or None if unparseable."""
    try:
        rest = etime
        days = 0
        if "-" in rest:
            days_s, rest = rest.split("-", 1)
            days = int(days_s)
        parts = [int(p) for p in rest.split(":")]
        if len(parts) == 3:
            h, m, s = parts
        elif len(parts) == 2:
            h, m, s = 0, parts[0], parts[1]
        elif len(parts) == 1:
            h, m, s = 0, 0, parts[0]
        else:
            return None
        return days * 24 * 60 + h * 60 + m + s / 60.0
    except (ValueError, AttributeError):
        return None


def classify(args):
    args_lower = args.lower()
    # "Helper" is checked case-sensitively (the macOS/Electron app-bundle
    # convention: "Claude Helper", "Cursor Helper (Renderer)", Contents/
    # Helpers/) so a generically-named "some-daemon-helper.sh" does not get
    # mistaken for a desktop app bundle ahead of the known-daemon check.
    if ".app/" in args_lower or "Helper" in args:
        return "desktop-app"
    if (
        "mcp-server" in args_lower
        or "modelcontextprotocol" in args_lower
        or "mcp_" in args_lower
        or (("npx" in args_lower or "uvx" in args_lower) and "mcp" in args_lower)
    ):
        return "mcp-server"
    if "daemon" in args_lower:
        return "known-daemon"
    if (
        "codex-companion" in args_lower
        or "rote play" in args_lower
        or "rote proc" in args_lower
        or ".rote/flows" in args_lower
    ):
        return "companion"
    if any(name in args_lower for name in ("claude", "codex", "aider", "opencode")):
        return "harness-cli"
    return "helper"


ORPHAN_ELIGIBLE_CATEGORIES = ("harness-cli", "mcp-server", "companion")


def is_orphan_suspect(ppid, category, etime):
    if ppid != 1:
        return False
    if category not in ORPHAN_ELIGIBLE_CATEGORIES:
        return False  # known-daemon and desktop-app are never orphan-suspects
    minutes = etime_to_minutes(etime)
    if minutes is None:
        return False  # unknown age is never claimed as a suspicion
    return minutes > ORPHAN_AGE_MINUTES


def cmd_short(args):
    if len(args) <= CMD_SHORT_MAX:
        return args
    return args[: CMD_SHORT_MAX - 1] + "…"


def system_ram_gb(packed_mem):
    if not packed_mem or packed_mem == "unknown":
        return None
    try:
        total_bytes = int(packed_mem)
    except ValueError:
        return None
    return round(total_bytes / (1024**3), 1)


def unpack_sessions(packed):
    """Mirrors unpack_rows above, for the session rows sessions.py packs.
    Returns (rows, raw_record_count) — see unpack_rows for why the caller
    needs both."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != SESSION_FIELDS:
            continue  # tolerate a malformed row rather than crash the sessions section
        harness, session_id, project, started_s, mtime_s, approx_s = fields
        try:
            started_epoch = float(started_s)
            mtime_epoch = float(mtime_s)
        except ValueError:
            continue
        rows.append(
            {
                "harness": harness,
                "session_id": session_id,
                "project": project,
                "started_epoch": started_epoch,
                "mtime_epoch": mtime_epoch,
                "started_approx": approx_s == "1",
            }
        )
    return rows, raw_record_count


def build_session_pid_map(raw_rows):
    """uuid (lowercased) -> the enumerated process row whose session_id
    field (extracted upstream, from that row's own FULL args — see
    enumerate.py's extract_session_id()/is_claude_exec()) matches. Reading
    the pre-extracted field here, rather than re-deriving it from this
    row's own (200-character-truncated) `args`, is required: a long
    invocation's join flag can fall past that truncation boundary (observed
    live: the VS Code extension's `--resume=<uuid>` shape routinely does),
    which would silently break the join if re-derived from truncated text.
    When more than one row carries the same uuid (observed live: a
    bg-pty-host wrapper process and the actual worker it forked both retain
    the same session_id), the row with the larger rss_kb wins — the heavier
    process is the one actually doing the session's work, not the thin
    wrapper around it. This is a best-effort tiebreak, not a guarantee."""
    best = {}
    for row in raw_rows:
        uuid = row.get("session_id", "")
        if not uuid:
            continue
        current = best.get(uuid)
        if current is None or row["rss_kb"] > current["rss_kb"]:
            best[uuid] = row
    return best


def codex_process_detected(raw_rows):
    """Whether any enumerated process's own executable identity resolves to
    "codex" — the same tier-1 path-component-root check enumerate.py
    performs on the exec token (first whitespace-delimited token of args,
    reduced per "/"-component to the part before its first -, _, or .).
    Duplicated here rather than imported: each resource script in this play
    is self-contained, matching its own packing contract."""
    for row in raw_rows:
        token = row["args"].split(None, 1)[0] if row["args"] else ""
        for part in token.split("/"):
            if not part:
                continue
            root = re.split(r"[-_.]", part, maxsplit=1)[0].lower()
            if root == "codex":
                return True
    return False


def format_ts(epoch):
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


_CLAUDE_ID = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_CODEX_ID = re.compile(r"[0-9a-zA-Z][0-9a-zA-Z-]{5,63}$")


def session_advisory(harness, session_id, state, idle_minutes_value):
    """TEXT ONLY — nothing here is ever executed by this play; see main.ts's
    "nothing was executed" banner these advisories render under.

    A resume command is only ever built from an id that matches the harness's
    known id shape — an arbitrary .jsonl basename must not become
    shell-looking command text (codex review, v0.2.0 finding #3)."""
    pattern = _CLAUDE_ID if harness == "claude" else _CODEX_ID
    if not pattern.match(session_id or ""):
        return None
    if state == "running-idle":
        return (
            "idle "
            + str(int(idle_minutes_value))
            + "m — if you're done: exit it, later resume with: claude --resume "
            + session_id
        )
    if state == "resumable":
        if harness == "claude":
            return "claude --resume " + session_id
        if harness == "codex":
            return "codex resume " + session_id
    return None


def main():
    packed_rows = arg(1, "")
    packed_mem = arg(2, "")
    top = clamp(parse_int_arg(3, "top", TOP_DEFAULT), TOP_MIN, TOP_MAX)
    min_rss_mb = clamp(parse_int_arg(4, "min_rss_mb", MIN_RSS_DEFAULT), MIN_RSS_MIN, MIN_RSS_MAX)
    packed_sessions = arg(5, "")
    idle_minutes = clamp(
        parse_int_arg(6, "idle_minutes", IDLE_MINUTES_DEFAULT), IDLE_MINUTES_MIN, IDLE_MINUTES_MAX
    )

    raw_rows, raw_record_count = unpack_rows(packed_rows)
    dropped_rows = raw_record_count - len(raw_rows)

    enriched = []
    for row in raw_rows:
        category = classify(row["args"])
        orphan = is_orphan_suspect(row["ppid"], category, row["etime"])
        enriched.append(
            {
                "pid": row["pid"],
                "ppid": row["ppid"],
                "category": category,
                "rss_mb": round(row["rss_kb"] / 1024.0, 1),
                "pcpu": row["pcpu"],
                "age": row["etime"],
                "cmd_short": cmd_short(row["args"]),
                "orphan_suspect": orphan,
            }
        )

    matched = len(enriched)
    # The reported footprint covers every matched agent process, not just the
    # ones min_rss_mb lets through the table — min_rss_mb is a display filter,
    # not a redefinition of what counts as "the agent footprint".
    agent_rss_mb = round(sum(p["rss_mb"] for p in enriched), 1)

    kept = [p for p in enriched if p["rss_mb"] >= min_rss_mb]
    filtered_below_min = matched - len(kept)

    ranked = sorted(kept, key=lambda p: -p["rss_mb"])
    shown = ranked[:top]

    # Computed from every enriched row, not `shown` — a suspect below
    # min_rss_mb or outside the top N must not silently disappear from the
    # report just because it didn't make the ranked display list.
    orphan_suspects = [p for p in enriched if p["orphan_suspect"]]
    # Snapshot pids can be reused by the time a human reads this: pair each
    # kill suggestion with a verify-first command keyed to the snapshot's
    # own identity/age, rather than a bare "kill <pid>" that trusts the pid
    # still means the same thing.
    kill_hints = [
        "ps -p "
        + str(p["pid"])
        + " -o pid=,ppid=,etime=,command=  # verify this is still \""
        + p["cmd_short"]
        + "\" (age "
        + p["age"]
        + ") before running: kill "
        + str(p["pid"])
        for p in orphan_suspects
    ]

    # --- sessions: join scan_sessions' on-disk rows against this same
    # process table (raw_rows, unfiltered by top/min_rss_mb — a session's
    # live process should never disappear from the join just because it
    # fell below the display floor for the PROCESS table above).
    session_raw_rows, session_raw_record_count = unpack_sessions(packed_sessions)
    session_dropped_rows = session_raw_record_count - len(session_raw_rows)

    session_pid_map = build_session_pid_map(raw_rows)
    codex_detected = codex_process_detected(raw_rows)
    now = time.time()

    session_rows = []
    for row in session_raw_rows:
        proc = session_pid_map.get(row["session_id"].lower()) if row["harness"] == "claude" else None
        # clamp at 0: an mtime in the future (clock skew, restored backup) must
        # not produce a negative idle time or an impossible timeline
        idle_minutes_value = max(0.0, (now - row["mtime_epoch"]) / 60.0)
        if proc is None:
            state = "resumable"
        else:
            state = "running-idle" if idle_minutes_value > idle_minutes else "running-active"
        session_rows.append(
            {
                "harness": row["harness"],
                "session_id": row["session_id"],
                "id_short": row["session_id"][:8],
                "project": row["project"],
                "started": format_ts(row["started_epoch"]),
                "started_approx": row["started_approx"],
                "last_active": format_ts(row["mtime_epoch"]),
                "idle_minutes": round(idle_minutes_value, 1),
                "state": state,
                "pid": proc["pid"] if proc else None,
                "rss_mb": round(proc["rss_kb"] / 1024.0, 1) if proc else None,
                "pcpu": proc["pcpu"] if proc else None,
                "advisory": session_advisory(row["harness"], row["session_id"], state, idle_minutes_value),
            }
        )

    # Display order: running-active, then running-idle, then resumable;
    # most-recently-active first within each bucket.
    state_order = {"running-active": 0, "running-idle": 1, "resumable": 2}
    session_rows.sort(key=lambda r: (state_order.get(r["state"], 9), r["idle_minutes"]))

    running_rows = [r for r in session_rows if r["state"] in ("running-active", "running-idle")]
    running_idle_rows = [r for r in session_rows if r["state"] == "running-idle"]
    resumable_rows = [r for r in session_rows if r["state"] == "resumable"]
    running_rss_mb = round(sum(r["rss_mb"] for r in running_rows if r["rss_mb"] is not None), 1)

    # Running sessions are never truncated -- there are always few, and they
    # are the ones a person most needs to see. Resumable sessions are capped
    # (this machine's own on-disk history ran to hundreds of files) so a
    # single step's stdout cannot grow past the runner's output ceiling; the
    # cap is display-only -- totals.resumable above is already the true
    # on-disk count, computed before this slice, so nothing is silently
    # dropped from the count the way it would be if resumable_rows itself
    # were sliced before totals was built.
    resumable_shown = resumable_rows[:RESUMABLE_SHOWN_MAX]
    shown_rows = running_rows + resumable_shown

    sessions_output = {
        "totals": {
            "running": len(running_rows),
            "running_idle": len(running_idle_rows),
            "resumable": len(resumable_rows),
            "resumable_shown": len(resumable_shown),
            "running_rss_mb": running_rss_mb,
            "claude_listed": sum(1 for r in session_rows if r["harness"] == "claude"),
            "codex_listed": sum(1 for r in session_rows if r["harness"] == "codex"),
        },
        "rows": shown_rows,
        "codex_process_detected": codex_detected,
    }
    if codex_detected:
        sessions_output["codex_running_unmatched_note"] = CODEX_RUNNING_UNMATCHED_NOTE

    output = {
        "ok": True,
        "totals": {
            "matched": matched,
            "shown": len(shown),
            "filtered_below_min": filtered_below_min,
            "agent_rss_mb": agent_rss_mb,
            "system_ram_gb": system_ram_gb(packed_mem),
        },
        "processes": shown,
        "orphan_suspects": orphan_suspects,
        "kill_hints": kill_hints,
        "sessions": sessions_output,
    }

    warnings = []
    if dropped_rows > 0:
        warnings.append(
            str(dropped_rows)
            + " malformed process row(s) from enumerate_processes could not be parsed and were skipped"
        )
    if session_dropped_rows > 0:
        warnings.append(
            str(session_dropped_rows)
            + " malformed session row(s) from scan_sessions could not be parsed and were skipped"
        )
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
