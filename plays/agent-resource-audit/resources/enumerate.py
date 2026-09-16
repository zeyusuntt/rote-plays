"""Enumerate agent-related processes on this machine via ps.

Read-only: runs `ps -axo pid=,ppid=,rss=,pcpu=,etime=,args=` exactly once.
No pid is ever signaled here, by this script or by its `ps` child: ps is run
without an internal timeout or kill of its own, so the only way this script
ever terminates a process is indirectly, if the step's declared timeout_ms
in main.ts elapses and rote's process.exec step runner reclaims the whole
step -- never a signal this script issues itself. Enumeration is this
step's whole job.

Matching an agent-shaped row is a two-tier decision, deliberately narrower
than "signature substring anywhere in the command line" (that used to
false-positive on this very machine: macOS's own `xprotectd` and
`CursorUIViewService` contain the substrings "rote" and "cursor" purely by
letter coincidence, and would otherwise be reported as agent processes):
  1. exec identity — every "/"-delimited component of the executable's own
     path (the first whitespace-delimited token of args, before any of its
     arguments) is reduced to the part before its first "-", "_", or "."
     separator and compared, case-insensitively, against a short list of
     whole tool names (claude, codex, cursor, aider, opencode, windsurf,
     copilot, rote). Checking every path component, not just the final
     basename, is required to catch real versioned installs where the
     final component is just a version number, e.g.
     ~/.local/share/claude/versions/2.1.251 -- the identifying "claude" is
     a directory segment, not the basename. Requiring a whole
     separator-delimited segment (not a substring) is what excludes
     xprotectd/CursorUIViewService: neither has a path component whose
     root is exactly "rote" or "cursor".
  2. invocation marker — a small set of compound, hyphen/underscore-joined
     tokens (mcp-server, modelcontextprotocol, mcp_, codex-companion,
     gemini-cli) checked as a substring of the full command line, because
     for launcher-style invocations (`npx @modelcontextprotocol/server-x`,
     `uvx mcp-server-git`, `python3 -m mcp_server.foo`) the identifying
     name is an argument, not the executable itself. These stay
     substring-based deliberately: each is a rare compound unlikely to
     appear by accident, unlike a single common word.
A search/inspection tool's own presence (grep, egrep, fgrep, rg, ag, ack,
pgrep) never counts as a match on its own basename, regardless of what it
was told to search for (`rg cursor`, `pgrep codex`).

Excluded from the result, regardless of the above:
  - this script's own pid and every ancestor in its ppid chain (so a play
    run of THIS play never reports itself or the runner that launched it)
  - the pid of the `ps` child process this script spawns
  - any row whose args mention this play's own sibling scripts
    (enumerate.py / classify.py / sysmem.py), so concurrent steps of this
    same play run never audit each other

Before packing, each row's args is:
  - stripped of any embedded chr(31)/chr(30) bytes (the packing separators
    below) so a pathological argv can never split into extra fields or
    records downstream
  - passed through a best-effort redaction of flag-shaped secret values
    (--token=..., --password ..., Authorization: Bearer ..., user:pass@host
    URLs) before the first-200-character slice, so a matched process
    launched with a credential in argv does not republish it verbatim.
    This is necessarily best-effort -- any ps-based tool can only ever
    redact what looks like a secret, never guarantee none is present -- and
    it redacts values, never the flag names or executable identity that
    matching and categorization depend on.

Emits one JSON object on stdout:
    {"ok": true, "count": N, "packed": "<rows>"}
Each row packs pid, ppid, rss_kb, pcpu, etime, session_id (the join signal
classify.py's sessions feature needs -- see extract_session_id() below;
empty string when this row isn't Claude Code's own executable, or Claude
Code's own executable but discloses no recognized session-id shape), and
the sanitized/redacted, first-200-characters args, joined with chr(31);
rows are joined with chr(30) — the ASCII unit and record separators the
modiqo plays use to move a collection through a single scalar argv slot.
session_id is read from this row's FULL, untruncated args before that
200-character slice is taken, so a long invocation's join signal is never
lost to the same truncation that (deliberately) bounds the displayed args.

ps failing entirely is a HARD FAULT: enumeration is this play's whole job,
so there is nothing honest left to degrade to. Message on stderr, exit 2.
"""

import json
import os
import re
import subprocess
import sys

FS, RS = chr(31), chr(30)

# Whole tool names, matched against a "/"-delimited path component of the
# executable's own path reduced to the part before its first -, _, or .
# separator. See module docstring tier 1.
EXEC_ROOT_SIGNATURES = {
    "claude",
    "codex",
    "cursor",
    "aider",
    "opencode",
    "windsurf",
    "copilot",
    "rote",
}

# Compound invocation markers, matched as a substring of the full command
# line. See module docstring tier 2.
INVOCATION_MARKERS = (
    "mcp-server",
    "modelcontextprotocol",
    "mcp_",
    "codex-companion",
    "gemini-cli",
)

# A search/inspection tool's own basename never counts as a match, no
# matter what signature-shaped text it was told to look for.
SEARCH_TOOL_BASENAMES = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "pgrep"}

# This play's own resource scripts; any row mentioning one is a sibling step
# of this same run (or this script itself), never something to report on.
OWN_SCRIPT_MARKERS = ("enumerate.py", "classify.py", "sysmem.py")

ARGS_MAX = 200

# Best-effort redaction of flag-shaped secret values. Only the value after
# an =/whitespace is replaced; the flag name (where identity markers like
# "mcp-server-token" live) is left intact.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_FLAG_RE = re.compile(
    r"(?i)((?:--?[\w]*(?:token|password|passwd|secret|apikey|api[_-]?key|bearer|auth)[\w-]*)(?:[=\s]+))(\S+)"
)
_USERINFO_URL_RE = re.compile(r"://([^\s/:@]+):([^\s/@]+)@")


def run_ps():
    """Run ps once; return (stdout_text, ps_pid). No timeout or signal is
    issued by this function itself -- the step's declared timeout_ms in
    main.ts is what bounds total runtime if ps hangs."""
    # No -ww/-www width flag: macOS's ps(1) documents "When output is not
    # to a terminal, an unlimited number of columns are always used" (and
    # this was confirmed empirically -- a 3000+ character argv came through
    # untruncated via this exact subprocess.Popen(..., stdout=PIPE) shape,
    # which is never a tty). Adding a width flag here would be a no-op on
    # macOS and a portability risk on Linux/BusyBox ps builds that may not
    # recognize it, which would turn a working invocation into the hard
    # fault below.
    argv = ["ps", "-axo", "pid=,ppid=,rss=,pcpu=,etime=,args="]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        sys.stderr.write("ps failed to start: " + str(exc) + "\n")
        sys.exit(2)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        sys.stderr.write(
            "ps exited "
            + str(proc.returncode)
            + ": "
            + (stderr or "").strip()[:200]
            + " (a minimal/BusyBox ps may not support the -axo keyword"
            + " format this play requires: pid=,ppid=,rss=,pcpu=,etime=,args=)\n"
        )
        sys.exit(2)
    return stdout, proc.pid


def parse_rows(raw):
    """Split ps -axo pid=,ppid=,rss=,pcpu=,etime=,args= output into a pid -> row map.

    The first five fields are whitespace-delimited by ps; args is everything
    left on the line, which may itself contain internal whitespace.
    """
    rows = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 5)
        if len(parts) < 6:
            continue
        pid_s, ppid_s, rss_s, pcpu_s, etime_s, args = parts
        try:
            pid = int(pid_s)
            ppid = int(ppid_s)
        except ValueError:
            continue
        rows[pid] = {
            "pid": pid,
            "ppid": ppid,
            "rss_kb": rss_s,
            "pcpu": pcpu_s,
            "etime": etime_s,
            "args": args,
        }
    return rows


def ancestor_chain(pid, rows):
    """Walk the ppid chain from pid up to root; guards against cycles."""
    seen = set()
    current = pid
    while current in rows and current not in seen:
        seen.add(current)
        current = rows[current]["ppid"]
    return seen


def exe_token(args):
    """The first whitespace-delimited token of args: the executable's own
    path/name, before any of its arguments."""
    return args.split(None, 1)[0] if args else ""


def path_component_roots(token):
    """Every "/"-delimited component of token, reduced to the part before
    its first -, _, or . separator, lowercased."""
    roots = []
    for part in token.split("/"):
        if not part:
            continue
        root = re.split(r"[-_.]", part, maxsplit=1)[0]
        roots.append(root.lower())
    return roots


def matches_agent(args):
    token = exe_token(args)
    basename = token.rsplit("/", 1)[-1].lower()
    if basename in SEARCH_TOOL_BASENAMES:
        return False
    if any(root in EXEC_ROOT_SIGNATURES for root in path_component_roots(token)):
        return True
    return any(marker in args.lower() for marker in INVOCATION_MARKERS)


def is_claude_exec(args):
    """Whether this row's executable identity resolves to exactly "claude"
    (the same tier-1 path-component-root check matches_agent() performs,
    narrowed to one specific tool). Session-id extraction below is scoped
    to this: the join signal is a Claude Code-specific argv convention, so
    matching it on an unrelated tool's row would only ever be coincidence,
    never a real signal."""
    return "claude" in path_component_roots(exe_token(args))


# Session-id join signal for classify.py's sessions feature. Two argv shapes
# were verified live on the machine this play was built on:
#   1. --session-id <uuid> / --session-id=<uuid> -- a forked/new session's
#      own id, paired with --fork-session and a --resume <path-to-source>
#      in the CLI's fork-from-an-existing-session shape.
#   2. --resume=<uuid> / --resume <uuid>, where the value is a BARE uuid,
#      not a path -- the VS Code extension's in-place-resume shape, where
#      the resumed session's id IS the process's own running session id.
#      --resume can ALSO take a path to a source .jsonl when paired with
#      --fork-session (shape 1's fork-from-existing-session case); that
#      path form is deliberately NOT matched by this pattern, since the
#      source of a fork is not the session the process is running as --
#      requiring the uuid to start immediately after "--resume[= ]" and end
#      at a word boundary excludes it naturally (a path there starts with
#      "/", never a bare uuid).
# Extracted here, from the FULL untruncated args, rather than in classify.py
# from the packed (200-char-truncated) args: a long invocation -- the VS
# Code extension's routinely does -- can carry --resume=<uuid> well past
# character 200, and re-deriving this signal from truncated text would
# silently lose it. This is not a new signal beyond this play's own
# contract: main.ts's description already documents a running Claude Code
# process's session id as a signal collected specifically to power the
# sessions join; this only widens it to the second real shape and reads it
# early enough to survive truncation.
_SESSION_ID_FLAG_RE = re.compile(
    r"--session-id[= ]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
_RESUME_UUID_RE = re.compile(
    r"--resume[= ]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=\s|$)"
)


def extract_session_id(args):
    """The join-relevant session uuid this row's FULL args disclose, or ""
    if none. --session-id wins when both patterns match (the
    fork-from-existing shape carries both; --session-id is the process's
    own running id there). Only called for rows is_claude_exec() already
    confirmed are Claude Code's own executable -- see its docstring."""
    match = _SESSION_ID_FLAG_RE.search(args)
    if match:
        return match.group(1).lower()
    match = _RESUME_UUID_RE.search(args)
    if match:
        return match.group(1).lower()
    return ""


def redact_secrets(args):
    """Best-effort scrub of flag-shaped secret values and userinfo-in-URL
    credentials. Not exhaustive; see module docstring."""
    text = _BEARER_RE.sub("Bearer ***REDACTED***", args)
    text = _SECRET_FLAG_RE.sub(lambda m: m.group(1) + "***REDACTED***", text)
    text = _USERINFO_URL_RE.sub(r"://\1:***REDACTED***@", text)
    return text


def sanitize_for_packing(args):
    """Strip the packing separators themselves out of args (a pathological
    argv could otherwise contain a literal chr(31)/chr(30) and split into
    extra fields/records downstream), then apply best-effort secret
    redaction, then truncate to ARGS_MAX."""
    text = args.replace(FS, "?").replace(RS, "?")
    text = redact_secrets(text)
    return text[:ARGS_MAX]


def main():
    raw, ps_pid = run_ps()
    rows = parse_rows(raw)

    excluded = ancestor_chain(os.getpid(), rows)
    excluded.add(ps_pid)

    matched = []
    for pid, row in rows.items():
        if pid in excluded:
            continue
        args = row["args"]
        if not matches_agent(args):
            continue
        if any(marker in args for marker in OWN_SCRIPT_MARKERS):
            continue
        matched.append(row)

    matched.sort(key=lambda r: r["pid"])

    packed_rows = [
        FS.join(
            [
                str(row["pid"]),
                str(row["ppid"]),
                str(row["rss_kb"]),
                str(row["pcpu"]),
                str(row["etime"]),
                extract_session_id(row["args"]) if is_claude_exec(row["args"]) else "",
                sanitize_for_packing(row["args"]),
            ]
        )
        for row in matched
    ]

    print(json.dumps({"ok": True, "count": len(matched), "packed": RS.join(packed_rows)}))


main()
