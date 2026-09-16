"""Locate recent LOCAL agent session transcripts: Claude Code and Codex.

Read-only: this script only stats and peeks at files, never opens a
transcript for real parsing (that is digest_claude.py's and
digest_codex.py's job, run in the next layer).

Claude Code transcripts live one level under ~/.claude/projects/<project>/
as <session-uuid>.jsonl -- a direct child, never the deeper per-session
<uuid>/ directories (checkpoints, subagent transcripts, tool-result
scratch) that sit alongside them. The glob below is intentionally
non-recursive so those never get swept in.

Codex transcripts live under ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
(or whatever a future layout equivalent puts there) -- nested, so that
glob is recursive. Codex's session directory is a "may not exist" surface:
its absence is a normal degrade (nothing installed/used here), never a
fault.

A file only counts as "obviously not a transcript" and gets skipped,
recorded in the skipped count, when it is zero bytes or its first non-empty
line does not parse as a JSON object -- a cheap peek, not a full read.

Every candidate path is stripped of embedded chr(31)/chr(30) bytes (the
packing separators below) before packing, so a pathological path can never
split into extra fields or records downstream; window_hours and
max_sessions are still respected even though this is unlikely in practice
for filesystem paths.

Emits one JSON object on stdout, always exit 0 once the two integer
arguments parse:
    {"ok": true,
     "claude_packed": "<RS-joined session paths>",
     "codex_packed": "<RS-joined session paths>",
     "window_hours": n,   # clamped/effective value actually used for cutoff
     "max_sessions": n,   # clamped/effective value actually used per source
     "counts": {"claude_scanned": n, "claude_in_window": n,
                "claude_selected": n, "claude_skipped": n,
                "codex_scanned": n, "codex_in_window": n,
                "codex_selected": n, "codex_skipped": n},
     "warning": "<optional -- e.g. one or both roots not found>"}

window_hours/max_sessions failing to int-parse is a HARD FAULT: rote's
param_type: integer gate should already guarantee this, so a non-integer
here means broken wiring between the play and this script, not an
expected absence. Message on stderr, exit 2.
"""

import glob
import json
import os
import sys
import time

FS, RS = chr(31), chr(30)

WINDOW_MIN, WINDOW_MAX, WINDOW_DEFAULT = 1, 168, 24
MAX_SESSIONS_MIN, MAX_SESSIONS_MAX, MAX_SESSIONS_DEFAULT = 1, 50, 12

CLAUDE_ROOT = os.path.expanduser("~/.claude/projects")
CODEX_ROOT = os.path.expanduser("~/.codex/sessions")


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


def looks_like_transcript(path):
    """Cheap peek: zero-byte files and files whose first non-empty line
    does not parse as a JSON object are obviously not transcripts."""
    try:
        if os.path.getsize(path) == 0:
            return False
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    return isinstance(json.loads(stripped), dict)
                except ValueError:
                    return False
        return False  # every line was blank
    except OSError:
        return False


def sanitize_path(path):
    """Strip the packing separators themselves out of a path (see module
    docstring)."""
    return path.replace(FS, "?").replace(RS, "?")


def scan(root, recursive, cutoff, max_sessions):
    """Returns (packed, scanned, in_window, selected, skipped, root_missing)."""
    if not os.path.isdir(root):
        return "", 0, 0, 0, 0, True

    pattern = os.path.join(root, "**", "*.jsonl") if recursive else os.path.join(root, "*", "*.jsonl")
    candidates = glob.glob(pattern, recursive=recursive)

    scanned = 0
    skipped = 0
    in_window = []  # (mtime, path)
    for path in candidates:
        scanned += 1
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            skipped += 1
            continue
        if mtime < cutoff:
            continue
        if not looks_like_transcript(path):
            skipped += 1
            continue
        in_window.append((mtime, path))

    in_window.sort(key=lambda pair: -pair[0])
    selected = in_window[:max_sessions]
    packed = RS.join(sanitize_path(path) for _, path in selected)
    return packed, scanned, len(in_window), len(selected), skipped, False


def main():
    window_hours = clamp(parse_int_arg(1, "window_hours", WINDOW_DEFAULT), WINDOW_MIN, WINDOW_MAX)
    max_sessions = clamp(parse_int_arg(2, "max_sessions", MAX_SESSIONS_DEFAULT), MAX_SESSIONS_MIN, MAX_SESSIONS_MAX)
    cutoff = time.time() - window_hours * 3600

    claude_packed, claude_scanned, claude_in_window, claude_selected, claude_skipped, claude_missing = scan(
        CLAUDE_ROOT, recursive=False, cutoff=cutoff, max_sessions=max_sessions
    )
    codex_packed, codex_scanned, codex_in_window, codex_selected, codex_skipped, codex_missing = scan(
        CODEX_ROOT, recursive=True, cutoff=cutoff, max_sessions=max_sessions
    )

    warnings = []
    if claude_missing:
        warnings.append("~/.claude/projects not found -- no Claude Code transcripts on this machine")
    if codex_missing:
        warnings.append("~/.codex/sessions not found -- no Codex transcripts on this machine (expected if Codex isn't used here)")

    output = {
        "ok": True,
        "claude_packed": claude_packed,
        "codex_packed": codex_packed,
        # Reported back so the presentation layer can render the window it
        # actually used to select files, not the raw (pre-clamp) parameter --
        # a caller passing window_hours=1000 gets files from the last 168h
        # (clamp above), and the digest text should say 168h, not 1000h.
        "window_hours": window_hours,
        "max_sessions": max_sessions,
        "counts": {
            "claude_scanned": claude_scanned,
            "claude_in_window": claude_in_window,
            "claude_selected": claude_selected,
            "claude_skipped": claude_skipped,
            "codex_scanned": codex_scanned,
            "codex_in_window": codex_in_window,
            "codex_selected": codex_selected,
            "codex_skipped": codex_skipped,
        },
    }
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
