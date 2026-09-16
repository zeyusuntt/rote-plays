"""List agent session FILES on disk, across harnesses (Claude Code, Codex).

Read-only, and narrower than that: this script never opens a session file at
all. Every fact it reports comes from the filesystem's own directory/inode
metadata (os.stat, glob, os.walk over path names) -- it never reads a byte
of any session transcript's contents. That is this play's trust line to the
person running it: "session files are listed by name and mtime only".

argv[1]  max_age_days -- only list on-disk sessions with an mtime newer than
         this many days ago (clamped to 1..365); must int-parse or empty for
         default. Non-integer is a hard fault (bad wiring), same reasoning
         as classify.py's top/min_rss_mb: this is a value rote's own
         parameters gate should already have validated as an integer, so a
         non-integer here means the wiring between steps is broken, not that
         the input is legitimately absent.
argv[2]  harness -- which harness(es) to scan: "all" (default), "claude", or
         "codex". An unrecognized value is likewise a hard fault -- there is
         no reasonable default degrade for "scan a harness I don't
         recognize the name of".

Claude Code sessions live at ~/.claude/projects/<project-slug>/<uuid>.jsonl
(glob'd non-recursively -- only direct children of a project directory are
session files; the same-named subdirectories some sessions also have are
Claude Code's own sidecar state, never listed as sessions themselves).
session_id is the filename without its .jsonl suffix. project is the
immediate parent directory's basename with its leading dash(es) stripped for
readability -- Claude Code encodes a project's absolute path into that slug
by replacing "/" with "-", which is lossy to reverse in general (a real
directory name containing "-" is indistinguishable from an encoded "/"), so
this script prettifies only the leading dash(es) it can be sure came from
the encoding, and leaves the rest of the slug exactly as recorded rather
than guess-decode a path it cannot verify.

Codex sessions were probed live on the machine this play was built on:
~/.codex/sessions/<year>/<month>/<day>/rollout-<UTC timestamp>-<uuid>.jsonl.
That is the only layout this script knows how to parse. Each file found
under ~/.codex/sessions is checked against that exact naming pattern;
non-matching files are skipped individually (a stray file some other Codex
version or tool dropped in that tree does not invalidate every session
around it). If ~/.codex/sessions does not exist, that harness is silently
empty (a machine that never used Codex is a normal, non-degraded state). If
it exists but contains files and NONE of them match the known pattern, this
is treated honestly as "the layout is not what this script was written
against" -- a warning is emitted and codex is reported as 0 sessions,
never a guess at what an unrecognized filename might mean.

Neither harness's absence, nor an unreadable/unrecognizable directory, is a
hard fault: session availability is inherently machine-dependent (someone
may only use one harness, or neither), so this script always emits
{"ok": true, ...} once its argv parses, carrying a "warning" only when a
harness could not be scanned the way it expected to.

Emits one JSON object on stdout:
    {"ok": true,
     "warning": "<optional -- one harness could not be scanned as expected>",
     "counts": {"claude_listed": n, "codex_listed": n,
                "codex_unrecognized_skipped": n},
     "packed": "<rows>"}
Each row packs harness, session_id, project, started_epoch, mtime_epoch, and
started_approx ("1" if started_epoch is a fallback approximation rather than
a true creation time -- see started_epoch_and_approx below), joined with
chr(31); rows are joined with chr(30) -- the same packing convention
enumerate.py/classify.py use to move a collection through one scalar argv
slot. project text is stripped of any embedded chr(31)/chr(30) bytes before
packing, the same defensive reasoning as enumerate.py's args sanitation:
a pathological directory name should never be able to split into extra
fields or records downstream.
"""

import glob
import json
import os
import re
import sys

FS, RS = chr(31), chr(30)

MAX_AGE_MIN, MAX_AGE_MAX, MAX_AGE_DEFAULT = 1, 365, 30
VALID_HARNESSES = ("all", "claude", "codex")

CLAUDE_PROJECTS_ROOT = os.path.expanduser("~/.claude/projects")
CODEX_SESSIONS_ROOT = os.path.expanduser("~/.codex/sessions")

# The exact layout probed live on this machine: rollout-<UTC timestamp with
# "-" in place of ":">-<uuid>.jsonl. See module docstring.
_CODEX_ROLLOUT_RE = re.compile(
    r"^rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"\.jsonl$"
)


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def clamp(value, lo, hi):
    return max(lo, min(hi, value))


def parse_max_age_days():
    raw = arg(1, "")
    if raw == "":
        return MAX_AGE_DEFAULT
    try:
        return clamp(int(raw), MAX_AGE_MIN, MAX_AGE_MAX)
    except ValueError:
        sys.stderr.write("max_age_days must be an integer, got: " + raw + "\n")
        sys.exit(2)


def parse_harness():
    raw = arg(2, "all") or "all"
    if raw not in VALID_HARNESSES:
        sys.stderr.write(
            "harness must be one of " + "|".join(VALID_HARNESSES) + ", got: " + raw + "\n"
        )
        sys.exit(2)
    return raw


def sanitize_for_packing(text):
    """Strip the packing separators out of a field before it goes in a row
    (see module docstring) -- mirrors enumerate.py's sanitize_for_packing."""
    return text.replace(FS, "?").replace(RS, "?")


def started_epoch_and_approx(st):
    """(started_epoch, approx). macOS exposes a true creation time via
    st_birthtime; where that attribute is absent (Linux; some filesystems),
    fall back to min(st_mtime, st_ctime) -- the earliest of "last content
    change" and "last metadata change" is the closest honest proxy for
    "when this file first appeared" available without a true birthtime, and
    is flagged approx so the presentation can label it as such rather than
    imply a precision this script cannot actually deliver."""
    birthtime = getattr(st, "st_birthtime", None)
    if birthtime is not None:
        return birthtime, False
    return min(st.st_mtime, st.st_ctime), True


def prettify_project(dirname):
    """Strip the leading dash(es) AND the encoded $HOME prefix of a Claude
    Code project slug. The slug encodes the project's absolute path with
    '/'->'-', so a raw slug leaks the username ("Users-<name>-..."). We cut
    the current $HOME's encoding when present, and as a defense for slugs
    recorded under a DIFFERENT user, any generic leading "Users-<name>-" /
    "home-<name>-" component. Only display text changes; join keys are ids."""
    name = re.sub(r"^-+", "", dirname)
    encoded_home = re.sub(r"^-+", "", os.path.expanduser("~").replace("/", "-"))
    if name.startswith(encoded_home + "-"):
        return name[len(encoded_home) + 1:]
    return re.sub(r"^(Users|home)-[^-]+-", "", name)


def scan_claude(cutoff_epoch):
    """Returns (rows, warning-or-None)."""
    if not os.path.isdir(CLAUDE_PROJECTS_ROOT):
        return [], None  # no Claude Code use on this machine -- not a degrade
    try:
        files = glob.glob(os.path.join(CLAUDE_PROJECTS_ROOT, "*", "*.jsonl"))
    except OSError as exc:
        return [], "claude sessions could not be listed: " + str(exc)

    rows = []
    for path in files:
        try:
            st = os.stat(path)
        except OSError:
            continue  # file vanished between glob and stat -- not a session
        if st.st_mtime < cutoff_epoch:
            continue
        started_epoch, approx = started_epoch_and_approx(st)
        session_id = os.path.basename(path)[: -len(".jsonl")]
        project = prettify_project(os.path.basename(os.path.dirname(path)))
        rows.append(
            {
                "harness": "claude",
                "session_id": session_id,
                "project": sanitize_for_packing(project),
                "started_epoch": started_epoch,
                "mtime_epoch": st.st_mtime,
                "started_approx": approx,
            }
        )
    return rows, None


def scan_codex(cutoff_epoch):
    """Returns (rows, unrecognized_skipped_count, warning-or-None)."""
    if not os.path.isdir(CODEX_SESSIONS_ROOT):
        return [], 0, None  # no Codex use on this machine -- not a degrade

    found = 0
    rows = []
    unrecognized = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(CODEX_SESSIONS_ROOT):
            for name in filenames:
                found += 1
                match = _CODEX_ROLLOUT_RE.match(name)
                if not match:
                    unrecognized += 1
                    continue
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue  # file vanished between walk and stat
                if st.st_mtime < cutoff_epoch:
                    continue
                started_epoch, approx = started_epoch_and_approx(st)
                rows.append(
                    {
                        "harness": "codex",
                        "session_id": match.group(1),
                        # Unlike Claude Code's per-project directory, Codex's
                        # own on-disk layout groups sessions by date, not by
                        # project -- there is no project name recoverable
                        # from the path/filename alone without opening the
                        # file, which this script never does. Left blank
                        # rather than guessed.
                        "project": "",
                        "started_epoch": started_epoch,
                        "mtime_epoch": st.st_mtime,
                        "started_approx": approx,
                    }
                )
    except OSError as exc:
        return [], 0, "codex sessions could not be walked: " + str(exc)

    if found > 0 and not rows and unrecognized == found:
        return [], unrecognized, (
            "codex sessions layout not recognized: found "
            + str(found)
            + " file(s) under ~/.codex/sessions but none matched the "
            + "rollout-<timestamp>-<uuid>.jsonl naming this script knows "
            + "how to parse -- codex reported as 0 sessions rather than "
            + "guessed"
        )
    return rows, unrecognized, None


def pack(rows):
    return RS.join(
        FS.join(
            [
                row["harness"],
                row["session_id"],
                row["project"],
                str(row["started_epoch"]),
                str(row["mtime_epoch"]),
                "1" if row["started_approx"] else "0",
            ]
        )
        for row in rows
    )


def main():
    import time

    max_age_days = parse_max_age_days()
    harness = parse_harness()
    cutoff_epoch = time.time() - max_age_days * 86400

    claude_rows = []
    codex_rows = []
    codex_unrecognized = 0
    warnings = []

    if harness in ("all", "claude"):
        claude_rows, claude_warning = scan_claude(cutoff_epoch)
        if claude_warning:
            warnings.append(claude_warning)
    if harness in ("all", "codex"):
        codex_rows, codex_unrecognized, codex_warning = scan_codex(cutoff_epoch)
        if codex_warning:
            warnings.append(codex_warning)

    # Most-recently-active first: the far more common human question is
    # "what have I touched lately", not filesystem order.
    all_rows = sorted(claude_rows + codex_rows, key=lambda r: -r["mtime_epoch"])

    output = {
        "ok": True,
        "counts": {
            "claude_listed": len(claude_rows),
            "codex_listed": len(codex_rows),
            "codex_unrecognized_skipped": codex_unrecognized,
        },
        "packed": pack(all_rows),
    }
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
