"""Discover every git repository under base_dir, bounded and pruned.

This is the whole job of this step: find repositories, nothing more. No git
config or git log call happens here -- that is scan_identities.py's job, one
step downstream, joined against this step's own packed output. Splitting
discovery from identity resolution (rather than folding both into one script
the way laptop-loss-drill's sweep_loss.py does) is a deliberate choice for
THIS play: the identity-resolution step already needs several git calls per
repo, and keeping "where are the repos" and "what identity would each one
commit with" as two steps keeps each script's job legible on its own.

Walks base_dir up to max_depth levels, pruning node_modules (the case this
play's spec calls out by name) plus the same conservative noise list
laptop-loss-drill's sweep_loss.py already established (.venv, venv,
__pycache__, Library, .Trash, and any other dot-directory) -- reused as-is
rather than re-derived by hand, since it is already-proven craft for the
identical "walk base_dir for git repos" job. The walk stops descending the
moment a repository's own .git is found (directory or worktree/submodule
file form), so a repository's internals are never walked into and a nested
repo inside another repo's .git is never mistaken for a second find.

argv[1]  base_dir  -- folder to sweep (tilde expanded); defaults to
                       ~/Documents
argv[2]  max_depth -- directory levels below base_dir to search; must
                       int-parse (a non-integer is a hard fault -- this is a
                       value rote's own param_type: integer gate should
                       already have validated, so a non-integer here means
                       broken step wiring, not a legitimate absence -- same
                       reasoning classify.py/sessions.py apply to their own
                       int argv), then clamped to 1..6

Degrade, not fail: base_dir not existing or not being a directory is a
normal, expected state (a typo, a not-yet-created folder, a narrowed test
path) -- not a hard fault. This step always emits {"ok": true, ...}; a
missing/unreadable base_dir instead reports repos_total: 0 with a warning,
mirroring sweep_loss.py's identical judgment call for the identical
parameter. The only two HARD faults are a max_depth that fails to
int-parse, and base_dir resolving to something that exists but is not
a directory at all after expansion -- neither is a legitimate "nothing
found" state, both are bad wiring or a bad parameter value.

Bounded: one wall-clock deadline covers the whole walk (a pathologically
large or deeply cross-linked base_dir can make os.walk itself slow), a
repository cap (MAX_REPOS) guards a base_dir with an unreasonable number of
repositories, and packed output only ever carries the ABSOLUTE repository
path -- home-redaction and the human-facing relative label are computed one
step downstream, in scan_identities.py, from this same absolute path plus
the same base_dir argument passed to it independently; nothing this step
emits is itself printed to a human.

Emits one JSON object on stdout, always exit 0 once argv parses:
    {"ok": true,
     "base": "<home-redacted base_dir, for the STAGES ledger only>",
     "max_depth": N,
     "depth_note": "..."|null,
     "repos_total": N,
     "truncated_by_deadline": bool,
     "truncated_by_repo_cap": bool,
     "packed": "<absolute repo paths, joined with chr(30)>",
     "warning": "..."|null}
"""

import json
import os
import sys
import time

RS = chr(30)
FS = chr(31)

DEADLINE_S = 15  # leaves headroom under this step's 20s timeout_ms
MAX_REPOS = 500  # a sanity cap against a pathologically large base_dir

DEFAULT_BASE = "~/Documents"
DEFAULT_DEPTH = 3
MIN_DEPTH, MAX_DEPTH = 1, 6

# Reused verbatim from laptop-loss-drill/resources/sweep_loss.py's
# already-proven discovery walk: node_modules is the case this play's own
# spec names explicitly; the rest is the same conservative noise list, plus
# (below) any dot-directory other than .git itself.
PRUNED_DIRS = ("node_modules", ".venv", "venv", "__pycache__", "Library", ".Trash")

HOME = os.path.expanduser("~")


def redact_home(text):
    if not text:
        return text
    return str(text).replace(HOME, "~") if HOME and HOME != "/" else str(text)


def sanitize(text):
    """Strip the packing separators out of a path before it goes in a row
    (a pathological directory name should never split into extra fields or
    records downstream) -- mirrors enumerate.py's sanitize_for_packing."""
    return text.replace(FS, "?").replace(RS, "?")


def arg(index, fallback):
    value = sys.argv[index] if len(sys.argv) > index else ""
    return value if value else fallback


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(2)


def parse_max_depth(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        fail("max_depth must be an integer, got: " + str(raw))
    clamped = max(MIN_DEPTH, min(MAX_DEPTH, value))
    note = None
    if clamped != value:
        note = "max_depth clamped from " + str(value) + " to " + str(clamped)
    return clamped, note


def is_repo_marker(dirs, files):
    """Matches a directory clone (.git/ is a dir) and a worktree/submodule
    (.git is a file holding a gitdir: pointer)."""
    return ".git" in dirs or ".git" in files


def discover(base, depth, deadline_at):
    """Returns (repos, truncated_by_deadline, truncated_by_repo_cap)."""
    repos = []
    truncated_by_deadline = False
    truncated_by_repo_cap = False
    for root, dirs, files in os.walk(base):
        if time.monotonic() >= deadline_at:
            truncated_by_deadline = True
            break
        relative = os.path.relpath(root, base)
        level = 0 if relative == "." else relative.count(os.sep) + 1
        if is_repo_marker(dirs, files):
            repos.append(root)
            dirs[:] = []  # never descend into a found repo -- .git internals included
            if len(repos) >= MAX_REPOS:
                truncated_by_repo_cap = True
                break
            continue
        dirs[:] = [d for d in dirs if d not in PRUNED_DIRS and not (d.startswith(".") and d != ".git")]
        if level >= depth:
            dirs[:] = []
    return sorted(repos), truncated_by_deadline, truncated_by_repo_cap


def main():
    raw_base = arg(1, DEFAULT_BASE)
    max_depth, depth_note = parse_max_depth(arg(2, str(DEFAULT_DEPTH)))

    expanded = os.path.expanduser(raw_base)

    if os.path.exists(expanded) and not os.path.isdir(expanded):
        fail("base_dir exists but is not a directory: " + redact_home(expanded))

    if not os.path.isdir(expanded):
        print(
            json.dumps(
                {
                    "ok": True,
                    "base": redact_home(expanded),
                    "max_depth": max_depth,
                    "depth_note": depth_note,
                    "repos_total": 0,
                    "truncated_by_deadline": False,
                    "truncated_by_repo_cap": False,
                    "packed": "",
                    "warning": "base_dir does not exist: " + redact_home(expanded),
                }
            )
        )
        return

    base_resolved = os.path.realpath(expanded)
    deadline_at = time.monotonic() + DEADLINE_S

    repos, truncated_by_deadline, truncated_by_repo_cap = discover(base_resolved, max_depth, deadline_at)

    warning = None
    if truncated_by_deadline:
        warning = "discovery's time budget was reached; not every repository under base_dir was found"
    elif truncated_by_repo_cap:
        warning = "MAX_REPOS (" + str(MAX_REPOS) + ") reached during discovery; not every repository under base_dir was found"

    print(
        json.dumps(
            {
                "ok": True,
                "base": redact_home(base_resolved),
                "max_depth": max_depth,
                "depth_note": depth_note,
                "repos_total": len(repos),
                "truncated_by_deadline": truncated_by_deadline,
                "truncated_by_repo_cap": truncated_by_repo_cap,
                "packed": RS.join(sanitize(r) for r in repos),
                "warning": warning,
            }
        )
    )


main()
