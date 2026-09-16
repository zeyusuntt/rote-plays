"""Validate the repo parameter and depth before any commit-log scan happens.

Read-only: the only git calls here are `git rev-parse --is-inside-work-tree`
and `git rev-parse HEAD`. Never runs `git log`, `git show`, or anything that
reads commit content -- that is scan_log.py's job. This script only confirms
the repo exists and is reachable.

Two failure lanes:
  - essential/bad-input (missing/invalid path, no .git, git not on PATH, a
    depth that does not int-parse or falls outside 1-1000): fail closed,
    stderr + exit 2. Nothing downstream can do anything useful without a
    valid repo and a valid depth, so there is no honest degrade here.
  - empty repo (a real, valid git repository with zero commits): NOT a
    failure. Emits ok:true, empty_repo:true, head:null, with a warning note
    so the caller renders this as a clean bill, not an error. Detected via
    `git rev-parse --verify -q HEAD`'s exit code alone (0 resolves, 1 means
    HEAD does not resolve), never by matching git's own English error text
    -- that text is locale-dependent and a localized git would otherwise
    turn this clean pass into a hard failure.

argv[1]  repo    -- path to the git repository (may be '.', '~/...', or
                     absolute). Steps run in the play's own workspace
                     directory, so a relative path resolves there, not
                     wherever the caller was thinking of -- expected
                     behavior, not a bug; this is exactly the footgun the
                     play's own `repo` parameter description warns about.
argv[2]  depth   -- how many recent commits scan_log will ask git log for

Emits one JSON object on stdout:
    {"ok": true, "repo_abs": "...", "depth": N, "head": "<sha40>"|null,
     "empty_repo": bool, "warning": "..." (only when empty_repo)}
"""

import json
import os
import shutil
import subprocess
import sys

DEPTH_MIN, DEPTH_MAX = 1, 1000
GIT_TIMEOUT_S = 10


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(2)


def main():
    repo_raw = arg(1, ".")
    depth_raw = arg(2, "50")

    if shutil.which("git") is None:
        fail("git not found on PATH")

    repo_abs = os.path.abspath(os.path.expanduser(repo_raw))

    if not os.path.isdir(repo_abs):
        fail("not a directory: " + repo_abs)

    if not os.path.exists(os.path.join(repo_abs, ".git")):
        # Two different situations wear the same symptom here, and only one
        # of them is an error. If the caller PASSED a path and it is not a
        # repository, that is bad input and fails closed, as before. If they
        # passed nothing, `repo` is still its default "." -- which resolves
        # to this play's own workspace and is never a repository -- so the
        # honest answer is not a failure at all, it is "you have not told me
        # which repository to read". Failing hard on that meant the DEFAULT
        # invocation of this published play always ended in red for anyone
        # running it cold from its URI. Depth is still validated first, so a
        # bad depth fails closed either way.
        if repo_raw.strip() in ("", "."):
            try:
                depth_check = int(depth_raw)
            except ValueError:
                fail("depth must be an integer, got: " + depth_raw)
            if depth_check < DEPTH_MIN or depth_check > DEPTH_MAX:
                fail("depth must be between " + str(DEPTH_MIN) + " and " + str(DEPTH_MAX) + ", got: " + str(depth_check))
            print(json.dumps({
                "ok": True,
                "no_repo_given": True,
                "repo_abs": "",
                "depth": depth_check,
                "head": None,
                "warning": "no repository given",
            }))
            return
        fail("not a git repository (no .git found at " + repo_abs + ")")

    try:
        depth = int(depth_raw)
    except ValueError:
        fail("depth must be an integer, got: " + depth_raw)
    if depth < DEPTH_MIN or depth > DEPTH_MAX:
        fail(
            "depth must be between "
            + str(DEPTH_MIN)
            + " and "
            + str(DEPTH_MAX)
            + ", got: "
            + str(depth)
        )

    try:
        tree_proc = subprocess.run(
            ["git", "-C", repo_abs, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail("git failed to run: " + str(exc))
    if tree_proc.returncode != 0 or tree_proc.stdout.strip() != "true":
        fail("not a git working tree: " + (tree_proc.stderr or "").strip()[:200])

    try:
        # `--verify -q` is the locale-independent emptiness probe: it
        # suppresses git's (English) error text and turns "HEAD does not
        # resolve" into a silent, well-defined exit code 1, distinct from
        # every other fatal git error (128 in practice). No stderr string
        # is ever pattern-matched to decide this.
        head_proc = subprocess.run(
            ["git", "-C", repo_abs, "rev-parse", "--verify", "-q", "HEAD"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail("git failed to run: " + str(exc))

    if head_proc.returncode == 0:
        head = head_proc.stdout.strip()
        print(
            json.dumps(
                {
                    "ok": True,
                    "repo_abs": repo_abs,
                    "depth": depth,
                    "head": head,
                    "empty_repo": False,
                }
            )
        )
        return

    if head_proc.returncode == 1:
        # A repo with zero commits is a valid, empty state -- not a
        # failure. Exit 1 from `--verify -q` is specifically "HEAD does
        # not resolve", not a general git error.
        print(
            json.dumps(
                {
                    "ok": True,
                    "repo_abs": repo_abs,
                    "depth": depth,
                    "head": None,
                    "empty_repo": True,
                    "warning": "repository has no commits yet",
                }
            )
        )
        return

    stderr = (head_proc.stderr or "").strip()
    fail("git rev-parse HEAD failed unexpectedly: " + stderr[:200])


main()
