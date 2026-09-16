"""Answer the other half of the drill: what git work exists ONLY on this disk?

This is a bounded, self-contained sweep -- discovery and every per-repo read
live in this one script/step, on purpose, so the play stays a two-root DAG
with no fan-out step in between (see main.ts). Discovery walks base_dir up to
max_depth levels, pruning node_modules and stopping the walk the moment a
repository's .git is found (so its internals are never descended into).

Every git invocation matches the conservative craft of sweep-git-repos:
--no-optional-locks (never takes a lock file), a scrubbed environment
(GIT_TERMINAL_PROMPT=0, LC_ALL=C, inherited GIT_DIR / GIT_WORK_TREE /
GIT_INDEX_FILE stripped), and a per-call timeout bounded by the ONE global
sweep deadline (see "Deadline discipline" below). Nothing is written to any
repository; the only bytes this script produces are the JSON row it prints.

For each repo this reports:
  - unpushed: a single repository-level, deduplicated count of commits
    reachable from ANY local branch (tracked or not) that are not reachable
    from ANY local remote-tracking ref -- `git rev-list --count --branches
    --not --remotes`, run once per repo. This is deliberately not a sum of
    each tracked branch's own "ahead of my upstream" count: summing those
    double-counts commits two branches share, and only ever compares a
    branch against its OWN upstream, so a commit already reachable from a
    second remote (a fork remote, a second push destination, ...) could be
    mislabeled "only on this disk." A single dedup call fixes both. This
    machine has no network access to any remote, so the honest claim is
    "not reachable from a LOCAL remote-tracking ref" -- never "nowhere else
    on earth."
  - local_only_branches: every local branch with NO upstream at all, or one
    whose upstream is [gone] (the remote branch was deleted). Each entry
    carries this play's best per-branch estimate of unique-commit exposure,
    but the repo-level `unpushed` count above -- not a sum of these -- is
    the authoritative loss number. `local_only_branch_count` only counts
    branches with a POSITIVE, successfully-read unique-commit count: a
    local-only branch whose commits are all reachable some other way (fully
    merged into a pushed branch, say) is a housekeeping label, not exposure,
    and is not counted as loss.
  - stashes, dirty: as reported by `stash list` and `status --porcelain=v2`.

Non-git files are never inventoried -- this script only ever looks at
directories that already are git repositories. A single unreadable repo
degrades to a labeled unknown row; git being entirely absent from PATH is the
one essential-capability failure that fails the whole step closed instead,
since no per-repo read could mean anything without it.

Every read this script performs to build a row -- status, stash list, the
repo-level unpushed count, branch enumeration, and each local-only branch's
own unique-commit read -- is REQUIRED: a failure at any of them degrades the
WHOLE repo to a labeled "unknown" row rather than silently defaulting that
one field to zero and calling the rest of the row clean. An unreadable stash
list or an unreadable branch list can hide real exposure; "unknown" is the
only honest answer when any of these reads did not succeed.

Deadline discipline: ONE wall-clock deadline is set before discovery even
starts (a pathologically large base_dir can make os.walk itself slow, and
that time has to come out of the same budget), and every subprocess call
anywhere in this script -- from discovery through the last per-branch read
of the last repo -- is bounded by the time remaining until that deadline,
never by a fixed constant. A read attempted with no time left raises
immediately (no subprocess is even spawned) so a repo out of budget degrades
to "unknown: sweep deadline reached" in well under a second rather than
waiting out a stale fixed timeout. This bounds the WORST case tail (one
already-in-flight subprocess call that started just before the deadline) to
one more GIT_TIMEOUT_S, not an unbounded pile of full-length timeouts across
however many branches a big repo happens to have.

Repos are analyzed with a small bounded thread pool (each repo's own git
calls are independent reads against its own working tree, so running several
repos at once is still read-only and safe). A repo not finished when the
deadline lands is simply left out of the swept count / reported unknown,
never force-included half-read. Python cannot forcibly kill a blocked OS
thread; what actually bounds worst-case wall time here is that every
subprocess call itself carries a `timeout=`, which reliably kills the git
child process and unblocks the thread -- the thread pool shutdown is a
best-effort cleanup on top of that, not the enforcement mechanism.

argv[1]  base directory to sweep (tilde expanded); defaults to ~/Documents
argv[2]  max depth below base to search; clamped to 1..6, defaults to 3

Emits one JSON object on stdout.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

GIT_TIMEOUT_S = 20  # ceiling for any single git call when the deadline allows it
MIN_CALL_TIMEOUT_S = 2  # floor so a call is never attempted with a sub-second budget
DEADLINE_S = 65  # leaves headroom under the step's 90s timeout: worst-case one
# in-flight call can run up to GIT_TIMEOUT_S past this, plus time for I/O + JSON
OUTER_SAFETY_S = DEADLINE_S + GIT_TIMEOUT_S + 5  # last-resort cap on the collection loop
MAX_WORKERS = 6  # matches the max_concurrency ceiling sweep-git-repos uses for its fan-out
MAX_REPOS = 300  # a sanity cap against a pathologically large base_dir
MAX_BRANCHES_PER_REPO = 50  # a sanity cap against a pathologically branchy repo
ERROR_CHARS = 160
LABEL_CHARS = 200

DEFAULT_BASE = "~/Documents"
DEFAULT_DEPTH = 3
MIN_DEPTH = 1
MAX_DEPTH = 6

PRUNED_DIRS = ("node_modules", ".venv", "venv", "__pycache__", "Library", ".Trash")

HOME = os.path.expanduser("~")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact_home(text):
    if not text:
        return text
    return str(text).replace(HOME, "~") if HOME and HOME != "/" else str(text)


def sanitize_label(text, max_len=LABEL_CHARS):
    """Strip control characters from anything user-authored (repo labels,
    branch names) before it reaches JSON/terminal output, and cap length so
    one pathological name can't blow up a step JSON payload."""
    if text is None:
        return text
    cleaned = CONTROL_CHARS_RE.sub("", str(text))
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned


def scrubbed_env():
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    for poison in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(poison, None)
    return env


_ENV = scrubbed_env()


def remaining_time(deadline_at):
    return deadline_at - time.monotonic()


def call_timeout(deadline_at):
    """The timeout for the NEXT subprocess call: bounded above by
    GIT_TIMEOUT_S, bounded below by MIN_CALL_TIMEOUT_S so a call is never
    attempted with an unreasonably small budget once time is short."""
    return max(MIN_CALL_TIMEOUT_S, min(GIT_TIMEOUT_S, remaining_time(deadline_at)))


def require_time(deadline_at, what):
    """Raise BEFORE spawning a subprocess if the deadline has already
    passed, instead of paying for one more (floored) timeout attempt."""
    if remaining_time(deadline_at) <= 0:
        raise RuntimeError("sweep deadline reached before " + what + " could run")


def git(repo, args, deadline_at, what):
    """A required read. Raises RuntimeError (message redacted+capped) on any
    failure -- including running out of the sweep's time budget -- for the
    caller to turn into this repo's "unknown" row."""
    require_time(deadline_at, what)
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo] + args,
            capture_output=True,
            text=True,
            timeout=call_timeout(deadline_at),
            env=_ENV,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(what + " timed out")
    if result.returncode != 0:
        msg = (result.stderr or "").strip()[:ERROR_CHARS] or "git failed"
        raise RuntimeError(redact_home(msg) + " (" + what + ")")
    return result.stdout


def nonempty_lines(text):
    return [line for line in text.splitlines() if line.strip()]


def arg(index, fallback):
    value = sys.argv[index] if len(sys.argv) > index else ""
    return value if value else fallback


def depth_arg(raw):
    try:
        return max(MIN_DEPTH, min(MAX_DEPTH, int(raw)))
    except (TypeError, ValueError):
        return DEFAULT_DEPTH


def is_repo_marker(dirs, files):
    """Matches a directory clone (.git/ is a dir) and a worktree/submodule
    (.git is a file holding a gitdir: pointer)."""
    return ".git" in dirs or ".git" in files


def discover(base, depth, deadline_at):
    """Walks base looking for repositories. Bounded by the SAME deadline
    every git call is bounded by (a pathologically large base_dir can make
    os.walk itself slow, and that time has to come out of one budget, not a
    separate one that starts only once discovery finishes). Returns
    (repos, truncated, reason) where truncated means "not every repository
    under base_dir was found" -- either the MAX_REPOS cap or the deadline."""
    repos = []
    for root, dirs, files in os.walk(base):
        if remaining_time(deadline_at) <= 0:
            return sorted(repos), True, "sweep deadline reached during discovery"
        relative = os.path.relpath(root, base)
        level = 0 if relative == "." else relative.count(os.sep) + 1
        if is_repo_marker(dirs, files):
            repos.append(root)
            dirs[:] = []  # never descend into a found repo -- .git internals included
            if len(repos) >= MAX_REPOS:
                return sorted(repos), True, "MAX_REPOS (" + str(MAX_REPOS) + ") reached during discovery"
            continue
        dirs[:] = [
            d for d in dirs if d not in PRUNED_DIRS and not (d.startswith(".") and d != ".git")
        ]
        if level >= depth:
            dirs[:] = []
    return sorted(repos), False, None


def dirty_count(status_text):
    return sum(1 for line in status_text.splitlines() if line.strip() and not line.startswith("#"))


def parse_branches(repo, deadline_at):
    """Every local branch and its upstream state, from one `for-each-ref`
    call. A REQUIRED read: an unreadable ref list means local-only branch
    exposure cannot be determined, so the caller turns that into this
    repo's "unknown" row rather than reporting zero local-only branches."""
    raw = git(
        repo,
        [
            "for-each-ref",
            "--format=%(refname:short)%09%(upstream:short)%09%(upstream:track)",
            "refs/heads",
        ],
        deadline_at,
        "branch enumeration",
    )
    branches = []
    for line in nonempty_lines(raw):
        parts = line.split("\t")
        name = parts[0] if len(parts) > 0 else ""
        upstream = parts[1] if len(parts) > 1 else ""
        track = parts[2] if len(parts) > 2 else ""
        if not name:
            continue
        branches.append({"name": name, "upstream": upstream, "track": track})
    return branches


def branch_unique_commits(repo, branch_name, deadline_at):
    """Commits reachable from this branch but from no local remote-tracking
    ref -- this branch's own share of "not reachable from a local
    remote-tracking ref." A REQUIRED read: if this can't be determined for a
    local-only branch, this play cannot honestly rule out that it is hiding
    unique commits, so the caller turns that into this repo's "unknown" row
    instead of silently treating an unreadable count as zero."""
    out = git(
        repo,
        ["rev-list", "--count", branch_name, "--not", "--remotes"],
        deadline_at,
        "unique-commit count for branch",
    )
    out = out.strip()
    if not out.isdigit():
        raise RuntimeError("unexpected rev-list output for a local-only branch's unique-commit count")
    return int(out)


def analyze(repo, base_resolved, deadline_at):
    try:
        label = sanitize_label(os.path.relpath(repo, base_resolved))
    except ValueError:
        label = sanitize_label(redact_home(repo))

    row = {
        "path": redact_home(repo),
        "repo": label,
        "unpushed": None,
        "local_only_branches": [],
        "local_only_branch_count": None,
        "local_only_branch_label_count": None,
        "branches_truncated": False,
        "stashes": None,
        "dirty": None,
        "unknown": None,
    }
    try:
        status_text = git(repo, ["status", "--porcelain=v2", "--branch"], deadline_at, "status")
        row["dirty"] = dirty_count(status_text)

        stash_text = git(repo, ["stash", "list"], deadline_at, "stash list")
        row["stashes"] = len(nonempty_lines(stash_text))

        unpushed_text = git(
            repo,
            ["rev-list", "--count", "--branches", "--not", "--remotes"],
            deadline_at,
            "repository-level unpushed count",
        )
        unpushed_text = unpushed_text.strip()
        if not unpushed_text.isdigit():
            raise RuntimeError("unexpected rev-list output for the repository-level unpushed count")
        row["unpushed"] = int(unpushed_text)

        branches = parse_branches(repo, deadline_at)
        if len(branches) > MAX_BRANCHES_PER_REPO:
            branches = branches[:MAX_BRANCHES_PER_REPO]
            row["branches_truncated"] = True

        local_only = []
        for b in branches:
            if b["upstream"] and "[gone]" not in b["track"]:
                continue  # tracked and live -- already inside the repo-level unpushed count above
            state = "gone" if b["upstream"] else "none"
            unique_commits = branch_unique_commits(repo, b["name"], deadline_at)
            local_only.append(
                {
                    "branch": sanitize_label(b["name"]),
                    "unique_commits": unique_commits,
                    "upstream_state": state,
                }
            )

        row["local_only_branches"] = local_only
        row["local_only_branch_label_count"] = len(local_only)
        # Loss, not label: only branches with a positive, successfully-read
        # unique-commit count count as exposure. A local-only branch fully
        # merged into a pushed branch elsewhere is a housekeeping label, not
        # something this laptop is the only copy of.
        row["local_only_branch_count"] = sum(1 for b in local_only if b["unique_commits"] > 0)
    except (RuntimeError, ValueError, subprocess.TimeoutExpired, OSError) as exc:
        row["unknown"] = sanitize_label(redact_home(str(exc)))[:ERROR_CHARS]
    return row


def unknown_row(repo, base_resolved, reason):
    try:
        label = sanitize_label(os.path.relpath(repo, base_resolved))
    except ValueError:
        label = sanitize_label(redact_home(repo))
    return {
        "path": redact_home(repo),
        "repo": label,
        "unpushed": None,
        "local_only_branches": [],
        "local_only_branch_count": None,
        "local_only_branch_label_count": None,
        "branches_truncated": False,
        "stashes": None,
        "dirty": None,
        "unknown": sanitize_label(reason)[:ERROR_CHARS],
    }


def main():
    if not shutil.which("git"):
        sys.stderr.write("sweep_loss: git is not on PATH; cannot read any repository")
        raise SystemExit(1)

    raw_base = arg(1, DEFAULT_BASE)
    requested_depth = arg(2, str(DEFAULT_DEPTH))
    max_depth = depth_arg(requested_depth)
    depth_note = None
    if str(requested_depth) != str(max_depth):
        depth_note = "max_depth clamped from " + str(requested_depth) + " to " + str(max_depth)

    expanded = os.path.expanduser(raw_base)
    if not os.path.isdir(expanded):
        print(
            json.dumps(
                {
                    "ok": True,
                    "base": redact_home(expanded),
                    "max_depth": max_depth,
                    "depth_note": depth_note,
                    "repos_total": 0,
                    "repos_swept": 0,
                    "truncated_by_deadline": False,
                    "truncated_by_repo_cap": False,
                    "rows": [],
                    "warning": "base_dir does not exist or is not a directory: " + redact_home(expanded),
                }
            )
        )
        return

    base_resolved = os.path.realpath(expanded)

    # ONE deadline, started before discovery: a pathologically large
    # base_dir can make os.walk itself slow, and that time comes out of the
    # same budget every git call below is also bounded by.
    deadline_at = time.monotonic() + DEADLINE_S
    repos, discovery_truncated, discovery_reason = discover(base_resolved, max_depth, deadline_at)

    rows = []
    truncated_by_deadline = discovery_reason == "sweep deadline reached during discovery"
    if repos:
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futures = {executor.submit(analyze, repo, base_resolved, deadline_at): repo for repo in repos}
            pending = set(futures.keys())
            outer_deadline_at = time.monotonic() + OUTER_SAFETY_S
            while pending:
                remaining = outer_deadline_at - time.monotonic()
                if remaining <= 0:
                    # Last-resort safety net: should not happen given every
                    # subprocess call above already carries its own
                    # deadline-bounded timeout, but a repo that somehow
                    # never returns must still get a row, not be silently
                    # dropped from repos_swept.
                    truncated_by_deadline = True
                    for future in pending:
                        future.cancel()
                        rows.append(
                            unknown_row(
                                futures[future],
                                base_resolved,
                                "did not complete within the sweep's overall time budget",
                            )
                        )
                    break
                done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
                for future in done:
                    rows.append(future.result())
                    if remaining_time(deadline_at) <= 0:
                        truncated_by_deadline = True
        finally:
            # Straggler threads (past the deadline) are left to finish and
            # exit on their own; this process moves on without waiting on
            # them. Python cannot forcibly kill a blocked OS thread -- what
            # actually bounds their wall time is that every subprocess call
            # inside them carries its own timeout=, which reliably kills the
            # git child process and unblocks the thread. This shutdown call
            # is best-effort cleanup, not the enforcement mechanism.
            executor.shutdown(wait=False, cancel_futures=True)

    repos_total = len(repos)
    repos_swept = len(rows)
    truncated_by_repo_cap = discovery_truncated and not truncated_by_deadline

    warning = None
    if discovery_reason and discovery_reason != "sweep deadline reached during discovery":
        warning = discovery_reason + "; not every repository under base_dir was found"
    if truncated_by_deadline:
        note = "sweep time budget reached before every discovered repository could be fully read"
        warning = (warning + "; " + note) if warning else note

    print(
        json.dumps(
            {
                "ok": True,
                "base": redact_home(base_resolved),
                "max_depth": max_depth,
                "depth_note": depth_note,
                "repos_total": repos_total,
                "repos_swept": repos_swept,
                "truncated_by_deadline": truncated_by_deadline,
                "truncated_by_repo_cap": truncated_by_repo_cap,
                "rows": rows,
                "warning": warning,
            }
        )
    )


main()
