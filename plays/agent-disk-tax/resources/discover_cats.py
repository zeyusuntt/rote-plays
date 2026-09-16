"""Discover which of a FIXED set of agent-tooling disk categories exist on
THIS machine, so measure_cat.py only fans out over roots that are actually
there.

Read-only: this script never walks a filesystem tree and never lists an
arbitrary directory to go looking for new categories. It only checks a
fixed, well-known table of candidate paths (all HOME-relative) with a
single os.lstat per candidate (see probe_root below), plus one narrow,
disclosed exception for the agent-worktrees category (see below). A category with more than one
candidate root (e.g. playwright-browsers checks both the macOS and Linux
cache locations) is INCLUDED as soon as at least one candidate exists;
"roots" then carries only the candidates that actually exist, never the
ones that do not.

  claude-transcripts    ~/.claude/projects
  claude-other          ~/.claude/{file-history,paste-cache,
                          shell-snapshots,debug} -- named subdirectories
                          only, never a walk of ~/.claude itself (which
                          would also catch claude-transcripts' own
                          ~/.claude/projects)
  codex                 ~/.codex
  rote                  ~/.rote
  playwright-browsers   ~/Library/Caches/ms-playwright, ~/.cache/ms-playwright
  uv-cache              ~/Library/Caches/uv, ~/.cache/uv
  npm-npx-cache         ~/.npm/_npx, ~/.npm/_cacache
  ollama-models         ~/.ollama
  lmstudio              ~/.cache/lm-studio, ~/.lmstudio
  huggingface           ~/.cache/huggingface
  agent-worktrees       ~/.claude-worktrees, plus any TOP-LEVEL entry
                          directly under ~/.claude whose name contains
                          "worktree" (case-insensitive) -- the one
                          dynamic check this script makes, and it is a
                          single non-recursive os.listdir of ~/.claude,
                          never a walk. Judgment-free: this category is
                          reported as a plain list of directories with
                          their sizes and modification times downstream,
                          never labeled stale/orphan/dead here.

Every path this script EMITS (in "items" and "checked") is HOME-
relative in tilde form ("~/.codex", never "/Users/<name>/.codos") -- these
are fixed, well-known locations from the table above, so tilde form loses
no information a reader needs, and it keeps this script's own stdout (and
any fixture captured from it) free of the local username by construction.
Real, expanded paths exist only transiently inside this process to call
os.path.isdir/os.listdir; measure_cat.py re-expands the same tilde strings
with os.path.expanduser on ITS OWN run of the same machine, in the same
`rote play run` invocation, which resolves back to the identical real path.
As a second, defensive layer against the one DYNAMIC, user-controlled
candidate below (a worktree directory NAME under ~/.claude, which -- unlike
every fixed-table entry above -- could theoretically contain the username
as a substring), "checked" and "skipped" additionally pass through
scrub_strings, which replaces the bare local username wherever it appears
as a substring, not only as a path prefix -- see measure_cat.py's
redact_username docstring for the real leak this pattern was written to
close (Claude Code's own transcript folder naming embeds a whole absolute
path, username included, inside a directory name). "items" is the one
deliberate exception: it is wiring, not a report -- the exact roots
measure_cat.py's for_each fans out over and re-expands with
os.path.expanduser on this same machine -- main.ts's presentation layer
reads only its length and each entry's category NAME (for counts and the
STAGES ledger), never the root paths inside it, the same trust boundary
mcp-context-tax draws around its own internal-only exec_store field.

Discovery has no essential capability to fail on -- a category whose root
cannot be stat'd (permission error, unexpected filesystem state) is simply
reported as not existing, never a crash -- so this script always exits 0
and always emits a JSON object with "ok": true.

A candidate root is REJECTED (never counted as existing, never handed to
measure_cat.py) in two cases, both defending the "never a filesystem walk
outside the fixed table" claim above:

  * it is itself a symlink. os.path.isdir follows symlinks, so a bare
    isdir check would accept a symlink pointing anywhere on this machine
    -- including into another category's own tree (double-counting it) or
    somewhere never disclosed as part of this play's scan scope. This
    matters most for the one DYNAMIC candidate, a worktree-named entry
    under ~/.claude, since that name (and therefore its target) is not
    something this script's own fixed table controls. lstat, never stat:
    this looks at the path itself, not what it points to.
  * its canonicalized (realpath) form equals, contains, or is contained
    by a root some EARLIER category in the fixed table already claimed.
    Fixed-table categories are checked in table order and always win;
    agent-worktrees (the one category with a dynamic, user-influenced
    candidate) is appended last, so it can never shadow or re-enter a
    fixed category's tree even without a symlink involved (e.g. an
    ancestor path component, not the root itself, being a symlink).
    Rejections here are reported in "overlap_rejections", not silently
    dropped.

A permission error partway through either check reads as "inaccessible",
distinct from "not-found" (see check_category), so a real access problem
is never silently reported as "this category does not exist on this
machine".

Emits one JSON object on stdout:
    {
      "ok": true,
      "generated_at": ISO-8601 UTC,
      "items": [{"category": str, "roots": [str, ...]}, ...],
      "checked": [
        {"category": str, "candidate_roots": [str, ...],
         "existing_roots": [str, ...], "inaccessible_roots": [str, ...],
         "rejected_symlink_roots": [str, ...], "included": bool},
        ...
      ],
      "count": N,
      "skipped": [category, ...],   # candidate roots checked, none existed
      "overlap_rejections": [{"category", "root", "reason"}, ...]
    }
"items" carries only included categories (existing_roots non-empty) --
this is exactly the array measure_cat.py's for_each fans out over, named
"items" per this pipeline's canonical fan-out contract (first depends_on
source exposes ".items"). "checked" carries every category this script
looked for, included or not, for an honest CHECKED/UNVERIFIED footer
downstream.
"""

import json
import os
import stat
import sys
from datetime import datetime, timezone

FIXED_CATEGORIES = [
    ("claude-transcripts", ["~/.claude/projects"]),
    (
        "claude-other",
        [
            "~/.claude/file-history",
            "~/.claude/paste-cache",
            "~/.claude/shell-snapshots",
            "~/.claude/debug",
        ],
    ),
    ("codex", ["~/.codex"]),
    ("rote", ["~/.rote"]),
    ("playwright-browsers", ["~/Library/Caches/ms-playwright", "~/.cache/ms-playwright"]),
    ("uv-cache", ["~/Library/Caches/uv", "~/.cache/uv"]),
    ("npm-npx-cache", ["~/.npm/_npx", "~/.npm/_cacache"]),
    ("ollama-models", ["~/.ollama"]),
    ("lmstudio", ["~/.cache/lm-studio", "~/.lmstudio"]),
    ("huggingface", ["~/.cache/huggingface"]),
]

WORKTREE_CATEGORY = "agent-worktrees"
WORKTREE_NAME_MATCH = "worktree"  # case-insensitive substring, top-level only

HOME = os.path.expanduser("~")
_HOME_BASENAME = os.path.basename(HOME.rstrip(os.sep)) if HOME not in ("", os.sep) else None


def redact_username(text):
    """Best-effort scrub of the bare local username wherever it appears as
    a substring in a string. See measure_cat.py's identically-named
    helper for the full rationale and the real leak this pattern closes;
    duplicated here rather than shared because each resource script in
    this play runs standalone via `python3 <script>.py`, never imported."""
    if not isinstance(text, str) or not _HOME_BASENAME:
        return text
    return text.replace(_HOME_BASENAME, "<redacted-user>")


def scrub_strings(value):
    """Recursively apply redact_username to every string leaf of a
    JSON-shaped structure. Run once, last, on the whole result object."""
    if isinstance(value, str):
        return redact_username(value)
    if isinstance(value, list):
        return [scrub_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub_strings(v) for k, v in value.items()}
    return value


def probe_root(path):
    """Classify one expanded candidate root path into exactly one of:
      "present"          -- a real directory, not itself a symlink.
      "not-found"        -- does not exist (or is some other non-dir type).
      "inaccessible"      -- a permission error prevented even lstat'ing it;
                             distinct from "not-found" so a real access
                             problem is never silently reported as "this
                             category is absent from this machine".
      "rejected-symlink" -- exists but IS a symlink; os.path.isdir would
                             follow it, which could escape the disclosed
                             fixed-table scan scope (see module docstring).
    Never raises. Uses os.lstat directly, NOT os.path.islink/isdir --
    both of those wrap a bare try/except OSError internally and return
    False on ANY error including permission-denied, which would make
    "inaccessible" unreachable and silently fold it back into
    "not-found", the exact bug this function exists to close."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "not-found"
    except OSError:
        return "inaccessible"
    if stat.S_ISLNK(st.st_mode):
        return "rejected-symlink"
    return "present" if stat.S_ISDIR(st.st_mode) else "not-found"


def canonical_path(path):
    """Realpath of an accepted root, used only for the cross-category
    overlap guard below. Symlink roots are already rejected before this is
    ever called (probe_root), so this only resolves symlinks that might
    appear in an ANCESTOR path component -- still worth resolving so two
    categories that reach the same real directory via different textual
    paths cannot both claim it. Falls back to the input path on error
    rather than raising."""
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def paths_overlap(a, b):
    """True if canonical path `a` equals `b`, or one is an ancestor of the
    other -- the only ways two category roots could ever see the same
    file during a walk."""
    if a == b:
        return True
    return a.startswith(b + os.sep) or b.startswith(a + os.sep)


def worktree_candidates():
    """~/.claude-worktrees plus any top-level ~/.claude entry whose name
    contains "worktree" (case-insensitive). A single non-recursive
    os.listdir -- never a walk -- and any error reading ~/.claude itself
    (missing, permission denied) degrades to "no dynamic candidates found"
    rather than failing this script. Every name-matched entry is added as
    a CANDIDATE regardless of its type (directory, symlink, plain file) --
    classification (present / not-found / inaccessible / rejected-symlink)
    is check_category's job, not this function's, precisely so a symlink
    masquerading as a worktree directory shows up in "checked" as a named,
    explicit rejected_symlink_roots entry rather than being filtered out
    here where a reader would never see it happened at all."""
    candidates = ["~/.claude-worktrees"]
    claude_dir = os.path.expanduser("~/.claude")
    try:
        entries = os.listdir(claude_dir)
    except OSError:
        entries = []
    for name in sorted(entries):
        if WORKTREE_NAME_MATCH in name.lower():
            candidates.append("~/.claude/" + name)
    return candidates


def check_category(category, candidate_roots):
    existing, inaccessible, rejected_symlink = [], [], []
    for root in candidate_roots:
        state = probe_root(os.path.expanduser(root))
        if state == "present":
            existing.append(root)
        elif state == "inaccessible":
            inaccessible.append(root)
        elif state == "rejected-symlink":
            rejected_symlink.append(root)
        # "not-found" contributes to none of the three lists
    return {
        "category": category,
        "candidate_roots": candidate_roots,
        "existing_roots": existing,
        "inaccessible_roots": inaccessible,
        "rejected_symlink_roots": rejected_symlink,
        "included": len(existing) > 0,
    }


def reject_cross_category_overlaps(checked):
    """Second, defensive layer beyond per-root symlink rejection: walk the
    already-checked table IN ORDER (fixed categories first, the one
    dynamic agent-worktrees category last) and drop any existing_roots
    entry whose canonical path equals, contains, or is contained by a root
    an EARLIER category already claimed. Mutates each checked entry's
    existing_roots/included in place. Returns the list of rejections for
    an honest report, never a silent drop."""
    claimed = []  # [(canonical_path, category), ...]
    rejections = []
    for c in checked:
        surviving = []
        for root in c["existing_roots"]:
            canon = canonical_path(os.path.expanduser(root))
            conflict = next((cc for cc in claimed if paths_overlap(canon, cc[0])), None)
            if conflict:
                rejections.append(
                    {
                        "category": c["category"],
                        "root": root,
                        "reason": "overlaps-%s" % conflict[1],
                    }
                )
                continue
            claimed.append((canon, c["category"]))
            surviving.append(root)
        c["existing_roots"] = surviving
        c["included"] = len(surviving) > 0
    return rejections


def main():
    table = list(FIXED_CATEGORIES)
    table.append((WORKTREE_CATEGORY, worktree_candidates()))

    checked = [check_category(name, roots) for name, roots in table]
    overlap_rejections = reject_cross_category_overlaps(checked)
    items = [
        {"category": c["category"], "roots": c["existing_roots"]}
        for c in checked
        if c["included"]
    ]
    skipped = [c["category"] for c in checked if not c["included"]]

    result = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "items": items,  # wiring only, deliberately not scrubbed -- see module docstring
        "checked": scrub_strings(checked),
        "count": len(items),
        "skipped": scrub_strings(skipped),
        "overlap_rejections": scrub_strings(overlap_rejections),
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
