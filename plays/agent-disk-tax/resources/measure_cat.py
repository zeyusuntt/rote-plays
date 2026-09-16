"""Measure ONE disk-tax category discovered by discover_cats.py -- a
for_each fan-out item, so each category gets its own time budget in its own
process (one huge or slow category, e.g. a multi-GB ~/.claude/projects,
can never block or starve another).

argv[1]  the discovered category as JSON (one element of discover_cats.py's
         "items" array, arriving as $item -- rote passes an object
         fan-out element to a script as one compact-JSON argv string):
         {"category": str, "roots": [str, ...]}. "roots" arrives in the
         same HOME-relative tilde form discover_cats.py emitted it in
         ("~/.codex") -- this script re-expands each with
         os.path.expanduser, which resolves back to the identical real
         path because it runs on the SAME machine, in the SAME
         `rote play run` invocation, that discover_cats.py just ran on.
argv[2]  per_category_seconds -- the TOTAL time budget for this whole
         category (shared across every one of its roots, not per-root);
         clamped to [5, 120], default 20 on anything unparsable.
argv[3]  top_files -- how many of this category's largest files to keep;
         clamped to [1, 10], default 3 on anything unparsable.
argv[4]  show_full_transcript_paths -- opt-in flag ("true"/"1"/"yes",
         case-insensitive; anything else, including absent, is false).
         See "Path projection" below.

Root existence, at measurement time: each root is re-probed with the same
three-way classification discover_cats.py uses ("present" / "not-found" /
"inaccessible" / "rejected-symlink"), duplicated here rather than imported
because each resource script in this play runs standalone via
`python3 <script>.py`, never imported. This is a deliberate TOCTOU
defense, not paranoia for its own sake: discover_cats.py and this script
run as SEPARATE processes/steps, so a root that was a real directory when
discovered could in principle be swapped for a symlink by the time this
step actually walks it; re-checking here means that swap is rejected here
too, not just trusted from the earlier step's say-so. A permission error
reads as "inaccessible", never folded into "not-found" ("vanished") the
way a bare os.path.isdir would.

Walk mechanics: a manual directory stack over os.scandir (no `du`
dependency, stdlib only), one root at a time, against a single shared
monotonic deadline. os.walk was deliberately NOT used here: it fully reads
and sorts a directory's entire entry list into dirnames/filenames before
it ever yields that directory's tuple, so a single pathologically large
directory could already blow past the requested budget before this
script's own deadline check runs again. Walking with os.scandir's live
iterator instead lets every single entry be checked against the deadline
as it is consumed, which is a much tighter bound -- though still not an
absolute one: a single slow syscall against a hung network mount could
still stall past the deadline before the next check runs, the same
residual soft edge any syscall-based walker has. A permission error
opening a directory, or stat'ing one entry, is caught and tallied in that
root's io error count -- that directory/entry is simply not counted,
never a crash -- and never surfaced as raw OS text (see the description's
trust line). A filesystem entry that is itself a symlink is counted in
neither size nor file_count and is never followed, whether it points at a
file or a directory -- a symlinked file's target may already be counted
elsewhere in the same walk, and a symlinked directory is never descended
into, so this walk cannot loop on a symlink cycle and cannot escape the
root it was given.

Hard-link dedup: every regular file's (st_dev, st_ino) is tracked in a
set shared across every ROOT of this one category (not shared with any
other category -- each runs in its own process). The first path seen for
a given inode is counted normally; every later path hard-linked to that
same inode is skipped for both size_bytes and largest_files, and tallied
in "hardlinks_deduped_within_category" -- content-addressable caches
(this play's own npm-npx-cache and uv-cache categories, notably) commonly
hard-link the same blob under multiple names, and counting it once per
name would inflate the reported total well past its real disk cost.
This is DISCLOSED, not exhaustive: the same inode hard-linked into a
DIFFERENT category's root (a much rarer arrangement) is NOT deduplicated
across the category boundary, since categories are measured in separate
processes with no shared state -- each category's number remains an
honest, independent measurement, but the GRAND total across categories
can still double-count a file hard-linked into two different category
trees. main.ts's footer discloses this scope explicitly.

Deadline honesty (no silent truncation): the monotonic deadline is checked
before opening each root and before processing each directory entry. The
moment it passes, this script stops walking immediately -- whatever was
already counted stands, root by root, and status is set to "partial"
(deadline hit mid-root) or "skipped-deadline" (deadline had already
passed before this root was even opened) rather than "complete". A root
that finished its walk but hit one or more I/O errors along the way
(permission denied on a subdirectory, a file that vanished mid-stat) is
labeled "partial-io" rather than "complete", since whatever was skipped
is unknown, not zero. Any category where at least one root is "partial",
"skipped-deadline", "partial-io", "inaccessible", or "rejected-symlink"
sets top-level "partial": true and a "partial_note" explaining every
contributing reason and stating that the true size is AT LEAST the
reported figure -- this script would rather under-report with a label
than either silently truncate, silently drop an unreadable root, or block
forever on a category too large for its budget. A root that simply does
not exist any more ("not-found") is NOT partial -- zero is the honest,
complete answer for a root that is genuinely gone, not a lower bound.

Largest-files math is EXACT, not approximate, even though only the top
`top_files` files per ROOT are kept in memory: the top `top_files` files
for the whole CATEGORY is the same value merged from each root's own top
`top_files` list and re-sorted, because a file cannot be in a category's
global top K without also being in its own root's top K (if more than K
files in the same root were larger, it would already be outside the
category's global top K too). This only holds for roots that finished
walking cleanly -- a "partial"/"skipped-deadline"/"partial-io" root's
largest_files can miss its own true largest file if that file lived in an
unwalked (or unreadable) part of the tree; the caller is expected to treat
a partial category's largest-files list as a lower bound, same as its
size.

Path projection: every path this script prints (largest-file paths, the
echoed root labels) has this machine's home directory replaced with "~"
-- home-redaction is applied at the point of emission, not left to a
downstream presentation layer, so nothing this script writes to stdout
(or to a fixture captured from it) ever carries the local username. This
is two layers, not one: redact_home strips the home directory as a path
PREFIX; scrub_strings then runs over the whole result and additionally
scrubs the bare username wherever it appears as a substring anywhere else
in the text -- needed because a tool can embed an absolute path inside a
directory NAME rather than a leading path segment (see redact_username's
docstring for the real example this was written for: Claude Code's own
transcript folder naming). That same folder-naming scheme is a THIRD leak
a prefix-and-username strip does not close: a claude-transcripts session
directory encodes the whole original working directory, project name
included ("-Users-<name>-Documents-<project>"), which is more than a
username -- it is exactly the kind of detail that should not end up in a
Discord post or a shared screenshot just because someone ran this play.
So the claude-transcripts category's largest_files list defaults to
FILENAME ONLY (os.path.basename, no directory component at all) unless
show_full_transcript_paths is explicitly set; every other category is
unaffected, since this specific leak is a property of Claude Code's own
directory-naming convention, not of category roots generally. The row's
"path_projection" field ("basename-only" or "full") always states which
mode was used, and roots_redacted / root_details (the category's own
configured root, e.g. "~/.claude/projects") are never projected -- those
are fixed, known locations already disclosed in CHECKED, not per-project
detail.

This is a best-effort, optional-capability job (a directory this user owns
being unreadable in parts is normal, not exceptional), so it degrades
rather than fails: a malformed $item, or any unexpected exception while
walking, is reported as "ok": false with a short fixed reason code and
this script still exits 0, so one bad category never sinks the sibling
categories running alongside it in the fan-out. The one case treated as an
essential-capability failure -- this script was not given an item at all --
writes to stderr and exits 1, since there is nothing useful this script can
report without it.

Emits one JSON object on stdout:
    {
      "ok": true,
      "category": str,
      "roots_redacted": [str, ...],
      "size_bytes": int, "file_count": int,
      "oldest_mtime": ISO-8601 or null, "newest_mtime": ISO-8601 or null,
      "largest_files": [{"path_redacted", "size_bytes", "mtime"}, ...],
      "top_files_requested": int,
      "path_projection": "basename-only" or "full",
      "partial": bool, "partial_note": str or null,
      "budget_seconds": int, "elapsed_seconds": float,
      "io_errors": int,   # total across every root
      "hardlinks_deduped_within_category": int,
      "roots_vanished": [str, ...],       # existed at discovery, gone by now
      "roots_inaccessible": [str, ...],   # permission denied, not "vanished"
      "roots_rejected_symlink": [str, ...],
      "root_details": [
        {"root_redacted", "size_bytes", "file_count",
         "oldest_mtime", "newest_mtime", "status", "io_errors"}, ...
      ],
      "error": null
    }
"root_details" is what lets the presentation layer list the agent-worktrees
category as one row per worktree directory (size + mtime, no judgment) --
every other category simply aggregates it away into the totals above.
"""

import heapq
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
_HOME_BASENAME = os.path.basename(HOME.rstrip(os.sep)) if HOME not in ("", os.sep) else None

MIN_BUDGET_S, MAX_BUDGET_S, DEFAULT_BUDGET_S = 5, 120, 20
MIN_TOP_FILES, MAX_TOP_FILES, DEFAULT_TOP_FILES = 1, 10, 3
ERROR_MAX_CHARS = 160

# A file's own st_mtime landing inside this window (the Unix epoch's first
# calendar day) is never a real per-user modification date -- it is the
# fingerprint of a reproducible-build/packaging tool pinning mtimes to (or
# just past) epoch zero, observed in practice under both ~/.codex and
# ~/.rote's own vendored plugin caches. Treated as an unavailable
# timestamp, never as a fact ("this file is from 1970"), both when
# tracking a root's own oldest/newest mtime and when rendering any mtime
# to ISO text.
MIN_PLAUSIBLE_MTIME_EPOCH_S = 86400

TRANSCRIPTS_CATEGORY = "claude-transcripts"
TRUE_STRINGS = {"true", "1", "yes", "y", "on"}


def parse_int_clamped(raw, lo, hi, default):
    """Never raises: an unparsable value falls back to `default`; any
    parsable integer is clamped into [lo, hi], never trusted verbatim."""
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        return default
    return max(lo, min(hi, value))


def parse_bool_flag(raw):
    """Never raises: anything other than a recognized true-ish token
    (case-insensitive) -- including an absent argv[4] -- is false. Fails
    closed toward the more private default, never the more exposing one."""
    return isinstance(raw, str) and raw.strip().lower() in TRUE_STRINGS


def redact_home(path):
    """Replace this machine's home-directory PREFIX with '~' in one path.
    Applied to every real filesystem path this script emits. This alone is
    not sufficient -- see redact_username/scrub_strings below for the
    embedded-username case a prefix strip cannot catch."""
    if not isinstance(path, str):
        return path
    if path == HOME:
        return "~"
    if path.startswith(HOME + os.sep):
        return "~" + path[len(HOME):]
    return path


def redact_username(text):
    """Best-effort scrub of the bare local username wherever it appears as
    a SUBSTRING in a string -- not just as a path prefix. Needed because
    some tools embed an absolute path, username included, inside a
    directory NAME rather than a leading path segment -- observed for real
    in this play's own claude-transcripts category: Claude Code's
    ~/.claude/projects/<cwd-with-slashes-as-dashes>/ session-folder naming
    puts "-Users-<username>-..." inside the folder name itself, which
    redact_home's prefix strip never touches since it is not a prefix of
    the walked path there, ~/.claude/projects IS. Defensive, not
    exhaustive, the same tradeoff every other redaction helper in this
    play family makes: no word-boundary matching, so a username that also
    happens to be a short, common substring of unrelated text could
    over-redact. Deliberately does NOT touch project/file names beyond the
    username itself -- this play's whole job is telling you which project
    is large, so scrubbing project names would defeat its purpose (see
    "Path projection" above for the one deliberate, opt-out exception:
    claude-transcripts file paths specifically, where the project name
    lives in the ENCLOSING directory name this script strips to basename
    by default)."""
    if not isinstance(text, str) or not _HOME_BASENAME:
        return text
    return text.replace(_HOME_BASENAME, "<redacted-user>")


def scrub_strings(value):
    """Recursively apply redact_username to every string leaf of a
    JSON-shaped structure. Run once, last, on the whole result object
    right before it is serialized, so no individual field can slip
    through un-scrubbed just because a new one is added here later."""
    if isinstance(value, str):
        return redact_username(value)
    if isinstance(value, list):
        return [scrub_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub_strings(v) for k, v in value.items()}
    return value


def iso(epoch_seconds):
    if epoch_seconds is None or epoch_seconds < MIN_PLAUSIBLE_MTIME_EPOCH_S:
        return None
    try:
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def emit(obj):
    """The single exit point for everything this script prints -- every
    call site funnels through scrub_strings here, so a field added at any
    call site later is covered automatically rather than relying on each
    call site to remember to scrub itself."""
    print(json.dumps(scrub_strings(obj)))


def probe_root_state(real_root):
    """Classify a root at measurement time into "present" / "not-found" /
    "inaccessible" / "rejected-symlink", mirroring discover_cats.py's
    probe_root (duplicated rather than imported -- this script runs
    standalone). This is the TOCTOU defense described in the module
    docstring: discovery already rejects symlink roots, but measurement
    runs as a separate step afterward, so this re-checks rather than
    trusting the earlier step's say-so. Never raises. Uses os.lstat
    directly, NOT os.path.islink/isdir -- both of those wrap a bare
    try/except OSError internally and return False on ANY error including
    permission-denied, which would make "inaccessible" unreachable and
    silently fold it back into "not-found", the exact bug this function
    exists to close."""
    try:
        st = os.lstat(real_root)
    except FileNotFoundError:
        return "not-found"
    except OSError:
        return "inaccessible"
    if stat.S_ISLNK(st.st_mode):
        return "rejected-symlink"
    return "present" if stat.S_ISDIR(st.st_mode) else "not-found"


def walk_root(root_display, deadline, top_n, seen_inodes):
    """Walk one root (received in tilde form, expanded here to a real path)
    until either its tree is exhausted or `deadline` (a time.monotonic()
    timestamp shared across every root in this category) passes. Never
    raises -- every failure mode below degrades this one root's status
    rather than aborting the category. `seen_inodes` is a set of
    (st_dev, st_ino) shared across every root of this SAME category (see
    module docstring's "Hard-link dedup"); mutated in place. Returns a
    dict; see module docstring's "root_details" shape for the fields that
    survive to stdout (this internal dict additionally carries
    "top_files" as raw (size, path, mtime) tuples, "hardlinks_deduped",
    and "errors", all consumed by main() and never printed directly)."""
    real_root = os.path.expanduser(root_display)

    if time.monotonic() >= deadline:
        return {
            "root": root_display, "size_bytes": 0, "file_count": 0,
            "oldest_mtime": None, "newest_mtime": None, "top_files": [],
            "status": "skipped-deadline", "errors": 0, "hardlinks_deduped": 0,
        }

    root_state = probe_root_state(real_root)
    if root_state != "present":
        # "not-found": existed at discovery, gone (or replaced by a
        # non-directory) by the time this fan-out item actually ran.
        # "inaccessible": a permission error prevented even lstat'ing it.
        # "rejected-symlink": swapped for a symlink between discovery and
        # measurement -- see probe_root_state's docstring.
        return {
            "root": root_display, "size_bytes": 0, "file_count": 0,
            "oldest_mtime": None, "newest_mtime": None, "top_files": [],
            "status": root_state, "errors": 0, "hardlinks_deduped": 0,
        }

    size_bytes = 0
    file_count = 0
    oldest_mtime = None
    newest_mtime = None
    heap = []  # min-heap of (size, path, mtime); heap[0] is the current smallest kept
    errors = 0
    hardlinks_deduped = 0
    hit_deadline = False

    stack = [real_root]
    while stack:
        if time.monotonic() >= deadline:
            hit_deadline = True
            break
        dirpath = stack.pop()
        try:
            scanner = os.scandir(dirpath)
        except OSError:
            errors += 1
            continue
        try:
            for entry in scanner:
                # Checked before every single entry, not once per
                # directory -- see module docstring's "Walk mechanics"
                # for why os.walk's own per-directory granularity is not
                # tight enough for a hard budget.
                if time.monotonic() >= deadline:
                    hit_deadline = True
                    break
                try:
                    is_symlink = entry.is_symlink()
                except OSError:
                    errors += 1
                    continue
                if is_symlink:
                    # Never counted, never followed -- a symlinked file's
                    # target may already be counted elsewhere in the same
                    # walk, and a symlinked directory could otherwise
                    # loop or escape this root entirely.
                    continue
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    errors += 1
                    continue
                if is_dir:
                    stack.append(entry.path)
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    errors += 1
                    continue
                if not stat.S_ISREG(st.st_mode):
                    # Socket/device/FIFO etc: never counted.
                    continue
                inode_key = (st.st_dev, st.st_ino)
                if inode_key in seen_inodes:
                    hardlinks_deduped += 1
                    continue
                seen_inodes.add(inode_key)
                size = st.st_size
                mtime = st.st_mtime
                size_bytes += size
                file_count += 1
                # A file still counts toward size_bytes/file_count above
                # even when its own mtime is an implausible near-epoch
                # sentinel (see MIN_PLAUSIBLE_MTIME_EPOCH_S) -- only the
                # oldest/newest DATE tracking skips it, so one packaged
                # asset with a pinned build timestamp cannot make an
                # entire root's genuinely-dated history report as 1970.
                if mtime >= MIN_PLAUSIBLE_MTIME_EPOCH_S:
                    if oldest_mtime is None or mtime < oldest_mtime:
                        oldest_mtime = mtime
                    if newest_mtime is None or mtime > newest_mtime:
                        newest_mtime = mtime
                fentry = (size, entry.path, mtime)
                if len(heap) < top_n:
                    heapq.heappush(heap, fentry)
                elif size > heap[0][0]:
                    heapq.heapreplace(heap, fentry)
        finally:
            scanner.close()
        if hit_deadline:
            break

    top_files = sorted(heap, key=lambda e: e[0], reverse=True)
    status = "partial" if hit_deadline else ("partial-io" if errors > 0 else "complete")
    return {
        "root": root_display,
        "size_bytes": size_bytes,
        "file_count": file_count,
        "oldest_mtime": oldest_mtime,
        "newest_mtime": newest_mtime,
        "top_files": top_files,
        "status": status,
        "errors": errors,
        "hardlinks_deduped": hardlinks_deduped,
    }


def project_path(real_path, category, show_full_paths):
    """Path shown for one largest-file entry. See module docstring's "Path
    projection": claude-transcripts defaults to filename-only, since its
    enclosing directory name is where Claude Code embeds the original
    project path; every other category is shown with normal home-redacted
    paths, unaffected."""
    if category == TRANSCRIPTS_CATEGORY and not show_full_paths:
        return os.path.basename(real_path)
    return redact_home(real_path)


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        sys.stderr.write("measure_cat: missing category item argv\n")
        raise SystemExit(1)

    budget_s = parse_int_clamped(
        sys.argv[2] if len(sys.argv) > 2 else "", MIN_BUDGET_S, MAX_BUDGET_S, DEFAULT_BUDGET_S
    )
    top_n = parse_int_clamped(
        sys.argv[3] if len(sys.argv) > 3 else "", MIN_TOP_FILES, MAX_TOP_FILES, DEFAULT_TOP_FILES
    )
    show_full_paths = parse_bool_flag(sys.argv[4] if len(sys.argv) > 4 else "")

    try:
        item = json.loads(sys.argv[1])
        if not isinstance(item, dict):
            raise ValueError("item is not a JSON object")
        category = item.get("category")
        roots = item.get("roots")
        if not isinstance(category, str) or not category:
            raise ValueError("item.category missing or not a string")
        if not isinstance(roots, list) or not roots:
            raise ValueError("item.roots missing or empty")
    except (ValueError, TypeError) as exc:
        emit(
            {
                "ok": False,
                "category": None,
                "roots_redacted": [],
                "size_bytes": 0,
                "file_count": 0,
                "oldest_mtime": None,
                "newest_mtime": None,
                "largest_files": [],
                "top_files_requested": top_n,
                "path_projection": "full",
                "partial": False,
                "partial_note": None,
                "budget_seconds": budget_s,
                "elapsed_seconds": 0.0,
                "io_errors": 0,
                "hardlinks_deduped_within_category": 0,
                "roots_vanished": [],
                "roots_inaccessible": [],
                "roots_rejected_symlink": [],
                "root_details": [],
                "error": ("malformed-item:%s" % type(exc).__name__)[:ERROR_MAX_CHARS],
            }
        )
        return

    try:
        start = time.monotonic()
        deadline = start + budget_s

        seen_inodes = set()
        root_details = []
        for root in roots:
            if not isinstance(root, str) or not root:
                continue
            root_details.append(walk_root(root, deadline, top_n, seen_inodes))

        size_bytes = sum(d["size_bytes"] for d in root_details)
        file_count = sum(d["file_count"] for d in root_details)
        total_io_errors = sum(d["errors"] for d in root_details)
        total_hardlinks_deduped = sum(d["hardlinks_deduped"] for d in root_details)
        oldest_candidates = [d["oldest_mtime"] for d in root_details if d["oldest_mtime"] is not None]
        newest_candidates = [d["newest_mtime"] for d in root_details if d["newest_mtime"] is not None]
        oldest_mtime = min(oldest_candidates) if oldest_candidates else None
        newest_mtime = max(newest_candidates) if newest_candidates else None

        all_top = []
        for d in root_details:
            all_top.extend(d["top_files"])
        all_top.sort(key=lambda e: e[0], reverse=True)
        largest_files = [
            {
                "path_redacted": project_path(p, category, show_full_paths),
                "size_bytes": s,
                "mtime": iso(m),
            }
            for (s, p, m) in all_top[:top_n]
        ]

        elapsed = time.monotonic() - start
        budget_hit_roots = [d for d in root_details if d["status"] in ("partial", "skipped-deadline")]
        io_error_roots = [d for d in root_details if d["status"] == "partial-io"]
        unreadable_roots = [d for d in root_details if d["status"] in ("inaccessible", "rejected-symlink")]
        partial = bool(budget_hit_roots or io_error_roots or unreadable_roots)
        pct_of_budget = round(min(100.0, (elapsed / budget_s) * 100), 1) if budget_s > 0 else 100.0

        note_parts = []
        if budget_hit_roots:
            note_parts.append(
                "measured %s%% of the %ss time budget before the deadline -- %d of %d root(s) did not finish walking"
                % (pct_of_budget, budget_s, len(budget_hit_roots), len(root_details))
            )
        if io_error_roots:
            note_parts.append(
                "%d I/O error(s) across %d root(s) (permission denied or a file vanished mid-walk) were skipped, not counted"
                % (total_io_errors, len(io_error_roots))
            )
        if unreadable_roots:
            note_parts.append(
                "%d root(s) could not be read at all (permission denied or rejected as a symlink)"
                % len(unreadable_roots)
            )
        partial_note = (
            ("true size is AT LEAST %d bytes -- " % size_bytes) + "; ".join(note_parts)
            if partial
            else None
        )

        emit(
            {
                "ok": True,
                "category": category,
                "roots_redacted": roots,
                "size_bytes": size_bytes,
                "file_count": file_count,
                "oldest_mtime": iso(oldest_mtime),
                "newest_mtime": iso(newest_mtime),
                "largest_files": largest_files,
                "top_files_requested": top_n,
                "path_projection": (
                    "basename-only"
                    if category == TRANSCRIPTS_CATEGORY and not show_full_paths
                    else "full"
                ),
                "partial": partial,
                "partial_note": partial_note,
                "budget_seconds": budget_s,
                "elapsed_seconds": round(elapsed, 2),
                "io_errors": total_io_errors,
                "hardlinks_deduped_within_category": total_hardlinks_deduped,
                "roots_vanished": [d["root"] for d in root_details if d["status"] == "not-found"],
                "roots_inaccessible": [d["root"] for d in root_details if d["status"] == "inaccessible"],
                "roots_rejected_symlink": [
                    d["root"] for d in root_details if d["status"] == "rejected-symlink"
                ],
                "root_details": [
                    {
                        "root_redacted": d["root"],
                        "size_bytes": d["size_bytes"],
                        "file_count": d["file_count"],
                        "oldest_mtime": iso(d["oldest_mtime"]),
                        "newest_mtime": iso(d["newest_mtime"]),
                        "status": d["status"],
                        "io_errors": d["errors"],
                    }
                    for d in root_details
                ],
                "error": None,
            }
        )
    except Exception as exc:  # pragma: no cover -- last-resort degrade, never a crash
        emit(
            {
                "ok": False,
                "category": category,
                "roots_redacted": roots if isinstance(roots, list) else [],
                "size_bytes": 0,
                "file_count": 0,
                "oldest_mtime": None,
                "newest_mtime": None,
                "largest_files": [],
                "top_files_requested": top_n,
                "path_projection": "full",
                "partial": False,
                "partial_note": None,
                "budget_seconds": budget_s,
                "elapsed_seconds": 0.0,
                "io_errors": 0,
                "hardlinks_deduped_within_category": 0,
                "roots_vanished": [],
                "roots_inaccessible": [],
                "roots_rejected_symlink": [],
                "root_details": [],
                "error": ("internal-exception:%s" % type(exc).__name__)[:ERROR_MAX_CHARS],
            }
        )


if __name__ == "__main__":
    main()
