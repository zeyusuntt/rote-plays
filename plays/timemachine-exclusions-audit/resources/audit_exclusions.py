"""Time Machine exclusions are invisible until restore day. This one script
runs BOTH steps of the play (dispatched by argv[1] -- "discover" or "check"),
kept as a single file on purpose: the two jobs share every helper below
(redaction, the shared wall-clock-deadline discipline, the FS/RS packing
convention) and neither job is large enough on its own to justify the extra
indirection of a second file.

JOB 1 -- discover (argv: discover <base_dir> <max_depth>):
Builds the list of paths this play will ask Time Machine about: every
"project dir" found by walking base_dir up to max_depth levels (a directory
qualifies the moment it directly contains one of PROJECT_MARKERS below; the
walk never descends past a match, mirroring the "stop the walk the moment a
repo is found" idiom laptop-loss-drill's sweep_loss.py already established
for git repos specifically), PLUS a fixed list of high-value roots
(~/Documents, ~/Desktop, ~/.ssh, ~/.claude), PLUS "dev dirs found" -- a
probe of common developer-root directory NAMES (~/Developer, ~/dev,
~/Projects, ~/projects, ~/src, ~/Code, ~/code, ~/repos, ~/workspace),
included only when they actually exist on this machine, the same
presence-only philosophy backup_status.py's LINUX_MARKERS probe uses. A
fixed root or dev dir that IS also base_dir itself, or that a project match
already found, is listed once, never twice. base_dir being missing or
unreadable degrades only the project-walk portion (a warning, not a crash)
-- the fixed roots and dev-dir probe are independent of base_dir and still
run. Never opens, reads, or hashes a file inside any discovered directory --
only directory NAMES and the presence of a marker FILE NAME are ever
inspected.

JOB 2 -- check (argv: check <paths_packed> <paths_total>):
For every path job 1 found, reports what this machine can determine about
its Time Machine exclusion status WITHOUT sudo, ever, from three sources:
  1. `tmutil isexcluded <path> ...` -- the authoritative answer, batched
     BATCH_SIZE paths per invocation (bounded concurrency across batches via
     a small thread pool) rather than one subprocess per path; tmutil prints
     one `[Included]`/`[Excluded]`/`[UNKNOWN]` line per path regardless of
     how many share the call. A batch that times out or errors degrades
     EVERY path in that one batch to its own labeled-unknown row -- never
     the whole step -- so "bounded concurrency via batching" still yields a
     per-path degrade.
  2. the sticky per-item xattr some tools and Time Machine's own "Exclude
     these items" UI set on an excluded directory --
     com.apple.metadata:com_apple_backup_excludeItem -- read one path at a
     time via `xattr -p` (also bounded-concurrency, since these calls are
     cheap but there can be up to MAX_PATHS of them); its absence (the
     common case) is read as data, not an error.
  3. the SYSTEM-wide SkipPaths list, read ONCE via
     `defaults export /Library/Preferences/com.apple.TimeMachine -` (parsed
     as a plist -- `defaults` goes through cfprefsd rather than a raw file
     read, which is what makes this readable without sudo even though the
     backing file itself is root-owned and SIP-guarded against a direct
     read); a path matches when it equals or is nested under a configured
     skip prefix. A missing domain or an absent SkipPaths key is the
     common, healthy "nothing configured here" case (not a degrade); a
     command failure, timeout, or unparseable plist degrades ONLY this one
     source to a labeled unknown -- every other check in this run still
     completes.
When `tmutil isexcluded` reports a path Excluded, source (2) and (3) are
consulted, in that order, to LABEL why; when neither source recognizes it,
the path is still reported Excluded, just with exclusion_source "unknown" --
this play never asserts a source it did not itself observe, and its two
readable-without-sudo channels are not exhaustive (see UNVERIFIED in the
emitted `unverified` list).

MACOS-ONLY, stated plainly: both jobs check `platform.system()` first. On
anything other than Darwin, discover skips the walk entirely and check skips
every subprocess call entirely -- both emit `{"ok": true, "platform": ...,
"note": "Time Machine is a macOS system"}` in well under a second, never a
crash, never a partial report pretending to mean something on a system with
no Time Machine.

Deadline discipline mirrors sweep_loss.py: ONE wall-clock deadline is set at
the top of whichever job runs, and every subprocess call after it -- batch
tmutil calls, per-path xattr calls, the one defaults call -- is bounded by
whatever remains of that budget, down to a floor of MIN_CALL_TIMEOUT_S (2s):
a call that begins with less than 2s left is still given the full 2s rather
than an unusably small timeout, so the shared deadline is a target this run
stays close to, not an exact ceiling every individual call obeys -- the
bounded worker pools, the 200-path cap, and the outer step timeouts are what
keep that grace from compounding into an unbounded run. A call attempted
with the deadline already passed (no time left) raises before a subprocess
is even spawned.

This play never sets, removes, or asks tmutil to change ANY exclusion,
against any path it discovers on its own -- write-shaped calls
(`tmutil addexclusion`, `tmutil removeexclusion`, `xattr -w`, `xattr -d`,
`defaults write`) do not appear anywhere in this file. Every helper call
here IS subject to a bounded timeout, though, and Python enforces that
timeout by terminating the child process: a batch tmutil call, a single
xattr -p call, or the one defaults call that overruns its share of the
budget is killed, not asked nicely. That termination only ever degrades the
one call (and, for a tmutil batch, every path in that one batch) to a
labeled unknown row, never the whole step -- and it is only ever aimed at a
helper subprocess this script itself spawned and is still waiting on, never
at anything else.

argv[1]  mode -- "discover" or "check" (required; anything else is a hard
         fault -- bad step wiring, not a legitimate degrade).

discover argv[2]  base_dir, tilde-expanded (default ~/Documents)
discover argv[3]  max_depth, clamped 1..4 (default 2)
discover emits: {"ok": true, "platform": ..., "note": null|str,
    "warning": null|str, "base_display": "~/...", "max_depth": n,
    "paths_total": n, "fixed_roots_found": n, "dev_dirs_found": n,
    "projects_found": n, "truncated": bool,
    "paths_packed": "<FS-joined: path, kind>RS-joined records"}
    kind is one of: root-fixed, root-devdir, project.
    base_display is redacted (see redact_home below); paths_packed is NOT --
    see the note on that field just below.

check argv[2]  paths_packed (from discover, FS/RS as above)
check argv[3]  paths_total (from discover, for reconciling record loss)
check emits: {"ok": true, "platform": ..., "note": null|str,
    "warning": null|str, "paths_total": n, "paths_checked": n,
    "excluded_count": n, "unknown_count": n,
    "system_skip_paths_state": "ok"|"error", "system_skip_paths_count": n,
    "system_skip_paths_detail": null|str, "tmutil_unavailable": bool,
    "excluded_rows": [{path_display, kind, exclusion_source, tmutil_state,
        inherited_from}],
    "unknown_rows": [{path_display, kind, reason}],
    "checked": [...], "unverified": [...]}
    Every *display* field this script emits (path_display in the two row
    lists, base_display in discover, inherited_from when set, and any path
    text folded into a warning/detail string) is redacted by redact_home:
    exactly $HOME becomes "~", and any OTHER account's home-directory
    prefix (/Users/<name> on macOS, /home/<name> on Linux) has that name
    replaced too, so auditing a base_dir that resolves under a different
    account's home on a shared machine does not disclose that account's
    username either. A base_dir path that carries no recognized
    home-directory prefix at all (an external volume, say) is shown in
    full -- the caller supplied that exact path as a parameter, and
    redacting it here would just hide the path this report exists to name.
    paths_packed is the one deliberate exception to all of the above: it is
    this script's internal discover-to-check transport, carrying the raw,
    UNREDACTED absolute path, because check needs the real path to call
    tmutil/xattr/os.path against the filesystem. If a run's step-level
    evidence (stdout, argv) is retained or logged by the runner outside
    this script, that intermediate value can disclose more than the final
    report's redacted display fields do -- redaction here only protects
    what this script itself prints as a human-facing result.

Both jobs always exit 0 once argv itself parses -- every failure mode here
is a labeled degrade, never a crash, because "could not determine" is
itself a correct, useful answer this play is built to give honestly.
"""

import json
import os
import platform
import plistlib
import re
import subprocess
import sys
import time
import xml.parsers.expat
from concurrent.futures import ThreadPoolExecutor

FS, RS = chr(31), chr(30)

HOME = os.path.expanduser("~")

# Matches another account's home-directory prefix -- /Users/<name> on macOS,
# /home/<name> on Linux -- AFTER this script's own $HOME has already been
# replaced with "~" by redact_home below, so anything this still matches
# belongs to some OTHER account, never this one.
OTHER_HOME_RE = re.compile(r"(/Users/|/home/)([^/]+)")

MIN_CALL_TIMEOUT_S = 2.0

# ---- discover job budgets/constants ----------------------------------------
DISCOVER_DEADLINE_S = 12.0  # step timeout is 15s; leaves ~3s for interpreter
# startup, the final combine/dedupe pass, and JSON serialization.
DEFAULT_BASE = "~/Documents"
DEFAULT_DEPTH = 2
MIN_DEPTH, MAX_DEPTH = 1, 4  # (1-4); tmutil per-path calls add up
MAX_PROJECTS = 150  # sanity cap against a pathologically large base_dir
MAX_PATHS = 200  # overall cap on what check_exclusions is asked to process

FIXED_ROOTS = ("~/Documents", "~/Desktop", "~/.ssh", "~/.claude")
# "dev dirs found": common developer-root NAMES, probed for existence only
# (never walked into for markers) -- a stated, documented interpretation of
# "dev dirs found" in this play's spec, the same presence-only philosophy
# backup_status.py's LINUX_MARKERS list already uses for a different job.
DEV_DIR_CANDIDATES = (
    "~/Developer", "~/dev", "~/Projects", "~/projects",
    "~/src", "~/Code", "~/code", "~/repos", "~/workspace",
)
# A directory qualifies as a "project dir" the moment it directly contains
# one of these marker file/dir names -- checked against this one directory's
# own children only, never a deeper scan.
PROJECT_MARKERS = (
    ".git", "package.json", "pyproject.toml", "Cargo.toml",
    "go.mod", "pom.xml", "Gemfile", "composer.json",
)
# Never descended into during the walk, regardless of depth budget --
# matches sweep_loss.py's PRUNED_DIRS philosophy for the same reason (huge,
# noisy, or already-covered-elsewhere subtrees). Hidden directories (name
# starting with ".") are pruned unconditionally by the walk itself, below.
HEAVY_DIRS = ("node_modules", ".venv", "venv", "__pycache__", "Library", ".Trash", "dist", "build", ".cache", ".npm")

# ---- check job budgets/constants -------------------------------------------
CHECK_DEADLINE_S = 75.0  # step timeout is 90s; ~15s headroom for the parts
# above (interpreter start, unpack, final JSON) plus one in-flight call's tail.
TMUTIL_CEILING_S = 20.0  # ceiling for a single tmutil isexcluded batch call
XATTR_CEILING_S = 5.0  # ceiling for a single xattr -p call (should be fast)
DEFAULTS_CEILING_S = 10.0  # ceiling for the one defaults export call
BATCH_SIZE = 20  # paths per tmutil isexcluded invocation
TMUTIL_WORKERS = 4  # bounded concurrency across tmutil batches
XATTR_WORKERS = 8  # bounded concurrency across per-path xattr reads
LINE_RE = re.compile(r"^\[(\w+)\]\s+(.*)$")
ANCESTOR_LOOKUP_MAX_LEVELS = 12  # bound on how far find_inherited_ancestor climbs


def redact_home(text):
    """Never let a raw $HOME path -- or another account's home-directory
    prefix -- leave this script in a *display* field. Exactly $HOME becomes
    '~'; any /Users/<name> or /home/<name> prefix still present afterward
    (so, by construction, some OTHER account's home, since this account's
    own was just replaced) has that name generalized to 'other-user' too --
    auditing a base_dir that resolves under a different account's home on a
    shared machine must not disclose that account's username in this
    report. A path with no recognized home-directory prefix at all (an
    external volume, say) passes through unchanged -- see the module
    docstring's note on why. NOT applied to paths_packed, the internal
    discover->check transport value; see that field's docstring note."""
    if not text:
        return text
    s = str(text)
    if HOME and HOME != "/":
        s = s.replace(HOME, "~")
    return OTHER_HOME_RE.sub(lambda m: m.group(1) + "other-user", s)


def strip_seps(text):
    """Strip the record/field separator bytes this play's siblings use to
    pack collections into a scalar, so a pathological path can never smuggle
    one through and split a downstream field/record."""
    if not isinstance(text, str):
        return text
    return text.replace(FS, "?").replace(RS, "?")


def remaining_time(deadline_at):
    return deadline_at - time.monotonic()


def run(argv, deadline_at, ceiling):
    """A subprocess call bounded by whatever remains of the shared step
    budget, never a fixed per-call constant -- see module docstring."""
    remaining = remaining_time(deadline_at)
    if remaining <= 0:
        raise TimeoutError("no time remaining in step budget")
    timeout = max(MIN_CALL_TIMEOUT_S, min(remaining, ceiling))
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def clamp(value, lo, hi):
    return max(lo, min(hi, value))


def emit(report):
    print(json.dumps(report))


def platform_note():
    """Returns (platform_str, note_or_None). Only Darwin gets a None note --
    every other platform gets the exact, stated, one-line honest note."""
    system_name = platform.system()
    if system_name == "Darwin":
        return "darwin", None
    return (system_name or "unknown").lower(), "Time Machine is a macOS system"


# =============================================================================
# JOB 1 -- discover
# =============================================================================


def parse_discover_args():
    base_raw = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else DEFAULT_BASE
    depth_raw = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "" else str(DEFAULT_DEPTH)
    try:
        depth = int(depth_raw)
    except ValueError:
        sys.stderr.write("max_depth must be an integer, got: " + depth_raw + "\n")
        sys.exit(2)
    depth = clamp(depth, MIN_DEPTH, MAX_DEPTH)
    return base_raw, depth


def walk_projects(base_abs, max_depth, deadline_at):
    """Depth-bounded walk for PROJECT_MARKERS. Stops descending the instant a
    directory matches (never opens its internals), stops descending past
    max_depth levels below base_abs otherwise, and stops the whole walk once
    MAX_PROJECTS is reached or the shared deadline runs out -- either case is
    disclosed via the returned flags, never silently."""
    projects = []
    truncated_by_cap = False
    truncated_by_deadline = False
    base_depth = base_abs.rstrip(os.sep).count(os.sep)
    for root, dirnames, filenames in os.walk(base_abs, topdown=True):
        if remaining_time(deadline_at) <= 0:
            truncated_by_deadline = True
            break
        depth = root.rstrip(os.sep).count(os.sep) - base_depth
        if root != base_abs:
            entries = set(filenames) | set(dirnames)
            if any(m in entries for m in PROJECT_MARKERS):
                projects.append(root)
                dirnames[:] = []  # found a project; never descend into it
                if len(projects) >= MAX_PROJECTS:
                    truncated_by_cap = True
                    break
                continue
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in HEAVY_DIRS]
        if depth >= max_depth:
            dirnames[:] = []
    return projects, truncated_by_cap, truncated_by_deadline


def run_discover():
    system_name, note = platform_note()
    if note:
        emit({"ok": True, "platform": system_name, "note": note, "warning": None,
              "base_display": None, "max_depth": None, "paths_total": 0,
              "fixed_roots_found": 0, "dev_dirs_found": 0, "projects_found": 0,
              "truncated": False, "paths_packed": ""})
        return

    base_raw, max_depth = parse_discover_args()
    base_abs = os.path.abspath(os.path.expanduser(base_raw))
    deadline_at = time.monotonic() + DISCOVER_DEADLINE_S

    warnings = []
    ordered = {}  # abs path -> kind, first registration wins (priority order)

    for root in FIXED_ROOTS:
        abs_path = os.path.abspath(os.path.expanduser(root))
        if os.path.isdir(abs_path) and abs_path not in ordered:
            ordered[abs_path] = "root-fixed"
    fixed_roots_found = len(ordered)

    dev_dirs_found = 0
    for cand in DEV_DIR_CANDIDATES:
        abs_path = os.path.abspath(os.path.expanduser(cand))
        if os.path.isdir(abs_path) and abs_path not in ordered:
            ordered[abs_path] = "root-devdir"
            dev_dirs_found += 1

    projects_found = 0
    truncated = False
    if not os.path.isdir(base_abs):
        warnings.append("base_dir '" + redact_home(base_raw) + "' does not exist or is not a directory; project discovery skipped, fixed roots and dev dirs found are still checked")
    else:
        projects, truncated_by_cap, truncated_by_deadline = walk_projects(base_abs, max_depth, deadline_at)
        projects_found = len(projects)
        for p in projects:
            if p not in ordered:
                ordered[p] = "project"
        if truncated_by_cap:
            truncated = True
            warnings.append("project discovery hit its " + str(MAX_PROJECTS) + "-project cap before finishing the walk")
        if truncated_by_deadline:
            truncated = True
            warnings.append("project discovery hit its time budget before finishing the walk under " + redact_home(base_abs))

    items = list(ordered.items())
    if len(items) > MAX_PATHS:
        # Trim from the project entries only -- fixed roots and dev dirs found
        # are small in count and stay high-value, so they are never dropped.
        kept, dropped = [], 0
        for path, kind in items:
            if kind == "project" and len([1 for p2, k2 in kept if k2 == "project"]) >= (MAX_PATHS - fixed_roots_found - dev_dirs_found):
                dropped += 1
                continue
            kept.append((path, kind))
        items = kept
        truncated = True
        warnings.append(str(dropped) + " project path(s) dropped past the " + str(MAX_PATHS) + "-path overall cap")

    records = []
    for path, kind in items:
        records.append(strip_seps(path) + FS + kind)
    packed = RS.join(records)

    emit({
        "ok": True,
        "platform": system_name,
        "note": None,
        "warning": "; ".join(warnings) if warnings else None,
        "base_display": redact_home(base_abs),
        "max_depth": max_depth,
        "paths_total": len(items),
        "fixed_roots_found": fixed_roots_found,
        "dev_dirs_found": dev_dirs_found,
        "projects_found": projects_found,
        "truncated": truncated,
        "paths_packed": packed,
    })


# =============================================================================
# JOB 2 -- check
# =============================================================================


def unpack_paths(packed, expected_total):
    if not packed:
        return [], 0
    records = packed.split(RS)
    parsed = []
    dropped = 0
    for rec in records:
        fields = rec.split(FS)
        if len(fields) != 2:
            dropped += 1
            continue
        path, kind = fields
        if not path:
            dropped += 1
            continue
        parsed.append((path, kind))
    return parsed, dropped


def read_system_skip_paths(deadline_at):
    """`defaults export` reads the real system domain via cfprefsd (readable
    without sudo even though the backing plist file itself is root-owned and
    SIP-guarded against a direct read). A missing domain or an absent
    SkipPaths key is the common, healthy "nothing configured" case -- state
    "ok" with an empty list, never a degrade."""
    if remaining_time(deadline_at) <= 0:
        return {"state": "error", "paths": [], "detail": "skipped: no time remaining in step budget"}
    try:
        result = run(["defaults", "export", "/Library/Preferences/com.apple.TimeMachine", "-"], deadline_at, DEFAULTS_CEILING_S)
    except subprocess.TimeoutExpired:
        return {"state": "error", "paths": [], "detail": "defaults export timed out"}
    except (subprocess.SubprocessError, OSError, TimeoutError) as exc:
        return {"state": "error", "paths": [], "detail": "could not run defaults export: " + redact_home(str(exc))[:120]}
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()[:160]
        return {"state": "error", "paths": [], "detail": redact_home(stderr) if stderr else "defaults export exited " + str(result.returncode)}
    try:
        data = plistlib.loads(result.stdout.encode("utf-8"))
    except (ValueError, TypeError, xml.parsers.expat.ExpatError):
        # plistlib.InvalidFileException is a ValueError subclass and is
        # caught by that branch; truncated/malformed XML plist text can
        # also escape straight to expat's own ExpatError, which is not a
        # ValueError -- caught explicitly here so one malformed plist
        # degrades only this SkipPaths source, never the whole check.
        return {"state": "error", "paths": [], "detail": "defaults export did not return a readable plist"}
    if not isinstance(data, dict):
        return {"state": "error", "paths": [], "detail": "unexpected plist shape (root is not a dict)"}
    raw = data.get("SkipPaths")
    if raw is None:
        return {"state": "ok", "paths": [], "detail": None}
    if not isinstance(raw, list):
        return {"state": "error", "paths": [], "detail": "SkipPaths present but not a list"}
    clean = [str(p) for p in raw if isinstance(p, str) and p]
    return {"state": "ok", "paths": clean, "detail": None}


def matches_skip_path(path, skip_paths):
    for sp in skip_paths:
        stripped = sp.rstrip("/")
        if not stripped:
            continue
        if path == stripped or path.startswith(stripped + "/"):
            return True
    return False


def check_xattr(path, deadline_at):
    """Returns (state, present, detail). present is True/False/None; None
    only when this script could not determine it (a real read error, or the
    path vanishing between discover and check)."""
    if remaining_time(deadline_at) <= 0:
        return "error", None, "skipped: no time remaining in step budget"
    try:
        result = run(["xattr", "-p", "com.apple.metadata:com_apple_backup_excludeItem", path], deadline_at, XATTR_CEILING_S)
    except subprocess.TimeoutExpired:
        return "error", None, "xattr -p timed out"
    except (subprocess.SubprocessError, OSError, TimeoutError) as exc:
        return "error", None, "could not run xattr -p: " + redact_home(str(exc))[:120]
    if result.returncode == 0:
        return "ok", True, None
    stderr_low = (result.stderr or "").strip().lower()
    if "no such xattr" in stderr_low:
        return "ok", False, None
    if "no such file" in stderr_low:
        return "error", None, "path no longer exists at check time"
    detail = (result.stderr or "").strip()[:160]
    return "error", None, redact_home(detail) if detail else "xattr -p exited " + str(result.returncode)


def find_inherited_ancestor(path, deadline_at):
    """tmutil reports every descendant of a sticky-excluded directory as
    Excluded too, but the sticky xattr itself is only ever set on the
    ancestor that carries the actual exclusion rule -- each such descendant
    would otherwise be mislabeled exclusion_source "unknown" instead of
    naming the one ancestor rule that actually accounts for it. Called only
    for a path tmutil reports Excluded whose own item has neither the
    sticky xattr nor a system SkipPaths match. Walks up from the path's
    parent, read-only, re-using check_xattr's own `xattr -p` probe one
    ancestor at a time, and returns the first ancestor found with the
    xattr present, redacted for display, or None if none was found before
    hitting a boundary: the filesystem root, $HOME itself (this play does
    not want to report "your whole home directory is excluded" as an
    inherited-from label), ANCESTOR_LOOKUP_MAX_LEVELS climbed, or the
    shared step deadline running out. Never writes or removes anything."""
    current = os.path.dirname(path.rstrip(os.sep))
    levels = 0
    while current and current != os.path.dirname(current) and levels < ANCESTOR_LOOKUP_MAX_LEVELS:
        if current == HOME or remaining_time(deadline_at) <= 0:
            break
        state, present, _detail = check_xattr(current, deadline_at)
        levels += 1
        if state == "ok" and present is True:
            return redact_home(current)
        current = os.path.dirname(current)
    return None


def run_tmutil_batch(paths, deadline_at):
    """One tmutil isexcluded call for a batch of paths. Returns (states, err)
    where states maps INPUT path -> "Included"/"Excluded"/"UNKNOWN" on
    success, and err is set (states is None) when the whole batch call
    itself failed, OR when its output could not be safely correlated to the
    inputs -- either way the caller degrades every path in that one batch to
    its own unknown row, never the whole step.

    tmutil echoes back the path it resolved, which is not always
    byte-identical to the path this script asked about -- macOS can
    canonicalize a symlinked path (for example /tmp -> /private/tmp).
    Matching lines to inputs by that echoed text against the original input
    string would silently turn a valid answer into a false unknown for
    every such path. tmutil prints exactly one status line per input path,
    in input order (the observed, documented behavior for this call), so
    lines are matched to inputs by POSITION instead, regardless of what
    path text tmutil echoed back. If the parsed line count does not match
    the input count, positional correlation is not safe -- the whole batch
    is reported as a correlation failure rather than guessing which line
    belongs to which input."""
    if remaining_time(deadline_at) <= 0:
        return None, "no time remaining in step budget"
    try:
        result = run(["tmutil", "isexcluded"] + list(paths), deadline_at, TMUTIL_CEILING_S)
    except subprocess.TimeoutExpired:
        return None, "tmutil isexcluded batch timed out"
    except (subprocess.SubprocessError, OSError, TimeoutError) as exc:
        return None, "could not run tmutil isexcluded: " + redact_home(str(exc))[:120]
    # tmutil's exit code is not trusted for isexcluded either (backup_status.py
    # documents the same caution for latestbackup) -- parsed from stdout text.
    statuses = []
    for line in (result.stdout or "").splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        statuses.append(m.group(1))
    if len(statuses) != len(paths):
        return None, (
            "tmutil isexcluded returned " + str(len(statuses)) + " status line(s) for "
            + str(len(paths)) + " path(s) asked in this batch -- positional correlation "
            "is not safe, so every path in this batch is reported unknown rather than guessed"
        )
    return dict(zip(paths, statuses)), None


def run_check():
    system_name, note = platform_note()
    if note:
        emit({"ok": True, "platform": system_name, "note": note, "warning": None,
              "paths_total": 0, "paths_checked": 0, "excluded_count": 0,
              "unknown_count": 0, "system_skip_paths_state": None,
              "system_skip_paths_count": 0, "system_skip_paths_detail": None,
              "tmutil_unavailable": False, "excluded_rows": [], "unknown_rows": [],
              "checked": [], "unverified": []})
        return

    packed = sys.argv[2] if len(sys.argv) > 2 else ""
    try:
        expected_total = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "" else None
    except ValueError:
        sys.stderr.write("paths_total must be an integer, got: " + sys.argv[3] + "\n")
        sys.exit(2)

    parsed, dropped = unpack_paths(packed, expected_total)
    warnings = []
    if dropped:
        warnings.append(str(dropped) + " malformed path record(s) dropped")
    if expected_total is not None and expected_total != len(parsed) + dropped:
        warnings.append("discover reported " + str(expected_total) + " path(s) but " + str(len(parsed) + dropped) + " record(s) were received")

    deadline_at = time.monotonic() + CHECK_DEADLINE_S

    skip = read_system_skip_paths(deadline_at)

    xattr_results = {}
    if parsed:
        with ThreadPoolExecutor(max_workers=XATTR_WORKERS) as pool:
            futures = {pool.submit(check_xattr, path, deadline_at): path for path, _ in parsed}
            for fut, path in futures.items():
                xattr_results[path] = fut.result()

    tmutil_states = {}
    tmutil_batch_errors = {}  # path -> reason, for paths whose whole batch failed
    all_paths = [p for p, _ in parsed]
    batches = [all_paths[i:i + BATCH_SIZE] for i in range(0, len(all_paths), BATCH_SIZE)]
    if batches:
        with ThreadPoolExecutor(max_workers=TMUTIL_WORKERS) as pool:
            futures = {pool.submit(run_tmutil_batch, b, deadline_at): b for b in batches}
            for fut, batch in futures.items():
                states, err = fut.result()
                if states is None:
                    for p in batch:
                        tmutil_batch_errors[p] = err
                else:
                    tmutil_states.update(states)

    excluded_rows = []
    unknown_rows = []
    excluded_count = 0
    unknown_count = 0
    # "Checked" = asked of tmutil, i.e. included in a dispatched batch call --
    # every parsed path is, since batches partition all of them up front. A
    # batch that itself failed still counts its paths as asked (just with an
    # unusable answer), never silently dropped from this count.
    paths_checked = len(parsed)

    for path, kind in parsed:
        display = redact_home(path)
        if path in tmutil_batch_errors:
            unknown_count += 1
            unknown_rows.append({"path_display": display, "kind": kind, "reason": tmutil_batch_errors[path]})
            continue
        state = tmutil_states.get(path, "UNKNOWN")
        if state == "Excluded":
            excluded_count += 1
            xattr_state, xattr_present, _xattr_detail = xattr_results.get(path, ("error", None, "xattr not attempted"))
            inherited_from = None
            if xattr_present is True:
                source = "sticky-xattr"
            elif skip["state"] == "ok" and matches_skip_path(path, skip["paths"]):
                source = "system"
            else:
                # Neither readable-without-sudo source recognizes this exact
                # item -- before giving up and labeling it "unknown", check
                # whether an ancestor carries the sticky xattr: tmutil marks
                # every descendant of a sticky-excluded directory Excluded
                # too, so this is very often one ancestor rule, not an
                # independent exclusion on this path specifically.
                ancestor = find_inherited_ancestor(path, deadline_at)
                if ancestor:
                    source = "inherited-sticky-xattr"
                    inherited_from = ancestor
                else:
                    source = "unknown"
            excluded_rows.append({
                "path_display": display, "kind": kind, "exclusion_source": source,
                "tmutil_state": state, "inherited_from": inherited_from,
            })
        elif state == "Included":
            continue
        else:
            unknown_count += 1
            unknown_rows.append({"path_display": display, "kind": kind, "reason": "tmutil reported " + state})

    # "Unavailable" (distinct from a clean bill): every single path that WAS
    # asked of tmutil (paths_checked > 0) came back UNKNOWN or errored -- i.e.
    # tmutil never gave one usable Included/Excluded answer this run. Ties to
    # laptop-loss-drill's own backup-not-configured state; see UNVERIFIED.
    definitively_answered = sum(1 for path, _ in parsed if tmutil_states.get(path) in ("Included", "Excluded") and path not in tmutil_batch_errors)
    tmutil_unavailable = paths_checked > 0 and definitively_answered == 0

    checked = []
    checked.append(str(paths_checked) + " of " + str(len(parsed)) + " discovered path(s) were asked of tmutil isexcluded")
    checked.append("sticky per-item exclusion xattr (com.apple.metadata:com_apple_backup_excludeItem) read on every discovered path, no sudo")
    if skip["state"] == "ok":
        checked.append("system SkipPaths list read via defaults export /Library/Preferences/com.apple.TimeMachine, no sudo (" + str(len(skip["paths"])) + " configured prefix(es))")
    else:
        checked.append("system SkipPaths list could not be read this run: " + str(skip["detail"]))
    checked.append(
        "excluded_count/excluded_rows count AFFECTED paths, not independent exclusion rules -- when an "
        "ancestor directory carries the sticky exclusion xattr, tmutil reports every path beneath it "
        "Excluded too; this run looks up that ancestor (read-only, no sudo) for any excluded path whose "
        "own item lacks both readable-without-sudo signals, and labels it exclusion_source "
        "\"inherited-sticky-xattr\" with inherited_from set, rather than counting it as its own rule"
    )

    unverified = [
        "whether Time Machine is even running, has ever completed a backup, or has a destination configured at all -- run laptop-loss-drill for that (cross-reference by name)",
        "any exclusion mechanism this play cannot read without sudo -- these are the only two readable-without-sudo sources this play knows about",
        "directories not discovered by this run's base_dir walk, fixed-root list, or dev-dir probe",
        "whether a path reported Included is actually being backed up right now (only that Time Machine's own exclusion check does not exclude it)",
    ]

    emit({
        "ok": True,
        "platform": system_name,
        "note": None,
        "warning": "; ".join(warnings) if warnings else None,
        "paths_total": len(parsed),
        "paths_checked": paths_checked,
        "excluded_count": excluded_count,
        "unknown_count": unknown_count,
        "system_skip_paths_state": skip["state"],
        "system_skip_paths_count": len(skip["paths"]),
        "system_skip_paths_detail": skip["detail"],
        "tmutil_unavailable": tmutil_unavailable,
        "excluded_rows": excluded_rows,
        "unknown_rows": unknown_rows,
        "checked": checked,
        "unverified": unverified,
    })


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "discover":
        run_discover()
    elif mode == "check":
        run_check()
    else:
        sys.stderr.write("unknown mode (expected 'discover' or 'check'), got: " + repr(mode) + "\n")
        sys.exit(2)


if __name__ == "__main__":
    # Guarded so test_audit_exclusions.py can import this module (to exercise
    # its functions directly, with subprocess/platform mocked) without also
    # triggering a real run against this process's own argv -- `python3
    # audit_exclusions.py <mode> ...`, the only way rote's step ever invokes
    # this file, still sets __name__ == "__main__" and behaves exactly as
    # before.
    main()
