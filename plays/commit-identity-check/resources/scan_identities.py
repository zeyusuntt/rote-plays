"""Resolve the EXACT git identity the NEXT commit would use in every repo
discover_repos.py found -- and flag the three ways that identity can bite
you. commit-attribution-guard (this play's identity-hygiene sibling) audits
what already landed in history; this step never looks at what already
happened except for one narrow, disclosed exception (recent author emails,
see below) -- its main job is entirely forward-looking.

IDENTITY RESOLUTION, never re-derived by hand: for each repo, this runs
exactly `git config --show-origin --show-scope --get user.name` / `...
user.email` with NO --local/--global/--system scope flag of its own, so git
itself walks its real precedence chain -- system, global, any
includeIf.gitdir section whose condition matches THIS repo's own path
(spliced in at the point global config is read), then the repository's own
local config, each later file overriding the earlier one -- and returns the
one value that would actually be used. --show-origin/--show-scope report
which file and which scope produced that winning value; this script only
ever reads and reports those two fields, it never re-implements git's own
conditional-include matching. Needs git 2.26+ for --show-scope (see
deps.toml).

CONDITIONAL-INCLUDE AWARENESS: once per run (not per repo -- this is
global-scope, repository-independent information), `git config --global
--get-regexp '^includeif\\.'` lists every includeIf CONDITION configured
(e.g. "gitdir:~/work/") -- this is names only, per this play's spec: it
never opens or reads the config file any of those conditions points at.
That target file's content is only ever read indirectly, when some specific
discovered repo's own path happens to match the condition, through the
identity-resolution git call above -- never here, and never for a condition
that no discovered repo actually triggers.

DRIFT CHECK, the one narrow exception to "forward-looking only": for every
repo with commits, `git log --first-parent -5 --format=%ae` reads the
author email (never the subject, never the body -- author identity only)
of up to the last 5 commits ON THIS BRANCH'S OWN LINE OF DESCENT --
--first-parent deliberately excludes merged-in side-branch commits and
survives a rebase (which rewrites authors, not the mainline shape) so the
sample always reflects who has actually been committing in THIS checkout,
never a foreign author dragged in by a merge. If NONE of them match the
identity just resolved above, that is the just-changed-jobs trap made
visible: recent history was written under one email, but the next commit
would silently use a different one. An empty repository (HEAD does not
resolve -- detected the same locale-independent way
commit-attribution-guard/validate.py does, via `rev-parse --verify -q
HEAD`'s exit code, never by matching git's own English error text) has no
history to compare against and is never flagged for drift. If the HEAD
probe itself fails in some OTHER way (neither 0 nor 1 -- a corrupt repo, a
permissions problem, git crashing), or the log read fails after HEAD
resolved cleanly, that failure reason is preserved and the repo is marked
drift_unverified rather than silently counted as a clean, drift-free scan.

FLAGS, three independent conditions per repo:
  - no identity configured anywhere: user.name or user.email resolved to
    nothing at any scope. The next commit here would fail outright (with
    user.useConfigOnly set) or fall back to git's own guessed
    login@hostname identity with a warning -- neither is a configured
    identity this play can vouch for.
  - suspect: this repo's resolved email differs from the DOMINANT email
    among its SIBLINGS -- every other discovered repo sharing the same
    immediate parent directory. Conservative by construction: a parent
    directory needs at least 2 repos with a resolved email to have a
    sibling group at all, and a group only HAS a dominant email when one
    email's count strictly exceeds every other email's count in that same
    group -- a tie (including every repo disagreeing 1-for-1) has no
    dominant email and flags nothing, per this play's "-suspect, never a
    certainty" language: this is a mismatch worth a look, not proof a repo
    is misconfigured.
  - drift: see DRIFT CHECK above.
A repo can carry more than one flag at once (e.g. no identity AND, once one
is later configured, would still need a fresh drift read).

DRIFT-UNVERIFIED, a data-quality caveat rather than a fourth flag: a repo
whose identity resolved fine (the essential job succeeded) but whose HEAD
probe returned something other than "commits" or a clean "empty" (an
unexpected rev-parse exit code) or whose --first-parent log read itself
failed. This is reported separately, with the failure reason preserved,
rather than folded silently into either "drift: false" (which would
overclaim the comparison happened) or an UNKNOWN row (which would
overclaim the identity itself is in doubt).

DEGRADE DISCIPLINE: every git call here is READ-ONLY, --no-optional-locks
(never takes a lock file), and run with a scrubbed environment
(GIT_TERMINAL_PROMPT=0, LC_ALL=C, inherited GIT_DIR/GIT_WORK_TREE/
GIT_INDEX_FILE stripped) -- the same conservative craft laptop-loss-drill's
sweep_loss.py already established. The identity-resolution reads (name,
email) are this repo's ESSENTIAL job: if either one errors (not merely
absent -- an absence is a clean, expected "not configured" result; an
error is git failing to run, timing out, or exiting unexpectedly) the
WHOLE repo degrades to an "unknown" row, never silently reported as
identity-less. The drift read is best-effort on top of an already-resolved
identity: if it fails, that repo simply carries no drift evidence, with its
own note -- it never turns an otherwise-successful identity resolution into
an unknown row. ONE wall-clock deadline covers every git call in this
script, from the includeIf listing through the last repo's drift read, the
same deadline-discipline sweep_loss.py established: a call attempted with
no time left raises immediately (no subprocess spawned) rather than paying
for one more timeout. A deadline hit during the best-effort drift portion
of an already-identity-resolved repo degrades that repo to
drift_unverified, never to a lost row; a deadline hit before a queued
repo's essential identity reads ever started (or any other unexpected
failure escaping analyze_repo) is caught per-future and degrades that ONE
repo to an "unknown" row -- it never propagates out and aborts the rest of
the sweep. git being entirely absent from PATH is the one
essential-capability failure that fails this whole step closed -- no
per-repo read could mean anything without it.

argv[1]  packed absolute repo paths from discover_repos (chr(30)-joined;
         empty string is a valid "nothing discovered" input)
argv[2]  repos_total from discover_repos -- the record count this step
         reconciles its own unpacked count against, so a packed value that
         silently lost rows in transit is caught and warned about rather
         than read as "discover_repos found nothing" (gotcha: every
         packed-collection consumer in this fleet reconciles against a
         declared count)
argv[3]  base_dir -- the SAME raw parameter discover_repos received;
         resolved independently here (expanduser + realpath is a pure,
         deterministic function of the same input, so two independent
         resolutions of the same string always agree) purely to compute
         each repo's human-facing relative label -- never to re-walk
         anything.

Emits one JSON object on stdout, always exit 0 once argv parses:
    {"ok": true,
     "warning": "..."|null,
     "totals": {"repos_total": N, "repos_scanned": N, "unknown_count": N,
                "distinct_emails": N, "no_identity_count": N,
                "suspect_count": N, "drift_count": N,
                "drift_unverified_count": N},
     "identity_groups": [{"email": "...", "repo_count": N,
                           "scopes": ["global", "local", ...]}, ...],
     "flags": {"no_identity": [...], "suspect": [...], "drift": [...],
               "drift_unverified": [...], "unknown": [...]},
     "includeif_patterns": ["gitdir:~/work/", ...],
     "includeif_warning": "..."|null}
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

FS, RS = chr(31), chr(30)

GIT_TIMEOUT_S = 8  # ceiling for any single git call when the deadline allows it
MIN_CALL_TIMEOUT_S = 1  # floor so a call is never attempted with a sub-second budget
DEADLINE_S = 45  # leaves headroom under this step's 60s timeout_ms
OUTER_SAFETY_S = DEADLINE_S + GIT_TIMEOUT_S + 5
MAX_WORKERS = 6  # matches sweep_loss.py's concurrency ceiling
MAX_REPOS = 500  # defensive mirror of discover_repos.py's own cap
ERROR_CHARS = 160
LABEL_CHARS = 200
MAX_RECENT_COMMITS = 5
MAX_FLAG_SHOWN = 200  # display cap per flag bucket; totals report the true count

HOME = os.path.expanduser("~")
# Every C0 control INCLUDING tab/newline/CR (a config value or path can
# legitimately contain any byte a filesystem allows), the DEL and C1
# control range, and the Unicode bidi/formatting controls (zero-width
# space/joiners, left-to-right/right-to-left marks and embedding/override/
# isolate codepoints, word joiner, BOM/ZWNBSP) that could otherwise spoof
# terminal columns or lines once a repo label or email-derived string is
# interpolated into a single-line render downstream in main.ts.
CONTROL_CHARS_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)


def redact_home(text):
    if not text:
        return text
    return str(text).replace(HOME, "~") if HOME and HOME != "/" else str(text)


def sanitize_label(text, max_len=LABEL_CHARS):
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
    return max(MIN_CALL_TIMEOUT_S, min(GIT_TIMEOUT_S, remaining_time(deadline_at)))


def require_time(deadline_at, what):
    if remaining_time(deadline_at) <= 0:
        raise RuntimeError("sweep deadline reached before " + what + " could run")


def arg(index, fallback=""):
    value = sys.argv[index] if len(sys.argv) > index else ""
    return value if value else fallback


def oneline(text, max_len=ERROR_CHARS):
    """Collapse a (possibly multi-line) stderr message to one line before it
    goes in a JSON field or a single-row terminal render -- git's own error
    text sometimes carries a leading warning line plus a fatal line."""
    collapsed = " ".join((text or "").split())
    return collapsed[:max_len]


def label_for(path, base_resolved):
    try:
        rel = os.path.relpath(path, base_resolved)
        return sanitize_label(rel)
    except ValueError:
        return sanitize_label(redact_home(path))


def unpack_repos(packed):
    """Returns (repo_paths, raw_record_count) -- see module docstring's
    argv[2] note for why the caller reconciles the two."""
    if not packed:
        return [], 0
    raw_record_count = 0
    repos = []
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        repos.append(record)
    return repos, raw_record_count


def list_includeif_patterns(deadline_at):
    """Once per run: the includeIf CONDITIONS configured in the global git
    config -- names only, never the target file's own path or contents.
    See module docstring's CONDITIONAL-INCLUDE AWARENESS section. Absence
    of any includeIf section is a clean, expected result (exit 1), not a
    degrade."""
    require_time(deadline_at, "includeIf listing")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "config", "--global", "--get-regexp", r"^includeif\."],
            capture_output=True,
            text=True,
            timeout=call_timeout(deadline_at),
            env=_ENV,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], "includeIf listing unavailable: " + str(exc)
    if proc.returncode == 1:
        return [], None
    if proc.returncode != 0:
        return [], "includeIf listing unavailable: git config exited " + str(proc.returncode) + ": " + oneline(proc.stderr)

    patterns = []
    seen = set()
    for line in proc.stdout.splitlines():
        if not line:
            continue
        key = line.split(" ", 1)[0]
        low = key.lower()
        if not low.startswith("includeif.") or not low.endswith(".path"):
            continue  # not an includeIf.<condition>.path key -- e.g. a stray includeif.* variant this script does not know
        condition = key[len("includeif."):-len(".path")]
        label = sanitize_label(redact_home(condition))
        if label not in seen:
            seen.add(label)
            patterns.append(label)
    return patterns[:MAX_FLAG_SHOWN], None


def read_identity_field(repo_abs, field, deadline_at):
    """Returns {"value", "scope", "origin", "warning"} for user.<field>.
    warning is None both when the value resolved AND when it is cleanly
    absent (exit 1) -- only an actual read failure sets it. See module
    docstring's IDENTITY RESOLUTION section."""
    require_time(deadline_at, field + " resolution")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo_abs, "config", "--show-origin", "--show-scope", "--get", "user." + field],
            capture_output=True,
            text=True,
            timeout=call_timeout(deadline_at),
            env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return {"value": None, "scope": None, "origin": None, "warning": field + " read timed out"}
    except OSError as exc:
        return {"value": None, "scope": None, "origin": None, "warning": "git failed to run: " + str(exc)}

    if proc.returncode == 1:
        return {"value": None, "scope": None, "origin": None, "warning": None}
    if proc.returncode != 0:
        msg = oneline(proc.stderr) or "git config failed"
        return {"value": None, "scope": None, "origin": None, "warning": "git config exited " + str(proc.returncode) + ": " + msg}

    first_line = proc.stdout.split("\n", 1)[0]
    parts = first_line.split("\t", 2)
    if len(parts) != 3:
        return {"value": None, "scope": None, "origin": None, "warning": "unexpected git config --show-origin/--show-scope output shape"}
    scope, origin, value = parts
    origin_clean = origin[len("file:"):] if origin.startswith("file:") else origin
    return {
        "value": sanitize_label(value, max_len=254),
        "scope": scope or None,
        "origin": sanitize_label(redact_home(origin_clean)),
        "warning": None,
    }


def head_state(repo_abs, deadline_at):
    """Returns (state, reason): state is "commits", "empty", or "unknown";
    reason is None unless state is "unknown", in which case it is the
    preserved failure detail -- never silently dropped, see module
    docstring's DRIFT-UNVERIFIED section. Mirrors validate.py's
    locale-independent emptiness probe exactly: `rev-parse --verify -q
    HEAD`'s exit code alone, 0 vs 1, never git's own English error text."""
    require_time(deadline_at, "HEAD check")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo_abs, "rev-parse", "--verify", "-q", "HEAD"],
            capture_output=True,
            text=True,
            timeout=call_timeout(deadline_at),
            env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return "unknown", "HEAD check timed out"
    except OSError as exc:
        return "unknown", "git failed to run: " + str(exc)
    if proc.returncode == 0:
        return "commits", None
    if proc.returncode == 1:
        return "empty", None
    return "unknown", "git rev-parse exited " + str(proc.returncode) + ": " + oneline(proc.stderr)


def recent_author_emails(repo_abs, deadline_at):
    """Returns (emails, warning). Author email only -- never the subject,
    never the body -- from this branch's OWN first-parent line of descent
    only, so a rebase (which rewrites authors, not the mainline shape) or a
    merged-in side branch never substitutes a foreign author for who has
    actually been committing here. Only called once head_state() has
    already confirmed HEAD resolves."""
    require_time(deadline_at, "drift check")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo_abs, "log", "--first-parent", "-" + str(MAX_RECENT_COMMITS), "--format=%ae"],
            capture_output=True,
            text=True,
            timeout=call_timeout(deadline_at),
            env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return [], "drift check timed out"
    except OSError as exc:
        return [], "git failed to run: " + str(exc)
    if proc.returncode != 0:
        return [], "git log exited " + str(proc.returncode) + ": " + oneline(proc.stderr)
    emails = [sanitize_label(line, max_len=254) for line in proc.stdout.splitlines() if line.strip()]
    return emails, None


def analyze_repo(repo_abs, base_resolved, deadline_at):
    row = {
        "path": redact_home(repo_abs),
        "repo": label_for(repo_abs, base_resolved),
        "parent": label_for(os.path.dirname(repo_abs), base_resolved),
        "parent_key": os.path.dirname(repo_abs),  # internal grouping key only -- never emitted
        "email": None,
        "email_scope": None,
        "email_origin": None,
        "name": None,
        "no_identity": None,
        "empty_repo": False,
        "recent_emails": [],
        "drift": False,
        "drift_warning": None,
        "drift_unverified": False,
        "suspect": False,
        "suspect_reason": None,
        "dominant_email": None,
        "unknown": None,
    }

    email_info = read_identity_field(repo_abs, "email", deadline_at)
    name_info = read_identity_field(repo_abs, "name", deadline_at)
    if email_info["warning"] or name_info["warning"]:
        row["unknown"] = sanitize_label(email_info["warning"] or name_info["warning"], max_len=ERROR_CHARS)
        return row

    row["email"] = email_info["value"]
    row["email_scope"] = email_info["scope"]
    row["email_origin"] = email_info["origin"]
    row["name"] = name_info["value"]
    row["no_identity"] = row["email"] is None or row["name"] is None

    # Drift is best-effort on top of an already-resolved identity (see
    # module docstring's DEGRADE DISCIPLINE): the deadline being reached
    # mid-probe degrades this repo to drift_unverified, it never discards
    # the identity already resolved above.
    try:
        state, head_reason = head_state(repo_abs, deadline_at)
    except RuntimeError as exc:
        state, head_reason = "unknown", str(exc)

    if state == "empty":
        row["empty_repo"] = True
    elif state == "commits":
        try:
            emails, drift_warning = recent_author_emails(repo_abs, deadline_at)
        except RuntimeError as exc:
            emails, drift_warning = [], str(exc)
        row["recent_emails"] = emails
        if drift_warning:
            row["drift_warning"] = sanitize_label(drift_warning, max_len=ERROR_CHARS)
        elif row["email"] and emails:
            row["drift"] = row["email"] not in emails
    else:  # state == "unknown": the HEAD probe itself failed unexpectedly
        row["drift_warning"] = sanitize_label(head_reason or "HEAD state could not be determined", max_len=ERROR_CHARS)

    row["drift_unverified"] = row["drift_warning"] is not None

    return row


def apply_sibling_suspect_flags(rows):
    """Flags a repo whose resolved email differs from the DOMINANT email
    among its siblings (same immediate parent directory) -- see module
    docstring's FLAGS section for the exact, conservative dominance rule."""
    groups = defaultdict(list)
    for row in rows:
        if row["unknown"] or not row["email"]:
            continue
        groups[row["parent_key"]].append(row)

    for members in groups.values():
        if len(members) < 2:
            continue
        counts = Counter(m["email"] for m in members)
        (top_email, top_count) = counts.most_common(1)[0]
        others = [c for e, c in counts.items() if e != top_email]
        if others and max(others) >= top_count:
            continue  # tie for most-common -- no dominant email, nothing to compare against
        for m in members:
            if m["email"] != top_email:
                m["suspect"] = True
                m["dominant_email"] = top_email
                m["suspect_reason"] = (
                    "differs from the dominant email in its sibling group ("
                    + top_email + ", " + str(top_count) + "/" + str(len(members)) + " sibling repos)"
                )


def unknown_row(repo_abs, base_resolved, reason):
    """Builds a fully-shaped UNKNOWN row for a repo that never got a real
    analyze_repo() result -- either because the sweep's outer deadline
    fired before its future finished, or because analyze_repo() itself
    raised (a deadline hit before its essential identity reads even
    started, or any other unexpected failure). Shared by both call sites
    below so a repo's failure never aborts the rest of the sweep -- see
    module docstring's DEGRADE DISCIPLINE section."""
    return {
        "path": redact_home(repo_abs),
        "repo": label_for(repo_abs, base_resolved),
        "parent": label_for(os.path.dirname(repo_abs), base_resolved),
        "parent_key": os.path.dirname(repo_abs),
        "email": None, "email_scope": None, "email_origin": None, "name": None,
        "no_identity": None, "empty_repo": False, "recent_emails": [], "drift": False,
        "drift_warning": None, "drift_unverified": False,
        "suspect": False, "suspect_reason": None, "dominant_email": None,
        "unknown": sanitize_label(reason, max_len=ERROR_CHARS),
    }


def main():
    packed = arg(1, "")
    repos_total_hint = arg(2, "")
    base_dir = arg(3, "")

    if not shutil.which("git"):
        sys.stderr.write("scan_identities: git is not on PATH; cannot resolve any identity\n")
        sys.exit(2)

    base_resolved = os.path.realpath(os.path.expanduser(base_dir)) if base_dir else ""

    repos, raw_record_count = unpack_repos(packed)
    hint_warning = None
    if repos_total_hint != "":
        try:
            hint = int(repos_total_hint)
            if hint != raw_record_count:
                hint_warning = (
                    str(raw_record_count) + " repo record(s) unpacked but discover_repos reported "
                    + str(hint) + " -- treating the unpacked count as authoritative"
                )
        except ValueError:
            pass  # bad wiring, not this step's job to fail over

    truncated_note = None
    if len(repos) > MAX_REPOS:
        repos = repos[:MAX_REPOS]
        truncated_note = "MAX_REPOS (" + str(MAX_REPOS) + ") reached; not every discovered repository was scanned"

    deadline_at = time.monotonic() + DEADLINE_S
    includeif_patterns, includeif_warning = list_includeif_patterns(deadline_at)

    rows = []
    if repos:
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futures = {executor.submit(analyze_repo, r, base_resolved, deadline_at): r for r in repos}
            pending = set(futures.keys())
            outer_deadline_at = time.monotonic() + OUTER_SAFETY_S
            while pending:
                remaining = outer_deadline_at - time.monotonic()
                if remaining <= 0:
                    for future in pending:
                        future.cancel()
                        r = futures[future]
                        rows.append(unknown_row(r, base_resolved, "did not complete within the scan's overall time budget"))
                    break
                done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
                for future in done:
                    r = futures[future]
                    try:
                        rows.append(future.result())
                    except Exception as exc:
                        # A queued repo whose future never even started before
                        # the shared deadline fired raises RuntimeError from
                        # require_time() (see module docstring's DEGRADE
                        # DISCIPLINE); any other unexpected exception is
                        # caught the same way. Either way this ONE repo
                        # degrades to an unknown row -- it never aborts the
                        # rest of the sweep.
                        rows.append(unknown_row(r, base_resolved, oneline(str(exc)) or "repo analysis failed"))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    apply_sibling_suspect_flags(rows)

    unknown_rows = [r for r in rows if r["unknown"]]
    known_rows = [r for r in rows if not r["unknown"]]
    no_identity_rows = [r for r in known_rows if r["no_identity"]]
    suspect_rows = [r for r in known_rows if r["suspect"]]
    drift_rows = [r for r in known_rows if r["drift"]]
    drift_unverified_rows = [r for r in known_rows if r["drift_unverified"]]

    groups_by_email = defaultdict(lambda: {"count": 0, "scopes": set()})
    for r in known_rows:
        if not r["email"]:
            continue
        g = groups_by_email[r["email"]]
        g["count"] += 1
        if r["email_scope"]:
            g["scopes"].add(r["email_scope"])
    identity_groups = sorted(
        (
            {"email": email, "repo_count": g["count"], "scopes": sorted(g["scopes"])}
            for email, g in groups_by_email.items()
        ),
        key=lambda g: (-g["repo_count"], g["email"]),
    )

    def strip_internal(row):
        return {k: v for k, v in row.items() if k != "parent_key"}

    flags = {
        "no_identity": [strip_internal(r) for r in no_identity_rows[:MAX_FLAG_SHOWN]],
        "suspect": [strip_internal(r) for r in suspect_rows[:MAX_FLAG_SHOWN]],
        "drift": [strip_internal(r) for r in drift_rows[:MAX_FLAG_SHOWN]],
        "drift_unverified": [strip_internal(r) for r in drift_unverified_rows[:MAX_FLAG_SHOWN]],
        "unknown": [strip_internal(r) for r in unknown_rows[:MAX_FLAG_SHOWN]],
    }

    warnings = [w for w in (hint_warning, truncated_note) if w]
    warning = "; ".join(warnings) if warnings else None

    print(
        json.dumps(
            {
                "ok": True,
                "warning": warning,
                "totals": {
                    "repos_total": len(rows),
                    "repos_scanned": len(rows),
                    "unknown_count": len(unknown_rows),
                    "distinct_emails": len(identity_groups),
                    "no_identity_count": len(no_identity_rows),
                    "suspect_count": len(suspect_rows),
                    "drift_count": len(drift_rows),
                    "drift_unverified_count": len(drift_unverified_rows),
                    "no_identity_shown": len(flags["no_identity"]),
                    "suspect_shown": len(flags["suspect"]),
                    "drift_shown": len(flags["drift"]),
                    "drift_unverified_shown": len(flags["drift_unverified"]),
                    "unknown_shown": len(flags["unknown"]),
                },
                "identity_groups": identity_groups,
                "flags": flags,
                "includeif_patterns": includeif_patterns,
                "includeif_warning": includeif_warning,
            }
        )
    )


main()
