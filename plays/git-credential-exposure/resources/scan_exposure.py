"""Scan the three places git authentication leaks in cleartext on this
machine, in two argv-selected modes -- mirroring the one-resource-script-per-
play craft already established by shell-history-leak-scan's scan_history.py:

  --global
      Root step (scan_global in main.ts). Two independent, unrelated jobs
      that happen to share this mode because neither needs a repository
      sweep:
        1. Reads ~/.git-credentials -- the file `credential.helper=store`
           writes, one URL per stored credential -- parsing every non-blank
           line as a URL and reducing every embedded user:token (or
           x-access-token:token) pair it finds to HOST, a token SHAPE (a
           recognized pattern -- sk-, ghp_, gho_, xox[bp]-, AKIA, an eyJ-led
           JWT -- else the generic "stored-credential" bucket), and a
           4-character-plus-length preview -- NEVER the token itself, and
           never the username either: a username can itself be a real email
           or personal identifier this play has no business repeating, so
           it is parsed (to isolate the password) and then discarded, never
           emitted anywhere. The file's permission bits are read via
           os.stat and flagged whenever group- or world-readable -- a
           credential store readable by anyone but its owner is its own
           finding regardless of what it contains.
        2. Resolves the EFFECTIVE `credential.helper` value at system and
           global scope, in that order -- `git config --system --get-all`
           then `git config --global --get-all` (never re-derived by hand,
           never assumed single-valued -- git treats this key as
           cumulative, so --get-all is used, never --get). Every configured
           value is classified into a coarse KIND only (store, cache,
           osxkeychain, ...) via classify_helper_kind() -- the raw value
           itself (which can be an arbitrary `!` shell command or an
           absolute path carrying arguments) is never emitted anywhere in
           this script's output. An empty value is git's own documented
           "reset the accumulated helper list" marker, preserved and
           replayed via build_helper_entries() rather than silently dropped
           -- `store` followed by a reset is correctly NOT flagged.
           helper=store is flagged only if `store` survives that replay as
           part of the final active list; an unset helper on macOS gets a
           plain informational note, since macOS enables no automatic
           Keychain integration for git on its own.
      A missing/unreadable ~/.git-credentials is a normal, expected machine
      state (most machines never used credential.helper=store) -- this mode
      always emits {"ok": true, ...}. git missing from PATH degrades only
      the credential.helper sub-check (with its own warning); the file scan
      needs no git binary at all and is unaffected.

  --repos
      Root step (scan_repos in main.ts). One bounded sweep of base_dir up
      to max_depth levels (pruning node_modules and the same conservative
      noise list this fleet's other git sweeps already established --
      reused as-is from discover_repos.py rather than re-derived by hand --
      never descending into a found repository's own .git internals), then
      for every discovered repo:
        - reads its EFFECTIVE `credential.helper` -- system, global, local,
          and worktree scope, in the exact cumulative order git itself
          applies them -- via a single `git config --get-all --show-scope`
          call with no explicit scope flag (git resolves that merged order
          on its own; see read_effective_helper()). This is deliberately
          NOT a local-only read: a local-only read cannot see a `store`
          inherited from global/system (a real, common case), and cannot
          see a local empty (reset) entry that neutralizes an inherited
          `store` back off either -- both are exactly what `store`
          "effectively active for this repo" means, and both matter for
          whether `git credential approve` will actually write a plaintext
          credential for this repo. Flagged rows also report `source`:
          "local" when the repo's own local/worktree scope explicitly
          configured `store` (a deliberate per-repo decision, independent
          of the global value), "inherited" when it did not.
        - reads `git remote -v`, parsing every remote URL for an embedded
          user:token or x-access-token:token credential the identical way
          the file scan parses stored-credential lines (see
          parse_embedded_credential below, shared by both modes),
          de-duplicated across a remote's fetch and push lines (which are
          almost always identical), reduced to remote name, host, shape,
          and the same 4-char preview.
      Every git call here is --no-optional-locks with a scrubbed
      environment (GIT_TERMINAL_PROMPT=0, LC_ALL=C, inherited
      GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE stripped) -- the same
      conservative craft commit-identity-check's scan_identities.py already
      established. Both checks (effective helper, remotes) are this repo's
      ESSENTIAL job for this step: if either git call errors (not merely
      absent -- an absence is a clean "not configured"/"no remotes"
      result; an error is git failing to run, timing out, or exiting
      unexpectedly) the WHOLE repo degrades to an "unknown" row, never
      silently reported as clean. git missing from PATH entirely is the
      one essential-capability failure that fails this whole step closed
      -- no per-repo read means anything without it. A single shared
      wall-clock budget covers the walk and every repo's git calls; a repo
      whose turn never came, or was cut short, degrades to "unknown" with
      its own reason -- it never aborts the rest of the sweep.

Degrade, not fail (see gotcha #10): a HARD FAULT means broken wiring, never
a legitimate absence -- bad/missing argv, max_depth failing to int-parse,
base_dir existing but not being a directory, or git missing from PATH for
--repos (its whole per-repo job is git calls). Every other outcome degrades
per-surface (--global) or per-repo (--repos) and still emits
{"ok": true, ...}.

4-char preview discipline: every credential value this script ever sees --
from ~/.git-credentials or from a remote URL -- is percent-decoded (bounded
-- unquote() only ever shrinks or preserves length) and then reduced to
preview()'s output (first 4 characters plus total length) the moment it is
captured, and the full value is never held past that point, never logged,
never included in an error message. The username half of every parsed URL
is discarded even sooner -- it is never even reduced to a preview, since a
username is not the secret this play is scanning for and repeating it
(a real email, a real handle) would be its own leak.

credential.helper values get a STRICTER discipline than the 4-char preview:
they are never emitted at all, in any form, anywhere -- not even a preview.
A helper value can be an arbitrary `!` shell command or an absolute path
carrying arguments, either of which could embed a token, URL, or path this
play has no business repeating, and unlike a stored credential or a remote
URL's password there is no fixed field this play needs to preview -- only a
coarse KIND (store, cache, osxkeychain, custom, ...) via
classify_helper_kind(), which is all that is ever reported. See
build_helper_entries() for the reset-replay this KIND classification feeds.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from urllib.parse import urlsplit, unquote

HOME = os.path.expanduser("~")

DEFAULT_BASE = "~/Documents"
DEFAULT_DEPTH = 3
MIN_DEPTH, MAX_DEPTH = 1, 6

GLOBAL_GIT_TIMEOUT_S = 8  # shared budget for --global mode's two scope calls
                          # (system, then global) -- kept well under this
                          # step's own 15000ms external timeout
MIN_GLOBAL_CALL_TIMEOUT_S = 1  # floor so a call is never attempted with a sub-second budget

# --repos budgets: one shared wall-clock envelope, split between the walk
# and the per-repo analysis phase, deliberately well under this step's own
# 60000ms external timeout so this script always has time left to print a
# partial, still-valid JSON result of its own accord before an external
# kill could lose everything.
WALK_BUDGET_S = 12
ANALYSIS_BUDGET_S = 33
GIT_TIMEOUT_S = 8  # ceiling for any single git call when the deadline allows it
MIN_CALL_TIMEOUT_S = 1  # floor so a call is never attempted with a sub-second budget
MAX_WORKERS = 6
MAX_REPOS = 500  # sanity cap against a pathologically large base_dir
MAX_SHOWN = 200  # display cap per list; totals report the true count
LABEL_CHARS = 200
ERROR_CHARS = 160

# Reused verbatim from discover_repos.py's already-proven discovery walk:
# node_modules is the case this play's own spec names explicitly; the rest
# is the same conservative noise list this fleet's other git sweeps
# already established.
PRUNED_DIRS = ("node_modules", ".venv", "venv", "__pycache__", "Library", ".Trash")

# Well-known token shapes, reused verbatim from scan_history.py's
# already-proven pattern set -- the same craft, the same names, so a
# finding classified here reads identically to one shell-history-leak-scan
# would report for the same token.
KNOWN_SHAPES = [
    ("openai-key", re.compile(r"sk-[A-Za-z0-9_-]{16,}")),
    ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github-oauth-token", re.compile(r"gho_[A-Za-z0-9]{20,}")),
    ("slack-token", re.compile(r"xox[bp]-[A-Za-z0-9-]{10,}")),
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# credential.helper basenames this script recognizes -- both the short form
# git resolves against its own libexec dir (e.g. "osxkeychain") and the full
# "git-credential-<name>" form an absolute path or explicit PATH lookup can
# use for the identical helper. Only the KIND on the right is ever reported
# anywhere in this script's output; the raw configured value (which can be
# an arbitrary `!` shell snippet or an absolute path carrying arguments) is
# never emitted -- see classify_helper_kind() and the module docstring's
# 4-char preview discipline, which this table exists specifically to avoid
# needing for credential.helper values at all.
KNOWN_HELPER_KINDS = {
    "store": "store", "git-credential-store": "store",
    "cache": "cache", "git-credential-cache": "cache",
    "osxkeychain": "osxkeychain", "git-credential-osxkeychain": "osxkeychain",
    "manager": "manager", "manager-core": "manager",
    "git-credential-manager": "manager", "git-credential-manager-core": "manager",
    "libsecret": "libsecret", "git-credential-libsecret": "libsecret",
    "wincred": "wincred", "git-credential-wincred": "wincred",
    "netrc": "netrc", "git-credential-netrc": "netrc",
}

# Every C0 control (including tab/newline/CR -- a stored credential value or
# path can legitimately contain any byte a filesystem allows), the DEL/C1
# range, and the Unicode bidi/formatting controls that could otherwise spoof
# terminal columns or lines once a host/repo label is interpolated into a
# single-line render downstream in main.ts. Reused verbatim from
# commit-identity-check/scan_identities.py.
_BIDI_FORMATTING_CHARS = "".join(
    chr(c) for c in (
        list(range(0x200B, 0x2010))  # zero-width space..hyphen (covers 200B-200F marks)
        + list(range(0x202A, 0x202F))  # LRE/RLE/PDF/LRO/RLO embedding/override
        + list(range(0x2060, 0x206A))  # word joiner..nomination digit shapes range
        + [0xFEFF]  # BOM / zero-width no-break space
    )
)
CONTROL_CHARS_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f" + re.escape(_BIDI_FORMATTING_CHARS) + "]"
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


def oneline(text, max_len=ERROR_CHARS):
    """Collapse a (possibly multi-line) stderr message to one line before it
    goes in a JSON field or a single-row terminal render."""
    collapsed = " ".join((text or "").split())
    return collapsed[:max_len]


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(2)


def preview(value):
    """First 4 characters plus total length -- never more, anywhere in this
    script's output. Reused verbatim from scan_history.py."""
    n = len(value)
    if n <= 4:
        return "%s, %d chars" % (value, n)
    return "%s…, %d chars" % (value[:4], n)


def classify_shape(value):
    for shape, pattern in KNOWN_SHAPES:
        if pattern.search(value):
            return shape
    return None


def classify_helper_kind(value):
    """Classify one raw credential.helper value into a coarse KIND -- never
    the value itself (see KNOWN_HELPER_KINDS above and the module
    docstring's 4-char preview discipline; a helper value can be an
    arbitrary `!` shell command or an absolute path carrying arguments,
    either of which could embed a token, URL, or path this play has no
    business repeating). An empty value is git's own documented "reset the
    helper list accumulated so far" marker, not a helper -- it is
    classified "reset", never silently dropped, so callers can replay it."""
    if value == "":
        return "reset"
    head = value.split(" ", 1)[0]
    if head.startswith("!"):
        return "shell-command"
    return KNOWN_HELPER_KINDS.get(os.path.basename(head), "custom")


def build_helper_entries(scoped_values):
    """scoped_values: ordered [(scope, raw_value), ...] in the EFFECTIVE
    order git itself applies them (system, then global, then local, then
    worktree -- see gitcredentials(7)). Returns (entries, active_kinds):

    `entries` is every configured occurrence in original order, each
    {"scope": ..., "kind": ...} -- including "reset" markers -- an
    auditable, non-secret ledger of what was ever set and where, distinct
    from what is currently active.

    `active_kinds` is the final ordered list of kinds surviving replay of
    git's own cumulative-with-reset semantics: a non-empty value APPENDS to
    the helper list; an empty value CLEARS everything accumulated so far,
    regardless of which scope contributed it. This is what git will
    actually invoke -- the correct basis for an is_store determination,
    not merely "did store appear anywhere in the raw values" (see the
    'store followed by an empty reset' false positive this replaces)."""
    entries = []
    active = []
    for scope, raw in scoped_values:
        kind = classify_helper_kind(raw)
        entries.append({"scope": scope, "kind": kind})
        if kind == "reset":
            active = []
        else:
            active.append(kind)
    return entries, active


def scrubbed_env():
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    for poison in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(poison, None)
    return env


_ENV = scrubbed_env()


def parse_embedded_credential(raw_url):
    """Return (host, password) if raw_url is an http(s) URL carrying an
    embedded user:password (or x-access-token:token, which parses the exact
    same way) credential, else None. Only the host and password are ever
    extracted -- the username is intentionally never reported anywhere in
    this script's output (see module docstring).

    The password is percent-decoded (bounded -- unquote() can only ever
    shrink or preserve length, never expand it) before it is classified or
    measured, so a credential whose shape-defining prefix (ghp_, sk-, ...)
    is itself percent-encoded in the URL is still recognized correctly and
    preview()'d against its real characters, not the encoded text."""
    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    try:
        password = parts.password
        host = parts.hostname
    except ValueError:
        return None  # malformed netloc (bad percent-encoding, etc.)
    if not password or not host:
        return None
    return host, unquote(password)


# ---------------------------------------------------------------------------
# --global
# ---------------------------------------------------------------------------

def scan_credentials_file(path):
    result = {
        "path": redact_home(path),
        "exists": False,
        "readable": False,
        "reason": None,
        "mode_octal": "",
        "world_readable": False,
        "group_readable": False,
        "perm_flagged": False,
        "entry_count": 0,
        "parse_error_count": 0,
        "findings": [],
        "findings_truncated": 0,
    }
    if not os.path.isfile(path):
        result["reason"] = "absent"
        return result
    result["exists"] = True

    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        result["mode_octal"] = oct(mode)[2:].zfill(3)
        result["world_readable"] = bool(mode & stat.S_IROTH)
        result["group_readable"] = bool(mode & stat.S_IRGRP)
        result["perm_flagged"] = result["world_readable"] or result["group_readable"]
    except OSError as exc:
        result["reason"] = "could not stat file: " + oneline(str(exc))
        return result

    if not os.access(path, os.R_OK):
        result["reason"] = "unreadable"
        return result
    result["readable"] = True

    findings = []
    entry_count = 0
    parse_errors = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, raw in enumerate(fh, start=1):
                line = raw.strip()
                if not line:
                    continue
                entry_count += 1
                parsed = parse_embedded_credential(line)
                if not parsed:
                    parse_errors += 1
                    continue
                host, password = parsed
                shape = classify_shape(password) or "stored-credential"
                if len(findings) < MAX_SHOWN:
                    findings.append({
                        "line": line_no,
                        "host": sanitize_label(host),
                        "shape": shape,
                        "value_preview": preview(password),
                    })
    except OSError as exc:
        result["readable"] = False
        result["reason"] = "read failed: " + oneline(str(exc))
        return result

    total_creds = entry_count - parse_errors
    result["entry_count"] = entry_count
    result["parse_error_count"] = parse_errors
    result["findings"] = findings
    result["findings_truncated"] = max(0, total_creds - len(findings))
    return result


def query_scope_helper(scope_flag, timeout_s):
    """Run `git config <scope_flag> --get-all credential.helper` for one
    explicit scope. Returns (ok, values, warning): ok is False only for a
    genuine git failure (crash, timeout, unexpected exit) -- "not
    configured at this scope" is ok=True, values=[], the normal, expected
    case for most scopes on most machines. values preserves empty (reset)
    entries verbatim; nothing here is sanitized or previewed because
    nothing here is ever a raw helper value in the returned dict -- see
    classify_helper_kind(), which is the only thing ever done with these
    values downstream."""
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "config", scope_flag, "--get-all", "credential.helper"],
            capture_output=True, text=True, timeout=timeout_s, env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return False, [], "credential.helper read timed out (" + scope_flag + ")"
    except OSError as exc:
        return False, [], "git failed to run: " + oneline(str(exc))
    if proc.returncode == 1:
        return True, [], None
    if proc.returncode != 0:
        return False, [], "git config exited " + str(proc.returncode) + ": " + oneline(proc.stderr)
    return True, proc.stdout.splitlines(), None


def read_global_helper():
    """Effective credential.helper for this machine outside any specific
    repository: system scope, then global scope, in that order -- the same
    cumulative-with-reset order git itself applies (gitcredentials(7)).
    Local/worktree scope is deliberately never consulted here (that would
    depend on which repository's directory this process happened to be
    run from, which this root step has no business depending on) --
    per-repository local scope is scan_repos' job (see
    read_effective_helper below)."""
    if not shutil.which("git"):
        return {
            "configured": False, "entries": [], "active_kinds": [], "is_store": False, "note": None,
            "warning": "git is not on PATH; global credential.helper could not be checked",
        }
    deadline_at = time.monotonic() + GLOBAL_GIT_TIMEOUT_S
    scoped_values = []
    for scope_flag, scope_name in (("--system", "system"), ("--global", "global")):
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            return {
                "configured": False, "entries": [], "active_kinds": [], "is_store": False, "note": None,
                "warning": "global credential.helper read timed out",
            }
        call_timeout = max(MIN_GLOBAL_CALL_TIMEOUT_S, min(GLOBAL_GIT_TIMEOUT_S, remaining))
        ok, values, warning = query_scope_helper(scope_flag, call_timeout)
        if not ok:
            return {
                "configured": False, "entries": [], "active_kinds": [], "is_store": False, "note": None,
                "warning": warning,
            }
        scoped_values.extend((scope_name, v) for v in values)

    entries, active_kinds = build_helper_entries(scoped_values)
    is_store = "store" in active_kinds
    configured = any(e["kind"] != "reset" for e in entries)

    note = None
    if not configured and sys.platform == "darwin":
        note = (
            "credential.helper is not configured at system or global scope; macOS does not enable "
            "Keychain integration for git automatically -- run `git config --global credential.helper "
            "osxkeychain` to store credentials safely instead of cleartext"
        )
    return {
        "configured": configured, "entries": entries, "active_kinds": active_kinds,
        "is_store": is_store, "note": note, "warning": None,
    }


def cmd_global():
    credentials_file = scan_credentials_file(os.path.expanduser("~/.git-credentials"))
    global_helper = read_global_helper()
    print(json.dumps({
        "ok": True,
        "warning": None,
        "platform": sys.platform,
        "credentials_file": credentials_file,
        "global_helper": global_helper,
    }))


# ---------------------------------------------------------------------------
# --repos
# ---------------------------------------------------------------------------

def arg(argv, index, fallback=""):
    value = argv[index] if len(argv) > index else ""
    return value if value else fallback


def parse_max_depth(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        fail("max_depth must be an integer, got: " + str(raw))
    return max(MIN_DEPTH, min(MAX_DEPTH, value))


def is_repo_marker(dirs, files):
    """Matches a directory clone (.git/ is a dir) and a worktree/submodule
    (.git is a file holding a gitdir: pointer)."""
    return ".git" in dirs or ".git" in files


def discover(base, depth, deadline_at):
    """Returns (repos, truncated_by_deadline, truncated_by_repo_cap). Reused
    verbatim from discover_repos.py's already-proven bounded walk."""
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


def label_for(path, base_resolved):
    try:
        rel = os.path.relpath(path, base_resolved)
        return sanitize_label(rel)
    except ValueError:
        return sanitize_label(redact_home(path))


def remaining_time(deadline_at):
    return deadline_at - time.monotonic()


def call_timeout(deadline_at):
    return max(MIN_CALL_TIMEOUT_S, min(GIT_TIMEOUT_S, remaining_time(deadline_at)))


def require_time(deadline_at, what):
    if remaining_time(deadline_at) <= 0:
        raise RuntimeError("scan deadline reached before " + what + " could run")


_REMOTE_SUFFIX_RE = re.compile(r"^(.*)\s+\((?:fetch|push)\)$")


_LOCAL_HELPER_SCOPES = ("local", "worktree")


def parse_scope_get_all(stdout_text):
    """Parse `git config --get-all --show-scope` output: one
    "<scope>\\t<value>" line per configured occurrence (value can be
    empty -- a reset marker -- but the tab is always present). Reused
    nowhere else; this exact two-field shape is specific to
    --show-scope."""
    entries = []
    for line in stdout_text.splitlines():
        scope, tab, value = line.partition("\t")
        if not tab:
            continue  # defensive; git always includes the tab, even for an empty value
        entries.append((scope, value))
    return entries


def read_effective_helper(repo_abs, deadline_at):
    """Effective credential.helper for repo_abs: system, global, local, and
    worktree scope, in the exact cumulative order git itself applies them
    -- one call, `git config --get-all --show-scope` with no explicit
    scope flag, which git resolves to precisely that merged order on its
    own (verified against gitcredentials(7) and this fleet's own scratch
    testing). This is the correct basis for "will this repo actually write
    a plaintext credential via `store`" -- a local-only read cannot see a
    store inherited from global/system, and cannot see a local empty entry
    that resets an inherited store back off either.

    Also reports whether the repo's OWN local/worktree scope ever
    configured `store` explicitly (regardless of whether the final active
    list still contains it), so a caller can distinguish "this repo
    explicitly opted into store" from "this repo merely inherits store
    from global/system" -- two different remediation targets."""
    require_time(deadline_at, "credential.helper read")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo_abs, "config", "--get-all", "--show-scope", "credential.helper"],
            capture_output=True, text=True, timeout=call_timeout(deadline_at), env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return {"_hard_error": "credential.helper read timed out"}
    except OSError as exc:
        return {"_hard_error": "git failed to run: " + oneline(str(exc))}
    if proc.returncode == 1:
        return {"entries": [], "active_kinds": [], "is_store": False, "source": None}
    if proc.returncode != 0:
        return {"_hard_error": "git config exited " + str(proc.returncode) + ": " + oneline(proc.stderr)}

    scoped_values = parse_scope_get_all(proc.stdout)
    entries, active_kinds = build_helper_entries(scoped_values)
    is_store = "store" in active_kinds
    source = None
    if is_store:
        local_configured_store = any(
            e["kind"] == "store" and e["scope"] in _LOCAL_HELPER_SCOPES for e in entries
        )
        source = "local" if local_configured_store else "inherited"
    return {"entries": entries, "active_kinds": active_kinds, "is_store": is_store, "source": source}


def read_remotes(repo_abs, deadline_at):
    require_time(deadline_at, "remote -v read")
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo_abs, "remote", "-v"],
            capture_output=True, text=True, timeout=call_timeout(deadline_at), env=_ENV,
        )
    except subprocess.TimeoutExpired:
        return {"_hard_error": "remote -v timed out"}
    except OSError as exc:
        return {"_hard_error": "git failed to run: " + oneline(str(exc))}
    if proc.returncode != 0:
        return {"_hard_error": "git remote -v exited " + str(proc.returncode) + ": " + oneline(proc.stderr)}

    seen = set()
    findings = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        remote_name, rest = parts
        m = _REMOTE_SUFFIX_RE.match(rest)
        url = m.group(1) if m else rest
        key = (remote_name, url)
        if key in seen:
            continue  # fetch/push lines for the same remote are almost always identical
        seen.add(key)
        parsed = parse_embedded_credential(url)
        if not parsed:
            continue
        host, password = parsed
        shape = classify_shape(password) or "embedded-credential"
        findings.append({
            "remote": sanitize_label(remote_name),
            "host": sanitize_label(host),
            "shape": shape,
            "value_preview": preview(password),
        })
    return {"findings": findings[:MAX_SHOWN], "findings_total": len(findings)}


def analyze_repo(repo_abs, base_resolved, deadline_at):
    row = {
        "repo": label_for(repo_abs, base_resolved),
        "helper_store": False,
        "helper_source": None,
        "embedded_findings": [],
        "embedded_findings_total": 0,
        "unknown": None,
    }
    helper_info = read_effective_helper(repo_abs, deadline_at)
    if "_hard_error" in helper_info:
        row["unknown"] = sanitize_label(helper_info["_hard_error"], max_len=ERROR_CHARS)
        return row
    row["helper_store"] = helper_info["is_store"]
    row["helper_source"] = helper_info["source"]

    remote_info = read_remotes(repo_abs, deadline_at)
    if "_hard_error" in remote_info:
        # Both checks are this repo's essential job (see module docstring);
        # a remote-read failure degrades the whole repo, not just this half.
        row["unknown"] = sanitize_label(remote_info["_hard_error"], max_len=ERROR_CHARS)
        return row
    row["embedded_findings"] = remote_info["findings"]
    row["embedded_findings_total"] = remote_info["findings_total"]
    return row


def unknown_row(repo_abs, base_resolved, reason):
    return {
        "repo": label_for(repo_abs, base_resolved),
        "helper_store": False, "helper_source": None,
        "embedded_findings": [], "embedded_findings_total": 0,
        "unknown": sanitize_label(reason, max_len=ERROR_CHARS),
    }


def cmd_repos(argv):
    raw_base = arg(argv, 0, DEFAULT_BASE)
    max_depth = parse_max_depth(arg(argv, 1, str(DEFAULT_DEPTH)))

    if not shutil.which("git"):
        fail("git is not on PATH; cannot check any repository's credential.helper or remotes")

    expanded = os.path.expanduser(raw_base)

    if os.path.exists(expanded) and not os.path.isdir(expanded):
        fail("base_dir exists but is not a directory: " + redact_home(expanded))

    empty_totals = {
        "repos_total": 0, "repos_scanned": 0, "unknown_count": 0,
        "helper_store_count": 0, "embedded_cred_repo_count": 0,
        "embedded_cred_finding_count": 0,
        "helper_store_shown": 0, "embedded_cred_shown": 0, "unknown_shown": 0,
    }

    if not os.path.isdir(expanded):
        print(json.dumps({
            "ok": True,
            "warning": "base_dir does not exist: " + redact_home(expanded),
            "base": redact_home(expanded), "max_depth": max_depth,
            "truncated_by_deadline": False, "truncated_by_repo_cap": False,
            "totals": empty_totals,
            "helper_store_repos": [], "embedded_cred_findings": [], "unknown_repos": [],
        }))
        return

    base_resolved = os.path.realpath(expanded)
    walk_deadline_at = time.monotonic() + WALK_BUDGET_S
    repos, truncated_by_deadline, truncated_by_repo_cap = discover(base_resolved, max_depth, walk_deadline_at)

    analysis_deadline_at = time.monotonic() + ANALYSIS_BUDGET_S
    outer_deadline_at = time.monotonic() + ANALYSIS_BUDGET_S + GIT_TIMEOUT_S + 5

    rows = []
    if repos:
        executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        try:
            futures = {executor.submit(analyze_repo, r, base_resolved, analysis_deadline_at): r for r in repos}
            pending = set(futures.keys())
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
                        rows.append(unknown_row(r, base_resolved, oneline(str(exc)) or "repo analysis failed"))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    unknown_rows = [r for r in rows if r["unknown"]]
    known_rows = [r for r in rows if not r["unknown"]]
    helper_store_rows = [r for r in known_rows if r["helper_store"]]
    embedded_rows = [r for r in known_rows if r["embedded_findings_total"] > 0]

    embedded_cred_findings = []
    for r in embedded_rows:
        for f in r["embedded_findings"]:
            if len(embedded_cred_findings) >= MAX_SHOWN:
                break
            embedded_cred_findings.append({"repo": r["repo"], **f})

    total_embedded_findings = sum(r["embedded_findings_total"] for r in known_rows)

    helper_store_shown = [{"repo": r["repo"], "source": r["helper_source"]} for r in helper_store_rows[:MAX_SHOWN]]
    unknown_shown = [{"repo": r["repo"], "reason": r["unknown"]} for r in unknown_rows[:MAX_SHOWN]]

    warnings = []
    if truncated_by_deadline:
        warnings.append("the scan's time budget was reached before the walk finished; not every repository under base_dir was found")
    if truncated_by_repo_cap:
        warnings.append("MAX_REPOS (" + str(MAX_REPOS) + ") reached during discovery; not every repository under base_dir was found")
    warning = "; ".join(warnings) if warnings else None

    print(json.dumps({
        "ok": True,
        "warning": warning,
        "base": redact_home(base_resolved),
        "max_depth": max_depth,
        "truncated_by_deadline": truncated_by_deadline,
        "truncated_by_repo_cap": truncated_by_repo_cap,
        "totals": {
            "repos_total": len(rows),
            "repos_scanned": len(known_rows),
            "unknown_count": len(unknown_rows),
            "helper_store_count": len(helper_store_rows),
            "embedded_cred_repo_count": len(embedded_rows),
            "embedded_cred_finding_count": total_embedded_findings,
            "helper_store_shown": len(helper_store_shown),
            "embedded_cred_shown": len(embedded_cred_findings),
            "unknown_shown": len(unknown_shown),
        },
        "helper_store_repos": helper_store_shown,
        "embedded_cred_findings": embedded_cred_findings,
        "unknown_repos": unknown_shown,
    }))


def main():
    if len(sys.argv) < 2:
        fail("usage: scan_exposure.py --global | --repos <base_dir> <max_depth>")
    mode = sys.argv[1]
    if mode == "--global":
        cmd_global()
    elif mode == "--repos":
        cmd_repos(sys.argv[2:])
    else:
        fail("unknown mode: " + mode)


main()
