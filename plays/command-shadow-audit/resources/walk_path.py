"""Walk THIS process's own $PATH, in order, and for a watchlist of command
names, list every hit -- every directory that PATH would actually find the
name in, in the order a shell would search them.

Touches no process, spawns nothing: every check here is os.path.isdir /
os.path.islink / os.readlink / os.access against directories already named
in $PATH. The $PATH this script reads is simply this process's own
inherited environment -- the shell that ran `rote play run` already sourced
whatever rc files it sources on its own; this script does not source
anything itself, and never reads or evaluates any rc file (that is
parse_rc.py's job, done by static text parsing only).

argv[1]  commands -- comma-separated extra command names to add to the
         built-in watchlist below. Each token is trimmed; empty tokens are
         dropped silently; a token is accepted only if it matches
         [A-Za-z0-9._-]+ (letters, digits, dot, dash, underscore) --
         anything else (spaces, slashes, shell metacharacters) is rejected
         and folded into extra_ignored_note rather than silently dropped,
         so a typo or a paste-in mistake is visible in the report, never
         just swallowed.

Every PATH entry is normalized to an absolute directory path before it is
ever walked, packed, fingerprinted, or (in resolve.py) probed: this
process's own $CWD is captured once at start, an EMPTY PATH component
(`PATH=:/bin`, `PATH=/bin:`) is normalized to that captured $CWD -- the
same "empty means here" rule every real shell applies, not a missing
directory -- and any other relative component is joined onto that same
captured $CWD. Without this, an empty component was previously walked but
counted as though it were missing, and a relative component stayed
relative in every downstream report, fingerprint, and probe path, making
the chosen file dependent on whatever directory happened to be current at
run time. dir_index (see below) still reflects the entry's original
position in $PATH either way.

A PATH entry only counts as a "hit" for a name when the candidate
(dir/name) exists AND, once every symlink hop is fully followed, resolves
to a REGULAR file (os.path.isfile, which follows symlinks itself -- a
symlink to a searchable directory is never reported as an executable
command just because a directory's own execute bit happens to be set)
AND is executable (os.access(..., os.X_OK)) -- mirroring real shell PATH
search, which silently skips a non-executable file and keeps looking in
the next directory. A directory named in $PATH that does not exist on disk
is counted (path_dirs_walked) but not scanned (path_dirs_existing excludes
it).

Per hit: is_symlink, and if so link_target resolved exactly ONE level (the
raw os.readlink() result -- if that target is itself a symlink, this script
does not chase it further; that matches walk_path's own job description,
"resolves one level", and keeps this script from ever needing to walk an
attacker-controlled symlink chain to an arbitrary depth).

fingerprint(dir) is a directory-path heuristic against well-known version-
manager and package-manager conventions -- never a registry lookup, never
an executed `--version` (that only ever happens in resolve.py, and only for
the fixed allowlist there). Checked most-specific first so e.g. a pyenv
shim never falls through to the generic "system" bucket:
    asdf-shims  -- .../.asdf/shims
    nvm         -- .../.nvm/...
    pyenv-shims -- .../.pyenv/shims
    rbenv       -- .../.rbenv/...
    conda       -- .../anaconda3, .../miniconda3, .../miniforge3,
                   .../condabin, or an "envs" path segment alongside
                   "conda"/"anaconda" in the same path
    rote-bin    -- exactly $HOME/.rote/bin
    local-bin   -- exactly $HOME/.local/bin
    brew        -- .../opt/homebrew/... (Apple Silicon default prefix), or
                   the RESOLVED (one-level) symlink target contains
                   "/Cellar/" -- catches Homebrew-managed binaries even
                   when linked into /usr/local/bin (the historic
                   Homebrew-on-Intel prefix), which this script cannot
                   otherwise tell apart from a plain system/vendor
                   install by directory name alone
    system      -- fallback for everything else (/usr/bin, /bin,
                   /usr/local/bin when not resolved to a Cellar path,
                   /System/..., /Library/Frameworks/... framework
                   installs, and any other unrecognized directory)

Emits one JSON object on stdout, always exit 0 -- there is no essential
capability here that can fail short of $PATH itself being unset, which is
handled as an empty walk, not a fault:
    {"ok": true,
     "path_dirs_walked": <int>, "path_dirs_existing": <int>,
     "path_dirs_missing": <int>,
     "watchlist_count": <int>, "builtin_count": <int>,
     "extra_valid_count": <int>, "extra_ignored_count": <int>,
     "extra_ignored_note": "<optional>",
     "hit_count": <int>,
     "watchlist_packed": "<RS-joined effective watchlist, in order>",
     "packed": "<RS-joined hit records>"}
Each hit record packs command|dir_index|dir|is_symlink|link_target|
fingerprint, FS-joined (chr(31)); records are RS-joined (chr(30)).
dir_index is this hit's position in the walked $PATH list (0-based),
preserved so resolve.py can order same-command hits without re-deriving
PATH order itself.
"""

import json
import os
import sys

FS, RS = chr(31), chr(30)

BUILTIN_WATCHLIST = [
    "python3", "python", "pip", "pip3", "node", "npm", "npx", "curl", "wget",
    "git", "rm", "ls", "cat", "ssh", "docker", "kubectl", "make", "java",
    "ruby", "go", "rustc", "cargo",
]

_EXTRA_NAME_RE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

HOME = os.path.expanduser("~")
ROTE_BIN = os.path.join(HOME, ".rote", "bin")
LOCAL_BIN = os.path.join(HOME, ".local", "bin")

_CONDA_MARKERS = ("/anaconda3", "/miniconda3", "/miniforge3", "condabin")


def is_valid_extra_name(token):
    return bool(token) and all(c in _EXTRA_NAME_RE_CHARS for c in token)


def parse_extra_commands(raw):
    """Returns (valid_names_in_order, ignored_raw_tokens)."""
    if not raw:
        return [], []
    valid, ignored = [], []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if is_valid_extra_name(token):
            valid.append(token)
        else:
            ignored.append(token)
    return valid, ignored


def build_watchlist(extra_raw):
    valid_extra, ignored = parse_extra_commands(extra_raw)
    effective = list(BUILTIN_WATCHLIST)
    seen = set(effective)
    added = 0
    for name in valid_extra:
        if name in seen:
            continue
        effective.append(name)
        seen.add(name)
        added += 1
    return effective, added, ignored


def fingerprint(dir_path, resolved_symlink_target_abs):
    if "/.asdf/shims" in dir_path:
        return "asdf-shims"
    if "/.nvm/" in dir_path:
        return "nvm"
    if "/.pyenv/shims" in dir_path:
        return "pyenv-shims"
    if "/.rbenv/" in dir_path:
        return "rbenv"
    if any(marker in dir_path for marker in _CONDA_MARKERS):
        return "conda"
    if "/envs/" in dir_path and ("conda" in dir_path.lower() or "anaconda" in dir_path.lower()):
        return "conda"
    if dir_path == ROTE_BIN:
        return "rote-bin"
    if dir_path == LOCAL_BIN:
        return "local-bin"
    if dir_path.startswith("/opt/homebrew/"):
        return "brew"
    if resolved_symlink_target_abs and "/Cellar/" in resolved_symlink_target_abs:
        return "brew"
    return "system"


def normalize_path_dirs(raw_path, cwd):
    """Splits $PATH on os.pathsep and normalizes every component to an
    absolute directory path against the given (already-captured) $CWD -- an
    empty component becomes exactly $CWD (real shells treat an empty PATH
    component as "here", not as "missing"); any other relative component is
    joined onto $CWD the same way. An already-absolute component passes
    through unchanged. See module docstring for why this matters for
    reports, fingerprints, and (in resolve.py) probe paths alike."""
    if not raw_path:
        return []
    dirs = []
    for component in raw_path.split(os.pathsep):
        if component == "":
            dirs.append(cwd)
        elif os.path.isabs(component):
            dirs.append(component)
        else:
            dirs.append(os.path.normpath(os.path.join(cwd, component)))
    return dirs


def main():
    extra_raw = sys.argv[1] if len(sys.argv) > 1 else ""
    effective, extra_valid_count, ignored = build_watchlist(extra_raw)

    raw_path = os.environ.get("PATH", "")
    dirs = normalize_path_dirs(raw_path, os.getcwd())

    hits = []
    existing_count = 0
    for dir_index, dir_path in enumerate(dirs):
        if not os.path.isdir(dir_path):
            continue
        existing_count += 1
        for name in effective:
            candidate = os.path.join(dir_path, name)
            is_symlink = os.path.islink(candidate)
            if is_symlink:
                try:
                    link_target = os.readlink(candidate)
                except OSError:
                    link_target = ""
                # One-level resolution only, for fingerprinting a Homebrew
                # Cellar target; do not chase further hops.
                resolved_abs = (
                    link_target
                    if os.path.isabs(link_target)
                    else os.path.normpath(os.path.join(dir_path, link_target))
                )
            elif os.path.isfile(candidate):
                link_target = ""
                resolved_abs = candidate
            else:
                continue  # not present in this dir at all

            # Regardless of the symlink branch above, the candidate must
            # resolve (following every hop, not just the one-level
            # fingerprint peek) to an actual regular file -- a symlink
            # aimed at a directory (or anything else non-regular) is never
            # a real command, even if that target happens to be
            # "executable" by directory-traversal convention.
            if not os.path.isfile(candidate):
                continue

            if not os.access(candidate, os.X_OK):
                continue  # exists but not executable -- a real shell would skip it too

            hits.append(
                (
                    name,
                    dir_index,
                    dir_path,
                    "1" if is_symlink else "0",
                    link_target.replace(FS, "?").replace(RS, "?"),
                    fingerprint(dir_path, resolved_abs),
                )
            )

    packed = RS.join(FS.join([h[0], str(h[1]), h[2], h[3], h[4], h[5]]) for h in hits)
    watchlist_packed = RS.join(effective)

    output = {
        "ok": True,
        "path_dirs_walked": len(dirs),
        "path_dirs_existing": existing_count,
        "path_dirs_missing": len(dirs) - existing_count,
        "watchlist_count": len(effective),
        "builtin_count": len(BUILTIN_WATCHLIST),
        "extra_valid_count": extra_valid_count,
        "extra_ignored_count": len(ignored),
        "hit_count": len(hits),
        "watchlist_packed": watchlist_packed,
        "packed": packed,
    }
    if ignored:
        output["extra_ignored_note"] = (
            str(len(ignored))
            + " extra command(s) ignored (letters, digits, dash, underscore, dot only): "
            + ", ".join(ignored)[:200]
        )

    print(json.dumps(output))


main()
