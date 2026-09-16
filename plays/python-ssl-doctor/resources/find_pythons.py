"""Find EVERY python3 (and bare python) executable on THIS machine's PATH --
all hits, not just the one `python3` itself would resolve to -- and
fingerprint each one's install source, version, TLS linkage, certifi
presence, and SSL_CERT_FILE/REQUESTS_CA_BUNDLE overrides. Shadowing is the
whole point: the broken interpreter may not be the one a human tests by
hand, it may be the one a cron job or a background tool actually runs.

PATH walk: every directory on PATH is listed once (missing/unreadable
directories are skipped, never a fault); a candidate name matches exactly
`python`, `python3`, or `python3.<digits>` (a strict regex, so
`python3-config`, `python3.11-gdb.py`, and similar dev-tool names are never
mistaken for a real interpreter) and must be an executable regular file.

Dedup by REALPATH: two different PATH entries that resolve to the same
real file (e.g. a `/usr/local/bin/python3` symlink pointing at the same
binary as a python.org framework build) are the same install, reported
once. Within one directory, `python3` is preferred as the display path
over a version-pinned `python3.NN` name, which is preferred over the bare
`python` name, purely so the retained path reads naturally; this never
changes WHICH interpreter is discovered, only which of its several PATH
names is shown.

TRUST BOUNDARY, disclosed explicitly, not just implied by "already on
PATH": this script executes EVERY matching candidate it finds, in EVERY
matching PATH directory -- not only the one a bare `python3` resolution
would ever reach. That breadth is the entire point (a shadowed interpreter
is, by definition, one a human's own `python3` never resolves to), so this
script cannot simply refuse to run anything past the first PATH hit
without defeating its own purpose. But a candidate is only a NAME match
(`python`, `python3`, or `python3.N`, executable, regular file) -- nothing
about that name proves the file is really a Python interpreter, or that
this user is the one who put it there. A same-named file anywhere on PATH
that is actually malicious or merely broken would otherwise run with this
user's own privileges, TWICE (once for this script's own fingerprint
probe below, once more for probe_ssl.py's TLS handshake). To make that
breadth safe rather than merely disclosed, every candidate is fail-closed
trust-checked immediately before it is ever executed -- see
is_trusted_executable() below, the same TOCTOU-safe realpath/ownership/
writability check command-shadow-audit's own resolve.py uses for its
opt-in version probes, applied here to every discovered candidate since
here every candidate is executed by design, not opt-in. A candidate that
fails that check is still reported as discovered (fingerprinting is real,
disclosed data the user should see) but it is never run; the rejection
reason is recorded in fingerprint_error, never a crash, never a silent
skip.

Fingerprinting: for every TRUSTED discovered path, this script runs a
tiny, fixed `-c` script (no user input, no arguments) with the DISCOVERED
interpreter's own TRUSTED, realpath-resolved binary -- never anything
downloaded or otherwise supplied by this play. That probe reports
sys.prefix (the authoritative signal for a Command Line Tools /
Xcode-provided python, whose own binary path gives no hint), the python
version, ssl.OPENSSL_VERSION, whether the `certifi` package is importable
and where its bundle lives, and whether SSL_CERT_FILE / REQUESTS_CA_BUNDLE
are set for that interpreter's environment -- as NAMES + a set/unset flag
+ whether the file the variable points at exists on disk, never the path
value itself and never file contents (the same trust line every play in
this fleet uses: env var VALUES are never printed).

Source classification ranks INTRINSIC evidence -- conda_meta (a direct
filesystem check the interpreter performs on its OWN sys.prefix), then
normalized sys.prefix (the interpreter's own self-report), then realpath
(the resolved target file) -- strictly ahead of the raw, AS-DISCOVERED
PATH candidate, which is merely an alias (e.g. a symlink sitting inside an
`anaconda3/` directory that actually resolves to a homebrew or python.org
install elsewhere) and is never used for classification when better
evidence exists. When ranked intrinsic signals genuinely disagree with
each other, that conflict is reported as "unknown" rather than guessed.
The raw path alias is consulted only as a last resort, when fingerprinting
failed entirely and no intrinsic evidence exists at all; the python is
still discovered and still handed to the TLS probe step either way, just
with less identifying detail. See classify_source() below.

This step is a best-effort read with no essential capability to fail on --
an empty or unset PATH, or every fingerprint probe timing out, is an
honest degrade (an empty or thin "pythons" list, plus a warning), never a
fault. Always exits 0.

Emits one JSON object on stdout:
    {
      "ok": true,
      "pythons": [
        {"id", "path", "path_redacted", "realpath", "source",
         "version", "sys_prefix", "openssl_version",
         "certifi": {"present", "path", "version"} | {"present": false},
         "env_overrides": {
             "SSL_CERT_FILE": {"set", "path_exists"},
             "REQUESTS_CA_BUNDLE": {"set", "path_exists"}
         },
         "fingerprint_ok", "fingerprint_error"},
        ...
      ],
      "count": N,
      "path_dirs_scanned": N,
      "candidates_found": N,
      "duplicates_deduped": N,
      "warning": null | "PATH is empty or unset -- nothing to discover"
    }
"""

import json
import os
import re
import stat
import subprocess
import sys
import time

CANDIDATE_RE = re.compile(r"^python(3(\.\d+)?)?$")

FINGERPRINT_TIMEOUT_S = 4
SCRIPT_BUDGET_S = 13.0  # step timeout_ms is 15000; leaves headroom for
                         # PATH walk + JSON encode + process overhead so a
                         # slow/hanging python degrades this SCRIPT's own
                         # output instead of the whole step getting killed
                         # by the runner with no output at all.

# A fixed, no-argument, no-user-input script run with EACH discovered
# interpreter via -c. Never prints an env var VALUE or file contents --
# only names, booleans, and short version strings.
FINGERPRINT_SCRIPT = r"""
import json, os, sys
out = {}
try:
    out["version"] = sys.version.split()[0]
except Exception:
    out["version"] = None
try:
    out["sys_prefix"] = sys.prefix
except Exception:
    out["sys_prefix"] = None
try:
    out["conda_meta"] = os.path.isdir(os.path.join(sys.prefix, "conda-meta"))
except Exception:
    out["conda_meta"] = False
try:
    import ssl
    out["openssl_version"] = ssl.OPENSSL_VERSION
except Exception:
    out["openssl_version"] = None
try:
    import importlib.util as iu
    spec = iu.find_spec("certifi")
    if spec is None:
        out["certifi"] = {"present": False}
    else:
        import certifi
        out["certifi"] = {
            "present": True,
            "path": certifi.where(),
            "version": getattr(certifi, "__version__", None),
        }
except Exception as exc:
    out["certifi"] = {"present": False, "probe_error": type(exc).__name__}
env = {}
for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
    val = os.environ.get(name)
    if val is None:
        env[name] = {"set": False, "path_exists": None}
    else:
        try:
            exists = os.path.exists(val)
        except Exception:
            exists = None
        env[name] = {"set": True, "path_exists": exists}
out["env_overrides"] = env
print(json.dumps(out))
"""


def candidate_sort_key(name):
    if name == "python3":
        return (0, name)
    if name.startswith("python3."):
        return (1, name)
    return (2, name)


def find_candidates():
    """Walk every PATH directory once; return (ordered candidate paths,
    directories actually scanned). Order preserves PATH precedence, and
    within one directory prefers python3 > python3.NN > python, purely for
    a nicer retained display path after dedup (see module docstring)."""
    path_env = os.environ.get("PATH", "")
    dirs = [d for d in path_env.split(os.pathsep) if d]
    candidates = []
    scanned = 0
    for d in dirs:
        try:
            entries = os.listdir(d)
        except OSError:
            continue
        scanned += 1
        matches = [n for n in entries if CANDIDATE_RE.match(n)]
        matches.sort(key=candidate_sort_key)
        for name in matches:
            full = os.path.join(d, name)
            try:
                if os.path.isfile(full) and os.access(full, os.X_OK):
                    candidates.append(full)
            except OSError:
                continue
    return candidates, scanned


def realpath_safe(p):
    try:
        return os.path.realpath(p)
    except OSError:
        return p


HOME = os.path.expanduser("~")


def redact_home(p):
    """Collapse this user's own home directory prefix to `~` for the
    table's display path -- a UX nicety, not a secrecy boundary (this is a
    report about the user's own machine, for that same user), but the play
    spec calls for a redacted display path column, so it is honored
    literally here rather than in the presentation layer, where a reliable
    home-directory value is not guaranteed to be available."""
    if not p:
        return p
    if p == HOME or p.startswith(HOME + os.sep):
        return "~" + p[len(HOME):]
    return p


def is_trusted_executable(candidate):
    """Fail-closed pre-exec trust check -- see module docstring TRUST
    BOUNDARY. Returns (real_path, None) when trusted, or (None, reason)
    when not; a rejection is a normal, disclosed skip, never a crash.
    Resolves the candidate's REAL path (following every symlink hop, not
    just a one-level peek) and only trusts it when the resolved target is
    a regular file, is owned by root (uid 0) or by this process's own real
    user, is not world-writable, is not writable by a group this user does
    not belong to, and does not live in a world-writable directory that
    lacks the sticky bit -- the same TOCTOU guard sudo's own secure-path
    checks use, and the same shape command-shadow-audit's resolve.py uses
    for its own version probes (is_trusted_executable() there).

    One deliberate, measured refinement over that sibling check: a bare
    group-write bit is trusted when the file's group is one this same
    user already belongs to (verified live on this machine: a default
    macOS conda/Anaconda install ships its own interpreter binary mode
    0775, group `staff` -- this user's own primary group -- which a
    strict "reject any group-write bit" rule would wrongly brand
    untrusted and silently stop fingerprinting/probing, defeating this
    play's most common real-world case for no real safety gain, since a
    group the user is already a member of grants no privilege beyond what
    that user's own account already has). Writable by a group the user is
    NOT a member of is still rejected -- that is the actual TOCTOU/planted-
    binary risk this check exists to catch."""
    real = os.path.realpath(candidate)
    try:
        file_stat = os.stat(real)
    except OSError as exc:
        return None, "cannot stat resolved path: " + type(exc).__name__
    if not stat.S_ISREG(file_stat.st_mode):
        return None, "resolved path is not a regular file"
    if file_stat.st_uid not in (0, os.getuid()):
        return None, "resolved path is owned by an untrusted user"
    if file_stat.st_mode & stat.S_IWOTH:
        return None, "resolved path is world-writable"
    if file_stat.st_mode & stat.S_IWGRP:
        try:
            my_groups = set(os.getgroups())
        except OSError:
            my_groups = set()
        my_groups.add(os.getgid())
        if file_stat.st_gid not in my_groups:
            return None, "resolved path is writable by a group this user does not belong to"
    parent = os.path.dirname(real) or "/"
    try:
        parent_stat = os.stat(parent)
    except OSError as exc:
        return None, "cannot stat containing directory: " + type(exc).__name__
    if (parent_stat.st_mode & stat.S_IWOTH) and not (parent_stat.st_mode & stat.S_ISVTX):
        return None, "containing directory is world-writable without a sticky bit"
    return real, None


def classify_pattern(value):
    """Pattern-match ONE piece of evidence in isolation -- never combined
    with another source of evidence into a shared haystack (see
    classify_source, and finding #2 in this play's own hardening review:
    blending path/realpath/prefix into one string let a PATH alias living
    under an `anaconda3/` directory outrank its own measured prefix).
    Returns a source label, or None when nothing matches."""
    if not value:
        return None
    if any(
        s in value
        for s in ("/anaconda3/", "/anaconda/", "/miniconda3/", "/miniconda/", "/miniforge3/", "/mambaforge/")
    ):
        return "conda-anaconda"
    if "/.pyenv/" in value:
        return "pyenv"
    if "/.local/share/uv/" in value:
        return "uv-managed"
    if any(s in value for s in ("/homebrew/", "/Cellar/", "/linuxbrew/")):
        return "homebrew"
    if "Xcode.app" in value or "CommandLineTools" in value:
        return "system CLT"
    if "/Library/Frameworks/Python.framework/" in value:
        return "python.org framework build"
    return None


def classify_source(path, real, prefix, conda_meta):
    """Ranked, intrinsic-evidence-first classification (see module
    docstring). Priority, most trustworthy first:
      1. conda_meta        a filesystem check the interpreter performed on
                            its OWN sys.prefix -- the strongest signal.
      2. sys.prefix         the interpreter's own self-report; cannot be
                            spoofed by a PATH symlink pointing elsewhere.
      3. realpath           the resolved target file -- still a filesystem
                            fact, though the interpreter did not report it
                            about itself.
      4. path (PATH alias)  the raw, AS-DISCOVERED candidate; used ONLY
                            when prefix is unavailable (fingerprinting
                            failed or timed out) AND realpath matched
                            nothing -- see docstring.
    When prefix and realpath both yield a hit and they DISAGREE, that is a
    genuine conflict (e.g. a symlink under `anaconda3/` whose realpath and
    measured prefix both point at homebrew instead), and the honest answer
    is "unknown", not a guess."""
    if conda_meta:
        return "conda-anaconda"
    prefix_hit = classify_pattern(prefix)
    real_hit = "system CLT" if real in ("/usr/bin/python3", "/usr/bin/python") else classify_pattern(real)
    if prefix_hit and real_hit:
        return prefix_hit if prefix_hit == real_hit else "unknown"
    if prefix_hit:
        return prefix_hit
    if real_hit:
        return real_hit
    if prefix is None:
        # No intrinsic evidence at all -- fingerprinting never ran or
        # never returned sys.prefix. The raw PATH alias is the only
        # evidence left; used purely so a still-unfingerprinted python
        # gets a best-effort label instead of none (see docstring).
        return classify_pattern(path) or "unknown"
    # Fingerprinting succeeded but neither prefix nor realpath matched any
    # known pattern -- an honest "unknown", never a guess from the raw
    # PATH alias (that would reintroduce the exact bug this ranking fixes).
    return "unknown"


def fingerprint(path, deadline):
    """Trust-checks `path` (see is_trusted_executable()), then, only when
    trusted, runs FINGERPRINT_SCRIPT with its REALPATH-resolved target --
    never the raw, as-discovered candidate, so the file actually executed
    is exactly the one that passed the trust check (no TOCTOU gap). Bounded
    by both a fixed per-probe timeout and whatever remains of this script's
    own overall deadline -- whichever is smaller. Returns
    (data_dict_or_None, error_or_None)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0.3:
        return None, "not fingerprinted: script time budget exhausted"
    trusted_path, reject_reason = is_trusted_executable(path)
    if trusted_path is None:
        return None, "not fingerprinted: untrusted executable, not run (%s)" % reject_reason
    budget = max(0.3, min(FINGERPRINT_TIMEOUT_S, remaining))
    try:
        proc = subprocess.run(
            [trusted_path, "-c", FINGERPRINT_SCRIPT],
            capture_output=True,
            text=True,
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        return None, "fingerprint probe timed out after %.1fs" % budget
    except OSError as exc:
        return None, "fingerprint probe failed to start: " + type(exc).__name__
    if proc.returncode != 0:
        return None, (
            "fingerprint probe exited %d -- child stderr not echoed here "
            "(may be arbitrary output from a non-python or misbehaving match)" % proc.returncode
        )
    try:
        data = json.loads(proc.stdout.strip())
    except ValueError:
        return None, "fingerprint probe output did not parse as JSON"
    if not isinstance(data, dict):
        return None, "fingerprint probe output was not a JSON object"
    return data, None


def main():
    start = time.monotonic()
    deadline = start + SCRIPT_BUDGET_S

    path_env = os.environ.get("PATH", "")
    if not path_env.strip():
        print(
            json.dumps(
                {
                    "ok": True,
                    "pythons": [],
                    "count": 0,
                    "path_dirs_scanned": 0,
                    "candidates_found": 0,
                    "duplicates_deduped": 0,
                    "warning": "PATH is empty or unset -- nothing to discover",
                }
            )
        )
        return

    candidates, scanned = find_candidates()

    seen_real = {}
    ordered_real = []
    for path in candidates:
        real = realpath_safe(path)
        if real not in seen_real:
            seen_real[real] = path
            ordered_real.append(real)

    duplicates_deduped = len(candidates) - len(ordered_real)

    pythons = []
    for i, real in enumerate(ordered_real):
        path = seen_real[real]
        data, err = fingerprint(path, deadline)
        if data is not None:
            source = classify_source(
                path, real, data.get("sys_prefix"), bool(data.get("conda_meta"))
            )
            pythons.append(
                {
                    "id": i,
                    "path": path,
                    "path_redacted": redact_home(path),
                    "realpath": real,
                    "source": source,
                    "version": data.get("version"),
                    "sys_prefix": data.get("sys_prefix"),
                    "openssl_version": data.get("openssl_version"),
                    "certifi": data.get("certifi") or {"present": False},
                    "env_overrides": data.get("env_overrides")
                    or {
                        "SSL_CERT_FILE": {"set": False, "path_exists": None},
                        "REQUESTS_CA_BUNDLE": {"set": False, "path_exists": None},
                    },
                    "fingerprint_ok": True,
                    "fingerprint_error": None,
                }
            )
        else:
            source = classify_source(path, real, None, False)
            pythons.append(
                {
                    "id": i,
                    "path": path,
                    "path_redacted": redact_home(path),
                    "realpath": real,
                    "source": source,
                    "version": None,
                    "sys_prefix": None,
                    "openssl_version": None,
                    "certifi": {"present": False},
                    "env_overrides": {
                        "SSL_CERT_FILE": {"set": False, "path_exists": None},
                        "REQUESTS_CA_BUNDLE": {"set": False, "path_exists": None},
                    },
                    "fingerprint_ok": False,
                    "fingerprint_error": err,
                }
            )

    warning = None
    if not pythons:
        warning = "no python3 or python executable found on PATH"

    print(
        json.dumps(
            {
                "ok": True,
                "pythons": pythons,
                "count": len(pythons),
                "path_dirs_scanned": scanned,
                "candidates_found": len(candidates),
                "duplicates_deduped": duplicates_deduped,
                "warning": warning,
            }
        )
    )


main()
