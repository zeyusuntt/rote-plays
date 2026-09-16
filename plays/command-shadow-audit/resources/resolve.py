"""Join parse_rc's rc-file definitions against walk_path's $PATH hits, per
watchlist command: who actually wins when you type it, and what does that
silently shadow.

This is the ONLY script in this play that ever spawns a child process, and
ONLY for a fixed, hardcoded allowlist of version-probe binaries -- never
anything derived from $commands or from what happens to be on $PATH. Even
if a user passes commands=rm or commands=ssh (both real watchlist entries),
neither is ever executed here: SAFE_VERSION_ALLOWLIST below is a closed,
hardcoded set, checked by exact string equality against the command's own
name, and nothing outside this script ever grows it.

argv[1]  packed rc-file definitions from parse_rc (kind|name|value|file|
         line|file_seq|conditional, FS/RS -- see parse_rc.py); empty string
         is valid ("no definitions found")
argv[2]  watchlist_packed from walk_path -- RS-joined command names, in
         effective-watchlist order; this is the authoritative list of
         commands this run reports on, including ones with zero PATH hits
argv[3]  packed PATH hits from walk_path (command|dir_index|dir|is_symlink|
         link_target|fingerprint, FS/RS -- see walk_path.py); empty string
         is valid ("nothing found on PATH for anything")
argv[4]  probe_versions -- 1 to read `--version` from the fixed allowlist
         below, 0 for pure path analysis with no execution at all. Defaults
         to 0 in this play's own frontmatter (main.ts) -- version probing
         is opt-in, never on by default, because it is the only thing this
         whole play ever executes; see PROBE SAFETY below for what running
         with it on does and does not trust. Must int-parse; a non-integer
         here is bad step wiring, not an expected absence -- hard fault,
         stderr + exit 2, matching this play's other scripts and the house
         pattern (main.ts's own param_type: integer gate should already
         prevent this).

WINNER, per command -- the shell's own precedence, stated explicitly here
because it is the one number this whole play hangs on: a shell FUNCTION
beats an alias beats the first PATH hit. Verified empirically on this
machine's own zsh 5.9 (a function defined after, or before, a same-named
alias wins either way -- zsh gives functions structural priority over
aliases). This differs from bash, where alias substitution is a lexical,
parse-time step that runs before function lookup, so a same-named alias
actually wins there; that is a known, disclosed nuance of applying one
unified precedence rule across rc files written for either shell, not a
claim this script verifies per-shell at report time. Because that nuance
is real (not just theoretical), whenever BOTH a function and an alias are
defined for the same command, the winner object carries
shell_precedence_ambiguous=true: the reported type is still "function"
(this script's stated zsh-verified default), but a bash session sourcing
these same files would run the alias instead -- this script does not know,
and does not guess, which shell will actually read them, so it reports
the ambiguity rather than silently picking one as though it were certain.

Same-named alias/function definitions can appear in more than one parsed
rc file; the one used as "the" winner is the one with the largest
(file_seq, line) -- see parse_rc.py's own docstring for exactly what that
ordering does and does not claim.

SHADOWS, per command:
  winner is a function -- every alias definition AND every PATH hit is
    shadowed (a function pre-empts both, same as an alias does -- see
    below).
  winner is an alias -- every OTHER alias definition (rare: more than one
    rc file defining the same alias name) AND every PATH hit is shadowed.
    An alias is real-shell text substitution that happens before PATH
    lookup is ever reached, so it silently pre-empts a real binary exactly
    the way a function does; this play does not treat alias-shadow as a
    lesser case just because it is a leaf in the story below.
  winner is the first PATH hit -- every LATER PATH hit for the same name
    is shadowed (the later-PATH-duplicate case the play's own title is
    named for).
  winner is none (name not found anywhere) -- nothing to shadow.

SEVERITY -- five tiers. The spec anchors three of them explicitly; the
other two (medium, none) are this script's own honest fill of the gaps
that are left over once those three are taken as fixed points:
  highest -- winner is a FUNCTION and at least one real PATH hit exists
             underneath it. This is the exact failure class that broke a
             real toolchain on a real machine: a shell function silently
             standing in for a real binary.
  high    -- winner is an ALIAS shadowing at least one real PATH hit (the
             same silent-substitution danger as `highest`, one tier down
             because the spec singles out the function case by name); OR
             two or more PATH hits for this command were probed and their
             FEATURE versions (the first two dot-components, e.g. "3.10"
             out of "3.10.9") disagree -- the anaconda-python3-vs-newer-
             python3 failure class this play must surface (a common real
             collision: an Anaconda python3 sits earlier on PATH than a
             newer interpreter -- different tomllib availability, same
             command). Comparison is deliberately major.MINOR, not just
             major: CPython's own scheme has kept major=3 for the entire
             Python 3 era, so a strict first-component-only compare would
             call 3.10 and 3.14 "the same version" and silently miss
             exactly the case this play exists to catch. A genuine
             first-component difference (Node 24 vs Node 21) is still
             caught the same way, since major.minor differing is implied
             by major differing.
  medium  -- two or more PATH hits exist for this command but version
             comparison could not be done (probe_versions=0, this command
             is not on SAFE_VERSION_ALLOWLIST, or a probe failed/timed
             out) -- a real duplicate-shadow situation exists; this script
             just cannot say whether it is a version mismatch or benign.
  info    -- two or more PATH hits exist and every probed feature version
             among them agrees.
  none    -- nothing is shadowed at all for this command (a single PATH
             hit and no alias/function, or the command was not found
             anywhere).

VERSION PROBES (only when probe_versions=1, itself opt-in -- see argv[4]
above): one subprocess call per DISTINCT (command, absolute path) PATH hit
whose command name is in SAFE_VERSION_ALLOWLIST, run directly as
[trusted_real_path, *version_argv] -- never through a shell, never via
PATH re-lookup (that would just find the winner again for every probe and
defeat the entire comparison). Bounded concurrency (a small thread pool;
each subprocess.run call still carries its own independent 3-second
timeout regardless of pool size) and a hard per-call 3-second timeout. A
probe that fails or times out is recorded as such on that one hit and
never aborts the run.

PROBE SAFETY (see is_trusted_executable()): a PATH hit is data walk_path.py
collected from directories this process's own $PATH happened to name --
including, deliberately, version-manager directories (asdf, nvm, pyenv,
rbenv, conda/anaconda, brew) this play exists to compare across, so this
script cannot simply refuse to probe anything outside a fixed system-only
directory list without defeating its own stated purpose (the anaconda-vs-
homebrew python3 case in the module docstring above IS a non-system-root
probe). Instead, before ANY probe subprocess is ever started, the exact
candidate is resolved with a full realpath() (every symlink hop, not just
walk_path's own one-level peek) and must pass ALL of: the resolved target
is a regular file; it is owned by root (uid 0) or by this process's own
real user (never a different, unprivileged owner -- a classic sign of a
planted binary on a shared machine); it is not group- or world-writable;
and its containing directory is not world-writable without the sticky bit
(the same TOCTOU guard sudo's own secure-path checks use). Any failed
check is a normal, disclosed skip (version=None, a version_error string
naming the reason) -- fail closed, never a crash, and the probe subprocess
is simply never started for that hit.

Emits one JSON object on stdout, always exit 0 once argv parses --
malformed input records are tolerated (dropped, counted, folded into
`warning`), never crash the join:
    {"ok": true,
     "warning": "<optional -- malformed record counts>",
     "commands": [{name, winner: {type, source, value, conditional,
        shell_precedence_ambiguous, fingerprint, is_symlink, link_target,
        version, version_error -- fingerprint/is_symlink/link_target/
        version/version_error present only when type is "path";
        conditional only when type is "function" or "alias";
        shell_precedence_ambiguous only when type is "function"}, shadows:
        {aliases: [...], path_hits: [...]}, path_hit_count, probed,
        severity}, ...],
     "path_exports": [{file, line, value, conditional}, ...],
     "totals": {"total_commands", "shadowed_by_function",
        "shadowed_by_alias", "shadowed_by_path_dup", "clean"}}
"""

import json
import os
import re
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

FS, RS = chr(31), chr(30)

DEF_FIELDS = 7  # kind, name, value, file, line, file_seq, conditional -- see parse_rc.py
HIT_FIELDS = 6  # command, dir_index, dir, is_symlink, link_target, fingerprint -- see walk_path.py

# Fixed, hardcoded allowlist -- see module docstring. Never derived from
# argv, never derived from the watchlist, never grown at runtime.
SAFE_VERSION_ALLOWLIST = {"python3", "python", "node", "git", "curl", "ruby", "go", "rustc", "java"}
VERSION_ARGV = {
    "python3": ["--version"],
    "python": ["--version"],
    "node": ["--version"],
    "git": ["--version"],
    "curl": ["--version"],
    "ruby": ["--version"],
    "go": ["version"],
    "rustc": ["--version"],
    "java": ["-version"],
}
PROBE_TIMEOUT_S = 3
PROBE_MAX_WORKERS = 4

VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+){1,3}")


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def parse_int_arg(index, name, default):
    raw = arg(index, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        sys.stderr.write(name + " must be an integer, got: " + raw + "\n")
        sys.exit(2)


def clamp(value, lo, hi):
    return max(lo, min(hi, value))


def is_trusted_executable(candidate):
    """Fail-closed pre-exec trust check for a version-probe candidate --
    see module docstring PROBE SAFETY. Returns (real_path, None) when
    trusted, or (None, reason) when not; a rejection is a normal, disclosed
    skip, never a crash. Resolves the candidate's REAL path (following
    every symlink hop, not just walk_path's own one-level peek) and only
    trusts it when the resolved target is a regular file, is owned by root
    (uid 0) or by this process's own real user, is not group- or
    world-writable, and does not live in a world-writable directory that
    lacks the sticky bit."""
    real = os.path.realpath(candidate)
    try:
        file_stat = os.stat(real)
    except OSError as exc:
        return None, "cannot stat resolved path: " + str(exc)
    if not stat.S_ISREG(file_stat.st_mode):
        return None, "resolved path is not a regular file"
    if file_stat.st_uid not in (0, os.getuid()):
        return None, "resolved path is owned by an untrusted user"
    if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None, "resolved path is group- or world-writable"
    parent = os.path.dirname(real) or "/"
    try:
        parent_stat = os.stat(parent)
    except OSError as exc:
        return None, "cannot stat containing directory: " + str(exc)
    if (parent_stat.st_mode & stat.S_IWOTH) and not (parent_stat.st_mode & stat.S_ISVTX):
        return None, "containing directory is world-writable without a sticky bit"
    return real, None


def unpack(packed, field_count):
    """Generic FS/RS unpack. Returns (rows_as_field_lists, raw_record_count)
    -- see enumerate.py/classify.py in agent-resource-audit for the same
    reconciliation shape this mirrors."""
    if not packed:
        return [], 0
    rows, raw_count = [], 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_count += 1
        fields = record.split(FS)
        if len(fields) != field_count:
            continue
        rows.append(fields)
    return rows, raw_count


def main():
    packed_defs = arg(1, "")
    watchlist_packed = arg(2, "")
    packed_hits = arg(3, "")
    # Default (when argv[4] is genuinely absent, e.g. direct manual
    # invocation) is 0 -- probes off, matching main.ts's own frontmatter
    # default: opt-in only, never on by default. See PROBE SAFETY above.
    probe_versions = clamp(parse_int_arg(4, "probe_versions", 0), 0, 1)

    def_rows, def_raw_count = unpack(packed_defs, DEF_FIELDS)
    hit_rows, hit_raw_count = unpack(packed_hits, HIT_FIELDS)
    dropped_defs = def_raw_count - len(def_rows)
    dropped_hits = hit_raw_count - len(hit_rows)

    watchlist = [name for name in watchlist_packed.split(RS) if name] if watchlist_packed else []

    # --- index definitions by command name ---
    aliases_by_name = {}
    functions_by_name = {}
    path_exports = []
    for kind, name, value, file, line_s, seq_s, conditional_s in def_rows:
        try:
            line, seq = int(line_s), int(seq_s)
        except ValueError:
            continue
        conditional = conditional_s == "1"
        record = {"file": file, "line": line, "value": value, "_seq": seq, "conditional": conditional}
        if kind == "alias":
            aliases_by_name.setdefault(name, []).append(record)
        elif kind == "function":
            functions_by_name.setdefault(name, []).append(record)
        elif kind == "export_path":
            path_exports.append(
                {"file": file, "line": line, "value": value, "_seq": seq, "conditional": conditional}
            )

    path_exports.sort(key=lambda r: (r["_seq"], r["line"]))
    for r in path_exports:
        del r["_seq"]

    # --- index PATH hits by command name, ordered by dir_index ---
    hits_by_name = {}
    for command, dir_index_s, dir_path, is_symlink_s, link_target, fp in hit_rows:
        try:
            dir_index = int(dir_index_s)
        except ValueError:
            continue
        hits_by_name.setdefault(command, []).append(
            {
                "dir": dir_path,
                "dir_index": dir_index,
                "is_symlink": is_symlink_s == "1",
                "link_target": link_target,
                "fingerprint": fp,
                "version": None,
                "version_error": None,
            }
        )
    for hits in hits_by_name.values():
        hits.sort(key=lambda h: h["dir_index"])

    # --- collect version probe jobs (only when probe_versions=1) ---
    probe_jobs = []  # (hit_dict, absolute_path)
    if probe_versions == 1:
        for command in watchlist:
            if command not in SAFE_VERSION_ALLOWLIST:
                continue
            for hit in hits_by_name.get(command, []):
                probe_jobs.append((command, hit))

    def run_probe(job):
        command, hit = job
        candidate = hit["dir"].rstrip("/") + "/" + command
        trusted_path, reject_reason = is_trusted_executable(candidate)
        if trusted_path is None:
            return hit, None, "skipped (untrusted binary): " + reject_reason
        argv = [trusted_path] + VERSION_ARGV[command]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT_S
            )
        except subprocess.TimeoutExpired:
            return hit, None, "timed out after " + str(PROBE_TIMEOUT_S) + "s"
        except OSError as exc:
            return hit, None, "exec failed: " + str(exc)
        combined = ((proc.stdout or "") + " " + (proc.stderr or "")).strip()
        match = VERSION_TOKEN_RE.search(combined)
        if match:
            return hit, match.group(0), None
        return hit, None, "no version token in output: " + combined[:80]

    if probe_jobs:
        with ThreadPoolExecutor(max_workers=PROBE_MAX_WORKERS) as pool:
            for hit, version, error in pool.map(run_probe, probe_jobs):
                hit["version"] = version
                hit["version_error"] = error

    # --- resolve winner + shadows + severity per watchlist command ---
    def last_def(defs):
        return max(defs, key=lambda d: (d["_seq"], d["line"])) if defs else None

    commands_out = []
    totals = {
        "total_commands": len(watchlist),
        "shadowed_by_function": 0,
        "shadowed_by_alias": 0,
        "shadowed_by_path_dup": 0,
        "clean": 0,
    }

    for command in watchlist:
        func_defs = functions_by_name.get(command, [])
        alias_defs = aliases_by_name.get(command, [])
        path_hits = hits_by_name.get(command, [])
        probed = probe_versions == 1 and command in SAFE_VERSION_ALLOWLIST and len(path_hits) > 0

        winner_func = last_def(func_defs)
        winner_alias = last_def(alias_defs)

        def clean_hit(h):
            return {k: v for k, v in h.items() if k != "dir_index"}

        if winner_func is not None:
            winner = {
                "type": "function",
                "source": winner_func["file"] + ":" + str(winner_func["line"]),
                "value": None,
                "conditional": winner_func["conditional"],
                # See module docstring WINNER: zsh gives functions priority
                # over a same-named alias, bash gives the alias priority --
                # when both exist for this command the "shell's own
                # precedence" this play reports is genuinely shell-dependent.
                "shell_precedence_ambiguous": len(alias_defs) > 0,
            }
            shadowed_aliases = [
                {"file": d["file"], "line": d["line"], "value": d["value"], "conditional": d["conditional"]}
                for d in alias_defs
            ]
            shadowed_hits = [clean_hit(h) for h in path_hits]
            totals["shadowed_by_function"] += 1
        elif winner_alias is not None:
            winner = {
                "type": "alias",
                "source": winner_alias["file"] + ":" + str(winner_alias["line"]),
                "value": winner_alias["value"],
                "conditional": winner_alias["conditional"],
            }
            other_aliases = [d for d in alias_defs if d is not winner_alias]
            shadowed_aliases = [
                {"file": d["file"], "line": d["line"], "value": d["value"], "conditional": d["conditional"]}
                for d in other_aliases
            ]
            shadowed_hits = [clean_hit(h) for h in path_hits]
            totals["shadowed_by_alias"] += 1
        elif path_hits:
            first = path_hits[0]
            winner = {
                "type": "path",
                "source": first["dir"],
                "value": None,
                "fingerprint": first["fingerprint"],
                "is_symlink": first["is_symlink"],
                "link_target": first["link_target"],
                "version": first["version"],
                "version_error": first["version_error"],
            }
            shadowed_aliases = []
            shadowed_hits = [clean_hit(h) for h in path_hits[1:]]
            if shadowed_hits:
                totals["shadowed_by_path_dup"] += 1
            else:
                totals["clean"] += 1
        else:
            winner = {"type": "none", "source": None, "value": None}
            shadowed_aliases = []
            shadowed_hits = []
            totals["clean"] += 1

        # Severity -- see module docstring for the full five-tier rationale.
        if winner["type"] == "function" and path_hits:
            severity = "highest"
        elif winner["type"] == "alias" and path_hits:
            severity = "high"
        elif len(path_hits) >= 2:
            versions = [h["version"] for h in path_hits if h["version"]]
            if not probed or len(versions) < 2:
                severity = "medium"
            else:
                # major.minor, not just major -- see module docstring SEVERITY
                # section for why (CPython's own major has stayed "3" across
                # the tomllib-defining 3.10-vs-3.11 boundary this play must
                # catch).
                feature_versions = {".".join(v.split(".")[:2]) for v in versions}
                severity = "high" if len(feature_versions) >= 2 else "info"
        else:
            severity = "none"

        commands_out.append(
            {
                "name": command,
                "winner": winner,
                "shadows": {"aliases": shadowed_aliases, "path_hits": shadowed_hits},
                "path_hit_count": len(path_hits),
                "probed": probed,
                "severity": severity,
            }
        )

    output = {
        "ok": True,
        "commands": commands_out,
        "path_exports": path_exports,
        "totals": totals,
    }

    warnings = []
    if dropped_defs > 0:
        warnings.append(str(dropped_defs) + " malformed definition row(s) from parse_rc were skipped")
    if dropped_hits > 0:
        warnings.append(str(dropped_hits) + " malformed PATH-hit row(s) from walk_path were skipped")
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
