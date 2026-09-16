"""Discover MCP server configs across installed harnesses on THIS machine,
and classify -- AT READ TIME, before anything is packed or printed -- the
SHAPE of every env var value each server config declares.

Read-only: reads the same fixed, well-known set of user-level config files
mcp-doctor's discover.py already established, ported here verbatim for
paths/parsers/TOML-fallback (see PORTED below), never a filesystem walk for
a stray project .mcp.json somewhere under ~/Documents et al.:

  ~/.claude.json                                       (Claude Code: global
                                                          mcpServers, plus
                                                          each project's own)
  ~/Library/Application Support/Claude/
      claude_desktop_config.json                        (Claude Desktop)
  ~/.cursor/mcp.json                                    (Cursor)
  ~/.codex/config.toml                                  ([mcp_servers.*]
                                                          tables, stdlib
                                                          tomllib)
  ~/.codeium/windsurf/mcp_config.json                   (Windsurf)

Each source is parsed independently and defensively: a missing file, an
empty/invalid JSON or TOML file, or an unexpected shape (root not an
object, or the mcpServers/mcp_servers map itself not an object) degrades
only that one source -- status "not-found" / "error: ..." respectively --
never the whole script, and never silently reported as "ok" with nothing
found.

THE ONE HARD INVARIANT THIS SCRIPT EXISTS TO PROTECT: an env var's raw
VALUE is read from disk, classified, and reduced to (shape, a 4-character
preview, a length) IMMEDIATELY, in this same function call -- it never
survives as a full string past classify_value_shape() below, is never
packed whole, and is never printed. Every downstream consumer of this
script's output (audit_configs.py, one step over; main.ts's presentation;
this play's own JSON result) only ever sees the already-reduced record.
This is a stricter invariant than mcp-doctor's discover.py, which solved
the same problem by never reading env values into its output AT ALL --
that option is not available here, since classifying value shape is this
play's entire job, so the value is read, but it is read once, in one place,
and reduced before it ever leaves this function.

PORTED from mcp-doctor's discover.py, unchanged in behavior unless noted:
  - the five source_*() path/parse functions, read_json_source(),
    validate_shape(), is_remote(), strip_seps() (separator hygiene -- a
    pathological config value can never smuggle a chr(31)/chr(30) through
    to split a downstream field/record)
  - the TOML fallback parser for Python < 3.11 (no stdlib tomllib), incl.
    its enabled-handling fix: "enabled" is parsed explicitly so a disabled
    entry is recognized as disabled the same way the tomllib path
    recognizes it, never silently missed by falling through the fallback's
    generic key scan. EXTENDED here (see _toml_mcp_fallback) to also read
    [mcp_servers.<name>.env] KEY = "value" / KEY = 'value' assignments --
    the original fallback deliberately never read env values at all
    ("env values are never read"), because mcp-doctor's discover.py never
    needed them; this play's whole job is reading them, so the extension
    is narrow (simple quoted-string assignments only, the same "parse only
    the shapes seen in practice, degrade the rest" philosophy the original
    fallback states for everything else) and never widens what the
    tomllib path already does for free.

DELIBERATE DEVIATION from mcp-doctor's discover.py: entries whose own
config marks them enabled: false ARE still included here (carrying an
"enabled": false field), where mcp-doctor's discover.py drops them
entirely. mcp-doctor drops them because it exists to decide whether to
SPAWN a server, and a harness never loads a disabled one. This play never
spawns anything -- its job is the secret sitting in the FILE, which is
just as real, and arguably more likely to be a forgotten/stale credential,
whether or not the harness currently loads that block. Excluding disabled
blocks from a *secrets* audit would under-report exactly the case a
hygiene tool should not miss.

File permissions are read once per source file (regardless of whether it
parsed), via a single os.stat(): a config that failed to parse can still
be world-readable, and that fact is worth reporting on its own -- an audit
of "is this file's permission posture safe" should not depend on this
script's own ability to read its contents.

Emits one JSON object on stdout:
    {"ok": true,
     "warning": "<optional -- e.g. N unsupported env value assignment(s)
         skipped by the codex TOML fallback reader; null when nothing was
         under-read>",
     "sources_count": 5,
     "servers_total": N,
     "env_vars_total": M,
     "sources_packed": "<7 fields x RS-joined records, FS-joined fields:
         harness, path, status, servers_found, mode_octal, world_readable
         (0/1), group_readable (0/1)>",
     "entries_packed": "<8 fields x RS-joined records, FS-joined fields:
         harness, source_path, server_name, var_name, shape, preview4,
         length, enabled (0/1)>"}

Discovery itself has no essential capability to fail on -- an unreadable
machine still emits an honest, mostly-empty inventory -- so this script
always exits 0.
"""

import json
import math
import os
import re
import stat
import sys
from collections import Counter

FS, RS = chr(31), chr(30)

NAME_MAX = 200
VAR_NAME_MAX = 100
PREVIEW_LEN = 4

# ---------------------------------------------------------------------------
# PORTED (verbatim in behavior) from mcp-doctor/resources/discover.py
# ---------------------------------------------------------------------------


def strip_seps(text):
    """Strip the record/field separator bytes this play's siblings use to
    pack collections into a scalar, so a pathological config value can
    never smuggle one through and split a downstream field/record."""
    if not isinstance(text, str):
        return text
    return text.replace(FS, "?").replace(RS, "?")


def is_remote(entry):
    """A remote server is declared with a url (or an http/sse-style type)
    instead of a local command; never contacted by this play or anything
    downstream of it -- only discovered and labeled."""
    if entry.get("url"):
        return True
    t = str(entry.get("type") or "").strip().lower()
    return t in ("http", "sse", "streamable-http", "streamablehttp", "remote")


def read_json_source(path):
    """Returns (data, status). status is "ok", "not-found", or an
    "error: ..." string; data is None unless status == "ok"."""
    if not os.path.isfile(path):
        return None, "not-found"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if not text.strip():
            return None, "error: empty file"
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        return None, "error: " + str(exc)[:150]
    return data, "ok"


def validate_shape(data, key):
    """Distinguishes "no servers configured" (key absent/None -- a normal,
    healthy case) from an "unexpected shape" (the root, or the server-map
    at `key`, is present but not an object) -- a broken/misconfigured file
    degrades to an honest error status instead of silently reporting zero
    servers as "ok"."""
    if not isinstance(data, dict):
        return "error: unexpected shape (root is not an object)"
    value = data.get(key)
    if value is None:
        return "ok"
    if not isinstance(value, dict):
        return "error: unexpected shape (%r is not an object)" % key
    return "ok"


# ---------------------------------------------------------------------------
# NEW: value-shape classification -- the whole reason this play exists.
# Applied once, at read time, to a raw value that is discarded immediately
# after this call returns. Never re-derived from a preview downstream.
# ---------------------------------------------------------------------------

# Base64url JWT shape: header.payload.signature, header starts "eyJ" (the
# base64 of a JSON object's opening `{"`).
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$")
_SK_RE = re.compile(r"^sk-[A-Za-z0-9_-]{10,}$")
_GHP_RE = re.compile(r"^ghp_[A-Za-z0-9]{16,}$")
_AKIA_RE = re.compile(r"^AKIA[A-Z0-9]{12,}$")
# High-entropy catch-all charset deliberately EXCLUDES "/" and whitespace:
# real MCP configs on this machine's own harnesses carry plenty of 40+
# character absolute file paths and JSON-ish blobs in their env blocks
# (verified live against ~/.codex/config.toml's node_repl.env), and both
# use "/" or braces/colons/quotes routinely -- excluding those characters
# trades a little recall (a base64 secret that happens to use "/") for far
# fewer false "inline secret" flags on ordinary path-shaped values. The
# UNVERIFIED footer discloses this tradeoff explicitly. This catch-all is
# ALSO known to flag non-secret opaque identifiers -- a 40+ character hex
# digest (a git commit, a content hash) or a long high-entropy hostname/
# slug can clear the same threshold; the "potential-" prefix on its shape
# name (below) says so honestly instead of asserting a confirmed match.
_HIGH_ENTROPY_CHARSET_RE = re.compile(r"^[A-Za-z0-9+._=-]{40,}$")
_HIGH_ENTROPY_MIN_BITS = 3.0

# Only the two documented forms are safe indirection: "$VAR" or "${VAR}".
# Both braces are matched as a pair, never independently optional -- a
# malformed "$VAR}" or "${VAR" is neither form and must fall through to
# "literal" (or another classification), never be waved through as safe.
_INDIRECTION_RE = re.compile(
    r"^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})$"
)


def _shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classify_value_shape(value):
    """Returns (shape, preview4, length). shape is one of:
      "empty"               -- value is the empty string
      "indirection"         -- $VAR or ${VAR}, safe -- no literal loaded here
      "secret-sk"            } literal secret-shaped values -- see module
      "secret-ghp"           } docstring for the "NEVER the value" invariant
      "secret-akia"          } this function protects. Only the returned
      "secret-jwt"           } (shape, preview4, length) survives this call.
      "potential-secret-highentropy" -- 40+ char, high-entropy catch-all;
                                "potential-" because this bucket is also
                                known to flag non-secret opaque identifiers
                                (a hex digest, a long hostname/slug) -- see
                                the constant's comment above.
      "literal"             -- anything else: a plain non-secret-shaped,
                                non-indirection literal (e.g. a file path,
                                a short flag value, a numeric-looking
                                string) -- not flagged, not "safe" either,
                                just not recognized as either extreme.
    preview4 is capped at PREVIEW_LEN characters everywhere, regardless of
    shape -- "4-char preview = max exposure anywhere" applies uniformly,
    not only to shapes classified as secrets.
    """
    v = value if isinstance(value, str) else str(value)
    length = len(v)
    preview = v[:PREVIEW_LEN]
    if v == "":
        return "empty", preview, length
    if _INDIRECTION_RE.match(v):
        return "indirection", preview, length
    if _JWT_RE.match(v):
        return "secret-jwt", preview, length
    if _SK_RE.match(v):
        return "secret-sk", preview, length
    if _GHP_RE.match(v):
        return "secret-ghp", preview, length
    if _AKIA_RE.match(v):
        return "secret-akia", preview, length
    if _HIGH_ENTROPY_CHARSET_RE.match(v) and _shannon_entropy(v) >= _HIGH_ENTROPY_MIN_BITS:
        return "potential-secret-highentropy", preview, length
    return "literal", preview, length


def is_disabled(entry):
    return entry.get("enabled") is False


def normalize_entries(raw, harness, source_path):
    """raw: dict[name -> config dict]. Returns a list of (server_name,
    enabled, [(var_name, shape, preview4, length), ...]) tuples, one per
    server entry -- pre-classified env rows only, per the module's hard
    invariant. Non-dict shapes are skipped. Disabled entries are INCLUDED
    (with enabled=False) -- see module docstring's DELIBERATE DEVIATION."""
    out = []
    if not isinstance(raw, dict):
        return out
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        server_name = strip_seps(str(name))[:NAME_MAX]
        enabled = not is_disabled(entry)
        env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
        env_rows = []
        for var_name, raw_value in env.items():
            shape, preview, length = classify_value_shape(raw_value)
            env_rows.append(
                (strip_seps(str(var_name))[:VAR_NAME_MAX], shape, strip_seps(preview), length)
            )
        out.append((server_name, enabled, env_rows))
    return out


# ---------------------------------------------------------------------------
# TOML fallback (Python < 3.11, no stdlib tomllib) -- ported from
# mcp-doctor/resources/discover.py, EXTENDED to also read simple quoted
# env value assignments (see module docstring). Still deliberately narrow:
# "parses ONLY the shapes those tables use in practice", anything else
# degrades by being skipped, never guessed.
# ---------------------------------------------------------------------------


def _toml_mcp_fallback(path):
    """Narrow TOML reader for [mcp_servers.<name>] tables on Python < 3.11.
    Returns (servers_map, None, skipped_env_count) or (None, reason, 0).
    skipped_env_count counts env-table lines this reader could not parse
    (see the "any other value shape" branch below) -- surfaced by the
    caller as a warning so an "ok" status can never silently under-report
    which env values it actually read."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return None, "error: " + (exc.strerror or "unreadable"), 0
    servers = {}
    current = None  # the currently open [mcp_servers.<name>] table dict
    env_target = None  # the currently open [mcp_servers.<name>.env] dict
    skipped_env_count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[mcp_servers\.([A-Za-z0-9_.-]+)(?:\.env)?\]$", line)
        if m:
            name = m.group(1)
            is_env_header = line.endswith(".env]") or name.endswith(".env")
            if name.endswith(".env"):
                name = name[:-4]
            server = servers.setdefault(name.split(".")[0], {})
            if is_env_header:
                env_target = server.setdefault("env", {})
                current = None
            else:
                current = server
                env_target = None
            continue
        if re.match(r"^\[", line):
            current = None  # some other table -- not ours
            env_target = None
            continue
        if env_target is not None:
            em = re.match(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$', line)
            if em:
                env_target[em.group(1)] = em.group(2).replace('\\"', '"').replace("\\\\", "\\")
                continue
            em2 = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*'([^']*)'\s*(?:#.*)?$", line)
            if em2:
                env_target[em2.group(1)] = em2.group(2)
                continue
            # any other value shape under an env table (numbers, bools,
            # multi-line strings, arrays) degrades by being skipped, not
            # guessed -- same philosophy as the rest of this fallback.
            # Counted (not silently dropped): the caller folds this into
            # a top-level warning so "ok" never overstates coverage.
            skipped_env_count += 1
            continue
        if current is None:
            continue
        em = re.match(r"^enabled\s*=\s*(true|false)\s*(?:#.*)?$", line)
        if em:
            current["enabled"] = em.group(1) == "true"
            continue
        km = re.match(r"^(command|args|url|type)\s*=\s*(.+)$", line)
        if not km:
            continue
        key, val = km.group(1), km.group(2).strip()
        if key in ("command", "url", "type"):
            vm = re.match(r'^"([^"]*)"\s*(?:#.*)?$', val)
            if vm:
                current[key] = vm.group(1)
        elif key == "args":
            if val.startswith("[") and val.endswith("]"):
                current[key] = re.findall(r'"([^"]*)"', val)
    if not servers:
        return None, "error: no [mcp_servers.*] tables this fallback parser could read", skipped_env_count
    return servers, None, skipped_env_count


# ---------------------------------------------------------------------------
# File permissions -- read once per source, regardless of parse status.
# ---------------------------------------------------------------------------


def file_perms(path):
    """Returns (mode_octal, world_readable, group_readable) for an existing
    file, or (None, False, False) if it cannot be stat'd (including
    not-found, indistinguishable here from a permission error -- both mean
    "nothing to report")."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None, False, False
    mode_octal = oct(stat.S_IMODE(mode))[2:].zfill(4)
    world_readable = bool(mode & stat.S_IROTH)
    group_readable = bool(mode & stat.S_IRGRP)
    return mode_octal, world_readable, group_readable


# ---------------------------------------------------------------------------
# Sources -- ported path list, one function per harness. Each returns
# (path, harness, status, entries, warning); warning is None for every
# source except codex's TOML fallback, which can under-read an env table
# (see _toml_mcp_fallback) without that ever being invisible.
# ---------------------------------------------------------------------------


def source_claude_code():
    path = os.path.expanduser("~/.claude.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries += normalize_entries(data.get("mcpServers"), "claude-code", path)
            projects = data.get("projects")
            if isinstance(projects, dict):
                for _proj_path, proj in projects.items():
                    if isinstance(proj, dict):
                        entries += normalize_entries(proj.get("mcpServers"), "claude-code", path)
    return path, "claude-code", status, entries, None


def source_claude_desktop():
    path = os.path.expanduser(
        "~/Library/Application Support/Claude/claude_desktop_config.json"
    )
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "claude-desktop", path)
    return path, "claude-desktop", status, entries, None


def source_cursor():
    path = os.path.expanduser("~/.cursor/mcp.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "cursor", path)
    return path, "cursor", status, entries, None


def source_codex():
    path = os.path.expanduser("~/.codex/config.toml")
    harness = "codex"
    if not os.path.isfile(path):
        return path, harness, "not-found", [], None
    try:
        import tomllib
    except ImportError:
        servers_map, reason, skipped_env_count = _toml_mcp_fallback(path)
        if servers_map is None:
            return path, harness, reason + " (tomllib needs Python 3.11+)", [], None
        data = {"mcp_servers": servers_map}
        status = validate_shape(data, "mcp_servers")
        if status != "ok":
            return path, harness, status, [], None
        warning = None
        if skipped_env_count > 0:
            warning = (
                "codex TOML fallback reader (no stdlib tomllib) skipped %d unsupported "
                "env value assignment(s) -- only single-line quoted strings are read; "
                "numbers, booleans, multiline strings, and arrays are not, and were not "
                "included in this audit. Upgrade to Python 3.11+ for full coverage."
                % skipped_env_count
            )
        return (
            path,
            harness,
            "ok (fallback toml reader)",
            normalize_entries(data.get("mcp_servers"), harness, path),
            warning,
        )
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        return path, harness, "error: " + str(exc)[:150], [], None
    status = validate_shape(data, "mcp_servers")
    if status != "ok":
        return path, harness, status, [], None
    entries = normalize_entries(data.get("mcp_servers"), harness, path)
    return path, harness, "ok", entries, None


def source_windsurf():
    path = os.path.expanduser("~/.codeium/windsurf/mcp_config.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "windsurf", path)
    return path, "windsurf", status, entries, None


def main():
    sources_records = []
    entries_records = []
    servers_total = 0
    env_vars_total = 0
    warnings = []

    for fn in (
        source_claude_code,
        source_claude_desktop,
        source_cursor,
        source_codex,
        source_windsurf,
    ):
        path, harness, status, servers, warning = fn()
        if warning:
            warnings.append(warning)
        mode_octal, world_readable, group_readable = file_perms(path)
        sources_records.append(
            FS.join(
                [
                    harness,
                    strip_seps(path),
                    strip_seps(status),
                    str(len(servers)),
                    mode_octal or "",
                    "1" if world_readable else "0",
                    "1" if group_readable else "0",
                ]
            )
        )
        servers_total += len(servers)
        for server_name, enabled, env_rows in servers:
            for var_name, shape, preview, length in env_rows:
                env_vars_total += 1
                entries_records.append(
                    FS.join(
                        [
                            harness,
                            strip_seps(path),
                            server_name,
                            var_name,
                            shape,
                            preview,
                            str(length),
                            "1" if enabled else "0",
                        ]
                    )
                )

    print(
        json.dumps(
            {
                "ok": True,
                "warning": "; ".join(warnings) if warnings else None,
                "sources_count": len(sources_records),
                "servers_total": servers_total,
                "env_vars_total": env_vars_total,
                "sources_packed": RS.join(sources_records),
                "entries_packed": RS.join(entries_records),
            }
        )
    )


main()
