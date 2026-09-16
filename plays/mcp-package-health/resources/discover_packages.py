"""Discover MCP server configs across installed harnesses on THIS machine,
then resolve each local stdio server to a PUBLIC PACKAGE IDENTITY (an npm
or PyPI package name) -- never spawning anything, never contacting a
network of any kind. Step 2 (fetch_registry.py) is the only part of this
play that ever talks to the network, and only after the gate at the bottom
of this file has approved a name.

CONFIG DISCOVERY (ported near-verbatim from mcp-doctor's discover.py --
same well-known, harness-owned paths, same guarded tomllib import with a
narrow fallback parser, same per-source degrade; only the exec-store
plumbing mcp-doctor needs to actually spawn a server was dropped, since
this play never spawns one):

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
empty/invalid JSON or TOML file, or an unexpected shape degrades only that
one source, never the whole script and never silently reported as "ok"
with zero servers found. Never a filesystem walk for a stray project
.mcp.json -- only these fixed, harness-owned paths are read. A disabled
server (enabled: false) is skipped, the same as its harness would skip it.

PACKAGE RESOLUTION (new to this play): reads ONLY the server's command +
real args to decide what, if anything, it names on a public registry --

  npx -y <pkg> / npx <pkg> / npx --yes <pkg>   -> npm package <pkg>
  npm exec -- <pkg> / npm exec <pkg> / npm x <pkg> -> npm package <pkg>
                                                 (npm's own current name
                                                  for what npx does)
  uvx <pkg>                                     -> PyPI package <pkg>
  uv tool run <pkg>                             -> PyPI package <pkg>
  pipx run <pkg>                                -> PyPI package <pkg>
  uvx --from <pkg> <cmd>                        -> PyPI package <pkg>
  pipx run --spec <pkg> <cmd>                   -> PyPI package <pkg>

For the three PyPI launchers, an explicit --from/--spec is authoritative
(it is how a server whose command name differs from its distribution name
is normally launched), and valued flags such as --python 3.12 are skipped
together with their value rather than being read as the package.

Leading npx flags (-y, --yes, -p, --package) are stripped before reading
the package spec; a scoped npm name (@scope/name) is handled as one unit.
A trailing @version (or ==version for the PyPI launchers) is read as a
PIN and reported separately from the bare package name -- never merged
into the name itself.

python -m <module> / python3 -m <module> is reported UNRESOLVABLE, on
purpose: an importable module name is not a distribution name (the module
"mcp_server_git" may come from a distribution named "mcp-server-git", or
from something else entirely) -- this script never guesses one by
swapping underscores for hyphens.

node <path>, docker ..., any absolute-path command, or any other launcher
this script does not recognize lands in NOT-A-REGISTRY-PACKAGE with an
honest reason (local script / container / unknown launcher) -- never
queried. A remote (url-based) server config has no command to read at
all and is bucketed separately, never contacted, by either step.

PRIVACY GATE -- the only thing step 2 is ever allowed to send over the
network is a package NAME, and this script enforces that here, not just
in prose: every candidate name is checked against a strict per-ecosystem
allowlist regex (npm: an optional @scope/ then [a-z0-9._-]; PyPI:
[A-Za-z0-9._-]) and a length cap (npm 214 chars, PyPI 128 chars) BEFORE it
is ever eligible to appear in the "packages" list this script emits. A
name that fails either check is dropped into "unresolvable" with reason
"name shape not safe to send" and is never queried -- this is what stops
a weird config value (a path, a URL, anything shaped wrong) from being
smuggled into an outbound request by step 2. Real argv VALUES otherwise
never reach this script's own JSON output at all -- only the specific
token that was actually judged (a resolved package spec, or an
unresolvable module name) ever appears, and even that only in the
human-facing unresolvable/not_registry rows on this same machine, never
sent anywhere.

Packages are deduped by (ecosystem, package) -- the same package declared
by three harnesses is queried once by step 2 -- and each merged row
carries every declaring server name and harness, plus every distinct pin
seen (a "pin_conflict" flag if two configs pin the same package to two
different versions, which is itself worth surfacing).

Emits one JSON object on stdout:
    {
      "ok": true,
      "generated_at": <iso8601>,
      "sources": [{"path","harness","status","servers_found"}, ...],
      "packages": [{"key","ecosystem","package","pinned_version",
                     "pinned_versions","pin_conflict","server_name",
                     "server_names","harness","harnesses"}, ...],
      "unresolvable": [{"server_name","harness","source_path","command",
                          "reason","candidate"?}, ...],
      "not_registry": [{"server_name","harness","source_path","command",
                          "reason"}, ...],
      "remote": [{"server_name","harness","source_path"}, ...],
      "counts": {"sources_read","servers_discovered","duplicates_dropped",
                  "packages","unresolvable","not_registry","remote",
                  "names_withheld_unsafe"},
      "warnings": [<str>, ...]
    }

Discovery and resolution have no essential capability to fail on -- an
unreadable machine still emits an honest, mostly-empty inventory -- so
this script always exits 0.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

FS, RS = chr(31), chr(30)

# Best-effort redaction of flag-shaped secret values, kept for defensive
# use on non-argv text (server names) only -- see discover.py's sibling
# copy of this same comment in mcp-doctor for why argv itself is never
# redacted piecemeal.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_FLAG_RE = re.compile(
    r"(?i)((?:--?[\w]*(?:token|password|passwd|secret|apikey|api[_-]?key|bearer|auth)[\w-]*)(?:[=\s]+))(\S+)"
)

ARGS_MAX_COUNT = 40
CANDIDATE_MAX_CHARS = 200

NPX_SKIP_FLAGS = {"-y", "--yes", "-p", "--package"}
# uvx / uv tool run / pipx run: flags whose NEXT token is that flag's VALUE,
# not the package. Skipping them in pairs is what stops
# `uvx --python 3.12 <pkg>` from reading "3.12" as the package (or, before
# this existed, from being written off as having no positional argument at
# all). --with names an ADDITIONAL dependency, not the thing being run, so
# its value is skipped rather than reported: naming it as the package would
# be a wrong answer, not a partial one.
PYPI_VALUED_FLAGS = {
    "--python", "-p", "--with", "--with-editable", "--with-requirements",
    "--index", "--index-url", "--extra-index-url", "--default-index",
    "--constraint", "-c", "--override", "--refresh-package",
    "--directory", "--project", "--cache-dir", "--pip-args",
}
# The flags that EXPLICITLY name the distribution to install, for the very
# common case where the package name and the command it provides differ
# (`uvx --from mcp-server-fetch python -m mcp_server_fetch`). When one of
# these is present it is authoritative: everything after it is the command
# to run inside that package, never the package itself.
PYPI_EXPLICIT_PKG_FLAGS = {"--from", "--spec"}
PY_LAUNCHER_RE = re.compile(r"^python3?(\.\d+)?$")
# Each component must start AND end with an alphanumeric -- this alone
# rejects "..", ".name", "a..", and every other leading/trailing-separator
# shape a real npm/PyPI name never has. Anchored with ^...$ for readability
# AND checked with fullmatch() (never match()) in validate_name() below --
# match() alone is not enough: Python's trailing "$" matches just before a
# final newline, so match() would let "safe\n" slip through this same
# pattern. fullmatch() has no such exception.
NPM_NAME_RE = re.compile(r"^@[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$|^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
NPM_MAX_LEN = 214
PYPI_MAX_LEN = 128
UNSAFE_NAME_REASON = "name shape not safe to send"


def strip_seps(text):
    """Strip the record/field separator bytes this play's siblings use to
    pack collections into a scalar, so a pathological config value can
    never smuggle one through and split a downstream field/record."""
    if not isinstance(text, str):
        return text
    return text.replace(FS, "?").replace(RS, "?")


def redact(text):
    """Best-effort scrub of flag-shaped secret values in one string.
    Defensive use only (e.g. a server name)."""
    out = _BEARER_RE.sub("Bearer ***REDACTED***", text)
    out = _SECRET_FLAG_RE.sub(lambda m: m.group(1) + "***REDACTED***", out)
    return out


def is_remote(entry):
    """A remote server is declared with a url (or an http/sse-style type)
    instead of a local command this play could resolve to a package."""
    if entry.get("url"):
        return True
    t = str(entry.get("type") or "").strip().lower()
    return t in ("http", "sse", "streamable-http", "streamablehttp", "remote")


def is_disabled(entry):
    return entry.get("enabled") is False


def normalize_entries(raw, harness, source_path):
    """raw: dict[name -> config dict]. Returns a list of normalized server
    dicts (pre-dedupe), skipping disabled entries and non-dict shapes.
    Each entry carries a private "_exec_args" (the REAL args, count-capped
    but never redacted/truncated in value) -- used ONLY inside this same
    script, by resolve_stdio() below, to read a package spec off argv; it
    is popped off before any entry is ever turned into printed JSON, the
    same discipline mcp-doctor's discover.py applies to its own exec
    store, just without ever writing those real args to disk here since
    nothing downstream needs to spawn anything with them."""
    out = []
    if not isinstance(raw, dict):
        return out
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        if is_disabled(entry):
            continue
        remote = is_remote(entry)
        command = entry.get("command") if not remote else None
        command = strip_seps(str(command)) if command else None
        raw_args = entry.get("args") if isinstance(entry.get("args"), list) else []
        exec_args = [strip_seps(str(a)) for a in raw_args[:ARGS_MAX_COUNT]]
        out.append(
            {
                "name": redact(strip_seps(str(name)))[:200],
                "harness": harness,
                "source_path": source_path,
                "transport": "remote" if remote else "stdio",
                "command": command,
                "url": strip_seps(str(entry.get("url"))) if remote and entry.get("url") else None,
                "_exec_args": exec_args if command else None,
            }
        )
    return out


def read_json_source(path):
    """Returns (data, status). status is "ok", "not-found", or an "error: ..."
    string; data is None unless status == "ok"."""
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
    at `key`, is present but not an object) -- so a broken/misconfigured
    file degrades to an honest error status instead of silently reporting
    zero servers as "ok"."""
    if not isinstance(data, dict):
        return "error: unexpected shape (root is not an object)"
    value = data.get(key)
    if value is None:
        return "ok"
    if not isinstance(value, dict):
        return "error: unexpected shape (%r is not an object)" % key
    return "ok"


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
    return path, "claude-code", status, entries


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
    return path, "claude-desktop", status, entries


def source_cursor():
    path = os.path.expanduser("~/.cursor/mcp.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "cursor", path)
    return path, "cursor", status, entries


def _toml_mcp_fallback(path):
    """Narrow TOML reader for [mcp_servers.<name>] tables on Python < 3.11.

    tomllib is stdlib only from 3.11; a 3.10 runner would otherwise lose
    all codex coverage. Parses ONLY the shapes those tables use in
    practice: [mcp_servers.name] section headers, command = "str",
    args = ["a", "b"], enabled = true/false, plus an env presence check.
    enabled is parsed explicitly so a disabled entry degrades exactly like
    the tomllib path does -- normalize_entries()'s is_disabled() is what
    actually excludes it, but only if this reader hands it a real
    "enabled" key. Anything else this reader cannot read with confidence
    degrades exactly like the tomllib-unavailable path did.
    Returns (servers_map, None) or (None, reason).
    """
    import re as _re
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return None, "error: " + (exc.strerror or "unreadable")
    servers = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _re.match(r'^\[mcp_servers\.([A-Za-z0-9_.-]+)(?:\.env)?\]$', line)
        if m:
            name = m.group(1)
            if name.endswith(".env"):
                name = name[:-4]
            current = servers.setdefault(name.split(".")[0], {})
            if line.endswith('.env]'):
                current["env"] = {"_present": True}
                current = None  # env values are never read
            continue
        if _re.match(r'^\[', line):
            current = None  # some other table -- not ours
            continue
        if current is None:
            continue
        em = _re.match(r'^enabled\s*=\s*(true|false)\s*(?:#.*)?$', line)
        if em:
            current["enabled"] = em.group(1) == "true"
            continue
        km = _re.match(r'^(command|args|url|type)\s*=\s*(.+)$', line)
        if not km:
            if _re.match(r'^env\s*=\s*\{', line):
                current["env"] = {"_present": True}
            continue
        key, val = km.group(1), km.group(2).strip()
        if key in ("command", "url", "type"):
            vm = _re.match(r'^"([^"]*)"\s*(?:#.*)?$', val)
            if vm:
                current[key] = vm.group(1)
        elif key == "args":
            if val.startswith("[") and val.endswith("]"):
                current[key] = _re.findall(r'"([^"]*)"', val)
    if not servers:
        return None, "error: no [mcp_servers.*] tables this fallback parser could read"
    return servers, None


def source_codex():
    path = os.path.expanduser("~/.codex/config.toml")
    harness = "codex"
    if not os.path.isfile(path):
        return path, harness, "not-found", []
    try:
        import tomllib
    except ImportError:
        # Python < 3.11: narrow fallback parser instead of losing codex coverage
        servers_map, reason = _toml_mcp_fallback(path)
        if servers_map is None:
            return path, harness, reason + " (tomllib needs Python 3.11+)", []
        data = {"mcp_servers": servers_map}
        status = validate_shape(data, "mcp_servers")
        if status != "ok":
            return path, harness, status, []
        return path, harness, "ok (fallback toml reader)", normalize_entries(data.get("mcp_servers"), harness, path)
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        return path, harness, "error: " + str(exc)[:150], []
    status = validate_shape(data, "mcp_servers")
    if status != "ok":
        return path, harness, status, []
    entries = normalize_entries(data.get("mcp_servers"), harness, path)
    return path, harness, "ok", entries


def source_windsurf():
    path = os.path.expanduser("~/.codeium/windsurf/mcp_config.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "windsurf", path)
    return path, "windsurf", status, entries


def identity(entry):
    """Dedup identity uses the REAL args (never a display summary), so two
    distinctly-configured servers that happen to look alike are never
    mistaken for duplicates. Includes harness AND server name (unlike the
    published engine this discovery logic was ported from, which drops
    them on purpose because it dedupes to avoid respawning the same
    physical process twice -- a concern that does not exist here, since
    this script never spawns anything). Keying on harness+name too means
    only a truly identical re-declaration (same harness, same server name,
    same command, same args) is ever treated as a duplicate; two DIFFERENT
    harnesses (or two differently-named servers) that happen to run the
    same underlying command are both kept, so merge_packages() below can
    still attribute the resolved package to every one of them."""
    if entry["transport"] == "remote":
        return ("remote", entry.get("harness") or "", entry.get("name") or "", entry.get("url") or "")
    return (
        "stdio",
        entry.get("harness") or "",
        entry.get("name") or "",
        entry.get("command") or "",
        tuple(entry.get("_exec_args") or ()),
    )


def basename(cmd):
    if not cmd:
        return ""
    return os.path.basename(str(cmd))


def split_npm_pin(spec):
    """"@scope/name@1.2.3" -> ("@scope/name", "1.2.3"); "name@1.2.3" ->
    ("name", "1.2.3"); either form with no @version -> (spec, None). A
    scoped name's OWN leading "@" is never mistaken for the pin marker."""
    if spec.startswith("@"):
        idx = spec.find("@", 1)
        if idx == -1:
            return spec, None
        return spec[:idx], spec[idx + 1:] or None
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, ver or None
    return spec, None


def split_pypi_pin(spec):
    """"pkg@1.2.3" or "pkg==1.2.3" -> ("pkg", "1.2.3"); no pin -> (spec, None)."""
    for sep in ("==", "@"):
        if sep in spec:
            name, _, ver = spec.partition(sep)
            return name, ver or None
    return spec, None


def validate_name(ecosystem, name):
    """The PRIVACY gate: the only thing eligible to reach step 2's
    outbound request later is a name that passes this. Returns
    (ok, reason_if_not)."""
    max_len, pattern = (NPM_MAX_LEN, NPM_NAME_RE) if ecosystem == "npm" else (PYPI_MAX_LEN, PYPI_NAME_RE)
    # fullmatch(), not match(): match() only anchors the START by default,
    # and even with a trailing "$" in the pattern it still accepts a string
    # that ends in a single newline (Python regex quirk) -- fullmatch()
    # requires the ENTIRE string to match with no such exception.
    if len(name) > max_len or not pattern.fullmatch(name):
        return False, UNSAFE_NAME_REASON
    return True, None


def strip_leading_flags(args, flags):
    i = 0
    while i < len(args) and args[i] in flags:
        i += 1
    return args[i:]


def resolve_stdio(entry):
    """entry has "command" (str or None) and "_exec_args" (real args,
    never printed). Returns (bucket, row) where bucket is one of
    "package" / "unresolvable" / "not_registry"."""
    command = entry.get("command") or ""
    args = entry.get("_exec_args") or []
    base = basename(command).lower()
    server_name = entry.get("name")
    harness = entry.get("harness")

    def unresolvable(reason, candidate=None):
        row = {"server_name": server_name, "harness": harness, "command": command or None, "reason": reason}
        if candidate is not None:
            row["candidate"] = strip_seps(str(candidate))[:CANDIDATE_MAX_CHARS]
        return "unresolvable", row

    def not_registry(reason):
        return "not_registry", {"server_name": server_name, "harness": harness, "command": command or None, "reason": reason}

    def package(ecosystem, spec):
        name, pin = split_npm_pin(spec) if ecosystem == "npm" else split_pypi_pin(spec)
        name = strip_seps(name)
        ok, reason = validate_name(ecosystem, name)
        if not ok:
            return unresolvable(reason, candidate=spec)
        return "package", {
            "ecosystem": ecosystem,
            "package": name,
            "pinned_version": strip_seps(pin)[:100] if pin else None,
            "server_name": server_name,
            "harness": harness,
        }

    if not command:
        return not_registry("no command configured (malformed server entry)")

    if base == "npx":
        rest = strip_leading_flags(args, NPX_SKIP_FLAGS)
        if not rest or rest[0].startswith("-"):
            return unresolvable("npx invocation has no positional package argument")
        return package("npm", rest[0])

    if base == "npm":
        if not args:
            return unresolvable("npm invocation has no subcommand")
        sub = args[0]
        if sub not in ("exec", "x"):
            return not_registry("npm subcommand other than 'exec'/'x' (not resolved by this play)")
        rest = args[1:]
        if rest and rest[0] == "--":
            rest = rest[1:]
        rest = strip_leading_flags(rest, NPX_SKIP_FLAGS)
        if not rest or rest[0].startswith("-"):
            return unresolvable("npm %s invocation has no positional package argument" % sub)
        return package("npm", rest[0])

    def resolve_pypi_launcher(rest, label):
        """Shared argument reading for uvx / uv tool run / pipx run. An
        explicit --from/--spec wins outright; otherwise flags are skipped
        (valued ones consuming their value) and the first positional token
        is the package spec."""
        for i, tok in enumerate(rest):
            if tok in PYPI_EXPLICIT_PKG_FLAGS:
                if i + 1 >= len(rest) or rest[i + 1].startswith("-"):
                    return unresolvable("%s given %s with no package argument" % (label, tok))
                return package("pypi", rest[i + 1])
            for flag in PYPI_EXPLICIT_PKG_FLAGS:
                if tok.startswith(flag + "="):
                    value = tok.split("=", 1)[1]
                    if not value:
                        return unresolvable("%s given %s with an empty package argument" % (label, flag))
                    return package("pypi", value)
        i = 0
        while i < len(rest):
            tok = rest[i]
            if not tok.startswith("-"):
                return package("pypi", tok)
            i += 2 if (tok in PYPI_VALUED_FLAGS and "=" not in tok) else 1
        return unresolvable("%s invocation has no positional package argument" % label)

    if base == "uvx":
        return resolve_pypi_launcher(args, "uvx")

    if base == "uv":
        if len(args) >= 2 and args[0] == "tool" and args[1] == "run":
            return resolve_pypi_launcher(args[2:], "uv tool run")
        return not_registry("uv subcommand other than 'tool run' (not resolved by this play)")

    if base == "pipx":
        if args and args[0] == "run":
            return resolve_pypi_launcher(args[1:], "pipx run")
        return not_registry("pipx subcommand other than 'run' (not resolved by this play)")

    if PY_LAUNCHER_RE.match(base):
        if args and args[0] == "-m":
            if len(args) < 2:
                return unresolvable("python -m invocation has no module argument")
            return unresolvable(
                "module name is not a distribution name; the distribution that provides it cannot be inferred "
                "(never guessed by replacing underscores with hyphens)",
                candidate=args[1],
            )
        return not_registry("python invocation not of the form '-m <module>' (local script or other invocation)")

    if base == "node":
        return not_registry("local script (node launcher)")

    if base == "docker":
        return not_registry("container launcher (docker)")

    if os.path.isabs(command):
        return not_registry("local absolute-path executable")

    return not_registry("unknown launcher '%s' (not mapped to a package registry)" % (base or "(empty)"))


def merge_packages(rows):
    """Dedupe resolved package rows by (ecosystem, package). Every
    declaring server name and harness is carried on the merged row so a
    package declared identically in three harnesses is still shown as
    declared three times, even though step 2 only queries it once. A pin
    conflict (two configs pinning the same package to two different
    versions) is surfaced rather than silently picking one."""
    merged = {}
    order = []
    for r in rows:
        key = "%s:%s" % (r["ecosystem"], r["package"])
        if key not in merged:
            merged[key] = {
                "key": key,
                "ecosystem": r["ecosystem"],
                "package": r["package"],
                "server_name": r["server_name"],
                "server_names": [],
                "harness": r["harness"],
                "harnesses": [],
                "_pins": [],
            }
            order.append(key)
        m = merged[key]
        if r["server_name"] not in m["server_names"]:
            m["server_names"].append(r["server_name"])
        if r["harness"] not in m["harnesses"]:
            m["harnesses"].append(r["harness"])
        if r.get("pinned_version") and r["pinned_version"] not in m["_pins"]:
            m["_pins"].append(r["pinned_version"])
    result = []
    for key in order:
        m = merged[key]
        pins = sorted(m.pop("_pins"))
        m["pin_conflict"] = len(pins) > 1
        m["pinned_version"] = pins[0] if len(pins) == 1 else None
        m["pinned_versions"] = pins
        result.append(m)
    return result


def main():
    sources_meta = []
    all_entries = []
    for fn in (
        source_claude_code,
        source_claude_desktop,
        source_cursor,
        source_codex,
        source_windsurf,
    ):
        path, harness, status, entries = fn()
        sources_meta.append(
            {"path": path, "harness": harness, "status": status, "servers_found": len(entries)}
        )
        all_entries.extend(entries)

    seen = {}
    deduped = []
    duplicates_dropped = 0
    for entry in all_entries:
        key = identity(entry)
        if key in seen:
            duplicates_dropped += 1
            continue
        seen[key] = entry
        deduped.append(entry)

    package_rows = []
    unresolvable_rows = []
    not_registry_rows = []
    remote_rows = []

    for entry in deduped:
        server_name = entry.get("name")
        harness = entry.get("harness")
        source_path = entry.get("source_path")
        if entry.get("transport") == "remote":
            remote_rows.append({"server_name": server_name, "harness": harness, "source_path": source_path})
            continue
        bucket, row = resolve_stdio(entry)
        row["source_path"] = source_path
        if bucket == "package":
            package_rows.append(row)
        elif bucket == "unresolvable":
            unresolvable_rows.append(row)
        else:
            not_registry_rows.append(row)

    packages = merge_packages(package_rows)
    names_withheld_unsafe = sum(1 for r in unresolvable_rows if r.get("reason") == UNSAFE_NAME_REASON)

    warnings = []
    for s in sources_meta:
        if s["status"] != "not-found" and not s["status"].startswith("ok"):
            warnings.append("%s config degraded (%s): %s" % (s["harness"], s["path"], s["status"]))
    if names_withheld_unsafe > 0:
        warnings.append(
            "%d candidate package name(s) withheld from any network request: %s"
            % (names_withheld_unsafe, UNSAFE_NAME_REASON)
        )

    print(
        json.dumps(
            {
                "ok": True,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "sources": sources_meta,
                "packages": packages,
                "unresolvable": unresolvable_rows,
                "not_registry": not_registry_rows,
                "remote": remote_rows,
                "counts": {
                    "sources_read": len(sources_meta),
                    "servers_discovered": len(deduped),
                    "duplicates_dropped": duplicates_dropped,
                    "packages": len(packages),
                    "unresolvable": len(unresolvable_rows),
                    "not_registry": len(not_registry_rows),
                    "remote": len(remote_rows),
                    "names_withheld_unsafe": names_withheld_unsafe,
                },
                "warnings": warnings,
            }
        )
    )


main()
