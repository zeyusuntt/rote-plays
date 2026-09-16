"""Discover MCP server configs across installed harnesses on THIS machine.

Read-only: reads a fixed, well-known set of user-level config files and
parses out the mcpServers/mcp_servers entries each one declares. Never a
filesystem walk -- a project-level .mcp.json sitting somewhere under a
common HOME-level directory (~/Documents, ~/Projects, ...) is deliberately
NOT scanned. That would mean reading strangers' project files this play was
never pointed at; only the well-known, harness-owned paths below are read:

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
object, or the mcpServers/mcp_servers map itself not an object -- e.g. a
list or a string where a map was expected) degrades only that one source,
status "not-found" / "error: ..." respectively, never the whole script and
never silently reported as "ok" with zero servers found.

A server entry is included only when it is not explicitly disabled
(enabled: false in its own config) -- a disabled server is not loaded by
its harness, so it is not part of anyone's context tax, and skipping it
also means this play never attempts to spawn one during probing.

Transport is "remote" when an entry configures a url or an http/sse-style
type instead of a local command; remote servers are never contacted by this
play or by anything downstream of it -- only discovered and labeled.

Only pid-free identity survives into this script's PRINTED output: name,
harness, transport, command, and args, plus has_env (bool) and env_count
(the NUMBER of env var NAMES configured). Env var VALUES are never read
into this script's output at all -- only the raw config file on disk ever
holds them, and this script never emits or transmits them anywhere.

argv VALUES are treated the same way, on purpose, because no regex-based
redaction can be exhaustive (a positional secret, or a flag name this
script has never seen, would simply pass through): "args" in the printed
servers array is a non-sensitive STRUCTURAL summary only -- a flag's NAME
survives (--python, --port, ... these are overwhelmingly semantic, not
secrets) but a flag's VALUE and every positional argument is replaced with
a length-bucketed placeholder like "<arg:23chars>". No argument VALUE ever
reaches stdout, a report, or any run log this script writes to.

The REAL command + args (needed only to actually spawn a server during
probing, never to display one) are written once to a private per-run
temp file -- owner-only-readable (mode 0600, the tempfile module default),
keyed by server id, referenced from each stdio server's "exec_store" path
so probe.py can look itself up and spawn with the config's real argv. That
file is never printed by either script. It is NOT deleted when this run
ends (there is no reliable single point across N independently-scheduled
probe.py fan-out invocations to do that from) -- it relies on normal OS
temp-directory hygiene, and it holds no more than the same local user could
already read in cleartext from the original config file it came from.

Only pid-free identity survives from each entry: name, harness, transport,
command, and args (see above), plus has_env/env_count.

Emits one JSON object on stdout:
    {
      "ok": true,
      "sources": [{"path", "harness", "status", "servers_found"}, ...],
      "servers": [{"id","name","harness","transport","command","args",
                    "has_env","env_count","exec_store"?}, ...],
      "count": N,
      "duplicates_dropped": N
    }
Duplicates are servers whose (transport, command, real-args) or
(transport, url) identity was already seen from an earlier source; first
occurrence wins. (Identity dedup uses the real args, not the display
summary, so two distinctly-configured servers that happen to summarize
identically are never mistaken for duplicates.)

Discovery itself has no essential capability to fail on -- an unreadable
machine still emits an honest, mostly-empty inventory -- so this script
always exits 0.
"""

import json
import os
import re
import sys
import tempfile

FS, RS = chr(31), chr(30)

# Best-effort redaction of flag-shaped secret values and userinfo-in-URL
# credentials, kept only for defensive use on non-argv text (server
# names). argv values themselves are never redacted piecemeal -- see
# summarize_args() and the module docstring for why.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_FLAG_RE = re.compile(
    r"(?i)((?:--?[\w]*(?:token|password|passwd|secret|apikey|api[_-]?key|bearer|auth)[\w-]*)(?:[=\s]+))(\S+)"
)

ARGS_MAX_COUNT = 40


def strip_seps(text):
    """Strip the record/field separator bytes this play's siblings use to
    pack collections into a scalar, so a pathological config value can never
    smuggle one through and split a downstream field/record."""
    if not isinstance(text, str):
        return text
    return text.replace(FS, "?").replace(RS, "?")


def redact(text):
    """Best-effort scrub of flag-shaped secret values in one string.
    Defensive use only (e.g. a server name) -- never applied to argv, which
    is summarized structurally instead of redacted piecemeal."""
    out = _BEARER_RE.sub("Bearer ***REDACTED***", text)
    out = _SECRET_FLAG_RE.sub(lambda m: m.group(1) + "***REDACTED***", out)
    return out


def summarize_args(args):
    """A non-sensitive STRUCTURAL summary of an argv list for display: a
    flag's NAME survives (e.g. --python, --port), but a flag's VALUE and
    every positional argument is replaced with a length-bucketed
    placeholder. No argument VALUE from the original config ever reaches
    this summary, so there is nothing left for a redaction regex to miss."""
    out = []
    for a in args[:ARGS_MAX_COUNT]:
        a = str(a)
        if a.startswith("--"):
            name = strip_seps(a.split("=", 1)[0])[:80]
            out.append(name + "=<value>" if "=" in a else name)
        elif a.startswith("-"):
            # a short flag can carry its value ATTACHED (-pSECRET); only the
            # two-char flag itself is structural, the rest is a value
            out.append(a[:2] + ("<value>" if len(a) > 2 else ""))
        else:
            out.append("<arg:%dchars>" % min(len(a), 9999))
    return out


def is_remote(entry):
    """A remote server is declared with a url (or an http/sse-style type)
    instead of a local command this play could spawn."""
    if entry.get("url"):
        return True
    t = str(entry.get("type") or "").strip().lower()
    return t in ("http", "sse", "streamable-http", "streamablehttp", "remote")


def is_disabled(entry):
    return entry.get("enabled") is False


def normalize_entries(raw, harness):
    """raw: dict[name -> config dict]. Returns a list of normalized server
    dicts (pre-dedupe), skipping disabled entries and non-dict shapes.
    Each entry carries a private "_exec_args" (the REAL args, count-capped
    but never redacted/truncated in value) alongside the public "args"
    (structural summary only) -- main() splits these into the private exec
    store and the printed shape, and "_exec_args" never itself reaches
    stdout."""
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
        env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
        out.append(
            {
                "name": redact(strip_seps(str(name)))[:200],
                "harness": harness,
                "transport": "remote" if remote else "stdio",
                "command": command,
                "url": strip_seps(str(entry.get("url"))) if remote and entry.get("url") else None,
                "args": summarize_args(raw_args),
                "_exec_args": exec_args if command else None,
                "has_env": bool(env),
                "env_count": len(env),
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
    """A parsed source is only as good as its shape: distinguishes "no
    servers configured" (key absent/None -- a normal, healthy case) from an
    "unexpected shape" (the root, or the server-map at `key`, is present
    but not an object) -- so a broken/misconfigured file degrades to an
    honest error status instead of silently reporting zero servers as
    "ok"."""
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
            entries += normalize_entries(data.get("mcpServers"), "claude-code")
            projects = data.get("projects")
            if isinstance(projects, dict):
                for _proj_path, proj in projects.items():
                    if isinstance(proj, dict):
                        entries += normalize_entries(proj.get("mcpServers"), "claude-code")
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
            entries = normalize_entries(data.get("mcpServers"), "claude-desktop")
    return path, "claude-desktop", status, entries


def source_cursor():
    path = os.path.expanduser("~/.cursor/mcp.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "cursor")
    return path, "cursor", status, entries



def _toml_mcp_fallback(path):
    """Narrow TOML reader for [mcp_servers.<name>] tables on Python < 3.11.

    tomllib is stdlib only from 3.11; a 3.10 runner would otherwise lose all
    codex coverage. This deliberately parses ONLY the shapes those tables use
    in practice: [mcp_servers.name] section headers, command = "str",
    args = ["a", "b"], plus an env presence check. Anything it cannot read
    with confidence degrades exactly like the tomllib-unavailable path did.
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
            # honor enabled=false exactly like the tomllib path does; without
            # this the fallback reader silently readmits DISABLED servers and
            # probe.py then spawns them (found hardening mcp-doctor)
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
        return path, harness, "ok (fallback toml reader)", normalize_entries(data.get("mcp_servers"), harness)
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        return path, harness, "error: " + str(exc)[:150], []
    status = validate_shape(data, "mcp_servers")
    if status != "ok":
        return path, harness, status, []
    entries = normalize_entries(data.get("mcp_servers"), harness)
    return path, harness, "ok", entries


def source_windsurf():
    path = os.path.expanduser("~/.codeium/windsurf/mcp_config.json")
    data, status = read_json_source(path)
    entries = []
    if status == "ok":
        status = validate_shape(data, "mcpServers")
        if status == "ok":
            entries = normalize_entries(data.get("mcpServers"), "windsurf")
    return path, "windsurf", status, entries


def identity(entry):
    """Dedup identity uses the REAL args (never the display summary), so
    two distinctly-configured servers that happen to summarize identically
    are never mistaken for duplicates."""
    if entry["transport"] == "remote":
        return ("remote", entry.get("url") or "")
    return ("stdio", entry.get("command") or "", tuple(entry.get("_exec_args") or ()))


def write_exec_store(exec_map):
    """Write the private exec-args store once: owner-only-readable
    (tempfile's default mode 0600), never printed. Returns the path, or
    None if it could not be written (probing degrades to spawning with no
    args at all in that case -- never a crash)."""
    if not exec_map:
        return None
    try:
        fd, path = tempfile.mkstemp(prefix="mcp-context-tax-exec-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(exec_map, fh)
        return path
    except OSError:
        return None


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
            {
                "path": path,
                "harness": harness,
                "status": status,
                "servers_found": len(entries),
            }
        )
        all_entries.extend(entries)

    seen = set()
    deduped = []
    duplicates_dropped = 0
    for entry in all_entries:
        key = identity(entry)
        if key in seen:
            duplicates_dropped += 1
            continue
        seen.add(key)
        deduped.append(entry)

    servers = []
    exec_map = {}
    for i, entry in enumerate(deduped):
        entry["id"] = i
        # url was only carried for identity/redaction; drop the raw field
        # name from the emitted shape in favor of the documented schema.
        entry.pop("url", None)
        exec_args = entry.pop("_exec_args", None)
        if entry["transport"] == "stdio" and entry.get("command") and exec_args is not None:
            exec_map[str(i)] = {"command": entry["command"], "args": exec_args}
        servers.append(entry)

    exec_store_path = write_exec_store(exec_map)
    if exec_store_path:
        for entry in servers:
            if str(entry["id"]) in exec_map:
                entry["exec_store"] = exec_store_path

    print(
        json.dumps(
            {
                "ok": True,
                "sources": sources_meta,
                "servers": servers,
                "count": len(servers),
                "duplicates_dropped": duplicates_dropped,
            }
        )
    )


main()
