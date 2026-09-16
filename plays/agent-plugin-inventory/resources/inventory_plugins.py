"""Inventory the agent-harness extensions installed on THIS machine: Claude
Code plugins, personal skills, marketplaces, and Codex plugin-equivalents
where present. Root step -- assess.py (one step later) turns these raw
facts into THE FLAGS; this script's whole job is observing and reporting,
never judging.

Read-only throughout. Every source below is a fixed, well-known,
harness-owned path -- never a filesystem walk to go looking for new ones:

  ~/.claude/plugins/installed_plugins.json   Claude Code: every installed
                                              plugin, its cache installPath,
                                              version, scope, timestamps
  ~/.claude/settings.json                    Claude Code: enabledPlugins map
  ~/.claude/plugins/known_marketplaces.json  Claude Code: known marketplaces
                                              and each one's last sync time
  ~/.claude/skills/*                         Claude Code: personal skills
                                              (each entry commonly a symlink
                                              to a skill directory elsewhere
                                              on disk; resolved defensively)
  <plugin installPath>/skills/*/SKILL.md     Claude Code: skills bundled
                                              INSIDE an installed plugin --
                                              read only to detect a name
                                              collision against a personal
                                              skill; never walked outside
                                              this one well-known
                                              sub-path per plugin
  ~/.codex/config.toml                       Codex: [plugins."name@mkt"]
                                              tables (enabled bool) and
                                              [marketplaces.<name>] tables
                                              (last_updated, when recorded)
  ~/.codex/plugins/cache/<mkt>/<name>        Codex: best-effort cache-dir
                                              presence check, same shape as
                                              Claude's own plugin cache tree

A source file that is missing, unreadable, or unexpectedly shaped (not an
object where an object is expected, a list where a map was expected, ...)
degrades only that ONE source -- reported as a distinct status string, never
a crash and never silently folded into "nothing found here". Codex support
in particular is disclosed as best-effort: this play still reports a full
Claude Code inventory when ~/.codex does not exist or config.toml cannot be
parsed at all.

Four jobs, one pass:
  1. Claude Code plugins -- every installPath entry under every plugin key
     in installed_plugins.json, cross-referenced against settings.json's
     enabledPlugins map (a key absent from that map is treated as enabled
     by Claude Code's own default, disclosed rather than guessed as
     disabled) and measured on disk (present/missing/empty/inaccessible,
     plus an apparent-size byte count -- POSIX st_size, no `du` dependency,
     matching agent-disk-tax's own no-shell-out approach).
  2. Skills -- one unified collection, personal (~/.claude/skills/*) and
     plugin-bundled (<installPath>/skills/*/SKILL.md) alike, each tagged
     with its owner so assess.py can flag a NAME that appears under more
     than one owner (a plugin skill shadowed by a personal skill, or two
     plugins bundling the same skill name) as a name-collision-suspect --
     which one actually wins at runtime is harness-defined, never asserted
     here. Only a skill's frontmatter `description:` FIRST LINE is ever
     read (truncated to 80 chars before it is packed) -- no other file
     content, from either a personal skill or a plugin-bundled one, is ever
     opened.
  3. Marketplaces -- every entry in known_marketplaces.json, with its
     recorded last-sync time when known_marketplaces.json actually records
     one (some entries do not -- reported honestly as unknown, never
     guessed as fresh).
  4. Codex plugin-equivalents -- every [plugins."name@marketplace"] table in
     ~/.codex/config.toml (enabled bool), each cross-referenced against a
     best-effort check of its own cache directory under
     ~/.codex/plugins/cache/<marketplace>/<name> and, when recorded, its
     owning [marketplaces.<name>] table's last_updated. tomllib (stdlib,
     Python 3.11+) is used when available; on an older interpreter this
     degrades to a narrow fallback reader that recognizes ONLY the
     [plugins."..."], [marketplaces.<name>], and `enabled = true/false` /
     `last_updated = "..."` shapes Codex's own config actually uses --
     never a full TOML parse -- so Codex coverage is not lost outright on
     Python 3.9/3.10, only narrowed, with that narrowing disclosed.

PRIVACY: every skill description is truncated to 80 characters before it is
packed -- no file content beyond that one frontmatter line is ever read.
Every path this script would otherwise print (an OSError's embedded path,
in particular) is reduced to a short, non-secret reason instead -- see
_os_reason() -- so a path is never a channel this script's own diagnostics
leak back out through. This script never emits an absolute path itself.

ARGV: none.

Emits one JSON object on stdout, always exit 0 (every source here degrades
on its own; there is no essential capability with no honest "nothing here"
fallback):
    {
      "ok": true,
      "generated_at": ISO-8601 UTC,
      "claude_plugins_status": "ok" | "not-found" | "error: ...",
      "claude_settings_status": "ok" | "not-found" | "error: ...",
      "claude_skills_status": "ok" | "not-found" | "error: ...",
      "claude_marketplaces_status": "ok" | "not-found" | "error: ...",
      "codex_config_status": "ok" | "not-found" | "error: ...",
      "codex_toml_reader": "tomllib" | "fallback" | null,
      "packed_plugins": "<PACKED PLUGIN ROWS>", "plugin_count": N,
      "packed_skills": "<PACKED SKILL ROWS>", "skill_count": N,
      "packed_marketplaces": "<PACKED MARKETPLACE ROWS>", "marketplace_count": N,
      "packed_codex": "<PACKED CODEX ROWS>", "codex_count": N,
      "warning": "..."   # present only when at least one source degraded
    }

PACKED PLUGIN ROWS -- one installed Claude Code plugin entry per record,
chr(30)-joined records of chr(31)-joined fields, 11 fields per row:
    key               "<name>@<marketplace>", installed_plugins.json's own
                       map key -- also the join key into enabledPlugins
    name               plugin short name (key, split at the last "@")
    marketplace        marketplace id (key, split at the last "@"), or ""
                       if the key held no "@"
    version            installed_plugins.json's own version field
    scope              "user" | "project" | whatever this entry recorded
    installed_at        ISO string, or ""
    last_updated         ISO string, or ""
    enabled            "1" | "0" | "" -- "" when this key is absent from
                       settings.json's enabledPlugins map entirely (Claude
                       Code's own default is enabled; disclosed, not
                       silently assumed downstream)
    cache_dir_status    "present" | "missing" | "empty" | "inaccessible" |
                       "no-install-path" (no installPath was recorded at
                       all -- not evidence of a broken install, nothing to
                       check) | "out-of-scope" (an installPath WAS
                       recorded but does not resolve under
                       CLAUDE_PLUGIN_CACHE_ROOT -- refused, never scanned)
    cache_size_bytes    apparent size in bytes (POSIX st_size), or "" when
                       not present/measured
    cache_partial       "1"/"0" -- "1" only if the defensive per-run file
                       budget was hit before this plugin's own directory
                       walk finished; cache_size_bytes is then a LOWER
                       BOUND, never a silent final figure

PACKED SKILL ROWS -- one skill per record, chr(30)-joined records of
chr(31)-joined fields, 5 fields per row:
    name               skill directory name
    owner_kind          "personal" | "plugin"
    owner_label          "personal" for a personal skill, else the owning
                       plugin's key ("<name>@<marketplace>")
    description         frontmatter description's first line, sanitized
                       and capped at 80 chars; "" if unreadable/absent
    mtime_epoch          file mtime of the skill's SKILL.md, seconds since
                       epoch, as a string; "" if unresolved

PACKED MARKETPLACE ROWS -- one known_marketplaces.json entry per record,
chr(30)-joined records of chr(31)-joined fields, 3 fields per row:
    name               marketplace id (the JSON object's own key)
    last_updated         ISO string when known_marketplaces.json records
                       one for this marketplace, else ""
    repo                source.repo when present (a public repo
                       identifier, e.g. "anthropics/claude-plugins-official"),
                       else ""

PACKED CODEX ROWS -- one Codex [plugins."..."] table per record,
chr(30)-joined records of chr(31)-joined fields, 6 fields per row:
    key               the table's own quoted key, "<name>@<marketplace>"
    name               plugin short name (key, split at the last "@")
    marketplace        marketplace id (key, split at the last "@"), or ""
    enabled            "1" | "0" | "" -- "" only if this narrow reader
                       could not resolve the field at all (never guessed)
    cache_dir_status    "present" | "missing" | "not-checked" -- best-effort
                       only; see module docstring, job 4
    marketplace_last_updated  ISO-ish string when this key's owning
                       [marketplaces.<name>] table records last_updated,
                       else ""
"""

import json
import os
import re
import stat
from datetime import datetime, timezone

FS, RS = chr(31), chr(30)
PLUGIN_FIELDS = 11
SKILL_FIELDS = 5
MARKETPLACE_FIELDS = 3
CODEX_FIELDS = 6

# A short, fixed cap on any free-text field this script ever packs (a skill
# description, a diagnostic reason) -- see sanitize_text(). Descriptions are
# additionally hard-capped to DESC_MAX_LEN per the PRIVACY contract; this
# wider cap only guards free-text reason strings from becoming unbounded.
TEXT_MAX_LEN = 200
DESC_MAX_LEN = 80

# Defensive, disclosed budget on the total number of files this script will
# stat while measuring plugin cache directories in one run -- keeps a
# pathologically large cache tree from blowing the step's own timeout_ms;
# any plugin whose own walk is cut short by this budget is reported
# cache_partial="1" rather than a silently truncated final size.
CACHE_WALK_FILE_BUDGET = 200_000

# CLAUDE_PLUGINS_ROOT is the whole harness-owned plugin directory tree --
# both the per-plugin cache (CLAUDE_PLUGIN_CACHE_ROOT, below) AND the
# marketplace checkouts under ~/.claude/plugins/marketplaces, because a
# plugin's own SKILL.md is commonly a symlink from its cache directory back
# to the marketplace checkout (confirmed live: real Claude Code plugin
# installs on this machine do this) rather than a physical copy. A crafted
# or corrupted installPath, or a directory/file symlink discovered along
# the way, that resolves OUTSIDE this whole tree is refused rather than
# scanned or opened -- see _is_contained() and its call sites in
# pack_plugin_row()/collect_plugin_skills(). installPath itself is held to
# the narrower CLAUDE_PLUGIN_CACHE_ROOT, since that is the one sub-path
# installed_plugins.json's own convention ever populates it with
# (<cache root>/<marketplace>/<name>/<version>).
CLAUDE_PLUGINS_ROOT = os.path.expanduser("~/.claude/plugins")
CLAUDE_PLUGIN_CACHE_ROOT = os.path.join(CLAUDE_PLUGINS_ROOT, "cache")

# Bounds on reading a SKILL.md's frontmatter block -- see
# read_skill_description(). FRONTMATTER_MAX_LINES bounds a pathological
# frontmatter with no closing "---" (or none at all); FRONTMATTER_MAX_BYTES
# additionally bounds a single pathologically long line (or the block as a
# whole) so an adversarially large skill file can never be pulled fully into
# memory before this function gives up -- see PRIVACY in the module
# docstring.
FRONTMATTER_MAX_LINES = 200
FRONTMATTER_MAX_BYTES = 65536

TRUE_TOKENS = {"true"}
FALSE_TOKENS = {"false"}


def _is_contained(path, root):
    """True iff path, once resolved through any symlink, is at or under
    root's own resolved location. Defends the cache-size walk and the
    plugin-bundled-skill scan against a crafted/corrupted installPath (or a
    directory symlink discovered along the way) redirecting a fixed-scope
    scan into an unrelated part of the filesystem. Never raises; an OSError
    while resolving either side is treated as "not contained"."""
    try:
        real_root = os.path.realpath(root)
        real_path = os.path.realpath(path)
    except OSError:
        return False
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _os_reason(exc):
    """A short, fixed, non-secret OS error description: strerror-based,
    deliberately never str(exc) -- which on an OSError embeds the real path
    it failed on. See module docstring, PRIVACY."""
    strerror = getattr(exc, "strerror", None)
    if strerror:
        return strerror
    return exc.__class__.__name__


def sanitize_text(text, max_len=TEXT_MAX_LEN):
    """The one place any free-text field passes through before packing:
    strips this format's own FS/RS separators plus every other ASCII
    control character (0x00-0x1F, 0x7F), then caps length."""
    if not text:
        return ""
    cleaned = []
    for ch in text:
        if ch in (FS, RS) or ord(ch) < 0x20 or ord(ch) == 0x7F:
            cleaned.append(" ")
        else:
            cleaned.append(ch)
    return "".join(cleaned).strip()[:max_len]


def load_json(path):
    """Returns (data, status). status is "ok", "not-found", or
    "error: <short reason>". Never raises."""
    if not os.path.isfile(path):
        return None, "not-found"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        return None, "error: " + _os_reason(exc)
    except ValueError as exc:
        return None, "error: invalid JSON (" + exc.__class__.__name__ + ")"
    return data, "ok"


# ---------------------------------------------------------------------------
# Job 1: Claude Code plugins
# ---------------------------------------------------------------------------


def split_plugin_key(key):
    """"<name>@<marketplace>" -> (name, marketplace). Split at the LAST "@"
    so a name that happened to contain "@" would still not corrupt the
    marketplace half; a key with no "@" returns (key, "")."""
    if "@" not in key:
        return key, ""
    name, marketplace = key.rsplit("@", 1)
    return name, marketplace


def measure_cache_dir(path, budget_state):
    """Classify + size one plugin's installPath. Returns
    (status, size_bytes, partial) where status is one of
    "present" | "missing" | "empty" | "inaccessible". budget_state is a
    single-element list used as a shared mutable file-count counter across
    every call in this run (see CACHE_WALK_FILE_BUDGET)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "missing", 0, False
    except OSError:
        return "inaccessible", 0, False
    if not stat.S_ISDIR(st.st_mode):
        return "missing", 0, False

    total = 0
    file_count = 0
    partial = False
    stack = [path]
    saw_any_entry = False
    inaccessible_at_top = False
    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError:
            if current == path:
                inaccessible_at_top = True
            continue
        # Iterate the scandir iterator lazily (never materialize it into a
        # list first) so CACHE_WALK_FILE_BUDGET is enforced against however
        # many entries os.scandir has actually handed back so far, not
        # against an entire pathologically wide directory read upfront.
        try:
            for entry in it:
                saw_any_entry = True
                if budget_state[0] >= CACHE_WALK_FILE_BUDGET:
                    partial = True
                    stack.clear()
                    break
                budget_state[0] += 1
                try:
                    is_symlink = entry.is_symlink()
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif not is_symlink and entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                        file_count += 1
                except OSError:
                    continue
        finally:
            it.close()

    if inaccessible_at_top and not saw_any_entry:
        return "inaccessible", 0, False
    if file_count == 0:
        return "empty", 0, partial
    return "present", total, partial


def pack_plugin_row(key, entry, enabled_map, budget_state):
    name, marketplace = split_plugin_key(key)
    install_path = entry.get("installPath") if isinstance(entry, dict) else None
    enabled = ""
    if key in enabled_map:
        enabled = "1" if enabled_map[key] else "0"

    if not isinstance(install_path, str) or not install_path:
        # No installPath recorded at all -- not evidence of a broken
        # install, just nothing to check. Kept distinct from "missing" (an
        # installPath WAS recorded but its directory does not exist), which
        # remains a real broken-install signal.
        cache_status, cache_size, cache_partial = "no-install-path", 0, False
    elif not _is_contained(install_path, CLAUDE_PLUGIN_CACHE_ROOT):
        # A recorded installPath that does not resolve under Claude's own
        # plugin cache root is refused, never scanned -- see _is_contained().
        cache_status, cache_size, cache_partial = "out-of-scope", 0, False
    else:
        cache_status, cache_size, cache_partial = measure_cache_dir(install_path, budget_state)

    fields = [
        key,
        name,
        marketplace,
        str(entry.get("version", "")) if isinstance(entry, dict) else "",
        str(entry.get("scope", "")) if isinstance(entry, dict) else "",
        str(entry.get("installedAt", "")) if isinstance(entry, dict) else "",
        str(entry.get("lastUpdated", "")) if isinstance(entry, dict) else "",
        enabled,
        cache_status,
        str(cache_size) if cache_status == "present" else "",
        "1" if cache_partial else "0",
    ]
    return FS.join(sanitize_text(f) for f in fields), install_path


def collect_plugins(installed_data, enabled_map, budget_state):
    """Returns (packed_rows list, plugin_install_paths dict[key] -> list of
    path, shape_status, dropped_entry_count).

    plugin_install_paths feeds job 2's plugin-bundled skill scan below --
    every distinct installPath actually recorded for that key is walked
    (installed_plugins.json can legitimately hold more than one install
    record per key, e.g. two versions), never a sibling version directory
    that was not itself recorded.

    shape_status is "ok" for the shape Claude Code itself writes (an object,
    with "plugins" either absent/empty or an object) -- including the
    legitimate empty cases -- and a distinct "error: ..." string for any
    other top-level shape (a bare list, "plugins" as a list or other
    non-object). An unrecognized shape is reported honestly rather than
    silently returning zero rows under an apparent "ok" status.

    dropped_entry_count counts individual non-object install records that
    were skipped -- one malformed record degrades only itself, never the
    whole source."""
    rows = []
    install_paths = {}
    dropped_entry_count = 0

    if not isinstance(installed_data, dict):
        return rows, install_paths, "error: unexpected top-level shape (expected an object)", dropped_entry_count

    if "plugins" not in installed_data:
        return rows, install_paths, "ok", dropped_entry_count

    plugins = installed_data["plugins"]
    if not isinstance(plugins, dict):
        shape_status = "error: unexpected 'plugins' shape (expected an object, got %s)" % type(plugins).__name__
        return rows, install_paths, shape_status, dropped_entry_count

    for key in sorted(plugins.keys()):
        entries = plugins[key]
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            if not isinstance(entry, dict):
                dropped_entry_count += 1
                continue
            row, install_path = pack_plugin_row(key, entry, enabled_map, budget_state)
            rows.append(row)
            if isinstance(install_path, str) and install_path:
                paths = install_paths.setdefault(key, [])
                if install_path not in paths:
                    paths.append(install_path)
    return rows, install_paths, "ok", dropped_entry_count


def load_enabled_map(settings_path):
    """Returns (enabled_map, status). A missing settings.json or a missing
    enabledPlugins key inside it is "not-found", not an error -- an honest
    absence, not a malformed file."""
    data, status = load_json(settings_path)
    if status != "ok":
        return {}, status
    enabled = data.get("enabledPlugins") if isinstance(data, dict) else None
    if not isinstance(enabled, dict):
        return {}, "not-found"
    return {str(k): bool(v) for k, v in enabled.items()}, "ok"


# ---------------------------------------------------------------------------
# Job 2: skills (personal + plugin-bundled, unified)
# ---------------------------------------------------------------------------

_FRONTMATTER_DESC_KEY_RE = re.compile(r"^description:\s*(.*)$")
_BLOCK_SCALAR_INDICATORS = {"", ">", ">-", ">+", "|", "|-", "|+"}


def read_skill_description(skill_md_path):
    """Reads ONLY the frontmatter block (between the first two "---"
    lines) of a SKILL.md and returns the description field's first line,
    sanitized and capped at DESC_MAX_LEN. Never reads past the frontmatter
    block; never reads the skill's body -- and never reads the file whole:
    lines are pulled one at a time, bounded by FRONTMATTER_MAX_LINES and
    FRONTMATTER_MAX_BYTES, so an adversarially large skill body (or a
    frontmatter block with no closing "---" at all) cannot be pulled fully
    into memory before this function gives up. Returns "" if the file is
    missing, unreadable, has no frontmatter, has no description key, or the
    frontmatter block never closes within these bounds."""
    frontmatter = []
    found_end = False
    try:
        with open(skill_md_path, "r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline(FRONTMATTER_MAX_BYTES)
            if first.strip() != "---":
                return ""
            total_bytes = len(first)
            for _ in range(FRONTMATTER_MAX_LINES):
                line = fh.readline(FRONTMATTER_MAX_BYTES)
                if not line:
                    break
                total_bytes += len(line)
                if line.strip() == "---":
                    found_end = True
                    break
                frontmatter.append(line)
                if total_bytes >= FRONTMATTER_MAX_BYTES:
                    break
    except (OSError, MemoryError, UnicodeError):
        return ""
    if not found_end:
        return ""
    for i, line in enumerate(frontmatter):
        m = _FRONTMATTER_DESC_KEY_RE.match(line)
        if not m:
            continue
        value = m.group(1).strip()
        if value and value[0] not in "'\"" and " #" in value:
            # A trailing "# comment" on an unquoted scalar (e.g.
            # "description: > # folded") is YAML comment syntax, not part
            # of the value -- strip it before checking for a block-scalar
            # indicator or returning a single-line value literally.
            value = value[: value.index(" #")].strip()
        if value in _BLOCK_SCALAR_INDICATORS:
            # Folded/literal block scalar: the description's first line of
            # text is the next non-blank, indented continuation line.
            for cont in frontmatter[i + 1 :]:
                if cont.strip() == "":
                    continue
                if cont[:1] not in (" ", "\t"):
                    return ""  # dedented -- frontmatter moved to the next key
                return sanitize_text(cont.strip(), DESC_MAX_LEN)
            return ""
        # Single-line value, optionally quoted.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        return sanitize_text(value, DESC_MAX_LEN)
    return ""


def pack_skill_row(name, owner_kind, owner_label, skill_md_path):
    description = read_skill_description(skill_md_path)
    try:
        mtime = str(os.stat(skill_md_path).st_mtime)
    except OSError:
        mtime = ""
    fields = [sanitize_text(name, DESC_MAX_LEN), owner_kind, sanitize_text(owner_label, DESC_MAX_LEN), description, mtime]
    return FS.join(fields)


def collect_personal_skills(skills_dir):
    """Non-recursive: one entry per item directly under ~/.claude/skills.
    Each entry is resolved through any symlink chain (the common shape on
    this machine) to find its own SKILL.md; an entry that does not resolve
    to a directory containing SKILL.md is skipped, not guessed at."""
    rows = []
    if not os.path.isdir(skills_dir):
        return rows, "not-found"
    try:
        names = sorted(os.listdir(skills_dir))
    except OSError as exc:
        return rows, "error: " + _os_reason(exc)
    for name in names:
        entry_path = os.path.join(skills_dir, name)
        real = os.path.realpath(entry_path)
        if not os.path.isdir(real):
            continue
        skill_md = os.path.join(real, "SKILL.md")
        if not os.path.isfile(skill_md):
            continue
        rows.append(pack_skill_row(name, "personal", "personal", skill_md))
    return rows, "ok"


def collect_plugin_skills(plugin_install_paths):
    """<installPath>/skills/*/SKILL.md only -- the one well-known
    sub-path a Claude Code plugin manifest uses to declare bundled
    skills; never a walk of the plugin's own tree beyond that.

    Every step is containment-checked with _is_contained(): installPath
    itself must resolve under the narrow CLAUDE_PLUGIN_CACHE_ROOT (checked
    first, same bound pack_plugin_row() holds it to); its skills/ child,
    each skill directory, and each SKILL.md file must resolve under the
    wider CLAUDE_PLUGINS_ROOT, which also covers the marketplace checkout a
    plugin's own SKILL.md is commonly symlinked back to. A directory/file
    symlink discovered along the way that resolves outside that whole
    harness-owned tree is refused rather than followed and opened --
    os.path.isdir()/isfile() alone would follow such a symlink silently."""
    rows = []
    for key, install_paths in sorted(plugin_install_paths.items()):
        for install_path in install_paths:
            if not _is_contained(install_path, CLAUDE_PLUGIN_CACHE_ROOT):
                continue
            skills_dir = os.path.join(install_path, "skills")
            if not os.path.isdir(skills_dir) or not _is_contained(skills_dir, CLAUDE_PLUGINS_ROOT):
                continue
            try:
                names = sorted(os.listdir(skills_dir))
            except OSError:
                continue
            for name in names:
                skill_dir = os.path.join(skills_dir, name)
                if not os.path.isdir(skill_dir) or not _is_contained(skill_dir, CLAUDE_PLUGINS_ROOT):
                    continue
                skill_md = os.path.join(skill_dir, "SKILL.md")
                if not os.path.isfile(skill_md) or not _is_contained(skill_md, CLAUDE_PLUGINS_ROOT):
                    continue
                rows.append(pack_skill_row(name, "plugin", key, skill_md))
    return rows


# ---------------------------------------------------------------------------
# Job 3: marketplaces (Claude Code)
# ---------------------------------------------------------------------------


def pack_marketplace_row(name, entry):
    last_updated = ""
    repo = ""
    if isinstance(entry, dict):
        last_updated = str(entry.get("lastUpdated", "") or "")
        source = entry.get("source")
        if isinstance(source, dict):
            repo = str(source.get("repo", "") or "")
    fields = [sanitize_text(name, DESC_MAX_LEN), last_updated, sanitize_text(repo, DESC_MAX_LEN)]
    return FS.join(fields)


def collect_marketplaces(data):
    rows = []
    if not isinstance(data, dict):
        return rows
    for name in sorted(data.keys()):
        rows.append(pack_marketplace_row(name, data[name]))
    return rows


# ---------------------------------------------------------------------------
# Job 4: Codex plugin-equivalents
# ---------------------------------------------------------------------------

_CODEX_PLUGIN_HEADER_RE = re.compile(r'^\[plugins\."([^"]+)"\]$')
_CODEX_MARKETPLACE_HEADER_RE = re.compile(r"^\[marketplaces\.([A-Za-z0-9_.-]+)\]$")
_CODEX_OTHER_HEADER_RE = re.compile(r"^\[")
_CODEX_ENABLED_RE = re.compile(r"^enabled\s*=\s*(true|false)\s*(?:#.*)?$")
_CODEX_LAST_UPDATED_RE = re.compile(r'^last_updated\s*=\s*"([^"]*)"\s*(?:#.*)?$')


def _codex_toml_fallback(text):
    """Narrow TOML reader for [plugins."name@mkt"] and [marketplaces.<name>]
    tables on Python < 3.11 -- see mcp-doctor's _toml_mcp_fallback for the
    same reasoning. Recognizes ONLY `enabled = true/false` inside a
    [plugins."..."] table and `last_updated = "..."` inside a
    [marketplaces.<name>] table; every other key in either table, and every
    other table in the file, is ignored outright. Returns
    (plugins_map, marketplaces_map) -- both {} on a file with none of
    these shapes; never raises."""
    plugins = {}
    marketplaces = {}
    current_plugin = None
    current_marketplace = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pm = _CODEX_PLUGIN_HEADER_RE.match(line)
        if pm:
            current_plugin = plugins.setdefault(pm.group(1), {})
            current_marketplace = None
            continue
        mm = _CODEX_MARKETPLACE_HEADER_RE.match(line)
        if mm:
            current_marketplace = marketplaces.setdefault(mm.group(1), {})
            current_plugin = None
            continue
        if _CODEX_OTHER_HEADER_RE.match(line):
            current_plugin = None
            current_marketplace = None
            continue
        if current_plugin is not None:
            em = _CODEX_ENABLED_RE.match(line)
            if em:
                current_plugin["enabled"] = em.group(1) == "true"
            continue
        if current_marketplace is not None:
            lm = _CODEX_LAST_UPDATED_RE.match(line)
            if lm:
                current_marketplace["last_updated"] = lm.group(1)
    return plugins, marketplaces


def load_codex_config(path):
    """Returns (plugins_map, marketplaces_map, status, reader) where reader
    is "tomllib" | "fallback" | None. plugins_map/marketplaces_map are the
    raw ["plugins"]/["marketplaces"] sub-tables (dict of dict), regardless
    of reader used."""
    if not os.path.isfile(path):
        return {}, {}, "not-found", None
    try:
        import tomllib
    except ImportError:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            return {}, {}, "error: " + _os_reason(exc), None
        plugins, marketplaces = _codex_toml_fallback(text)
        return plugins, marketplaces, "ok", "fallback"
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        return {}, {}, "error: " + _os_reason(exc), None
    except ValueError as exc:
        return {}, {}, "error: invalid TOML (" + exc.__class__.__name__ + ")", None
    plugins = data.get("plugins") if isinstance(data, dict) else None
    marketplaces = data.get("marketplaces") if isinstance(data, dict) else None
    return (
        plugins if isinstance(plugins, dict) else {},
        marketplaces if isinstance(marketplaces, dict) else {},
        "ok",
        "tomllib",
    )


def codex_cache_status(codex_root, marketplace, name):
    """Best-effort only (see module docstring, job 4): a plain isdir check
    against the one well-known Codex cache sub-path, never a size walk."""
    if not marketplace or not name:
        return "not-checked"
    candidate = os.path.join(codex_root, "plugins", "cache", marketplace, name)
    try:
        return "present" if os.path.isdir(candidate) else "missing"
    except OSError:
        return "not-checked"


def pack_codex_row(key, plugin_entry, marketplaces_map, codex_root):
    name, marketplace = split_plugin_key(key)
    enabled = ""
    if isinstance(plugin_entry, dict) and isinstance(plugin_entry.get("enabled"), bool):
        enabled = "1" if plugin_entry["enabled"] else "0"
    marketplace_entry = marketplaces_map.get(marketplace) if marketplace else None
    marketplace_last_updated = ""
    if isinstance(marketplace_entry, dict):
        marketplace_last_updated = str(marketplace_entry.get("last_updated", "") or "")
    cache_status = codex_cache_status(codex_root, marketplace, name)
    fields = [key, name, marketplace, enabled, cache_status, marketplace_last_updated]
    return FS.join(sanitize_text(f) for f in fields)


def collect_codex(plugins_map, marketplaces_map, codex_root):
    rows = []
    if not isinstance(plugins_map, dict):
        return rows
    for key in sorted(plugins_map.keys()):
        rows.append(pack_codex_row(key, plugins_map[key], marketplaces_map, codex_root))
    return rows


def main():
    warnings = []
    budget_state = [0]

    claude_dir = os.path.expanduser("~/.claude")
    installed_data, installed_status = load_json(os.path.join(claude_dir, "plugins", "installed_plugins.json"))

    enabled_map, enabled_status = load_enabled_map(os.path.join(claude_dir, "settings.json"))
    if enabled_status != "ok":
        warnings.append("Claude Code enabled-plugins map: " + enabled_status)

    plugin_rows, plugin_install_paths, plugins_shape_status, dropped_plugin_entries = collect_plugins(
        installed_data or {}, enabled_map, budget_state
    )
    if installed_status == "ok" and plugins_shape_status != "ok":
        # The file parsed as JSON but its top-level shape did not match
        # what Claude Code itself writes -- report that honestly instead of
        # the file-level "ok" a bare load_json() success would otherwise
        # carry forward. See collect_plugins()'s own docstring.
        installed_status = plugins_shape_status
    if installed_status != "ok":
        warnings.append("Claude Code plugin inventory: " + installed_status)
    if dropped_plugin_entries:
        warnings.append("%d malformed plugin install record(s) skipped" % dropped_plugin_entries)

    skills_status = "ok"
    personal_rows, skills_status = collect_personal_skills(os.path.join(claude_dir, "skills"))
    if skills_status not in ("ok", "not-found"):
        warnings.append("Claude Code personal skills: " + skills_status)
    plugin_skill_rows = collect_plugin_skills(plugin_install_paths)
    skill_rows = personal_rows + plugin_skill_rows

    marketplaces_data, marketplaces_status = load_json(os.path.join(claude_dir, "plugins", "known_marketplaces.json"))
    if marketplaces_status != "ok":
        warnings.append("Claude Code marketplaces: " + marketplaces_status)
    marketplace_rows = collect_marketplaces(marketplaces_data)

    codex_root = os.path.expanduser("~/.codex")
    codex_plugins_map, codex_marketplaces_map, codex_status, codex_reader = load_codex_config(
        os.path.join(codex_root, "config.toml")
    )
    if codex_status not in ("ok", "not-found"):
        warnings.append("Codex config: " + codex_status)
    codex_rows = collect_codex(codex_plugins_map, codex_marketplaces_map, codex_root)

    output = {
        "ok": True,
        "generated_at": now_iso(),
        "claude_plugins_status": installed_status,
        "claude_settings_status": enabled_status,
        "claude_skills_status": skills_status,
        "claude_marketplaces_status": marketplaces_status,
        "codex_config_status": codex_status,
        "codex_toml_reader": codex_reader,
        "packed_plugins": RS.join(plugin_rows),
        "plugin_count": len(plugin_rows),
        "packed_skills": RS.join(skill_rows),
        "skill_count": len(skill_rows),
        "packed_marketplaces": RS.join(marketplace_rows),
        "marketplace_count": len(marketplace_rows),
        "packed_codex": RS.join(codex_rows),
        "codex_count": len(codex_rows),
    }
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
