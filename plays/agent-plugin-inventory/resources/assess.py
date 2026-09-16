"""Assess the rows inventory.py found: turn raw per-item facts into THE
FLAGS. Value edge, one step after inventory. Pure computation over its four
packed inputs plus stale_days -- touches no file, no process, no network.

argv[1]  packed plugin rows from inventory (chr(31)/chr(30) -- see
         inventory.py's PACKED PLUGIN ROWS docstring; 11 fields per row)
argv[2]  plugin_count -- inventory's own record count for that collection,
         used only to detect whether any row was silently lost between the
         two steps (see unpack_records below); a mismatch is reported as a
         warning, never a crash
argv[3]  packed skill rows from inventory (5 fields per row)
argv[4]  skill_count -- inventory's own record count for that collection
argv[5]  packed marketplace rows from inventory (3 fields per row)
argv[6]  marketplace_count -- inventory's own record count for that
         collection
argv[7]  packed Codex plugin-equivalent rows from inventory (6 fields per
         row)
argv[8]  codex_count -- inventory's own record count for that collection
argv[9]  stale_days -- a marketplace whose last recorded sync is older than
         this many days is flagged stale-suspect (clamped to 1..365). Must
         int-parse; a non-integer is a hard fault (this is bad wiring
         between the parameter gate and this step, not an expected
         absence) -- message on stderr, exit 2.
Every count argument is optional (empty string is tolerated as "0 rows
reported"); an empty packed string is always a valid "nothing found" input
for its own collection.

THE FLAGS, each conservative and worded "-suspect" -- none of these is
asserted as a certainty; see main.ts's FLAGS section for the full
disclosure text:

  name_collision_suspect  A skill NAME that appears under more than one
                          owner (two different plugins bundling the same
                          skill name, or a plugin skill sharing a name with
                          a personal skill), compared case-INsensitively
                          (a case-insensitive filesystem, or a harness that
                          normalizes names before loading, could still
                          collide two skills whose names differ only in
                          case) -- the flag's own "detail" text discloses
                          the exact casing seen from each source when it
                          varies. Which one actually wins at runtime for a
                          given harness is not evaluated here -- harness
                          precedence rules vary and this script never
                          spawns or loads anything to find out.
  broken_install_suspect  A Claude Code or Codex plugin entry whose own
                          cache directory is missing or empty. Deliberately
                          excludes "inaccessible" (a permission error is
                          not evidence of a broken install, only of an
                          unreadable one) and "no-install-path"/
                          "out-of-scope" (no installPath was ever recorded,
                          or the recorded one fell outside Claude's own
                          plugin cache root -- neither is evidence of a
                          broken install, only that there was nothing safe
                          to check) -- both counts are carried separately
                          in totals for an honest footer, never silently
                          folded into this flag.
  stale_suspect            A Claude Code marketplace (known_marketplaces.json
                          only -- Codex's own marketplace sync recency is
                          not evaluated by this play) whose recorded
                          last-sync time is older than stale_days. A
                          marketplace with no recorded last-sync time at
                          all is never flagged -- staleness is reported
                          only when known_marketplaces.json actually
                          records a timestamp to compare.
  disabled_but_cached      A plugin (Claude Code or Codex) explicitly
                          disabled (enabled=false in its own harness
                          config) whose cache directory is still present on
                          disk -- a disk note, not a security finding; see
                          agent-disk-tax (published separately) for what
                          that disk cost actually measures.

Emits one JSON object on stdout, always exit 0 once inputs parse:
    {"ok": true,
     "warning": "<optional -- N malformed row(s) dropped / count mismatch>",
     "totals": {"plugin_count", "plugin_enabled_count",
                "plugin_disabled_count", "plugin_enabled_unknown_count",
                "plugin_cache_inaccessible_count",
                "plugin_cache_not_applicable_count", "personal_skill_count",
                "plugin_skill_count", "marketplace_count",
                "marketplace_unknown_staleness_count", "codex_count",
                "codex_enabled_count", "stale_days"},
     "plugins": [...], "personal_skills": [...], "plugin_skills": [...],
     "marketplaces": [...], "codex": [...],
     "flags": {"name_collision_suspect": [...], "broken_install_suspect": [...],
                "stale_suspect": [...], "disabled_but_cached": [...]}}
Each flags.* entry carries {"name"/"key", ..., "detail": "..."} -- detail is
a short, non-secret, non-command description of WHY the item was flagged;
no advice text or shell command is built here at all -- this play reads
config and disk metadata only, and recommends nothing beyond "review this
yourself" in the presentation layer."""

import json
import sys
import time

FS, RS = chr(31), chr(30)
PLUGIN_FIELDS = 11
SKILL_FIELDS = 5
MARKETPLACE_FIELDS = 3
CODEX_FIELDS = 6

STALE_DAYS_MIN, STALE_DAYS_MAX, STALE_DAYS_DEFAULT = 1, 365, 30
SECONDS_PER_DAY = 86400.0


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


def unpack_records(packed, field_count):
    """Returns (rows, raw_record_count). rows is a list of field-lists,
    each exactly field_count long; a record whose field count does not
    match is dropped (tolerated) rather than crashing the whole
    assessment. raw_record_count is every non-empty RS-delimited record
    seen, so main() can tell "nothing found" apart from "rows were
    silently lost to a malformed record"."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != field_count:
            continue
        rows.append(fields)
    return rows, raw_record_count


def reconcile(name, raw_record_count, reported_count, warnings):
    if reported_count and reported_count != raw_record_count:
        warnings.append(
            "inventory reported %d %s row(s) but %d record(s) arrived at this step"
            % (reported_count, name, raw_record_count)
        )


def main():
    packed_plugins = arg(1, "")
    plugin_count_reported = parse_int_arg(2, "plugin_count", 0)
    packed_skills = arg(3, "")
    skill_count_reported = parse_int_arg(4, "skill_count", 0)
    packed_marketplaces = arg(5, "")
    marketplace_count_reported = parse_int_arg(6, "marketplace_count", 0)
    packed_codex = arg(7, "")
    codex_count_reported = parse_int_arg(8, "codex_count", 0)
    stale_days = clamp(parse_int_arg(9, "stale_days", STALE_DAYS_DEFAULT), STALE_DAYS_MIN, STALE_DAYS_MAX)

    warnings = []
    dropped_total = 0

    plugin_raw, plugin_raw_count = unpack_records(packed_plugins, PLUGIN_FIELDS)
    dropped_total += plugin_raw_count - len(plugin_raw)
    reconcile("plugin", plugin_raw_count, plugin_count_reported, warnings)

    skill_raw, skill_raw_count = unpack_records(packed_skills, SKILL_FIELDS)
    dropped_total += skill_raw_count - len(skill_raw)
    reconcile("skill", skill_raw_count, skill_count_reported, warnings)

    marketplace_raw, marketplace_raw_count = unpack_records(packed_marketplaces, MARKETPLACE_FIELDS)
    dropped_total += marketplace_raw_count - len(marketplace_raw)
    reconcile("marketplace", marketplace_raw_count, marketplace_count_reported, warnings)

    codex_raw, codex_raw_count = unpack_records(packed_codex, CODEX_FIELDS)
    dropped_total += codex_raw_count - len(codex_raw)
    reconcile("codex", codex_raw_count, codex_count_reported, warnings)

    now = time.time()

    # ---- plugins (Claude Code) --------------------------------------------
    plugins = []
    for fields in plugin_raw:
        (
            key, name, marketplace, version, scope, installed_at, last_updated,
            enabled, cache_status, cache_size, cache_partial,
        ) = fields
        plugins.append(
            {
                "key": key,
                "name": name,
                "marketplace": marketplace,
                "version": version,
                "scope": scope,
                "installed_at": installed_at or None,
                "last_updated": last_updated or None,
                "enabled": {"1": True, "0": False}.get(enabled),
                "cache_dir_status": cache_status,
                "cache_size_bytes": int(cache_size) if cache_size.isdigit() else None,
                "cache_partial": cache_partial == "1",
                "harness": "claude",
            }
        )

    # ---- skills (split back into personal / plugin-bundled) ---------------
    personal_skills = []
    plugin_skills = []
    # Keyed case-INsensitively for collision detection only (see FLAGS,
    # name_collision_suspect below) -- a case-insensitive filesystem, or a
    # harness that normalizes names before loading, could still collide two
    # skills whose names differ only in case; skills_by_name and the
    # personal_skills/plugin_skills lists themselves keep each skill's own
    # original casing untouched.
    skills_by_name_ci = {}
    for fields in skill_raw:
        name, owner_kind, owner_label, description, mtime_epoch = fields
        row = {
            "name": name,
            "owner_kind": owner_kind,
            "owner_label": owner_label,
            "description": description or None,
            "mtime_epoch": float(mtime_epoch) if mtime_epoch else None,
        }
        if owner_kind == "personal":
            personal_skills.append(row)
        else:
            plugin_skills.append(row)
        skills_by_name_ci.setdefault(name.lower(), []).append(row)

    # ---- marketplaces (Claude Code) ----------------------------------------
    marketplaces = []
    marketplace_unknown_staleness_count = 0
    for fields in marketplace_raw:
        name, last_updated, repo = fields
        age_days = None
        if last_updated:
            try:
                # ISO 8601 with a trailing "Z" -- Python's fromisoformat needs
                # "+00:00" in place of that before 3.11; normalize defensively.
                normalized = last_updated[:-1] + "+00:00" if last_updated.endswith("Z") else last_updated
                import datetime as _dt

                age_days = (now - _dt.datetime.fromisoformat(normalized).timestamp()) / SECONDS_PER_DAY
            except (ValueError, OverflowError):
                age_days = None
        if age_days is None:
            marketplace_unknown_staleness_count += 1
        marketplaces.append(
            {
                "name": name,
                "last_updated": last_updated or None,
                "repo": repo or None,
                "age_days": round(age_days, 1) if age_days is not None else None,
            }
        )

    # ---- Codex plugin-equivalents ------------------------------------------
    codex = []
    for fields in codex_raw:
        key, name, marketplace, enabled, cache_status, marketplace_last_updated = fields
        codex.append(
            {
                "key": key,
                "name": name,
                "marketplace": marketplace,
                "enabled": {"1": True, "0": False}.get(enabled),
                "cache_dir_status": cache_status,
                "marketplace_last_updated": marketplace_last_updated or None,
                "harness": "codex",
            }
        )

    # ---- FLAGS --------------------------------------------------------------
    name_collision_suspect = []
    for lname, rows in sorted(skills_by_name_ci.items()):
        owners = sorted({r["owner_label"] for r in rows})
        if len(owners) <= 1:
            continue
        variants = sorted({r["name"] for r in rows})
        detail = "same skill name from %d source(s): %s -- which one wins is harness-defined" % (
            len(owners),
            ", ".join(owners),
        )
        if len(variants) > 1:
            detail += " (case varies: %s)" % ", ".join(variants)
        name_collision_suspect.append(
            {
                "name": variants[0] if len(variants) == 1 else "/".join(variants),
                "detail": detail,
                "owners": owners,
            }
        )

    broken_install_suspect = []
    plugin_cache_inaccessible_count = 0
    plugin_cache_not_applicable_count = 0
    for p in plugins:
        status = p["cache_dir_status"]
        if status == "inaccessible":
            plugin_cache_inaccessible_count += 1
        elif status in ("no-install-path", "out-of-scope"):
            # No installPath was recorded at all, or the recorded
            # installPath fell outside Claude's own plugin cache root --
            # neither is evidence of a broken install, only that this play
            # had nothing safe to check. Counted separately for an honest
            # footer, never folded into broken-install-suspect.
            plugin_cache_not_applicable_count += 1
        elif status in ("missing", "empty"):
            broken_install_suspect.append(
                {
                    "key": p["key"],
                    "harness": "claude",
                    "detail": "cache directory %s" % status,
                }
            )
    for c in codex:
        if c["cache_dir_status"] == "missing":
            broken_install_suspect.append(
                {"key": c["key"], "harness": "codex", "detail": "cache directory missing"}
            )

    stale_suspect = []
    for m in marketplaces:
        if m["age_days"] is not None and m["age_days"] >= stale_days:
            stale_suspect.append(
                {
                    "name": m["name"],
                    "detail": "last synced %.1f day(s) ago (>= %d)" % (m["age_days"], stale_days),
                }
            )

    disabled_but_cached = []
    for p in plugins:
        if p["enabled"] is False and p["cache_dir_status"] == "present":
            size_note = (
                "%d byte(s) on disk" % p["cache_size_bytes"]
                if p["cache_size_bytes"] is not None
                else "on disk, size not measured"
            )
            disabled_but_cached.append(
                {"key": p["key"], "harness": "claude", "detail": "disabled but cached -- " + size_note}
            )
    for c in codex:
        if c["enabled"] is False and c["cache_dir_status"] == "present":
            disabled_but_cached.append(
                {
                    "key": c["key"],
                    "harness": "codex",
                    "detail": "disabled but cached -- on disk, size not measured (best-effort check)",
                }
            )

    plugin_enabled_count = sum(1 for p in plugins if p["enabled"] is True)
    plugin_disabled_count = sum(1 for p in plugins if p["enabled"] is False)
    plugin_enabled_unknown_count = sum(1 for p in plugins if p["enabled"] is None)
    codex_enabled_count = sum(1 for c in codex if c["enabled"] is True)

    output = {
        "ok": True,
        "totals": {
            "plugin_count": len(plugins),
            "plugin_enabled_count": plugin_enabled_count,
            "plugin_disabled_count": plugin_disabled_count,
            "plugin_enabled_unknown_count": plugin_enabled_unknown_count,
            "plugin_cache_inaccessible_count": plugin_cache_inaccessible_count,
            "plugin_cache_not_applicable_count": plugin_cache_not_applicable_count,
            "personal_skill_count": len(personal_skills),
            "plugin_skill_count": len(plugin_skills),
            "marketplace_count": len(marketplaces),
            "marketplace_unknown_staleness_count": marketplace_unknown_staleness_count,
            "codex_count": len(codex),
            "codex_enabled_count": codex_enabled_count,
            "stale_days": stale_days,
        },
        "plugins": plugins,
        "personal_skills": personal_skills,
        "plugin_skills": plugin_skills,
        "marketplaces": marketplaces,
        "codex": codex,
        "flags": {
            "name_collision_suspect": name_collision_suspect,
            "broken_install_suspect": broken_install_suspect,
            "stale_suspect": stale_suspect,
            "disabled_but_cached": disabled_but_cached,
        },
    }

    if dropped_total > 0:
        warnings.append("%d malformed row(s) from inventory could not be parsed and were skipped" % dropped_total)
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
