"""Aggregate discover_configs.py's already-classified rows into the
per-file table, the findings list, and the counts this play reports.

Read-only, pure computation over its three inputs. Never touches a
filesystem path itself, never re-derives a value from a preview -- the
4-character preview and length discover_configs.py already computed are
the most this script (or anything downstream of it) ever sees of a
classified env value. This step's whole job is joining and counting rows
that were already reduced to safe fields one step upstream; see
discover_configs.py's module docstring for the invariant that makes this
step-boundary safe to cross with a packed scalar in the first place.

argv[1]  sources_packed  from discover_configs (chr(31)/chr(30) -- see
         discover_configs.py; 7 fields per record: harness, path, status,
         servers_found, mode_octal, world_readable (0/1), group_readable
         (0/1)); always exactly 5 records (one per fixed harness path,
         "not-found" included) unless discover_configs itself degraded.
argv[2]  entries_packed  from discover_configs (8 fields per record:
         harness, source_path, server_name, var_name, shape, preview4,
         length, enabled (0/1)); empty string is a valid "no env vars
         anywhere" input.
argv[3]  verbose -- 0 (default) or 1; when 1, an additional per-entry
         detail row is emitted for EVERY env var this run examined (not
         only the secret-shaped ones), so a human can audit the "literal"
         and "indirection" calls too, not just take the secret count on
         faith. Must int-parse; a non-integer is a hard fault (bad step
         wiring, not a legitimate absence -- same reasoning classify.py/
         scan_identities.py apply to their own int argv).

Malformed packed records (wrong field count, non-integer counts) are
tolerated rather than crashing the whole audit, but are not silently
invisible: raw record counts are compared against successfully-parsed
counts, and any loss is folded into a top-level `warning`.

"Config files" in this play's counts means files that EXIST on disk
(status != "not-found"), regardless of whether their contents parsed --
an empty or broken file can still carry a real permission posture, and
hiding it from file-level counts would hide that. `config_files_parsed`
narrows to files whose contents were actually readable as server configs.

The "top flag" this play exists to surface: a file that is world- or
group-readable AND holds at least one inline secret-shaped value. Every
other combination (readable-but-clean, secret-but-locked-down) is a lower
concern, reported but not called out the same way.

Emits one JSON object on stdout, always exit 0 once argv parses:
    {"ok": true,
     "warning": "<optional -- N malformed row(s) dropped>",
     "totals": {"config_files_found": n, "config_files_parsed": n,
                "servers_total": n, "env_entries_total": n,
                "inline_secret_count": n, "world_readable_count": n,
                "group_readable_count": n, "flagged_file_count": n},
     "files": [{harness, path, path_display, status, servers_found,
                 env_entries, inline_secret_count, mode_octal,
                 world_readable, group_readable, flagged}, ...],
     "findings": [{var_name, shape, preview, length, harness, server,
                    path_display, enabled}, ...],
     "verbose_rows": [...] (only when verbose=1, else []),
     "advisory": "<text>"|null,
     "checked": [...], "unverified": [...]}
"""

import json
import os
import sys

FS, RS = chr(31), chr(30)

SOURCE_FIELDS = 7  # harness, path, status, servers_found, mode_octal, world_readable, group_readable
ENTRY_FIELDS = 8  # harness, source_path, server_name, var_name, shape, preview4, length, enabled

# The "4-character preview = max exposure" invariant is enforced upstream in
# discover_configs.py's classify_value_shape(), but is re-enforced here too,
# defensively, at the boundary where a packed field is unpacked back into a
# structured record -- a corrupted step output or a future producer
# regression must never let a longer value survive into this play's own
# findings/JSON, no matter what a malformed record claims.
PREVIEW_MAX = 4

VERBOSE_MIN, VERBOSE_MAX, VERBOSE_DEFAULT = 0, 1, 0

HOME = os.path.expanduser("~")

ADVISORY_TEXT = (
    "move it to your OS keychain / a local env manager, reference by name -- "
    "MCP configs travel in backups and dotfile repos"
)


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


def redact_home(path):
    """Display-only home-directory redaction, computed here (one step
    downstream of discover_configs, which packs the real absolute path
    unredacted) -- the same "redaction happens where it is displayed, not
    where it is discovered" split commit-identity-check's scan_identities.py
    already established for the identical class of problem."""
    if not path:
        return path
    if HOME and path.startswith(HOME):
        return "~" + path[len(HOME):]
    return path


def unpack_sources(packed):
    """Returns (rows, raw_record_count)."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != SOURCE_FIELDS:
            continue
        harness, path, status, servers_found_s, mode_octal, world_s, group_s = fields
        try:
            servers_found = int(servers_found_s)
        except ValueError:
            continue
        rows.append(
            {
                "harness": harness,
                "path": path,
                "status": status,
                "servers_found": servers_found,
                "mode_octal": mode_octal or None,
                "world_readable": world_s == "1",
                "group_readable": group_s == "1",
            }
        )
    return rows, raw_record_count


def unpack_entries(packed):
    """Returns (rows, raw_record_count)."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != ENTRY_FIELDS:
            continue
        harness, source_path, server_name, var_name, shape, preview, length_s, enabled_s = fields
        try:
            length = int(length_s)
        except ValueError:
            continue
        rows.append(
            {
                "harness": harness,
                "source_path": source_path,
                "server": server_name,
                "var_name": var_name,
                "shape": shape,
                "preview": preview[:PREVIEW_MAX],
                "length": length,
                "enabled": enabled_s == "1",
            }
        )
    return rows, raw_record_count


def main():
    sources, sources_raw_count = unpack_sources(arg(1))
    entries, entries_raw_count = unpack_entries(arg(2))
    verbose = clamp(parse_int_arg(3, "verbose", VERBOSE_DEFAULT), VERBOSE_MIN, VERBOSE_MAX)

    dropped = (sources_raw_count - len(sources)) + (entries_raw_count - len(entries))
    warning = None
    if dropped > 0:
        warning = "%d malformed row(s) dropped while unpacking discover_configs output" % dropped

    entries_by_path = {}
    for e in entries:
        entries_by_path.setdefault(e["source_path"], []).append(e)

    files = []
    findings = []
    verbose_rows = []
    world_readable_count = 0
    group_readable_count = 0
    flagged_file_count = 0
    config_files_found = 0
    config_files_parsed = 0
    servers_total = 0
    env_entries_total = 0
    inline_secret_count = 0

    for s in sources:
        path_entries = entries_by_path.get(s["path"], [])
        # Both prefixes are "shape matched a secret-like pattern": confirmed
        # literal forms (secret-sk/-ghp/-akia/-jwt) AND the "potential-"
        # high-entropy catch-all, which is deliberately named to admit it
        # also flags non-secret opaque identifiers (see discover_configs.py)
        # while still surfacing for a human to judge -- it is not dropped
        # from counts just because it is less certain than a shaped match.
        secret_rows = [
            e for e in path_entries
            if e["shape"].startswith("secret-") or e["shape"].startswith("potential-secret-")
        ]
        world_readable = s["world_readable"]
        group_readable = s["group_readable"]
        flagged = (world_readable or group_readable) and len(secret_rows) > 0

        if s["status"] != "not-found":
            config_files_found += 1
        # "ok" and the codex fallback's "ok (fallback toml reader)" both
        # mean the file's contents were actually readable as a config;
        # anything else (not-found, or an "error: ..." parse failure)
        # is not counted as parsed even though it may still be found.
        if s["status"] == "ok" or s["status"].startswith("ok ("):
            config_files_parsed += 1
        if world_readable:
            world_readable_count += 1
        if group_readable:
            group_readable_count += 1
        if flagged:
            flagged_file_count += 1
        servers_total += s["servers_found"]
        env_entries_total += len(path_entries)
        inline_secret_count += len(secret_rows)

        files.append(
            {
                "harness": s["harness"],
                "path": s["path"],
                "path_display": redact_home(s["path"]),
                "status": s["status"],
                "servers_found": s["servers_found"],
                "env_entries": len(path_entries),
                "inline_secret_count": len(secret_rows),
                "mode_octal": s["mode_octal"],
                "world_readable": world_readable,
                "group_readable": group_readable,
                "flagged": flagged,
            }
        )

        for e in secret_rows:
            findings.append(
                {
                    "var_name": e["var_name"],
                    "shape": e["shape"],
                    "preview": e["preview"],
                    "length": e["length"],
                    "harness": e["harness"],
                    "server": e["server"],
                    "path_display": redact_home(e["source_path"]),
                    "enabled": e["enabled"],
                }
            )

        if verbose == 1:
            for e in path_entries:
                verbose_rows.append(
                    {
                        "harness": e["harness"],
                        "server": e["server"],
                        "var_name": e["var_name"],
                        "shape": e["shape"],
                        "path_display": redact_home(e["source_path"]),
                        "enabled": e["enabled"],
                    }
                )

    advisory = ADVISORY_TEXT if inline_secret_count > 0 else None

    checked = [
        "%d/%d fixed harness config path(s) exist on this machine (%d parsed as a valid server config)"
        % (config_files_found, len(sources), config_files_parsed),
        "%d env entr(y/ies) across %d server entr(y/ies) classified by value shape"
        % (env_entries_total, servers_total),
        "file permissions read once per existing config path, independent of whether its contents parsed",
        "disabled server blocks (enabled: false) are included in this audit -- a secret in a disabled block is still a secret on disk",
    ]
    unverified = [
        "whether a shape-match (sk-/ghp_/AKIA/JWT/40+ char high-entropy token) is a REAL, still-live secret, or a revoked/rotated/fake-looking string that merely matches the shape",
        "the 'potential-secret-highentropy' bucket specifically is also known to flag non-secret opaque identifiers -- a hex digest (git commit, content hash) or a long high-entropy hostname/slug can clear the same 40+ char/entropy threshold as a real token",
        "secret formats this play does not recognize -- a short custom API key, or a base64 secret containing '/' (deliberately excluded from the high-entropy bucket to avoid flagging ordinary file-path env values)",
        "whether a $VAR/${VAR} indirection resolves, elsewhere, to something that is itself stored unsafely -- this play only classifies the literal value sitting in the config file",
        "config files outside the fixed harness paths this play reads (a project-level .mcp.json, a non-default harness install location) -- never a filesystem walk, by design",
    ]

    print(
        json.dumps(
            {
                "ok": True,
                "warning": warning,
                "totals": {
                    "config_files_found": config_files_found,
                    "config_files_parsed": config_files_parsed,
                    "servers_total": servers_total,
                    "env_entries_total": env_entries_total,
                    "inline_secret_count": inline_secret_count,
                    "world_readable_count": world_readable_count,
                    "group_readable_count": group_readable_count,
                    "flagged_file_count": flagged_file_count,
                },
                "files": files,
                "findings": findings,
                "verbose_rows": verbose_rows,
                "advisory": advisory,
                "checked": checked,
                "unverified": unverified,
            }
        )
    )


main()
