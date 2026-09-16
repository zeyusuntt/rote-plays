"""Classify the jobs enum_jobs.py found: healthy, target-missing,
stale-suspect, silent-failure-suspect, or opaque. Pure computation plus
filesystem existence/mtime checks over enum_jobs.py's own output -- no
crontab, plist, or launchd job is ever touched here; nothing is signaled,
loaded, or unloaded.

argv[1]  packed job rows from enum_jobs (chr(31)/chr(30) -- see
         enum_jobs.py's PACKED JOBS docstring; empty string is a valid
         "nothing found" input)
argv[2]  packed launchctl status rows from enum_jobs (chr(31)/chr(30) --
         see enum_jobs.py's PACKED STATUS docstring; empty string is a
         valid "nothing loaded" input)
argv[3]  stale_days -- a target script untouched this long, with no recent
         run evidence, is flagged stale-suspect (clamped to 30..3650)
argv[3] must int-parse; a non-integer is a hard fault (bad wiring between
steps, not an expected absence) -- message on stderr, exit 2.

CLASSIFICATION, most specific/severe signal wins, checked in this order:
  1. opaque                -- this row's command could not be parsed at
                               all (enum_jobs.py's parse_note), or no
                               absolute-path token was found in it. Never
                               guessed at: a relative or absent path is
                               opaque, not silently treated as anything
                               else.
  2. target-missing        -- the extracted target_token does not exist
                               on disk right now.
  3. silent-failure-suspect -- LaunchAgent rows only: launchd's own last
                               exit status for this job (via `launchctl
                               list`) is nonzero. Checked ahead of
                               staleness because a live failure signal is
                               more actionable than an old mtime. Worded
                               as "last exit N -- check it", never
                               "broken" -- see CONSERVATISM below.
  4. stale-suspect          -- the target's mtime is older than
                               stale_days AND no recent-run evidence was
                               found (see RECENT-RUN EVIDENCE below).
  5. healthy                -- everything else: target exists, and either
                               its last launchd exit was 0, it is not old
                               enough to flag, or it shows recent-run
                               evidence despite an old mtime.
crontab and systemd_timer rows can only ever reach opaque, target-missing,
stale-suspect, or healthy -- launchd's last-exit status has no cron/systemd
equivalent this play reads, so silent-failure-suspect is a LaunchAgent-only
state, by design, not an oversight.

RECENT-RUN EVIDENCE (what keeps an old-mtime script out of "stale-suspect"):
  - a live pid in `launchctl list` right now, or
  - the LaunchAgent's own StandardOutPath/StandardErrorPath file has an
    mtime newer than the stale_days cutoff.
Neither is available for crontab or systemd_timer rows -- cron's run
history lives in the system mail spool or syslog, neither of which this
play reads -- so an old-mtime cron/systemd job is unconditionally
stale-suspect. This asymmetry is disclosed here and in the play's
UNVERIFIED footer, not hidden.

CONSERVATISM: silent-failure-suspect and stale-suspect are inferential
labels, not verdicts -- the wording says so ("-suspect", "check it", never
"broken" or "dead"). mtime is circumstantial evidence of staleness, not
proof: no run-history source (cron's mail spool, syslog) is ever inspected
here, so stale-suspect only ever means "the file hasn't changed, and we
found no sign of a recent run" -- it can still be running successfully
via a mechanism this play doesn't read. A launchd job with no row in
`launchctl list` at all (on disk but never loaded, or unloaded since) has
no exit-status evidence one way or the other; that absence is itself
reported as evidence text, not silently treated as either healthy or a
failure.
"""

import json
import os
import sys
import time

FS, RS = chr(31), chr(30)
JOB_FIELDS = 8
STATUS_FIELDS = 3

STALE_DAYS_DEFAULT = 365
STALE_DAYS_MIN = 30
STALE_DAYS_MAX = 3650

SOURCE_LABELS = {
    "user_crontab": "crontab",
    "user_launchagent": "LaunchAgent",
    "systemd_timer": "systemd timer",
}


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


def unpack_jobs(packed):
    """Returns (rows, raw_record_count) -- see classify.py's unpack_rows in
    agent-resource-audit for the same tolerant-of-malformed-rows shape this
    mirrors: a row whose field count is wrong is skipped, not crashed on,
    and raw_record_count lets main() report how many were dropped."""
    if not packed:
        return [], 0
    rows = []
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != JOB_FIELDS:
            continue
        source, label, schedule_summary, target_token, command_display, stdout_path, stderr_path, parse_note = fields
        rows.append(
            {
                "source": source,
                "label": label,
                "schedule_summary": schedule_summary,
                "target_token": target_token,
                "command_display": command_display,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "parse_note": parse_note,
            }
        )
    return rows, raw_record_count


def unpack_status(packed):
    """Returns (status_by_label, raw_record_count). status_by_label maps a
    launchd Label to (pid, status_int_or_None, status_raw); status_int is
    None when the Status column itself did not int-parse (never observed
    live, but a malformed launchctl row must degrade, not crash)."""
    if not packed:
        return {}, 0
    status_by_label = {}
    raw_record_count = 0
    for record in packed.split(RS):
        if not record:
            continue
        raw_record_count += 1
        fields = record.split(FS)
        if len(fields) != STATUS_FIELDS:
            continue
        label, pid, status_raw = fields
        try:
            status_int = int(status_raw)
        except ValueError:
            status_int = None
        status_by_label[label] = (pid, status_int, status_raw)
    return status_by_label, raw_record_count


def has_recent_run_evidence(row, status_entry, stale_days, now):
    """See module docstring RECENT-RUN EVIDENCE. Returns (bool, detail)."""
    if status_entry is not None:
        pid, _status_int, _status_raw = status_entry
        if pid not in ("", "-"):
            return True, "process is currently running (pid " + pid + ")"
    cutoff = now - stale_days * 86400
    for which, path in (("stdout", row["stdout_path"]), ("stderr", row["stderr_path"])):
        if not path:
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime >= cutoff:
            return True, which + " log touched recently (" + path + ")"
    return False, ""


def classify_row(row, status_by_label, stale_days, now):
    source = row["source"]
    label = row["label"]
    source_display = SOURCE_LABELS.get(source, source)

    if row["parse_note"]:
        return {
            "source": source_display,
            "label": label,
            "schedule_summary": row["schedule_summary"],
            "state": "opaque",
            "evidence": row["parse_note"],
        }

    target = row["target_token"]
    if not target:
        return {
            "source": source_display,
            "label": label,
            "schedule_summary": row["schedule_summary"],
            "state": "opaque",
            "evidence": "no absolute-path token found in command; cannot verify target existence",
        }

    if not os.path.exists(target):
        return {
            "source": source_display,
            "label": label,
            "schedule_summary": row["schedule_summary"],
            "state": "target-missing",
            "evidence": "target not found: " + target,
        }

    status_entry = status_by_label.get(label) if source == "user_launchagent" else None

    if status_entry is not None:
        _pid, status_int, status_raw = status_entry
        if status_int is not None and status_int != 0:
            evidence = "last exit " + str(status_int) + " -- check it"
            return {
                "source": source_display,
                "label": label,
                "schedule_summary": row["schedule_summary"],
                "state": "silent-failure-suspect",
                "evidence": evidence,
                "exit_status": status_int,
            }

    try:
        mtime = os.path.getmtime(target)
    except OSError as exc:
        return {
            "source": source_display,
            "label": label,
            "schedule_summary": row["schedule_summary"],
            "state": "healthy",
            "evidence": "target exists (age unknown -- could not stat: " + str(exc) + ")",
        }

    age_days = (now - mtime) / 86400.0

    if age_days > stale_days:
        recent, detail = has_recent_run_evidence(row, status_entry, stale_days, now)
        if not recent:
            return {
                "source": source_display,
                "label": label,
                "schedule_summary": row["schedule_summary"],
                "state": "stale-suspect",
                "evidence": "target untouched for %d days (> %d) -- mtime is circumstantial evidence, "
                "no run-history source was inspected"
                % (int(age_days), stale_days),
            }
        return {
            "source": source_display,
            "label": label,
            "schedule_summary": row["schedule_summary"],
            "state": "healthy",
            "evidence": "target is %d days old but shows recent run evidence: %s" % (int(age_days), detail),
        }

    if status_entry is not None:
        _pid, status_int, _status_raw = status_entry
        evidence = "target exists, %d days old, last exit %s" % (
            int(age_days),
            status_int if status_int is not None else "unparseable",
        )
    elif source == "user_launchagent":
        evidence = "target exists, %d days old (not currently loaded -- no launchctl status)" % int(age_days)
    else:
        evidence = "target exists, %d days old" % int(age_days)

    return {
        "source": source_display,
        "label": label,
        "schedule_summary": row["schedule_summary"],
        "state": "healthy",
        "evidence": evidence,
    }


def advisory_for(row_result):
    """Text-only advisories -- nothing here is ever executed on the user's
    behalf, exactly like every kill/resume hint the rest of this codebase's
    plays print."""
    state = row_result["state"]
    if state == "target-missing":
        return "remove or fix: " + row_result["label"]
    if state == "silent-failure-suspect" and row_result.get("exit_status") == 127:
        return (
            "on macOS this often means the job cannot read a protected folder (TCC) -- "
            "run the command by hand once"
        )
    return None


def main():
    packed_jobs = arg(1, "")
    packed_status = arg(2, "")
    stale_days = clamp(parse_int_arg(3, "stale_days", STALE_DAYS_DEFAULT), STALE_DAYS_MIN, STALE_DAYS_MAX)

    raw_jobs, raw_job_count = unpack_jobs(packed_jobs)
    dropped_jobs = raw_job_count - len(raw_jobs)

    status_by_label, raw_status_count = unpack_status(packed_status)

    now = time.time()
    results = [classify_row(row, status_by_label, stale_days, now) for row in raw_jobs]

    advisories = []
    for result in results:
        text = advisory_for(result)
        if text:
            advisories.append({"label": result["label"], "state": result["state"], "text": text})

    counts = {"total": len(results)}
    for state in ("healthy", "target-missing", "stale-suspect", "silent-failure-suspect", "opaque"):
        counts[state] = sum(1 for r in results if r["state"] == state)

    # Display order: the states most worth a human's attention first.
    state_order = {
        "target-missing": 0,
        "silent-failure-suspect": 1,
        "stale-suspect": 2,
        "opaque": 3,
        "healthy": 4,
    }
    results.sort(key=lambda r: (state_order.get(r["state"], 9), r["source"], r["label"]))

    output = {
        "ok": True,
        "stale_days": stale_days,
        "counts": counts,
        "jobs": results,
        "advisories": advisories,
    }

    dropped_status = raw_status_count - len(status_by_label)
    warnings = []
    if dropped_jobs > 0:
        warnings.append(str(dropped_jobs) + " malformed job row(s) from enum_jobs could not be parsed and were skipped")
    if dropped_status > 0:
        warnings.append(
            str(dropped_status) + " malformed launchctl status row(s) from enum_jobs could not be parsed and were skipped"
        )
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
