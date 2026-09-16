"""Answer one half of the drill: how stale is the last backup of THIS machine?

No sudo, ever, and this script never writes backup data or triggers a
backup. On macOS this consults only `tmutil latestbackup -t` and `tmutil
destinationinfo -X`, both of which a normal user account can run without
elevation (they may still fail -- no configured destination, an unmounted
network share, Full Disk Access denied -- and that failure is read as data,
not an error to crash on). tmutil's own exit code is not trustworthy here:
`latestbackup` returns 0 even when it prints "Failed to mount backup
destination" or "No destinations configured", so failure is detected from
the text, not the exit status.

This script is read-only in the sense that it never writes anything and
never asks tmutil to start, stop, or delete a backup. It is NOT a "no
network" guarantee: Apple's own documentation for `tmutil latestbackup`
notes it may mount an already-configured network backup destination as a
side effect of being asked for the latest snapshot, and this script cannot
prevent or detect that from the outside. Anyone relying on this play running
with zero network activity on a machine with a network Time Machine
destination configured should know that promise cannot be made here.

Both tmutil calls share ONE wall-clock budget (STEP_BUDGET_S, kept safely
under the step's declared timeout) instead of each getting the same fixed
timeout independently: two sequential calls each allowed to use the full
per-call ceiling could together exceed the step's timeout and get killed
before any JSON -- even the degraded kind -- is written. `latestbackup` (the
primary signal) runs first; `destinationinfo` (used only to label the
destination and to explain a missing/unreachable one) gets whatever budget
is left, and is skipped -- not attempted with an unreasonably small timeout
-- if that budget has already run out.

A missing destination is reported as one of a few distinct STATES, not
collapsed into a single "no destination configured" message: `ok` (read
cleanly, list may be empty), `configured_empty` (the plist parsed fine and
genuinely lists no destinations -- Time Machine has never been set up), and
`error` (the command failed to run, timed out, or returned something this
script could not parse -- which covers Full Disk Access denial and a
generic tmutil failure alike). An `error` state is never allowed to be
reported as if it meant "not configured": a real failure to read
destinations is surfaced as its own reason, ahead of the (weaker) "no
destination configured" diagnosis.

On Linux there is no equivalent of Time Machine to query, so this looks only
for the obvious markers of the three common unattended backup tools -- a
binary on PATH or one of their well-known state directories -- and reports
that as context. It never reads a repository, a snapshot list, or any file
content, so it can never tell you how OLD a borg/restic/timeshift backup is,
only that the tool appears to be set up. Anywhere else, the answer is an
honest, plainly-labeled unknown.

Emits one JSON object on stdout, always with "ok": true -- every failure mode
here is a labeled degrade, never a crash, because "backup status unknown" is
itself the correct answer on plenty of real machines.
"""

import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import time
from datetime import datetime

STEP_BUDGET_S = 17.0  # step timeout is 20s; this leaves ~3s for interpreter
# startup, plist/text parsing, and JSON serialization of the (possibly
# degraded) result -- the one thing this script must always still emit.
MIN_CALL_TIMEOUT_S = 2.0  # a call is never attempted with less than this
CALL_CEILING_S = 15.0  # a single call is never given more than this, even
# early in the budget, so one slow call can't eat the whole step budget
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{6}$")

HOME = os.path.expanduser("~")


def redact_home(text):
    """Never let a raw $HOME path leave this script -- '~' reads the same to
    a human and gives away nothing about the account name."""
    if not text:
        return text
    return str(text).replace(HOME, "~") if HOME and HOME != "/" else str(text)


def truncate_on_boundary(text, max_len):
    """Trim to max_len on a word or punctuation boundary, never mid-word,
    marking the cut with an explicit ellipsis -- a shortened reason must
    never read as if it ended cleanly when it did not."""
    if len(text) <= max_len:
        return text
    clipped = text[:max_len]
    boundary = max(clipped.rfind(" "), clipped.rfind(","), clipped.rfind(";"), clipped.rfind("."))
    if boundary > max_len // 2:
        clipped = clipped[:boundary]
    return clipped.rstrip(" ,.;") + "..."


def remaining_time(deadline_at):
    return deadline_at - time.monotonic()


def run(argv, deadline_at):
    """A tmutil call bounded by whatever remains of the shared step budget,
    never a fixed per-call constant -- so two sequential calls can never
    together exceed the budget this script has to still emit JSON within."""
    remaining = remaining_time(deadline_at)
    if remaining <= 0:
        raise TimeoutError("no time remaining in step budget")
    timeout = max(MIN_CALL_TIMEOUT_S, min(remaining, CALL_CEILING_S))
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def read_destinations(deadline_at):
    """tmutil destinationinfo -X, parsed as a plist. Never raises: any
    failure comes back as an explicit state so the caller can tell a real
    error (command failure, timeout, unparseable output -- includes Full
    Disk Access denial) apart from a plist that legitimately lists zero
    destinations."""
    if remaining_time(deadline_at) <= 0:
        return {"state": "error", "destinations": [], "detail": "skipped: no time remaining in step budget"}
    try:
        result = run(["tmutil", "destinationinfo", "-X"], deadline_at)
    except subprocess.TimeoutExpired:
        return {"state": "error", "destinations": [], "detail": "tmutil destinationinfo timed out"}
    except (subprocess.SubprocessError, OSError, TimeoutError) as exc:
        return {"state": "error", "destinations": [], "detail": "could not run tmutil destinationinfo: " + redact_home(str(exc))[:120]}
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()[:160]
        return {
            "state": "error",
            "destinations": [],
            "detail": redact_home(stderr) if stderr else "tmutil destinationinfo exited " + str(result.returncode),
        }
    try:
        data = plistlib.loads(result.stdout.encode("utf-8"))
    except (ValueError, TypeError):
        return {"state": "error", "destinations": [], "detail": "tmutil destinationinfo did not return a readable plist"}
    if not isinstance(data, dict):
        return {"state": "error", "destinations": [], "detail": "tmutil destinationinfo returned an unexpected plist shape"}
    destinations = data.get("Destinations")
    if not isinstance(destinations, list) or not destinations:
        return {"state": "configured_empty", "destinations": [], "detail": None}
    clean = []
    for entry in destinations:
        if isinstance(entry, dict):
            clean.append({"kind": entry.get("Kind"), "name": entry.get("Name")})
    if not clean:
        return {"state": "configured_empty", "destinations": [], "detail": None}
    return {"state": "ok", "destinations": clean, "detail": None}


def read_latest_backup(deadline_at):
    """tmutil latestbackup -t. Returns (timestamp_str_or_None, reason_or_None).
    Exit code is not trustworthy (0 on failure too); an empty/unmatched stdout
    is the real signal that nothing usable came back."""
    if remaining_time(deadline_at) <= 0:
        return None, "skipped: no time remaining in step budget"
    try:
        result = run(["tmutil", "latestbackup", "-t"], deadline_at)
    except subprocess.TimeoutExpired:
        return None, "tmutil latestbackup timed out"
    except (subprocess.SubprocessError, OSError, TimeoutError) as exc:
        return None, "could not run tmutil latestbackup: " + redact_home(str(exc))[:120]
    text = (result.stdout or "").strip().splitlines()[:1]
    ts = text[0].strip() if text else ""
    if not ts:
        stderr = redact_home((result.stderr or "").strip())
        if not stderr:
            return None, "tmutil latestbackup returned nothing"
        return None, truncate_on_boundary(stderr, 400)
    if not TIMESTAMP_RE.match(ts):
        return None, "unexpected latestbackup timestamp format: " + redact_home(ts)[:60]
    return ts, None


def macos_report():
    deadline_at = time.monotonic() + STEP_BUDGET_S

    # latestbackup is the primary signal and runs first; destinationinfo is
    # supplementary (labels a destination / explains a missing one) and gets
    # whatever budget latestbackup left behind.
    ts, latest_reason = read_latest_backup(deadline_at)
    dest = read_destinations(deadline_at)
    destinations = dest["destinations"]

    report = {
        "ok": True,
        "platform": "darwin",
        "backup_kind": None,
        "last_backup_iso": None,
        "age_hours": None,
        "age_days": None,
        "destination_kind": destinations[0]["kind"] if destinations else None,
        "destination_name": destinations[0]["name"] if destinations else None,
        "destination_count": len(destinations),
        "destination_state": dest["state"],
        "markers_found": [],
        "reason": None,
        "note": None,
        "warning": None,
    }

    if ts is not None:
        try:
            parsed = datetime.strptime(ts, "%Y-%m-%d-%H%M%S")
        except ValueError:
            report["reason"] = "could not parse latestbackup timestamp: " + ts
            report["warning"] = report["reason"]
            return report
        age_hours = (datetime.now() - parsed).total_seconds() / 3600
        report["backup_kind"] = "time-machine"
        report["last_backup_iso"] = parsed.isoformat()
        report["age_hours"] = round(age_hours, 2)
        report["age_days"] = round(age_hours / 24, 2)
        return report

    # No usable timestamp. Priority order for the ONE reason surfaced:
    #  1. A real read failure on OUR side of destinationinfo (command error,
    #     timeout, unparseable output -- covers Full Disk Access denial) is
    #     the strongest, most specific diagnosis and always wins.
    #  2. A live, specific signal from tmutil itself about latestbackup --
    #     e.g. "Failed to mount backup destination" -- observed in practice
    #     to happen even when destinationinfo separately reports zero
    #     destinations (an unmounted/stale network destination tmutil still
    #     remembers trying to reach). That is more informative than "no
    #     destination configured" and must not be buried in `note`.
    #  3. Only once neither side reported anything specific does this fall
    #     back to "Time Machine has no destination configured on this Mac".
    generic_no_reason = latest_reason in (None, "tmutil latestbackup returned nothing")
    if dest["state"] == "error":
        report["reason"] = "could not determine Time Machine destinations: " + dest["detail"]
        if not generic_no_reason:
            report["note"] = latest_reason
    elif not generic_no_reason:
        report["reason"] = latest_reason
        if dest["state"] == "configured_empty":
            report["note"] = "tmutil destinationinfo separately reports no configured destination"
    elif dest["state"] == "configured_empty":
        report["reason"] = "Time Machine has no destination configured on this Mac"
    else:
        report["reason"] = "tmutil latestbackup did not return a usable result"
    report["warning"] = report["reason"]
    return report


LINUX_MARKERS = (
    ("borg", ("borg", "borgmatic"), ("~/.cache/borg", "~/.config/borg", "~/.config/borgmatic")),
    ("restic", ("restic",), ("~/.cache/restic",)),
    ("timeshift", ("timeshift",), ("/etc/timeshift/timeshift.json", "/etc/timeshift-btrfs.json")),
)


def linux_report():
    found = []
    for name, bins, paths in LINUX_MARKERS:
        if any(shutil.which(b) for b in bins) or any(
            os.path.exists(os.path.expanduser(p)) for p in paths
        ):
            found.append(name)
    report = {
        "ok": True,
        "platform": "linux",
        "backup_kind": None,
        "last_backup_iso": None,
        "age_hours": None,
        "age_days": None,
        "destination_kind": None,
        "destination_name": None,
        "destination_count": 0,
        "destination_state": None,
        "markers_found": found,
        "reason": None,
        "note": (
            "Time Machine is macOS-only; on Linux this checks only for a borg, "
            "restic, or timeshift binary on PATH or one of their well-known state "
            "paths, and never reads a snapshot list, so backup age is not available "
            "here either way."
        ),
        "warning": None,
    }
    if found:
        report["reason"] = (
            "backup tool marker(s) detected (" + ", ".join(found) + ") but this play "
            "does not read their repositories, so last-backup age is still unknown"
        )
    else:
        report["reason"] = "no borg, restic, or timeshift marker found on this host"
    report["warning"] = report["reason"]
    return report


def other_platform_report(system_name):
    return {
        "ok": True,
        "platform": (system_name or "unknown").lower(),
        "backup_kind": None,
        "last_backup_iso": None,
        "age_hours": None,
        "age_days": None,
        "destination_kind": None,
        "destination_name": None,
        "destination_count": 0,
        "destination_state": None,
        "markers_found": [],
        "reason": "backup detection is only implemented for macOS (Time Machine) and Linux (marker probe): " + str(system_name),
        "note": None,
        "warning": "unsupported platform for backup detection: " + str(system_name),
    }


def main():
    system_name = platform.system()
    try:
        if system_name == "Darwin":
            report = macos_report()
        elif system_name == "Linux":
            report = linux_report()
        else:
            report = other_platform_report(system_name)
    except Exception as exc:  # last-resort degrade: never crash this step
        report = {
            "ok": True,
            "platform": (system_name or "unknown").lower(),
            "backup_kind": None,
            "last_backup_iso": None,
            "age_hours": None,
            "age_days": None,
            "destination_kind": None,
            "destination_name": None,
            "destination_count": 0,
            "destination_state": None,
            "markers_found": [],
            "reason": "unexpected error reading backup status: " + redact_home(str(exc))[:160],
            "note": None,
            "warning": "unexpected error reading backup status: " + redact_home(str(exc))[:160],
        }
    print(json.dumps(report))


main()
