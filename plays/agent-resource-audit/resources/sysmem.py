"""Read total system RAM once, macOS or Linux. Touches no process.

macOS: `sysctl -n hw.memsize` (bytes) via subprocess.
Linux: MemTotal from /proc/meminfo (reported in kB, converted to bytes).

Either path being unavailable is a DEGRADE, not a fault: total memory is
optional context for the audit's headline ("N agent processes holding X MB
of your Y GB"), never required for the enumeration or classification the
play actually does.

Emits one JSON object on stdout, always exit 0:
    {"ok": true, "packed": "<total bytes>"}                          # normal
    {"ok": true, "warning": "total memory unknown: <reason>", "packed": "unknown"}  # degraded
"""

import json
import platform
import subprocess
import sys

SYSCTL_TIMEOUT_S = 10


def read_macos():
    try:
        proc = subprocess.run(
            ["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=SYSCTL_TIMEOUT_S
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "sysctl failed to run: " + str(exc)
    if proc.returncode != 0:
        return None, "sysctl exited " + str(proc.returncode) + ": " + (proc.stderr or "").strip()[:200]
    text = (proc.stdout or "").strip()
    try:
        return int(text), None
    except ValueError:
        return None, "sysctl returned non-numeric output: " + text[:80]


def read_linux():
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) * 1024, None
        return None, "MemTotal not found in /proc/meminfo"
    except OSError as exc:
        return None, "could not read /proc/meminfo: " + str(exc)


def main():
    system = platform.system()
    if system == "Darwin":
        total_bytes, reason = read_macos()
    elif system == "Linux":
        total_bytes, reason = read_linux()
    else:
        total_bytes, reason = None, "unsupported platform: " + system

    if total_bytes is None:
        print(
            json.dumps(
                {
                    "ok": True,
                    "warning": "total memory unknown: " + (reason or "unknown reason"),
                    "packed": "unknown",
                }
            )
        )
        return

    print(json.dumps({"ok": True, "packed": str(total_bytes)}))


main()
