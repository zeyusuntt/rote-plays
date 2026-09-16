"""Probe ONE python discovered by find_pythons.py with exactly one bounded
TLS handshake against a fixed, well-known host -- a for_each fan-out item,
so each interpreter gets its own timeout budget.

argv[1]  the discovered python as JSON (one element of find_pythons.py's
         "pythons" array, arriving as $item -- rote passes an object
         fan-out element to a script as one compact-JSON argv string)
argv[2]  item_index (this python's 0-based position, bound by rote's
         fan-out as $item_index; carried through for parity with the
         upstream id, not otherwise used)
argv[3]  timeout_s (the user's per-python TLS handshake timeout, 1-30,
         already validated by rote's integer param gate; re-clamped here
         as a script-level guard per this fleet's degrade-vs-fail rule)

NETWORK DISCLOSURE: this script's entire job is one TLS handshake to
pypi.org:443 -- socket connect, then an SSL wrap_socket() handshake, no
HTTP request line, no bytes sent beyond what completing a TLS handshake
requires, nothing received or parsed beyond the handshake itself. It is
run once per discovered interpreter (never more), and it is the ONLY
network activity in this play -- because that handshake outcome IS the
diagnosis this play exists to produce.

TRUST BOUNDARY: `item.path` names a candidate find_pythons.py already
discovered as a name match (`python`/`python3`/`python3.N`), not a proven
Python interpreter -- see find_pythons.py's own module docstring for why
that distinction matters (every matching PATH entry is executed here too,
by design, to catch a shadowed interpreter). Independently of whatever
find_pythons.py decided at discovery time (which may be stale by the time
this fan-out item actually runs), this script re-runs the identical
fail-closed trust check -- see is_trusted_executable() below -- immediately
before spawning the handshake child, and never executes an untrusted
candidate; a rejection reports verdict=probe_error with a fixed reason,
never a crash and never a silent skip.

The handshake itself is run with the DISCOVERED interpreter's TRUSTED,
realpath-resolved binary (not this script's own python), via a second,
fixed, no-argument-beyond-a-timeout `-c` script (HANDSHAKE_SCRIPT below)
-- so the exact ssl module, exact OpenSSL/LibreSSL build, and exact
default certificate store that interpreter would use for any of its own
HTTPS calls is precisely what gets exercised here, not a proxy measurement
taken from a different python.

Verdict is exactly one of:
  verified              handshake completed; this python trusts pypi.org's
                         certificate chain fine
  cert_verify_failed     ssl.SSLCertVerificationError, or another SSLError
                         whose message contains CERTIFICATE_VERIFY_FAILED
                         -- the classic broken-trust-store failure this
                         play exists to catch
  ssl_other               some other ssl.SSLError (protocol mismatch,
                         handshake failure not identified as a cert
                         problem) -- still TLS-layer broken, but not the
                         classic signature, called out as such
  network_unreachable    the INNER handshake script's own caught OSError or
                         socket.timeout (DNS failure, connection refused,
                         handshake deadline) -- the network was the
                         problem, not necessarily this python's trust
                         store; kept as an HONEST, separate bucket from a
                         real cert failure
  probe_error            this script's OWN subprocess could not even be
                         started, timed out AS A WHOLE (which can just as
                         easily mean this interpreter's own startup/import
                         cost or a hung wrapper as a network stall -- never
                         assumed to be network), its output did not parse,
                         OR the inner script's own catch-all caught
                         something that is not a network/TLS symptom at
                         all (an internal/programming error in the fixed
                         handshake script itself) -- could not test this
                         python at all, and this play does not guess which
                         of those it was.

The inner HANDSHAKE_SCRIPT reports its OWN error_category alongside
error_class -- one of "cert", "ssl", "network", or "internal" -- so this
script's classify() never has to infer a verdict from error_class alone
(guessing "network" for whatever it does not recognize, which is exactly
how an unrelated internal failure used to get mislabeled as a network
outage). error_class is always ONE of a small, fixed set of Python
exception class names (or "timeout" for the outer subprocess-level
timeout) -- never raw child stderr, never an arbitrary string.
error_message is the exception's own str(), truncated to 300 characters --
it can legitimately mention the hostname or a certificate field, never
anything this script read from the filesystem or an environment variable.

This script does not kill or signal anything beyond the ONE `-c` child it
spawns for the handshake, and that child is bounded by subprocess.run's
own timeout (which terminates it on expiry) -- there is no persistent
process, no process group management needed, no server left running.

Emits one JSON object on stdout and always exits 0, EXCEPT when argv[1]
itself is missing, empty, not valid JSON, or missing "path" -- a
fundamental contract violation from the upstream fan-out, not a probeable
python's own failure -- which fails closed: stderr + exit 1.
"""

import json
import os
import stat
import subprocess
import sys
import time

HOST = "pypi.org"
PORT = 443

MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 30
DEFAULT_TIMEOUT_S = 5

# Extra headroom on top of the user's own handshake timeout to cover THIS
# interpreter's own startup/import cost before it even reaches the socket
# connect call -- never counted against the handshake itself (the inner
# script times the handshake independently and reports its own elapsed_ms).
STARTUP_BUFFER_S = 5

ERROR_MESSAGE_MAX_CHARS = 300

# A fixed script, run with the DISCOVERED interpreter via -c. Takes the
# handshake timeout as argv[1] (never user-composed text -- just an
# integer this script itself already validated). Never sends or receives
# anything beyond the TLS handshake itself.
HANDSHAKE_SCRIPT = r"""
import json, socket, ssl, sys, time
host, port = %r, %d
timeout_s = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
CertErr = getattr(ssl, "SSLCertVerificationError", ssl.SSLError)
result = {"host": host, "port": port}
start = time.monotonic()
sock = None
try:
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=timeout_s)
    sock.settimeout(timeout_s)
    with ctx.wrap_socket(sock, server_hostname=host):
        pass
    result["ok"] = True
    result["error_class"] = None
    result["error_message"] = None
    result["error_category"] = None
except CertErr as e:
    result["ok"] = False
    result["error_class"] = "SSLCertVerificationError"
    result["error_message"] = str(e)
    result["error_category"] = "cert"
except ssl.SSLError as e:
    result["ok"] = False
    result["error_class"] = type(e).__name__
    result["error_message"] = str(e)
    result["error_category"] = "ssl"
except socket.timeout:
    result["ok"] = False
    result["error_class"] = "timeout"
    result["error_message"] = "connection or handshake exceeded %%.1fs" %% timeout_s
    result["error_category"] = "network"
except OSError as e:
    result["ok"] = False
    result["error_class"] = type(e).__name__
    result["error_message"] = str(e)
    result["error_category"] = "network"
except Exception as e:
    # Anything NOT caught above is not a TLS or network symptom at all --
    # a bug in this fixed script, an unexpected local runtime failure --
    # tagged "internal" so the outer classify() never has to guess
    # "network" for something it does not recognize (see TRUST BOUNDARY /
    # Verdict docs above).
    result["ok"] = False
    result["error_class"] = type(e).__name__
    result["error_message"] = str(e)
    result["error_category"] = "internal"
finally:
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
result["elapsed_ms"] = round((time.monotonic() - start) * 1000)
print(json.dumps(result))
""" % (HOST, PORT)


def fail_closed(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def parse_timeout(raw):
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        return DEFAULT_TIMEOUT_S
    return max(MIN_TIMEOUT_S, min(MAX_TIMEOUT_S, value))


def base_row(item):
    return {"id": item.get("id"), "path": item.get("path")}


def is_trusted_executable(candidate):
    """Fail-closed pre-exec trust check, independently re-run here (never
    just trusted from find_pythons.py's own earlier decision -- see TRUST
    BOUNDARY above) immediately before the ONE subprocess this script ever
    spawns. Identical shape to find_pythons.py's own is_trusted_executable
    -- see that module's docstring for the full rationale, including the
    one deliberate refinement (a group-write bit is trusted when the file's
    group is one this same user already belongs to -- verified live in
    practice: a default macOS conda install ships group-writable `staff`,
    the invoking user's own primary group). Returns (real_path, None) when
    trusted, or (None, reason) when not."""
    real = os.path.realpath(candidate)
    try:
        file_stat = os.stat(real)
    except OSError as exc:
        return None, "cannot stat resolved path: " + type(exc).__name__
    if not stat.S_ISREG(file_stat.st_mode):
        return None, "resolved path is not a regular file"
    if file_stat.st_uid not in (0, os.getuid()):
        return None, "resolved path is owned by an untrusted user"
    if file_stat.st_mode & stat.S_IWOTH:
        return None, "resolved path is world-writable"
    if file_stat.st_mode & stat.S_IWGRP:
        try:
            my_groups = set(os.getgroups())
        except OSError:
            my_groups = set()
        my_groups.add(os.getgid())
        if file_stat.st_gid not in my_groups:
            return None, "resolved path is writable by a group this user does not belong to"
    parent = os.path.dirname(real) or "/"
    try:
        parent_stat = os.stat(parent)
    except OSError as exc:
        return None, "cannot stat containing directory: " + type(exc).__name__
    if (parent_stat.st_mode & stat.S_IWOTH) and not (parent_stat.st_mode & stat.S_ISVTX):
        return None, "containing directory is world-writable without a sticky bit"
    return real, None


def classify(error_class, error_message, error_category):
    if error_class is None:
        return "verified"
    # The classic signature is checked ahead of category so a message that
    # DOES name CERTIFICATE_VERIFY_FAILED is never missed even if a future
    # inner-script change ever mis-tags its own category.
    if error_class == "SSLCertVerificationError":
        return "cert_verify_failed"
    if "CERTIFICATE_VERIFY_FAILED" in (error_message or ""):
        return "cert_verify_failed"
    if error_category == "cert":
        return "cert_verify_failed"
    if error_category == "ssl":
        return "ssl_other"
    if error_category == "network":
        return "network_unreachable"
    # "internal" (an inner catch-all -- not a TLS/network symptom) and any
    # missing/unrecognized category (a defensive fallback, e.g. an older-
    # shape inner result) both mean this python could not actually be
    # TESTED -- never guessed as a network outage.
    return "probe_error"


def emit(row):
    print(json.dumps(row))


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        fail_closed("probe_ssl.py: missing $item -- fan-out contract violation, not a probeable python's failure")
    try:
        item = json.loads(sys.argv[1])
    except ValueError:
        fail_closed("probe_ssl.py: $item did not parse as JSON -- fan-out contract violation")
    if not isinstance(item, dict) or not item.get("path"):
        fail_closed("probe_ssl.py: $item missing required 'path' field -- fan-out contract violation")

    timeout_s = parse_timeout(sys.argv[3] if len(sys.argv) > 3 else DEFAULT_TIMEOUT_S)
    python_path = item["path"]

    row = base_row(item)
    row["timeout_s"] = timeout_s
    row["host"] = HOST
    row["port"] = PORT

    # Fail-closed pre-exec trust check, independently re-run here right
    # before the ONE subprocess this script spawns -- see TRUST BOUNDARY
    # above. Never trusts find_pythons.py's own earlier decision blindly:
    # that decision may be stale (this fan-out item can run tens of
    # seconds after discovery), and this is the actual moment of exec.
    trusted_path, reject_reason = is_trusted_executable(python_path)
    if trusted_path is None:
        row.update(
            {
                "ok": False,
                "verdict": "probe_error",
                "error_class": "untrusted-executable",
                "error_message": "not probed: failed pre-exec trust check (%s)" % reject_reason,
                "elapsed_ms": None,
            }
        )
        emit(row)
        return

    try:
        proc = subprocess.run(
            [trusted_path, "-c", HANDSHAKE_SCRIPT, str(timeout_s)],
            capture_output=True,
            text=True,
            timeout=timeout_s + STARTUP_BUFFER_S,
        )
    except subprocess.TimeoutExpired:
        # The OUTER subprocess (interpreter startup + import cost + the
        # handshake itself) never returned within budget -- this is NOT
        # necessarily a network symptom: it can just as easily be this
        # interpreter's own slow/hung startup or a wrapper script that
        # never exits. The inner script's OWN socket.timeout (a real,
        # measured handshake deadline) is what earns network_unreachable;
        # this outer timeout means the python could not be tested at all,
        # matching this script's own documented probe_error contract (see
        # module docstring Verdict).
        row.update(
            {
                "ok": False,
                "verdict": "probe_error",
                "error_class": "timeout",
                "error_message": "no response within %.1fs (handshake timeout + startup buffer) -- could not test this python at all (interpreter startup/hang, not confirmed to be network)" % (timeout_s + STARTUP_BUFFER_S),
                "elapsed_ms": None,
            }
        )
        emit(row)
        return
    except OSError as exc:
        row.update(
            {
                "ok": False,
                "verdict": "probe_error",
                "error_class": type(exc).__name__,
                "error_message": ("could not start this interpreter: " + str(exc))[:ERROR_MESSAGE_MAX_CHARS],
                "elapsed_ms": None,
            }
        )
        emit(row)
        return

    if proc.returncode != 0:
        row.update(
            {
                "ok": False,
                "verdict": "probe_error",
                "error_class": "nonzero-exit:%d" % proc.returncode,
                "error_message": "handshake script exited %d -- child stderr not echoed here (may be arbitrary output from a non-python or misbehaving match)" % proc.returncode,
                "elapsed_ms": None,
            }
        )
        emit(row)
        return

    try:
        inner = json.loads((proc.stdout or "").strip())
    except ValueError:
        row.update(
            {
                "ok": False,
                "verdict": "probe_error",
                "error_class": "bad-output",
                "error_message": "handshake script produced no parseable JSON",
                "elapsed_ms": None,
            }
        )
        emit(row)
        return

    error_class = inner.get("error_class")
    error_message = inner.get("error_message")
    error_category = inner.get("error_category")
    row.update(
        {
            "ok": bool(inner.get("ok")),
            "verdict": classify(error_class, error_message, error_category),
            "error_class": error_class,
            "error_category": error_category,
            "error_message": (error_message or None) and str(error_message)[:ERROR_MESSAGE_MAX_CHARS],
            "elapsed_ms": inner.get("elapsed_ms"),
        }
    )
    emit(row)


main()
