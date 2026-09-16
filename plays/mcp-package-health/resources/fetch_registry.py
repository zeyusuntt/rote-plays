"""Ask the public registry about ONE package discovered by
discover_packages.py -- a for_each fan-out item, so each package gets its
own timeout budget and one package's failure never touches another's.

argv[1]  the package to query, as JSON (one element of discover_packages.py's
         "packages" array, arriving as $item -- rote passes an object
         fan-out element to a script as one compact-JSON argv string)
argv[2]  item_index (this package's 0-based position, bound by rote's
         fan-out as $item_index; carried through but not otherwise used --
         ordering is the caller's business, not this script's)
argv[3]  per_request_timeout_s (seconds curl is given for the one GET; an
         empty/absent argument uses the documented default (10s), but a
         SUPPLIED value that is not an integer in 1-60 is a contract
         violation -- same discipline as a missing argv[1] package -- and
         fails closed: stderr + exit 1, never silently clamped)

Exactly ONE HTTPS GET per invocation, to exactly one of two hosts:
  npm:  https://registry.npmjs.org/<name>        (scoped names URL-encode
                                                    the slash as %2F, never
                                                    the @)
  pypi: https://pypi.org/pypi/<name>/json

curl only -- never Python's own urllib/http.client/socket -- resolved to
an absolute path once via this process's own PATH, then invoked with an
explicitly EMPTY environment and -q as its first argument, so no
.curlrc/CURL_HOME/XDG_CONFIG_HOME/*_PROXY variable on this machine can
inject extra options, credentials, or an alternate destination into the
request; --noproxy '*' is also passed as a second, independent guard
against a proxy rerouting the request even if the empty-environment
protection above were ever weakened. Run with --silent --show-error --fail
--max-time <n>, no cookies, no auth headers, no credentials of any kind.
--location is deliberately NEVER passed -- a redirect is not followed, it
degrades that one package to a labeled unknown, because following one
would let the registry (or anything sitting in front of it) point this
script at an undisclosed third host, contradicting the exactly-two-hosts
boundary below. The response body is written to a private temp file
(never stdout, never a shell pipe), read once to pull out the handful of
fields below, then discarded -- the raw payload is never echoed anywhere,
in any output this script produces.

Extraction, per ecosystem (registry facts only, nothing inferred):
  npm:  dist-tags.latest, time[<latest>] (that version's publish time),
        whether versions[<latest>] carries a "deprecated" string (message
        truncated to ~200 chars), maintainers count.
  pypi: info.version, the newest upload_time_iso_8601 among the files for
        that version (from "urls", which are exactly the files for
        info.version), info.yanked / info.yanked_reason, and info.archived
        if that field happens to be present (it usually is not -- PyPI has
        no standard "archived" concept; this is forward-defensive, not a
        claim the field normally exists).

This script derives nothing beyond arithmetic on those facts (days since a
timestamp, pinned-vs-latest string comparison) -- it never calls a package
"abandoned", "dead", or "unmaintained"; that judgment call, and the ranking
of these facts against each other, belongs to the presentation layer,
which also owns the stale_release_days threshold. This script only ever
reports "no release in N days" as a bare fact.

Classification per package ("state"):
  ok          the registry answered (HTTP 2xx) and the response carried at
              least the one field this script cannot derive anything
              without (dist-tags.latest for npm, info.version for PyPI)
  not_found   HTTP 404 -- may be private, internal, renamed, or unpublished;
              never reported as "does not exist"
  unknown     network failure, timeout, HTTP 429 (rate-limited), curl
              itself could not be run/parsed, OR the registry answered but
              the body was missing even that one load-bearing field --
              carries a short fixed "reason" code, never raw curl/child
              text

Emits one JSON object on stdout and always exits 0 for any PER-PACKAGE
outcome (network failure, timeout, malformed/incomplete response), EXCEPT
for two fundamental contract violations, neither of which is one
queryable package's failure, which fail closed instead -- stderr + exit 1:
argv[1] itself missing, or a SUPPLIED per_request_timeout_s outside its
documented integer 1-60 shape.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import quote

NPM_REGISTRY_URL = "https://registry.npmjs.org/%s"
PYPI_REGISTRY_URL = "https://pypi.org/pypi/%s/json"

DEFAULT_TIMEOUT_S = 10
MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 60
SUBPROCESS_GRACE_S = 5  # backstop above curl's own --max-time, in case curl itself hangs

DEPRECATED_MSG_MAX = 200

# "latest" is a floating dist-tag/specifier, not a frozen version -- npx
# pkg@latest and uvx pkg@latest both mean "whatever is newest right now",
# the same thing an unpinned invocation already means. Comparing it
# against the registry's own current latest would always "drift" by
# construction and mislabel a floating install as a stale pin.
FLOATING_PIN_TAGS = {"latest"}

EMPTY_FACTS = {
    "latest_version": None,
    "latest_published_at": None,
    "days_since_release": None,
    "deprecated": False,
    "deprecated_message": None,
    "yanked": False,
    "yanked_reason": None,
    "archived": None,
    "maintainer_count": None,
    "pin_drift": False,
    "pinned_published_at": None,
    "pinned_days_old": None,
}


def parse_timeout(raw):
    """Returns (timeout_s, error_or_None). An absent/empty argument (raw is
    "" -- argv[3] was never supplied) uses the documented default; this is
    the normal case for every run that does not override the parameter. A
    value that WAS supplied but is not an integer, or is outside the
    documented 1-60s range, is a contract violation -- the same discipline
    main() already applies to a missing argv[1] package -- and is reported
    as an error rather than silently clamped into range: a per-item degrade
    would hide a genuinely broken parameter behind a run that looks like it
    succeeded."""
    if raw is None or str(raw).strip() == "":
        return DEFAULT_TIMEOUT_S, None
    try:
        value = int(str(raw).strip())
    except (ValueError, TypeError):
        return None, "per_request_timeout_s must be an integer, got %r" % (raw,)
    if value < MIN_TIMEOUT_S or value > MAX_TIMEOUT_S:
        return None, "per_request_timeout_s must be between %d and %d, got %d" % (
            MIN_TIMEOUT_S,
            MAX_TIMEOUT_S,
            value,
        )
    return value, None


def parse_int(raw, fallback):
    try:
        return int(str(raw).strip())
    except (ValueError, TypeError):
        return fallback


def emit(row):
    print(json.dumps(row))


def base_row(item):
    return {
        "key": item.get("key"),
        "ecosystem": item.get("ecosystem"),
        "package": item.get("package"),
        "pinned_version": item.get("pinned_version"),
        "server_names": item.get("server_names") if isinstance(item.get("server_names"), list) else [],
        "harnesses": item.get("harnesses") if isinstance(item.get("harnesses"), list) else [],
    }


def npm_url(name):
    # Scoped names URL-encode the slash as %2F; the "@" itself stays literal
    # (registry.npmjs.org expects "@scope%2Fname", not "%40scope%2Fname").
    return NPM_REGISTRY_URL % quote(name, safe="@")


def pypi_url(name):
    return PYPI_REGISTRY_URL % quote(name, safe="")


def fetch(url, timeout_s):
    """One HTTPS GET via curl, body written to a private temp file (never
    stdout). Returns (state, body_text_or_None, reason_or_None). state is
    "ok" / "not_found" / "unknown". The temp file is always removed before
    returning, success or failure alike."""
    fd, path = tempfile.mkstemp(prefix="mcp-package-health-", suffix=".json")
    os.close(fd)
    try:
        # Resolve curl to an absolute path using THIS process's own PATH,
        # once, right here -- so the child process below can be run with an
        # entirely empty environment and still be found. An empty
        # environment means no HOME/CURL_HOME/XDG_CONFIG_HOME (no .curlrc
        # of any kind can be located, belt-and-suspenders alongside -q
        # below) and no *_PROXY variable can reach curl at all.
        curl_path = shutil.which("curl")
        if curl_path is None:
            return "unknown", None, "curl-not-found"
        cmd = [
            curl_path,
            "-q",  # MUST be curl's first argument: skip .curlrc entirely, regardless of where one might be found
            "--silent", "--show-error", "--fail",
            "--max-time", str(timeout_s),
            "--noproxy", "*",  # independent guard: no proxy, even if a *_PROXY var somehow reached this process
            "-o", path, "-w", "%{http_code}",
            url,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s + SUBPROCESS_GRACE_S,
                env={},  # no ambient environment reaches curl at all
            )
        except FileNotFoundError:
            return "unknown", None, "curl-not-found"
        except subprocess.TimeoutExpired:
            return "unknown", None, "curl-hard-timeout"
        except OSError:
            return "unknown", None, "curl-spawn-failed"
        code = (proc.stdout or "").strip()
        if proc.returncode == 0 and code.startswith("2"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    body = fh.read()
            except OSError:
                return "unknown", None, "response-unreadable"
            return "ok", body, None
        if code == "404":
            return "not_found", None, None
        if code == "429":
            return "unknown", None, "rate-limited"
        if code and code.isdigit():
            return "unknown", None, "http-%s" % code
        return "unknown", None, "curl-exit:%d" % proc.returncode
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def newest_upload_time(files):
    times = [
        f.get("upload_time_iso_8601")
        for f in files
        if isinstance(f, dict) and isinstance(f.get("upload_time_iso_8601"), str)
    ]
    return max(times) if times else None


def extract_npm(body, pinned_version):
    try:
        data = json.loads(body)
    except ValueError:
        return None, "invalid-json"
    if not isinstance(data, dict):
        return None, "invalid-json"
    dist_tags = data.get("dist-tags") if isinstance(data.get("dist-tags"), dict) else {}
    latest = dist_tags.get("latest")
    if not isinstance(latest, str) or not latest:
        # Without dist-tags.latest we don't even know WHICH version is
        # "latest" -- every fact this function derives (deprecated status,
        # publish time) depends on that identity, so a 200 that lacks it is
        # not a usable "ok" response; it degrades the whole package to
        # unknown rather than being reported as healthy with silent nulls.
        return None, "missing-dist-tags-latest"
    time_map = data.get("time") if isinstance(data.get("time"), dict) else {}
    latest_published_at = time_map.get(latest) if isinstance(latest, str) else None
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    latest_meta = versions.get(latest) if isinstance(latest, str) else None
    deprecated, deprecated_msg = False, None
    if isinstance(latest_meta, dict):
        dep = latest_meta.get("deprecated")
        if isinstance(dep, str) and dep.strip():
            deprecated, deprecated_msg = True, dep[:DEPRECATED_MSG_MAX]
    maintainers = data.get("maintainers")
    maintainer_count = len(maintainers) if isinstance(maintainers, list) else None
    pinned_published_at = None
    if isinstance(pinned_version, str) and isinstance(time_map.get(pinned_version), str):
        pinned_published_at = time_map.get(pinned_version)
    return {
        "latest_version": latest if isinstance(latest, str) else None,
        "latest_published_at": latest_published_at if isinstance(latest_published_at, str) else None,
        "deprecated": deprecated,
        "deprecated_message": deprecated_msg,
        "yanked": False,
        "yanked_reason": None,
        "archived": None,
        "maintainer_count": maintainer_count,
        "pinned_published_at": pinned_published_at,
    }, None


def extract_pypi(body, pinned_version):
    try:
        data = json.loads(body)
    except ValueError:
        return None, "invalid-json"
    if not isinstance(data, dict):
        return None, "invalid-json"
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    latest = info.get("version")
    if not isinstance(latest, str) or not latest:
        # Symmetric with extract_npm above: without info.version we don't
        # know which release this response is even describing.
        return None, "missing-info-version"
    urls = data.get("urls") if isinstance(data.get("urls"), list) else []
    latest_published_at = newest_upload_time(urls)
    yanked = bool(info.get("yanked"))
    yanked_reason = info.get("yanked_reason") if isinstance(info.get("yanked_reason"), str) else None
    archived = info.get("archived") if isinstance(info.get("archived"), bool) else None
    releases = data.get("releases") if isinstance(data.get("releases"), dict) else {}
    pinned_published_at = None
    if isinstance(pinned_version, str) and isinstance(releases.get(pinned_version), list):
        pinned_published_at = newest_upload_time(releases.get(pinned_version))
    return {
        "latest_version": latest if isinstance(latest, str) else None,
        "latest_published_at": latest_published_at,
        "deprecated": False,
        "deprecated_message": None,
        "yanked": yanked,
        "yanked_reason": yanked_reason,
        "archived": archived,
        "maintainer_count": None,
        "pinned_published_at": pinned_published_at,
    }, None


def days_since(iso_str, now):
    if not isinstance(iso_str, str) or not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0, (now - dt).days)


def degraded(row, state, reason):
    row = dict(row)
    row["state"] = state
    row["reason"] = reason
    row.update(EMPTY_FACTS)
    return row


def main():
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        sys.stderr.write("fetch_registry: missing package item argv\n")
        raise SystemExit(1)

    parse_int(sys.argv[2] if len(sys.argv) > 2 else "", 0)  # item_index: not used here, ordering is the caller's job
    timeout_s, timeout_error = parse_timeout(sys.argv[3] if len(sys.argv) > 3 else "")
    if timeout_error:
        # A contract violation, same discipline as a missing argv[1]
        # package -- every fan-out item shares this one parameter, so
        # letting it silently clamp would hide a genuinely broken run
        # behind per-item degrades instead of failing the run closed.
        sys.stderr.write("fetch_registry: %s\n" % timeout_error)
        raise SystemExit(1)

    try:
        item = json.loads(sys.argv[1])
        if not isinstance(item, dict):
            raise ValueError("item is not a JSON object")
    except (ValueError, TypeError) as exc:
        emit(degraded(
            {"key": None, "ecosystem": None, "package": None, "pinned_version": None, "server_names": [], "harnesses": []},
            "unknown",
            "malformed-item:%s" % type(exc).__name__,
        ))
        return

    row = base_row(item)
    try:
        ecosystem = row.get("ecosystem")
        package = row.get("package")
        pinned_version = row.get("pinned_version")

        if ecosystem not in ("npm", "pypi") or not package:
            emit(degraded(row, "unknown", "malformed-item:missing-ecosystem-or-package"))
            return

        url = npm_url(package) if ecosystem == "npm" else pypi_url(package)
        state, body, reason = fetch(url, timeout_s)

        if state in ("not_found", "unknown"):
            emit(degraded(row, state, reason))
            return

        extractor = extract_npm if ecosystem == "npm" else extract_pypi
        facts, extract_error = extractor(body, pinned_version)
        body = None  # only the facts above survive; the payload itself is discarded now
        if facts is None:
            emit(degraded(row, "unknown", extract_error or "unparseable-response"))
            return

        now = datetime.now(timezone.utc)
        latest_version = facts["latest_version"]
        pin_drift = (
            bool(pinned_version)
            and pinned_version not in FLOATING_PIN_TAGS
            and bool(latest_version)
            and pinned_version != latest_version
        )
        row.update({
            "state": "ok",
            "reason": None,
            "latest_version": latest_version,
            "latest_published_at": facts["latest_published_at"],
            "days_since_release": days_since(facts["latest_published_at"], now),
            "deprecated": facts["deprecated"],
            "deprecated_message": facts["deprecated_message"],
            "yanked": facts["yanked"],
            "yanked_reason": facts["yanked_reason"],
            "archived": facts["archived"],
            "maintainer_count": facts["maintainer_count"],
            "pin_drift": pin_drift,
            "pinned_published_at": facts["pinned_published_at"],
            "pinned_days_old": days_since(facts["pinned_published_at"], now),
        })
        emit(row)
    except Exception as exc:  # pragma: no cover -- last-resort degrade, never a crash
        emit(degraded(row, "unknown", "internal-exception:%s" % type(exc).__name__))


main()
