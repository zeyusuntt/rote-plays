import json, os, re, sys, tempfile
from datetime import datetime, timezone, timedelta

try:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    recent_hours = int(sys.argv[2]) if len(sys.argv) > 2 else 48
except ValueError:
    sys.stderr.write("limit and recent_hours must be integers\n")
    sys.exit(2)
author = sys.argv[3].strip() if len(sys.argv) > 3 else ""
URL = "https://www.modiqo.ai/api/public-registry"
FALLBACK = "https://www.modiqo.ai/feeds/public-plays.v1.json"

# Cross-run delta state. Uses the same relative-path state pattern as the repo sweep: a relative path
# under the run workspace that rote reuses across runs of this play, so a
# plain read/write here is all "cross-run memory" takes. Single JSON file
# (no fan-out here, unlike sweep-git-repos, so no sharding needed).
STATE_DIR = "standings-state"
STATE_FILE = os.path.join(STATE_DIR, "last-snapshot.json")
MAX_SNAPSHOT_ENTRIES = 5000  # size-bound safety net; the registry is a few hundred plays

import subprocess

def fetch(url):
    # urllib hits IncompleteRead on this CDN's chunked responses; curl --compressed is reliable.
    last = None
    for attempt in range(3):
        p = subprocess.run(
            ["curl", "-fsSL", "--compressed", "--max-time", "25",
             "-A", "playoffs-standings/0.2", url],
            capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return json.loads(p.stdout)
        last = f"curl exit {p.returncode}: {p.stderr.strip()[:120]}"
    raise RuntimeError(last or "empty response")


def load_snapshot():
    """Read the previous run's snapshot. Returns (snapshot_or_None, reason), reason in:
      "none"    -- no snapshot file exists yet (a genuine first run)
      "corrupt" -- a snapshot file exists but is unreadable/malformed (a *degraded* first
                   run: state that can't be trusted, honestly discarded and rebuilt)
      "ok"      -- loaded and validated
    Corrupt or unreadable state is never an error -- degrade lane, not a crash -- but it is
    NOT the same claim as "this play has never run before," so callers must be able to tell
    the two apart rather than silently reporting a generic "first run." One malformed entry
    taints the whole snapshot (simplest honest reading: we cannot trust partial state), so a
    corrupt file falls back to first-run delta behavior but says so."""
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError:
        return None, "none"
    try:
        snap = json.loads(raw)
    except ValueError:
        return None, "corrupt"
    if (
        not isinstance(snap, dict)
        or not isinstance(snap.get("entries"), dict)
        or not isinstance(snap.get("saved_at"), str)
    ):
        return None, "corrupt"
    if any(not isinstance(v, dict) for v in snap["entries"].values()):
        return None, "corrupt"
    return snap, "ok"


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def clean_display(value, max_len=120):
    """`reference`/`owner` come from the public registry feed -- text any publisher can set,
    not text we generate -- and are rendered verbatim into another user's terminal by
    main.ts. Strip C0/DEL control characters (this kills ESC, so a crafted registry entry
    can't smuggle a terminal-escape / ANSI injection into someone else's run) and cap length
    so one oversized entry can't blow out a table row. Never raises on a non-string input."""
    if not isinstance(value, str):
        return value
    cleaned = _CONTROL_RE.sub("", value)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned


def as_int(value, default=0):
    """Coerce a snapshot field to int; anything unexpected degrades to default
    instead of raising deeper in the delta math."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def base_ref(reference):
    """Stable play identity across version bumps: 'owner/name@1.2.0' -> 'owner/name'.
    Keying deltas by versioned reference would misreport every version bump as one
    NEW plus one GONE — and in this event people bump daily (codex review, v0.2.0
    finding: identity keying). Downloads in the feed accumulate per play, so the
    unversioned key compares cleanly across versions."""
    if not isinstance(reference, str):
        return reference
    return reference.split("@", 1)[0]


def snap_version(reference):
    if not isinstance(reference, str) or "@" not in reference:
        return None
    return reference.split("@", 1)[1]


def save_snapshot(rows, now, previous_high=None):
    """Atomically persist a compact snapshot — reference, downloads,
    published_at only, everything else stripped — so the next run can diff.
    Best-effort: a failure to persist never fails this run, only next run's delta."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        entries = {}
        for r in rows:
            ref = r.get("reference")
            if not ref:
                continue
            key = base_ref(ref)
            # high-water mark: a cached/older feed generation can report FEWER
            # downloads than we already saw; saving the lower value would make the
            # recovery look like a false MOVER next run (codex finding #4). Keep
            # the max ever observed as the baseline.
            prior = entries.get(key, {}).get("downloads", 0)
            entries[key] = {
                "downloads": max(as_int(r.get("downloads", 0)), as_int(prior)),
                "version": snap_version(ref),
                "published_at": r.get("published_at"),
            }
            if len(entries) >= MAX_SNAPSHOT_ENTRIES:
                break
        if previous_high:
            for key, prev in previous_high.items():
                if key in entries:
                    entries[key]["downloads"] = max(entries[key]["downloads"], as_int(prev.get("downloads")))
        snapshot = {"saved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "schema": 2, "entries": entries}
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=STATE_DIR, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(snapshot, handle, ensure_ascii=False)
            os.replace(tmp, STATE_FILE)
            tmp = None
            return True, None
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except OSError as e:
        return False, str(e)[:120]


source, warning = URL, None
try:
    data = fetch(URL)
except Exception as e:
    try:
        data = fetch(FALLBACK)
        source, warning = FALLBACK, f"live endpoint unreachable ({e}); using cached feed snapshot"
    except Exception as e2:
        print(json.dumps({"ok": False, "error": f"both endpoints failed: {e} / {e2}"}))
        sys.exit(0)  # degrade, never die: report the unknown

items = data.get("items", [])
now = datetime.now(timezone.utc)
cutoff = now - timedelta(hours=recent_hours)

def row(it):
    return {
        "reference": clean_display(it.get("reference")),
        "owner": clean_display(it.get("registry_organization")),
        "downloads": (it.get("stats") or {}).get("downloads", 0),
        "installs": (it.get("stats") or {}).get("installs", 0),
        "quality": it.get("quality_score"),
        "published_at": it.get("published_at"),
    }

rows = [row(it) for it in items]
top = sorted(rows, key=lambda r: (-r["downloads"], r["reference"] or ""))[:limit]
def ts(r):
    try: return datetime.fromisoformat(r["published_at"].replace("Z", "+00:00"))
    except Exception: return None
recent = sorted([r for r in rows if (t := ts(r)) and t >= cutoff], key=lambda r: r["published_at"], reverse=True)
by_owner = {}
for r in rows:
    o = by_owner.setdefault(r["owner"] or "?", {"plays": 0, "downloads": 0})
    o["plays"] += 1; o["downloads"] += r["downloads"]

# ---- delta vs the previous run (the daily-habit feature) -------------------
# Diffed against every known play, not just the top-N shown on screen, so a
# brand-new play outside the ranking still shows up as NEW, and a play that
# drops off the registry entirely still shows up as GONE.
previous_snapshot, snapshot_status = load_snapshot()
first_run = previous_snapshot is None
first_run_reason = None if not first_run else (
    "previous_snapshot_unreadable" if snapshot_status == "corrupt" else "no_previous_snapshot"
)
previous_entries = (previous_snapshot or {}).get("entries", {}) if previous_snapshot else {}
as_of = previous_snapshot.get("saved_at") if previous_snapshot else None

# Migrate a schema-1 snapshot (versioned keys) to base-ref keys, keeping the
# high-water downloads per play, so the identity change doesn't fake a NEW wave.
if previous_entries and any("@" in k for k in previous_entries):
    migrated = {}
    for k, v in previous_entries.items():
        key = base_ref(k)
        keep = migrated.get(key)
        if keep is None or as_int(v.get("downloads")) > as_int(keep.get("downloads")):
            migrated[key] = dict(v, version=snap_version(k))
    previous_entries = migrated

new_since_last = []
movers = []
updated = []
gone = []
went_backward = 0
if not first_run:
    for r in rows:
        ref = r.get("reference")
        if not ref:
            continue
        key = base_ref(ref)
        prev = previous_entries.get(key)
        if prev is None:
            new_since_last.append({
                "reference": ref, "downloads": r["downloads"], "published_at": r.get("published_at"),
            })
            continue
        d = r["downloads"] - as_int(prev.get("downloads"))
        ver_now = snap_version(ref)
        if prev.get("version") not in (None, ver_now):
            updated.append({
                "reference": ref, "from_version": prev.get("version"),
                "to_version": ver_now, "delta": max(d, 0),
            })
        if d > 0:
            movers.append({"reference": ref, "downloads": r["downloads"], "delta": d})
        elif d < 0:
            # Registry feed is cached (~10 min TTL); a generation going
            # backward is honest data, not clamped or hidden — just counted
            # here so the human view can add one disclosure note. The saved
            # baseline keeps the high-water mark, so this dip cannot fake a
            # MOVER when the feed recovers.
            went_backward += 1
    movers.sort(key=lambda m: -m["delta"])
    movers = movers[:10]
    updated = updated[:10]
    current_keys = {base_ref(r.get("reference")) for r in rows if r.get("reference")}
    gone = [
        {"reference": key, "last_downloads": as_int(prev.get("downloads"))}
        for key, prev in previous_entries.items() if key not in current_keys
    ]

stale_note = (
    f"{went_backward} reference(s) show fewer downloads than the last snapshot — "
    "the registry feed is cached (~10 min TTL), so small dips can happen; shown as-is, no clamping."
    if went_backward > 0 else None
)

# ---- optional author watch --------------------------------------------------
author_watch = None
if author:
    full_ranked = sorted(rows, key=lambda r: (-r["downloads"], r["reference"] or ""))
    author_plays = []
    for idx, r in enumerate(full_ranked):
        if (r.get("owner") or "") != author:
            continue
        prev = None if first_run else previous_entries.get(r["reference"])
        delta_val = (r["downloads"] - as_int(prev.get("downloads"))) if prev else None
        author_plays.append({
            "reference": r["reference"], "rank": idx + 1,
            "downloads": r["downloads"], "delta": delta_val,
        })
    author_watch = {"name": author, "plays": author_plays}

saved, save_error = save_snapshot(rows, now, previous_entries if not first_run else None)

# ---- self-budgeted output ---------------------------------------------------
# rote captures a BOUNDED amount of a step's stdout. Going over does not fail
# loudly: the capture is cut mid-JSON, the presentation cannot parse it, and
# the run reports that it could not read this step at all. The registry has
# grown past that point -- `recent` alone reached 58 KB of a 62 KB payload on
# a real run -- so this script now budgets its own output and trims the one
# unbounded collection ITSELF, with a declared count, rather than letting the
# runner cut it blind. recent_total always reports the true number found in
# the window, so a trimmed list is visibly a trimmed list and never reads as
# the whole answer.
OUTPUT_BUDGET_BYTES = 56000   # headroom under the runner's capture cap
MIN_RECENT_SHOWN = 10         # never trim below this; a report showing none of
                              # what was published in the window has no content

recent_total = len(recent)
recent_shown = recent

def payload(shown):
    return {
        "ok": True, "source": source, "warning": warning,
        "feed_generated_at": data.get("generated_at"),
        "totals": {"plays": len(rows), "owners": len(by_owner)},
        "top_by_downloads": top,
        "recent": shown,
        "recent_total": recent_total,
        "recent_omitted": recent_total - len(shown),
        "owners": dict(sorted(by_owner.items(), key=lambda kv: -kv[1]["downloads"])[:15]),
        "delta": {
            "first_run": first_run,
            "first_run_reason": first_run_reason,
            "as_of": as_of,
            "new_since_last": new_since_last,
            "movers": movers,
            "updated": updated,
            "gone": gone,
            "stale_note": stale_note,
        },
        "author": author_watch,
        "snapshot": {"saved": saved, "path": STATE_FILE, "error": save_error},
    }

encoded = json.dumps(payload(recent_shown), ensure_ascii=False)
while len(encoded.encode("utf-8")) > OUTPUT_BUDGET_BYTES and len(recent_shown) > MIN_RECENT_SHOWN:
    # halve toward the floor rather than stepping one at a time
    recent_shown = recent_shown[: max(MIN_RECENT_SHOWN, len(recent_shown) // 2)]
    encoded = json.dumps(payload(recent_shown), ensure_ascii=False)

print(encoded)
