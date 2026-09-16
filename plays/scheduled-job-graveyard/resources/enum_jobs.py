"""Enumerate the scheduled jobs this machine knows about: the user's own
crontab, the user's own LaunchAgents, launchd's live status for those
LaunchAgents, and -- names only, content never read -- /etc/crontab,
/etc/cron.d, and the system LaunchDaemons directories. On Linux, the
crontab is read the same way and systemd user timers stand in for
LaunchAgents. Read-only throughout: no crontab entry is edited, no plist is
rewritten, no launchd job is loaded/unloaded/kicked, no sudo is ever
invoked, and no file under a *system* LaunchDaemons/crontab path is opened
for content -- only os.listdir() on those two directories, which is what
"LIST-ONLY" means everywhere in this script's comments and the play's
description. Enumeration is this step's whole job: interpreting the facts
gathered here (target existence, staleness, launchd exit status) is
classify_jobs.py's job, one step later.

Emits one JSON object on stdout, always exit 0 (every source here degrades
on its own rather than failing the whole play -- see per-source notes
below; there is no essential capability in this step that has no honest
"nothing found" fallback):
    {
      "ok": true,
      "counts": {...},
      "packed_jobs": "<rows -- see PACKED JOBS below>",
      "packed_status": "<rows -- see PACKED STATUS below>",
      "system": {
        "etc_crontab_present": bool,
        "etc_cron_d_names": [...],
        "launchdaemons_library_names": [...],
        "launchdaemons_apple_count": int|null
      },
      "warning": "..."   # present only when at least one source degraded
    }

PACKED JOBS -- one candidate scheduled job per record, chr(30)-joined
records of chr(31)-joined fields (see FS/RS below), 8 fields per row:
    source            "user_crontab" | "user_launchagent" | "systemd_timer"
    label             crontab: "crontab:L<line-number>"; LaunchAgent: its
                       plist's own Label key, or the filename stem when the
                       plist could not be parsed at all; systemd: the
                       .timer unit name
    schedule_summary  a conservative, best-effort paraphrase computed here
                       (see summarize_cron_fields / summarize_launchd_schedule
                       below) -- never invented beyond a short list of
                       recognized simple shapes; anything else is shown as
                       its own raw schedule text rather than guessed at
    target_token      the FIRST absolute-path (starts with "/") token found
                       among this job's command tokens, or "" if none was
                       found -- classify_jobs.py tests exactly this token
                       for existence/staleness and nothing else. See the
                       module-level NOTE ON TARGET-TOKEN EXTRACTION below
                       for the deliberate interpreter-wrapped-command
                       consequence of this simple rule.
    command_display   the full command, best-effort secret-redacted (see
                       redact_secrets -- recognized shapes only, never a
                       completeness guarantee) and length-capped, for the
                       presentation table's evidence column only -- never
                       used for parsing (target_token above already
                       carries the one fact classify_jobs.py needs)
    stdout_path        LaunchAgent StandardOutPath, or "" (crontab/systemd
                       rows never have one -- this play never inspects a
                       user's own cron mail spool)
    stderr_path        LaunchAgent StandardErrorPath, or ""
    parse_note         "" normally; non-empty means this row could not be
                       parsed into a command classify_jobs.py can test --
                       it MUST be reported as opaque downstream, regardless
                       of whatever target_token happens to hold

PACKED STATUS -- one `launchctl list` row per record, 3 chr(31)-joined
fields: label (sanitized the same way as a job row's label, and filtered
to only the labels this scan actually enumerated from the user's own
LaunchAgents -- launchd's full user-domain inventory, everything else it
has loaded, is never packed or logged), pid ("-" when not running),
status (the last-exit column; launchctl overloads negative values for
"terminated by signal N"). Only loaded jobs appear here at all -- a
LaunchAgent plist that exists on disk but was never loaded (or was
unloaded) simply has no row, which classify_jobs.py reports honestly as
"not currently loaded", not as a clean exit.

NOTE ON TARGET-TOKEN EXTRACTION: for a LaunchAgent whose command is
`<interpreter> <script>` (e.g. ["/bin/zsh", "/Users/.../daily_brief.sh"]),
the first absolute-path token is the interpreter, not the script -- this
script does not special-case "skip past an interpreter" because deciding
which token is "the real target" for an arbitrary command is itself a
guess (a command could be `env FOO=1 /bin/zsh -c '...'`, or a bare script
with no interpreter at all), and the whole point of this rule is to never
guess. The interpreter existing is still an honest, true fact about the
job. This is a disclosed blind spot, not a bug: it is why this play leans
on launchd's own last-exit status (silent-failure-suspect) as the primary
signal for interpreter-wrapped jobs, target-missing/stale-suspect being a
secondary signal that only fires cleanly for jobs whose command's first
token IS the actual script (no interpreter wrapper).

Never touches a process: launchctl list and launchctl print are read
commands (list is used; print is not, to avoid per-job noise); nothing is
loaded, unloaded, started, stopped, or signaled by this script.
"""

import json
import os
import platform
import re
import shlex
import shutil
import subprocess

FS, RS = chr(31), chr(30)
JOB_FIELDS = 8

CRONTAB_TIMEOUT_S = 8
LAUNCHCTL_TIMEOUT_S = 10
PLUTIL_TIMEOUT_S = 5
SYSTEMCTL_TIMEOUT_S = 8

DISPLAY_MAX = 300

CRON_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Same best-effort secret redaction agent-resource-audit's enumerate.py
# uses, reused verbatim for consistency across this codebase's plays: only
# the value after an =/whitespace is replaced, never the flag name.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_FLAG_RE = re.compile(
    r"(?i)((?:--?[\w]*(?:token|password|passwd|secret|apikey|api[_-]?key|bearer|auth)[\w-]*)(?:[=\s]+))(\S+)"
)
_USERINFO_URL_RE = re.compile(r"://([^\s/:@]+):([^\s/@]+)@")
# Env-var-style secret assignment anywhere in the command line, e.g.
# `API_TOKEN=abc123 /usr/bin/thing` or a bare `TOKEN=abc123` -- not just
# at a leading `-flag` position, which _SECRET_FLAG_RE already covers. The
# keyword-prefix is wrapped `(?:...)?` so the keyword itself may start the
# name (bare "TOKEN=", not just "API_TOKEN="); the negative lookbehind
# keeps this from re-matching the tail of an already-handled `--token=...`
# flag (which is preceded by a hyphen/word char, not a boundary).
_ENV_SECRET_RE = re.compile(
    r"(?i)(?<![\w-])((?:[A-Za-z_][A-Za-z0-9_]*)?(?:token|password|passwd|secret|apikey|api[_-]?key|bearer|auth)[A-Za-z0-9_]*)=(\S+)"
)
# `Authorization: <anything>` header text -- everything up to the next
# quote/newline is taken, not just the first word, so a two-word scheme
# ("Bearer <token>", "Basic <base64>") is fully redacted rather than
# leaving the actual credential exposed after the scheme name.
_AUTH_HEADER_RE = re.compile(r'(?i)\bauthorization\s*:\s*[^"\'\r\n]*')


def redact_secrets(text):
    """Best-effort only -- see PACKED JOBS docstring above; this can never
    promise every secret shape is caught (an un-flagged positional value
    with no recognizable key name is fundamentally indistinguishable from
    any other bare argument), only that the recognized shapes below are."""
    out = _AUTH_HEADER_RE.sub("Authorization: ***REDACTED***", text)
    out = _BEARER_RE.sub("Bearer ***REDACTED***", out)
    out = _SECRET_FLAG_RE.sub(lambda m: m.group(1) + "***REDACTED***", out)
    out = _ENV_SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***", out)
    out = _USERINFO_URL_RE.sub(r"://\1:***REDACTED***@", out)
    return out


def strip_separators(text):
    """Strip the packing separators themselves out of a field so a
    pathological command line can never split into extra fields/records
    downstream (see PACK JOBS docstring above)."""
    return (text or "").replace(FS, "?").replace(RS, "?")


def sanitize_for_packing(text):
    """strip_separators, then best-effort secret redaction, then a length
    cap -- for display-only fields. Never applied to target_token, which
    must stay byte-exact for the filesystem check classify_jobs.py runs
    against it."""
    return redact_secrets(strip_separators(text))[:DISPLAY_MAX]


def extract_target_token(command_text):
    """Shell-aware, conservative target-token extractor for a raw shell
    command line (crontab's command text, systemd's ExecStart line).
    Tokenizes with shlex.split() so quoting/escaping is respected -- a
    quoted, space-containing path survives as one token, and shell
    punctuation (e.g. a trailing `;`) or a wrapper's own quoted argument
    (e.g. `sh -c "..."`) is never re-split the way a naive str.split()
    would. Only the FIRST token remaining after stripping any leading
    VAR=value environment assignments is ever inspected -- exactly the
    same "only the first token counts, never scan ahead into a later
    argument" rule this play already documents for LaunchAgent
    interpreter-wrapped commands (see module docstring's NOTE ON
    TARGET-TOKEN EXTRACTION) -- so a relative command followed by an
    absolute-looking data argument (a log path, an output file) is never
    mistaken for the executable, and a shell wrapper's quoted -c string is
    never guessed into.

    Returns (target_token, parse_note). target_token is "" whenever
    executable identity is ambiguous (the first token isn't an absolute
    path, or nothing is left after stripping environment assignments);
    classify_jobs.py already reports opaque for an empty target_token, so
    parse_note is left "" in that ordinary-ambiguity case and only set
    here to explain a hard tokenizing failure (unbalanced quoting), a
    rarer, distinct case.
    """
    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError as exc:
        return "", "could not tokenize command as shell words: " + str(exc)
    while tokens and CRON_ENV_RE.match(tokens[0]):
        tokens.pop(0)
    if tokens and tokens[0].startswith("/"):
        return tokens[0], ""
    return "", ""


def pack_job_row(source, label, schedule_summary, target_token, command_display, stdout_path, stderr_path, parse_note):
    return FS.join(
        [
            source,
            sanitize_for_packing(label),
            strip_separators(schedule_summary),
            strip_separators(target_token),
            command_display,
            strip_separators(stdout_path),
            strip_separators(stderr_path),
            strip_separators(parse_note),
        ]
    )


# ---------------------------------------------------------------- crontab --

def read_crontab_lines():
    """Returns (lines, warning). "no crontab for <user>" is the documented,
    completely normal absence -- most machines have none -- and is never a
    warning. The crontab binary itself being missing, or any other nonzero
    exit, is reported as a warning (source degraded, not a hard fault)."""
    try:
        proc = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=CRONTAB_TIMEOUT_S
        )
    except OSError as exc:
        return [], "crontab command not available: " + str(exc)
    except subprocess.TimeoutExpired:
        return [], "crontab -l timed out after %ss" % CRONTAB_TIMEOUT_S
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        if "no crontab" in stderr.lower():
            return [], None
        return [], "crontab -l exited " + str(proc.returncode) + ": " + stderr[:200]
    return proc.stdout.splitlines(), None


def summarize_cron_fields(minute, hour, dom, month, dow):
    """A short list of recognized simple shapes only -- anything with a
    range, list, step (*/5), or non-wildcard day/month/weekday field is
    shown as its own raw text, never paraphrased, per this play's
    never-guess rule."""
    if minute.isdigit() and hour.isdigit() and dom == "*" and month == "*" and dow == "*":
        return "daily at %02d:%02d" % (int(hour), int(minute))
    if minute.isdigit() and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return "hourly at :%02d" % int(minute)
    if minute == "*" and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return "every minute"
    return "cron: " + " ".join([minute, hour, dom, month, dow])


_CRON_FIELD_RANGES = {
    "minute": (0, 59),
    "hour": (0, 23),
    "dom": (1, 31),
    "month": (1, 12),
    "dow": (0, 7),
}


def invalid_cron_field(minute, hour, dom, month, dow):
    """Range-checks each of the 5 standard cron fields ONLY when it is a
    bare digit string (isdigit()) -- exactly the shape summarize_cron_fields
    above tries to interpret numerically (e.g. "daily at 99:99" for a
    minute/hour that is digits but out of range). Anything else (*, a
    list, a range, a step, a name) is left untouched; this play's
    deliberate never-guess rule already renders those verbatim via the raw
    "cron: ..." fallback rather than attempting full cron grammar, and
    that fallback is not itself a false claim the way "99:99" is. Returns
    a short description of the first out-of-range field found, or None
    when every digit field (if any) is in range."""
    for name, value in (("minute", minute), ("hour", hour), ("dom", dom), ("month", month), ("dow", dow)):
        if not value.isdigit():
            continue
        lo, hi = _CRON_FIELD_RANGES[name]
        if not (lo <= int(value) <= hi):
            return "%s=%s is out of range %d-%d" % (name, value, lo, hi)
    return None


def parse_crontab_lines(lines):
    rows = []
    for i, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or CRON_ENV_RE.match(line):
            continue
        label = "crontab:L%d" % i
        if line.startswith("@"):
            parts = line.split(None, 1)
            if len(parts) < 2:
                rows.append(
                    pack_job_row(
                        "user_crontab", label, "unparsed", "", sanitize_for_packing(line), "", "",
                        "crontab line has a schedule macro but no command",
                    )
                )
                continue
            schedule_summary, command_text = parts[0], parts[1]
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                rows.append(
                    pack_job_row(
                        "user_crontab", label, "unparsed", "", sanitize_for_packing(line), "", "",
                        "could not parse crontab line into 5 schedule fields plus a command",
                    )
                )
                continue
            minute, hour, dom, month, dow, command_text = parts
            bad_field = invalid_cron_field(minute, hour, dom, month, dow)
            if bad_field:
                rows.append(
                    pack_job_row(
                        "user_crontab", label, "cron: " + " ".join([minute, hour, dom, month, dow]), "",
                        sanitize_for_packing(line), "", "",
                        "invalid cron field: " + bad_field,
                    )
                )
                continue
            schedule_summary = summarize_cron_fields(minute, hour, dom, month, dow)
        target_token, target_parse_note = extract_target_token(command_text)
        rows.append(
            pack_job_row(
                "user_crontab", label, schedule_summary, target_token,
                sanitize_for_packing(command_text), "", "", target_parse_note,
            )
        )
    return rows


# ------------------------------------------------------------ LaunchAgents --

def list_launchagent_plists():
    """Returns (paths, warning). A missing ~/Library/LaunchAgents directory
    (non-macOS, or a fresh account) is an honest absence, not a warning."""
    dir_path = os.path.join(os.path.expanduser("~"), "Library", "LaunchAgents")
    if not os.path.isdir(dir_path):
        return [], None
    try:
        names = sorted(f for f in os.listdir(dir_path) if f.endswith(".plist"))
    except OSError as exc:
        return [], "could not list " + dir_path + ": " + str(exc)
    return [os.path.join(dir_path, n) for n in names], None


def parse_plist_json(path):
    """plutil -convert json -o - <path>, per-file degrade: any failure here
    (plutil missing, this one plist malformed, plutil timing out) is
    returned as (None, reason) and only ever costs THIS file its content --
    it never aborts the rest of the LaunchAgents scan."""
    try:
        proc = subprocess.run(
            ["plutil", "-convert", "json", "-o", "-", path],
            capture_output=True, text=True, timeout=PLUTIL_TIMEOUT_S,
        )
    except OSError as exc:
        return None, "plutil failed to run: " + str(exc)
    except subprocess.TimeoutExpired:
        return None, "plutil timed out after %ss" % PLUTIL_TIMEOUT_S
    if proc.returncode != 0:
        return None, "plutil exited " + str(proc.returncode) + ": " + (proc.stderr or "").strip()[:200]
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as exc:
        return None, "plutil output did not parse as JSON: " + str(exc)


def summarize_calendar_dict(d):
    if not isinstance(d, dict):
        return "calendar: (unrecognized shape)"
    if not d:
        return "on load (empty StartCalendarInterval)"
    hour = d.get("Hour") if isinstance(d.get("Hour"), int) else None
    minute = d.get("Minute") if isinstance(d.get("Minute"), int) else None
    if set(d.keys()) <= {"Hour", "Minute"}:
        if hour is not None and minute is not None:
            return "daily at %02d:%02d" % (hour, minute)
        if minute is not None:
            return "hourly at :%02d" % minute
        if hour is not None:
            return "daily at %02d:00" % hour
    return "calendar: " + json.dumps(d, sort_keys=True)


def summarize_launchd_schedule(data):
    cal = data.get("StartCalendarInterval")
    if isinstance(cal, dict):
        return summarize_calendar_dict(cal)
    if isinstance(cal, list) and cal:
        if len(cal) <= 4:
            return "; ".join(summarize_calendar_dict(d) for d in cal)
        return "%d calendar triggers/day (see plist for detail)" % len(cal)
    interval = data.get("StartInterval")
    if isinstance(interval, int) and interval > 0:
        if interval % 3600 == 0:
            return "every %dh" % (interval // 3600)
        if interval % 60 == 0:
            return "every %dm" % (interval // 60)
        return "every %ds" % interval
    if data.get("RunAtLoad") is True:
        return "at login/load (RunAtLoad)"
    keep_alive = data.get("KeepAlive")
    if keep_alive is True or (isinstance(keep_alive, dict) and keep_alive):
        return "kept alive continuously (KeepAlive)"
    return "no recognized trigger (opaque schedule)"


def launchagent_command_tokens(data):
    """Display-only argv, for the evidence column's command_display --
    NEVER used to derive target_token (see launchagent_target_token
    below): showing the full argv the plist configures is honest and
    useful even though only Program (or ProgramArguments[0]) is ever
    tested for existence."""
    program_args = data.get("ProgramArguments")
    if isinstance(program_args, list) and program_args:
        return [str(t) for t in program_args]
    program = data.get("Program")
    if isinstance(program, str) and program:
        return [program]
    return []


def launchagent_target_token(data):
    """Returns (target_token, parse_note). Program, when present, is
    unambiguously the executable launchd will run -- it is always checked
    first and ProgramArguments is never searched for one, matching
    launchd's own semantics (ProgramArguments[0] can be an arbitrary
    argv[0] nickname, not necessarily a path, whenever Program is also
    set -- see `man launchd.plist`). When Program is absent,
    ProgramArguments[0] -- and ONLY that first element, per this play's
    conservative never-scan-past-the-first-token rule -- stands in as the
    executable. Any other shape (Program present but not an absolute
    path; ProgramArguments present but its first element isn't an
    absolute path; neither key present at all) is reported opaque via a
    parse_note rather than guessed at from a later argument."""
    program = data.get("Program")
    program_args = data.get("ProgramArguments")
    has_program = isinstance(program, str) and program
    has_args = isinstance(program_args, list) and program_args
    if not has_program and not has_args:
        return "", "plist has neither Program nor ProgramArguments -- no command to classify"
    if has_program:
        if program.startswith("/"):
            return program, ""
        return "", (
            "Program is not an absolute path (" + program + "); ProgramArguments is not "
            "searched for an executable, per launchd's Program-wins semantics"
        )
    first = str(program_args[0])
    if first.startswith("/"):
        return first, ""
    return "", "ProgramArguments[0] is not an absolute path (" + first + ") and no Program key is present"


def build_launchagent_rows(paths):
    """Returns (rows, plutil_missing, raw_labels). raw_labels is the set
    of un-redacted label values used to identify each row (the plist's own
    Label, or the filename stem when the plist could not be parsed at
    all) -- kept separate from the sanitized label pack_job_row emits so
    main() can filter `launchctl list`'s full inventory down to exactly
    these jobs (see MAJOR #10 in the hardening log) using the real,
    unredacted label text launchd itself reports."""
    rows = []
    raw_labels = set()
    plutil_missing = shutil.which("plutil") is None
    for path in paths:
        stem = os.path.basename(path)
        if stem.endswith(".plist"):
            stem = stem[: -len(".plist")]
        data, err = parse_plist_json(path)
        if err is not None:
            raw_labels.add(stem)
            rows.append(
                pack_job_row(
                    "user_launchagent", stem, "unparseable", "", "", "", "",
                    "plutil could not parse this plist: " + err,
                )
            )
            continue
        if not isinstance(data, dict):
            raw_labels.add(stem)
            rows.append(
                pack_job_row(
                    "user_launchagent", stem, "unparseable", "", "", "", "",
                    "plutil output was not a JSON object",
                )
            )
            continue
        label = data.get("Label") if isinstance(data.get("Label"), str) and data.get("Label") else stem
        raw_labels.add(label)
        schedule_summary = summarize_launchd_schedule(data)
        tokens = launchagent_command_tokens(data)
        target_token, target_parse_note = launchagent_target_token(data)
        command_display = " ".join(tokens)
        stdout_path = data.get("StandardOutPath") if isinstance(data.get("StandardOutPath"), str) else ""
        stderr_path = data.get("StandardErrorPath") if isinstance(data.get("StandardErrorPath"), str) else ""
        rows.append(
            pack_job_row(
                "user_launchagent", label, schedule_summary, target_token,
                sanitize_for_packing(command_display), stdout_path, stderr_path, target_parse_note,
            )
        )
    return rows, plutil_missing, raw_labels


# ---------------------------------------------------------------- launchd --

def read_launchctl_status():
    """Returns (status_rows, warning). status_rows is a list of
    (label, pid, status) tuples for every job launchd currently has
    loaded -- a plist on disk that was never loaded (or was later
    unloaded) simply has no row here.

    Parsing is header-driven rather than assuming a fixed PID/Status/Label
    column order: the first output line is read as the header and used to
    locate each column, so a column-order or whitespace variant across
    macOS versions still parses correctly instead of silently discarding
    every row. Any data row whose field count doesn't match the header's
    is counted, not silently dropped -- if any are rejected, this source
    degrades with a warning naming the count rather than returning a
    silently-incomplete list."""
    try:
        proc = subprocess.run(
            ["launchctl", "list"], capture_output=True, text=True, timeout=LAUNCHCTL_TIMEOUT_S
        )
    except OSError as exc:
        return [], "launchctl list failed to run: " + str(exc)
    except subprocess.TimeoutExpired:
        return [], "launchctl list timed out after %ss" % LAUNCHCTL_TIMEOUT_S
    if proc.returncode != 0:
        return [], "launchctl list exited " + str(proc.returncode) + ": " + (proc.stderr or "").strip()[:200]

    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    if not lines:
        return [], None

    header_cols = lines[0].split("\t")
    required = ("PID", "Status", "Label")
    if any(name not in header_cols for name in required):
        return [], "launchctl list header did not contain the expected PID/Status/Label columns: " + lines[0][:200]
    col_index = {name: header_cols.index(name) for name in required}

    rows = []
    rejected = 0
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(header_cols):
            rejected += 1
            continue
        pid_s = parts[col_index["PID"]]
        status_s = parts[col_index["Status"]]
        label = parts[col_index["Label"]]
        rows.append((label, pid_s, status_s))

    warning = (
        "%d launchctl list row(s) did not match the header's column count and were skipped" % rejected
        if rejected
        else None
    )
    return rows, warning


# ------------------------------------------------- system, LIST-ONLY only --

def list_system_sources():
    """Names only, never content: /etc/crontab existence, /etc/cron.d
    filenames, and the two system LaunchDaemons directories' plist
    filenames (the built-in /System/Library one is counted, not listed by
    name -- its ~400 entries are Apple's own infrastructure, never
    "forgotten" by a user, and listing all of them would drown the one
    directory -- /Library/LaunchDaemons -- a user could plausibly have
    installed something into). No plutil call is ever made against a
    system LaunchDaemons plist; this is the LIST-ONLY boundary the play's
    description promises.

    Returns (info, warning). A directory that does not exist is a
    confirmed, honest empty/absent result ([] or 0/False) -- but a
    directory that DOES exist and fails to list (permissions, I/O error)
    is reported as None (unknown), distinct from a confirmed-empty
    listing, plus a warning naming exactly which source failed; a bare
    `except OSError: pass` would otherwise silently present "unknown" as
    if it were "confirmed empty", which is dishonest per-source
    degradation."""
    warnings = []
    etc_crontab_present = os.path.isfile("/etc/crontab")

    cron_d_names = []
    if os.path.isdir("/etc/cron.d"):
        try:
            cron_d_names = sorted(os.listdir("/etc/cron.d"))
        except OSError as exc:
            cron_d_names = None
            warnings.append("could not list /etc/cron.d: " + str(exc))

    library_names = []
    if os.path.isdir("/Library/LaunchDaemons"):
        try:
            library_names = sorted(
                f[: -len(".plist")] for f in os.listdir("/Library/LaunchDaemons") if f.endswith(".plist")
            )
        except OSError as exc:
            library_names = None
            warnings.append("could not list /Library/LaunchDaemons: " + str(exc))

    apple_count = None
    if os.path.isdir("/System/Library/LaunchDaemons"):
        try:
            apple_count = sum(1 for f in os.listdir("/System/Library/LaunchDaemons") if f.endswith(".plist"))
        except OSError as exc:
            apple_count = None
            warnings.append("could not count /System/Library/LaunchDaemons: " + str(exc))

    info = {
        "etc_crontab_present": etc_crontab_present,
        "etc_cron_d_names": cron_d_names,
        "launchdaemons_library_names": library_names,
        "launchdaemons_apple_count": apple_count,
    }
    return info, ("; ".join(warnings) if warnings else None)


# --------------------------------------------------------- systemd (Linux) --

def read_systemd_timer_lines():
    if shutil.which("systemctl") is None:
        return [], "systemctl not found (not a systemd host, or no user session available)"
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "list-timers", "--all", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT_S,
        )
    except OSError as exc:
        return [], "systemctl list-timers failed to run: " + str(exc)
    except subprocess.TimeoutExpired:
        return [], "systemctl --user list-timers timed out after %ss" % SYSTEMCTL_TIMEOUT_S
    if proc.returncode != 0:
        return [], "systemctl --user list-timers exited " + str(proc.returncode) + ": " + (proc.stderr or "").strip()[:200]
    return [l for l in proc.stdout.splitlines() if l.strip()], None


def parse_list_timers_line(line):
    """Split one `systemctl --user list-timers --no-legend` line into
    (schedule_text, unit, activates). NEXT/LEFT/LAST/PASSED are
    variable-width human date text with embedded spaces, so rather than
    guess where each column starts, the last two whitespace-delimited
    tokens are trusted structurally -- list-timers always emits UNIT then
    ACTIVATES last, in that order -- and everything before that is kept
    verbatim as schedule_text, never reformatted into a false precision
    this play does not actually have."""
    tokens = line.split()
    if len(tokens) < 2:
        return None
    activates, unit = tokens[-1], tokens[-2]
    schedule_text = " ".join(tokens[:-2]).strip() or "(no timing shown)"
    return schedule_text, unit, activates


def read_unit_execstart(unit):
    try:
        proc = subprocess.run(
            ["systemctl", "--user", "cat", unit], capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT_S
        )
    except OSError as exc:
        return "", "systemctl --user cat failed: " + str(exc)
    except subprocess.TimeoutExpired:
        return "", "systemctl --user cat %s timed out after %ss" % (unit, SYSTEMCTL_TIMEOUT_S)
    if proc.returncode != 0:
        return "", "systemctl --user cat %s exited %d" % (unit, proc.returncode)
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("ExecStart="):
            return stripped[len("ExecStart="):].strip(), None
    return "", "no ExecStart= line found in " + unit


def build_systemd_rows(lines):
    rows = []
    for line in lines:
        parsed = parse_list_timers_line(line)
        if parsed is None:
            rows.append(
                pack_job_row(
                    "systemd_timer", "(unparsed)", "unparsed", "", sanitize_for_packing(line), "", "",
                    "could not parse this systemctl list-timers line",
                )
            )
            continue
        schedule_text, unit, activates = parsed
        execstart, err = read_unit_execstart(activates)
        if err:
            rows.append(
                pack_job_row(
                    "systemd_timer", unit, schedule_text, "", "",
                    "", "", "could not read " + activates + "'s command: " + err,
                )
            )
            continue
        target_token, target_parse_note = extract_target_token(execstart)
        rows.append(
            pack_job_row(
                "systemd_timer", unit, schedule_text, target_token,
                sanitize_for_packing(execstart), "", "", target_parse_note,
            )
        )
    return rows


# ---------------------------------------------------------------------- --

def main():
    warnings = []
    system_name = platform.system()

    crontab_lines, crontab_warning = read_crontab_lines()
    if crontab_warning:
        warnings.append(crontab_warning)
    job_rows = parse_crontab_lines(crontab_lines)
    user_crontab_count = len(job_rows)

    user_launchagents_count = 0
    launchagent_labels = set()
    if system_name == "Darwin":
        plist_paths, launchagents_warning = list_launchagent_plists()
        if launchagents_warning:
            warnings.append(launchagents_warning)
        launchagent_rows, plutil_missing, launchagent_labels = build_launchagent_rows(plist_paths)
        if plutil_missing and plist_paths:
            warnings.append(
                "plutil was not found -- all %d LaunchAgent plist(s) are reported opaque instead of classified"
                % len(plist_paths)
            )
        job_rows.extend(launchagent_rows)
        user_launchagents_count = len(launchagent_rows)

    systemd_timers_count = 0
    if system_name == "Linux":
        timer_lines, systemd_warning = read_systemd_timer_lines()
        if systemd_warning:
            warnings.append(systemd_warning)
        systemd_rows = build_systemd_rows(timer_lines)
        job_rows.extend(systemd_rows)
        systemd_timers_count = len(systemd_rows)

    status_rows = []
    if system_name == "Darwin":
        status_tuples, launchctl_warning = read_launchctl_status()
        if launchctl_warning:
            warnings.append(launchctl_warning)
        # Only pack status rows for labels this scan actually enumerated
        # from the user's own LaunchAgents -- `launchctl list` on its own
        # reports launchd's ENTIRE user-domain inventory (system agents,
        # every running app), and packing/logging all of it would be an
        # unnecessary, unrelated disclosure. The label is sanitized with
        # the same deterministic function used for the matching job row's
        # label, so the two still compare equal downstream in
        # classify_jobs.py even though redaction can rewrite either.
        status_rows = [
            FS.join([sanitize_for_packing(label), pid, status])
            for label, pid, status in status_tuples
            if label in launchagent_labels
        ]

    if system_name == "Darwin":
        system_info, system_warning = list_system_sources()
    else:
        etc_cron_d_names = []
        if os.path.isdir("/etc/cron.d"):
            try:
                etc_cron_d_names = sorted(os.listdir("/etc/cron.d"))
            except OSError as exc:
                etc_cron_d_names = None
                system_warning = "could not list /etc/cron.d: " + str(exc)
            else:
                system_warning = None
        else:
            system_warning = None
        system_info = {
            "etc_crontab_present": os.path.isfile("/etc/crontab"),
            "etc_cron_d_names": etc_cron_d_names,
            "launchdaemons_library_names": [],
            "launchdaemons_apple_count": None,
        }
    if system_warning:
        warnings.append(system_warning)

    output = {
        "ok": True,
        "counts": {
            "platform": system_name,
            "user_crontab": user_crontab_count,
            "user_launchagents": user_launchagents_count,
            "systemd_timers": systemd_timers_count,
            "launchctl_status_rows": len(status_rows),
        },
        "packed_jobs": RS.join(job_rows),
        "packed_status": RS.join(status_rows),
        "system": system_info,
    }
    if warnings:
        output["warning"] = "; ".join(warnings)

    print(json.dumps(output))


main()
