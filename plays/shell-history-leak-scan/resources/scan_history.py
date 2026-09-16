"""Scan the five known shell/tool history files for secret-shaped content.

A git-history scanner reads what got committed. It never reads what got
TYPED: export/curl/psql/python invocations carrying a raw credential at a
shell prompt land in ~/.zsh_history, ~/.bash_history,
~/.local/share/fish/fish_history, ~/.python_history, or ~/.psql_history
instead -- files no commit-scanner ever opens. This script is this play's
whole job, in two argv-selected modes, mirroring the git-history-secret-scan
craft of one resource script serving every step:

  --locate
      Root step. STATS the five files -- exists, readable, size, mtime --
      and never opens or reads their content. A missing or unreadable file
      is a normal, expected machine state (most machines never installed
      psql, or never enabled fish), never a failure: this mode always
      emits {"ok": true, ...}, one row per file, in fixed order, so every
      downstream consumer can name exactly what was and was not found,
      never silently skip one. The only packed field a downstream step can
      use to actually OPEN a file is the absolute path; the "~"-redacted,
      human-facing label is computed one step downstream in --scan mode,
      the same discover_repos.py -> scan_identities.py split this fleet
      already established for an identical "here are some paths, here is
      what to do with them" handoff.

  --scan
      Depends on --locate's packed output (a value edge, per this fleet's
      own idiom: one scalar argv slot, chr(31)/chr(30)-packed, record-count
      reconciled by the caller). Streams every located, readable file line
      by line -- never loads a whole file into memory, so a multi-gigabyte
      history is never a problem -- matching secret-shaped content against
      the pattern set below, and NEVER keeps or emits more than the first 4
      characters plus total length of any matched value: not the full
      value, not the full line, anywhere in this script's own JSON output,
      because one history line can hold both a real secret and an
      unrelated private command. Every emitted finding NAME (a variable or
      flag name) is independently length-capped too -- see MAX_NAME_LEN --
      so a pattern bug can never smuggle attacker-controlled value text
      into a field this script does not otherwise redact. Findings beyond
      max_findings are counted, never buffered: only the first max_findings
      reduced (preview-only) records are ever held in memory at once, and a
      self-imposed wall-clock budget (SCAN_BUDGET_SECONDS, sliced fairly
      across the files still owed a turn) guarantees this script always
      prints a still-valid, partial JSON result of its own accord well
      before the step's own external process timeout could kill it and
      lose everything.

What counts as secret-shaped (the exact patterns are defined below):
  1. export/declare/typeset VAR=value, a bare inline VAR=value prefix
     before a command (and, for shells, every VAR=value word in a leading
     RUN of them before the actual command -- `SAFE=x TOKEN=y command` is
     walked in full, not just its first word), or fish's `set -x`/`set -gx
     VAR value` form, where VAR's name looks secret-related -- a long,
     distinctive word (token, secret, password, credential, ...) matched
     as a bare substring, so a fused compound like PGPASSWORD or
     CLIENTSECRET still counts; a short word (key, auth, pat, pass) that
     collides with ordinary words as a substring (monkey, author, path)
     matched only as a whole underscore/camelCase SEGMENT instead, never a
     substring -- see looks_secret_named() below -- AND the value is a
     LITERAL sitting in the clear. `export KEY=$FROM_ENV` (or a
     backtick/`$(...)` command substitution, ANYWHERE in the value, not
     only a leading position -- `KEY=prefix-$FROM_ENV` is exactly as SAFE
     as `KEY=$FROM_ENV`, since an unquoted or double-quoted `$`/backtick
     anywhere still triggers shell expansion) is the deliberately SAFE case
     and is never flagged -- only a value that cannot have been expanded is
     (a single-quoted value is always literal in real shell semantics, so
     `$`/backtick inside single quotes is never treated as expansion).
     Shell history (zsh/bash/fish) requires the strict, no-space `NAME=`
     shell grammar actually uses (`NAME = value` is not an assignment to a
     real shell, it is a command named NAME); python_history/psql_history
     are not shell command lines, so a spaced `NAME = value` there is
     recognized too -- see _allow_spaced_assignment().
  2. `curl -H "Authorization: Bearer <token>"`, quoted or not, and a bare
     `Bearer <token>` outside that header shape too.
  3. A `--password`/`--token` (or lookalike PREFIX: --api-token,
     --auth-password, ...) flag carrying a literal value -- never a bare
     flag, never one immediately followed by another flag with no value of
     its own, and never one where an unrelated SUFFIX run-on after the
     recognized word (`--token-<anything>`) is mistaken for part of the
     flag's own name; the flag name always ends exactly at
     password/passwd/token, immediately followed by its `=`/whitespace
     value separator, never absorbing what should have been the value.
  4. Well-known token shapes -- sk-, ghp_, gho_, xox[bp]-, AKIA, an
     eyJ-led JWT -- matched ANYWHERE in a line, with or without the
     context above, but never double-counted against a match a name or
     flag already explained (span-tracked below), and never inside the
     PATH portion of a URL (`.../docs/sk-...` is a documentation link, not
     a credential) unless it is also credential-bearing context the other
     rules above already recognize.
  Every contextual value above (assignment, fish set, flag, Bearer) is
  captured quote-aware: a `'...'`/`"..."` run is taken whole, inner
  whitespace and all, so `TOKEN="fake secret value"` is never truncated or
  dropped; an UNQUOTED value stops at the first whitespace or shell
  metacharacter (`;`, `&`, `|`) so it never runs on into an unrelated
  chained command sharing the same history line (`TOKEN=a;privatecommand`
  reports only `a`, never a byte of `privatecommand`).
Comment lines (a literal leading "#", however common a typed "remember to
rotate the api key" aside is) are never treated as a command and never
matched at all -- there is no VAR=value or flag shape in prose.

zsh's EXTENDED_HISTORY `: <ts>:<elapsed>;cmd` framing is parsed when
present, and its backslash line-continuation is honored, so a multi-line
paste is read as the one logical entry it was, not several unrelated
fragments each missing the context that made them secret-shaped -- bounded
to MAX_LOGICAL_ENTRY_CHARS/MAX_LOGICAL_ENTRY_LINES so one corrupt or
adversarial run of backslash-continued lines can never make this streaming
scanner buffer an unbounded "one entry" in memory; whatever text was
captured before the bound is still scanned, a secret pasted early in an
oversized paste is not missed just because the paste itself misbehaves.
fish's `- cmd: ...` / `  when: ...` block format is parsed the same way
(fish itself escapes an embedded real newline inside one cmd as literal
`\n` text, never a physical line break, so no continuation reconstruction
is needed there). Plain files (bash, python, psql) are one entry per
physical line, the same as always.

Degrade, not fail: a HARD FAULT here means broken wiring, never a
legitimate absence -- bad/missing argv, or max_findings failing to
int-parse (the same reasoning this fleet's other scripts already apply to
their own int argv; rote's own param_type: integer gate should already
have caught this upstream). Every other outcome -- a file absent, a file
unreadable, a file that raises OSError mid-read, a file whose turn never
came or was cut short because SCAN_BUDGET_SECONDS ran out (reported
"budget-exceeded", never silently merged into "scanned"), --locate's own
packed output arriving empty or malformed at --scan -- degrades per-file
(or, for a wholly empty upstream, with a warning) and still emits
{"ok": true, ...}.
"""

import json
import os
import re
import sys
import time

FS, RS = chr(31), chr(30)

HOME = os.path.expanduser("~")

# The five known shell/tool history files this play checks, in this fixed
# order. Every one of the five is always reported on, present or not, so
# nothing is ever silently skipped.
HISTORY_FILES = [
    "~/.zsh_history",
    "~/.bash_history",
    "~/.local/share/fish/fish_history",
    "~/.python_history",
    "~/.psql_history",
]

MIN_FINDINGS, MAX_FINDINGS = 1, 500

# Self-imposed wall-clock budget for one whole --scan invocation, sliced
# fairly across whichever files still haven't had their turn (see
# cmd_scan()) -- deliberately well under the step's own external process
# timeout (main.ts) so this script always has time left to print a
# partial, still-valid JSON result of its own accord before an external
# kill would lose everything. A file cut off mid-scan, or one whose turn
# never came at all, is reported "budget-exceeded", never silently folded
# into "scanned".
SCAN_BUDGET_SECONDS = 24
LINES_PER_DEADLINE_CHECK = 2000


def redact_home(text):
    if not text:
        return text
    return str(text).replace(HOME, "~") if HOME and HOME != "/" else str(text)


def sanitize(text):
    """Strip the packing separators out of text before it goes in a packed
    row (a pathological path should never split into extra fields or
    records downstream) -- mirrors enumerate.py/discover_repos.py."""
    return text.replace(FS, "?").replace(RS, "?")


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(2)


def iso_date(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


# ---------------------------------------------------------------------------
# Secret-shaped pattern set
# ---------------------------------------------------------------------------

# Two tiers, mirroring enumerate.py's own two-tier redaction craft
# (exec-identity vs invocation-marker): a STRONG word is long/distinctive
# enough that it is checked as a bare substring of the whole name --
# "password" is never accidentally part of an unrelated word, so
# "PGPASSWORD"/"DB_PASSWORD"/"CLIENTSECRET" (no separator between the
# product name and the secret word) all still match. A SEGMENT-ONLY word is
# short enough to collide with ordinary words as a substring -- "key" is
# inside "monkey", "auth" is inside "author"/"authenticate", "pat" is
# inside "path" -- so those are only ever checked as one WHOLE
# underscore/camelCase-delimited segment of the name, never a substring.
STRONG_SECRET_WORDS = (
    "password", "passwd", "token", "secret", "credential",
    "apikey", "privatekey", "accesskey", "clientsecret",
)
SEGMENT_ONLY_SECRET_WORDS = {"key", "auth", "pat", "pass"}


def _segments(name):
    """Split name into lowercase word segments on underscores/hyphens and
    camelCase boundaries, so "OPENAI_API_KEY", "apiKey", and "API-KEY" all
    decompose the same way."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [s.lower() for s in re.split(r"[^A-Za-z0-9]+", spaced) if s]


def looks_secret_named(name):
    lowered = name.lower()
    if any(word in lowered for word in STRONG_SECRET_WORDS):
        return True
    return any(s in SEGMENT_ONLY_SECRET_WORDS for s in _segments(name))


# A name/flag-context value shorter than this is never reported on its own
# -- a 1-2 character "secret" is far more likely a stray token boundary
# (an escaped space, a truncated paste) than a real credential, and this
# floor is well under any real key/token/password worth rotating. The
# well-known token-shape patterns below carry their own, longer length
# requirements and are unaffected by this floor.
MIN_LITERAL_LEN = 6

# Every emitted finding NAME (a variable or flag name) is capped to this
# length independently of whatever regex produced it -- defense in depth
# against any future pattern bug that lets attacker-controlled text run on
# past a real flag/variable name into the one field this script does not
# otherwise reduce to a preview. A name this long was never a real flag or
# variable name to begin with.
MAX_NAME_LEN = 80


def sanitize_name(raw):
    name = str(raw) if raw is not None else "?"
    if len(name) > MAX_NAME_LEN:
        name = name[:MAX_NAME_LEN] + "…(name truncated)"
    return name


def is_literal_value(value, single_quoted):
    """False for the deliberately SAFE cases: empty, too short to
    plausibly be a credential (see MIN_LITERAL_LEN), or -- unless the
    value was single-quoted, which real shell syntax never expands -- a
    value that contains a `$` or backtick ANYWHERE, not only in a leading
    position: `prefix-$FROM_ENV` and `prefix-$(lookup)` depend on
    parameter/command expansion exactly as much as a bare `$FROM_ENV`
    does, and this script only ever sees the typed text, never what the
    shell actually expanded it to."""
    if not value:
        return False
    if len(value) < MIN_LITERAL_LEN:
        return False
    if not single_quoted and ("$" in value or "`" in value):
        return False
    return True


def _raw_is_single_quoted(raw):
    s = raw.strip()
    return len(s) >= 2 and s[0] == "'" and s[-1] == "'"


def clean_value(raw):
    """Trim a captured value down to its literal content: a surrounding
    matched quote pair first, then trailing shell/JSON punctuation an
    unquoted capture can still sweep in (a trailing ; ending the history
    line, a trailing ,/) from JSON or a subshell)."""
    v = raw.strip()
    if len(v) >= 2 and v[0] in "'\"" and v[-1] == v[0]:
        v = v[1:-1]
    v = v.rstrip("\"');,")
    return v


KNOWN_SHAPES = [
    ("openai-key", re.compile(r"sk-[A-Za-z0-9_-]{16,}")),
    ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github-oauth-token", re.compile(r"gho_[A-Za-z0-9]{20,}")),
    ("slack-token", re.compile(r"xox[bp]-[A-Za-z0-9-]{10,}")),
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]


def classify_shape(value):
    """The most specific known shape name for value, else None."""
    for shape, pattern in KNOWN_SHAPES:
        if pattern.search(value):
            return shape
    return None


# ---------------------------------------------------------------------------
# Quote-aware, shell-metacharacter-aware value/segment tokenizing
# ---------------------------------------------------------------------------

_SHELL_META = ";&|"


def _take_value(text, i):
    """Consume one shell "word" starting at text[i], honoring quoting.

    A '...' or "..." run is consumed whole -- including any inner
    whitespace or metacharacters -- up to its matching close quote
    (backslash-escaped only inside double quotes, never single quotes,
    matching real shell rules), so 'TOKEN="a b;c"' never truncates at the
    inner ';'. An unquoted run stops at the first whitespace OR shell
    metacharacter (;, &, |) -- those chain a NEW command, whose text is
    never part of this value, so 'TOKEN=a;privatecommand' never absorbs so
    much as one byte of privatecommand. Returns (raw_value, end_index);
    raw_value keeps its surrounding quotes, same as the old \\S+ capture
    did, so clean_value()'s existing quote-stripping still applies
    unchanged.
    """
    n = len(text)
    if i >= n:
        return "", i
    if text[i] in "'\"":
        quote = text[i]
        j = i + 1
        while j < n:
            if text[j] == "\\" and quote == '"' and j + 1 < n:
                j += 2
                continue
            if text[j] == quote:
                j += 1
                break
            j += 1
        return text[i:j], j
    j = i
    while j < n and not text[j].isspace() and text[j] not in _SHELL_META:
        j += 1
    return text[i:j], j


def _command_starts(text):
    """Boundaries where a new simple command begins: position 0, and the
    position right after each run of unquoted `;`, `&`, `|` (and the
    whitespace following it) -- quote-aware, so a `;` sitting inside a
    quoted value (`TOKEN="a;b" cmd`) is never mistaken for a command
    separator."""
    starts = [0]
    i, n = 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"":
            quote = c
            i += 1
            continue
        if c in _SHELL_META:
            i += 1
            while i < n and text[i] in _SHELL_META:
                i += 1
            while i < n and text[i].isspace():
                i += 1
            starts.append(i)
            continue
        i += 1
    return starts


_URL_RE = re.compile(r"https?://[^\s'\"]+")


def _url_path_spans(text):
    """(start, end) spans covering only the PATH portion -- host up to the
    first ?/# -- of every URL on the line, so a documentation link like
    `.../docs/sk-abcdefghijklmnop` is never reported as a leaked key. A
    credential legitimately riding in a query string (`?access_token=...`)
    is outside every span this returns and is unaffected."""
    spans = []
    for m in _URL_RE.finditer(text):
        url = m.group(0)
        q = re.search(r"[?#]", url)
        path_end = m.start() + (q.start() if q else len(url))
        spans.append((m.start(), path_end))
    return spans


def _in_url_path(start, end, url_path_spans):
    return any(start >= s and end <= e for s, e in url_path_spans)


# ---------------------------------------------------------------------------
# Assignment (VAR=value) parsing, shell-strict and spaced-generic
# ---------------------------------------------------------------------------

_KEYWORD_PREFIX_RE = re.compile(
    r"(?:export\s+|declare\s+(?:-\S+\s+)?|typeset\s+(?:-\S+\s+)?)"
)
_ASSIGN_HEAD_RE_STRICT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
_ASSIGN_HEAD_RE_SPACED = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")


def find_assignments(text, starts, allow_spaced_eq):
    """Yield (name, raw_value, v_start, v_end) for every leading VAR=value
    word at the start of each command segment in text -- one segment per
    `starts` boundary (see _command_starts) -- so a prefix RUN of
    assignments before the actual command (`SAFE=x TOKEN=fakevalue123
    command`) is walked in full, not just its first word. An optional
    single export/declare/typeset keyword is skipped once per segment,
    matching a real shell's own grammar. allow_spaced_eq permits `NAME =
    value` (spaces around `=`) for contexts where that is a real
    assignment -- python_history, psql_history -- never for shell history,
    where `NAME = value` is not an assignment at all, it is a command named
    NAME with two argument words."""
    results = []
    head_re = _ASSIGN_HEAD_RE_SPACED if allow_spaced_eq else _ASSIGN_HEAD_RE_STRICT
    for start in starts:
        pos = start
        m = _KEYWORD_PREFIX_RE.match(text, pos)
        if m:
            pos = m.end()
        while True:
            m = head_re.match(text, pos)
            if not m:
                break
            name = m.group(1)
            raw_value, end = _take_value(text, m.end())
            if raw_value:
                results.append((name, raw_value, m.end(), end))
                pos = end
            else:
                pos = m.end()
            # A real shell separates successive assignment words with
            # whitespace; if the very next character is not whitespace (or
            # end of text), this was not a standalone assignment word --
            # stop rather than guess at where the command itself begins.
            if pos < len(text) and not text[pos].isspace():
                break
            while pos < len(text) and text[pos].isspace():
                pos += 1
    return results


def _allow_spaced_assignment(path):
    """python_history and psql_history are language/SQL statement text, not
    shell command lines -- `TOKEN = fakevalue123` is a real assignment
    there. Every other known history file keeps the strict, no-space `=`
    a real shell actually requires."""
    return os.path.basename(path) in (".python_history", ".psql_history")


_FISH_SET_PREFIX_RE = re.compile(
    r"(?:^|[;&|]\s*)set\s+(?:-\S+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s+"
)
_FLAG_PREFIX_RE = re.compile(
    r"(?i)(--?[\w-]*(?:password|passwd|token))(?:[=\s]+)"
)
_BEARER_PREFIX_RE = re.compile(r"(?i)(Authorization:\s*)?\bBearer\s+")

# Cheap literal prefilters, mirroring the git-history-secret-scan.py craft
# already established in this fleet: almost every history line contains
# none of a given stage's own trigger words, and a handful of plain
# substring checks is far cheaper than always running that stage's
# regex/tokenizer work. Every marker is a mandatory literal of what its
# stage actually looks for, so skipping on a miss can never lose a real
# match -- this only ever skips work that would have found nothing anyway.
_KNOWN_SHAPE_MARKERS = ("sk-", "ghp_", "gho_", "xox", "AKIA", "eyJ")


def scan_line(text, allow_spaced_eq=False):
    """Return every secret-shaped match in one line/logical-entry of
    history text as {"name", "shape", "value"} dicts. Values are returned
    here for shape/preview computation ONLY -- the caller must reduce each
    one to a 4-char+length preview before it is stored or emitted
    anywhere; this function itself never truncates."""
    findings = []
    claimed = []

    def claim(start, end):
        claimed.append((start, end))

    def overlaps(start, end):
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    if "=" in text:
        starts = _command_starts(text)
        for name, raw_value, v_start, v_end in find_assignments(text, starts, allow_spaced_eq):
            if not looks_secret_named(name):
                continue
            single_quoted = _raw_is_single_quoted(raw_value)
            value = clean_value(raw_value)
            if not is_literal_value(value, single_quoted):
                continue
            shape = classify_shape(value) or "env-var-literal"
            findings.append({"name": name, "shape": shape, "value": value})
            claim(v_start, v_end)

    if "set " in text:
        for m in _FISH_SET_PREFIX_RE.finditer(text):
            name = m.group(1)
            if not looks_secret_named(name):
                continue
            raw_value, v_end = _take_value(text, m.end())
            if not raw_value:
                continue
            v_start = m.end()
            if overlaps(v_start, v_end):
                continue
            single_quoted = _raw_is_single_quoted(raw_value)
            value = clean_value(raw_value)
            if not is_literal_value(value, single_quoted):
                continue
            shape = classify_shape(value) or "env-var-literal"
            findings.append({"name": name, "shape": shape, "value": value})
            claim(v_start, v_end)

    text_lower = text.lower()
    url_path_spans = _url_path_spans(text) if "://" in text else []

    for m in (_FLAG_PREFIX_RE.finditer(text) if (
        "token" in text_lower or "password" in text_lower or "passwd" in text_lower
    ) else ()):
        flag = m.group(1)
        raw_value, v_end = _take_value(text, m.end())
        if not raw_value or raw_value.startswith("-"):
            continue  # no literal value -- the next token is another flag
        v_start = m.end()
        if overlaps(v_start, v_end):
            continue
        single_quoted = _raw_is_single_quoted(raw_value)
        value = clean_value(raw_value)
        if not is_literal_value(value, single_quoted):
            continue
        shape = classify_shape(value) or "cli-flag-literal"
        findings.append({"name": flag, "shape": shape, "value": value})
        claim(v_start, v_end)

    if "bearer" in text_lower:
        for m in _BEARER_PREFIX_RE.finditer(text):
            name = "Authorization" if m.group(1) else "Bearer"
            raw_value, v_end = _take_value(text, m.end())
            if not raw_value:
                continue
            v_start = m.end()
            if overlaps(v_start, v_end):
                continue
            single_quoted = _raw_is_single_quoted(raw_value)
            value = clean_value(raw_value)
            if not is_literal_value(value, single_quoted):
                continue
            shape = classify_shape(value) or "bearer-token"
            findings.append({"name": name, "shape": shape, "value": value})
            claim(v_start, v_end)

    if any(marker in text for marker in _KNOWN_SHAPE_MARKERS):
        for shape, pattern in KNOWN_SHAPES:
            for m in pattern.finditer(text):
                if overlaps(m.start(), m.end()):
                    continue
                if _in_url_path(m.start(), m.end(), url_path_spans):
                    continue
                value = clean_value(m.group(0))
                if not value:
                    continue
                findings.append({"name": "(bare token)", "shape": shape, "value": value})
                claim(m.start(), m.end())

    return findings


def preview(value):
    n = len(value)
    if n <= 4:
        return "%s, %d chars" % (value, n)
    return "%s…, %d chars" % (value[:4], n)


# ---------------------------------------------------------------------------
# Per-format entry iteration
# ---------------------------------------------------------------------------

_ZSH_EXT_RE = re.compile(r"^: (\d+):(\d+);(.*)$")

# ~1MB / 50k lines. A real pasted zsh command, however long, is never
# remotely this size; these bound a corrupt or adversarial run of
# backslash-continued lines so it can never make this streaming scanner
# buffer an unbounded, multi-gigabyte "one entry" in memory (either by raw
# character count or by sheer line count -- a run of thousands of
# empty/whitespace-only continuation lines would grow the char count by
# nothing at all, so both bounds are needed). Once a bound is hit, further
# continuation lines are still consumed (to stay in sync with the file's
# own line numbering) but their text is discarded, not appended; whatever
# was captured before the bound is still scanned -- a secret pasted early
# in an oversized paste is not missed just because the paste itself
# misbehaves.
MAX_LOGICAL_ENTRY_CHARS = 1_000_000
MAX_LOGICAL_ENTRY_LINES = 50_000


def iter_zsh_entries(path):
    """Yield (start_line_no, command_text) logical entries from a zsh
    history file, honoring EXTENDED_HISTORY's `: <ts>:<elapsed>;cmd`
    framing when present and its backslash line-continuation for
    multi-line commands. A plain (non-extended) zsh history -- the setting
    is per-shell, not a file-format guarantee -- falls through to one
    entry per physical line, same as every other plain-text history file."""
    line_no = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        pending = None  # (start_line_no, [text_parts], accumulated_chars, line_count)
        for raw in f:
            line_no += 1
            line = raw.rstrip("\n")
            if pending is not None:
                start_no, parts, size, count = pending
                continues = line.endswith("\\")
                chunk = line[:-1] if continues else line
                if size <= MAX_LOGICAL_ENTRY_CHARS and count < MAX_LOGICAL_ENTRY_LINES:
                    parts.append(chunk)
                    size += len(chunk)
                count += 1
                if continues:
                    pending = (start_no, parts, size, count)
                    continue
                yield start_no, "\n".join(parts)
                pending = None
                continue
            m = _ZSH_EXT_RE.match(line)
            cmd = m.group(3) if m else line
            if cmd.endswith("\\"):
                pending = (line_no, [cmd[:-1]], len(cmd) - 1, 1)
                continue
            yield line_no, cmd
        if pending is not None:
            # Truncated file tail mid-continuation; yield what we have
            # rather than silently dropping it.
            start_no, parts, size, count = pending
            yield start_no, "\n".join(parts)


_FISH_CMD_RE = re.compile(r"^-\s*cmd:\s?(.*)$")


def iter_fish_entries(path):
    """fish_history is a YAML-like stream of `- cmd: ...` / `  when: ...`
    blocks; only `cmd:` lines can carry command text. Every physical line
    is still yielded -- unrecognized ones (when:, blank, list markers)
    simply match no pattern below, the same as a comment line."""
    line_no = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line_no += 1
            line = raw.rstrip("\n")
            m = _FISH_CMD_RE.match(line)
            yield line_no, (m.group(1) if m else line)


def iter_plain_entries(path):
    line_no = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line_no += 1
            yield line_no, raw.rstrip("\n")


def entries_for(path):
    base = os.path.basename(path)
    if base == ".zsh_history":
        return iter_zsh_entries(path)
    if base == "fish_history":
        return iter_fish_entries(path)
    return iter_plain_entries(path)


def scan_file(path, remaining, allow_spaced_eq, deadline):
    """Stream one history file, matching every entry against scan_line().

    Reduces and discards each match immediately: at most `remaining`
    reduced (preview-only) records are ever held onto from this file, the
    rest are only ever counted, so neither their raw value nor a growing
    per-file buffer of full findings is ever retained in memory. Checked
    periodically (never per-line, which would cost more than it saves)
    against `deadline`; a file still running past it is cut off, its
    partial line/finding counts kept, never silently reported as fully
    "scanned". A mid-read OSError degrades this one file, it never aborts
    the run.

    Returns (shown, total, lines_scanned, error|None, cut_off).
    """
    shown = []
    total = 0
    lines_scanned = 0
    cut_off = False
    try:
        for line_no, text in entries_for(path):
            lines_scanned += 1
            if lines_scanned % LINES_PER_DEADLINE_CHECK == 0 and time.monotonic() > deadline:
                cut_off = True
                break
            if text.lstrip().startswith("#"):
                continue
            for f in scan_line(text, allow_spaced_eq=allow_spaced_eq):
                total += 1
                if len(shown) < remaining:
                    shown.append({
                        "line": line_no,
                        "name": sanitize_name(f["name"]),
                        "shape": f["shape"],
                        "value_preview": preview(f["value"]),
                    })
    except OSError as exc:
        return shown, total, lines_scanned, str(exc), cut_off
    return shown, total, lines_scanned, None, cut_off


# ---------------------------------------------------------------------------
# --locate
# ---------------------------------------------------------------------------

def cmd_locate():
    rows = []
    any_present = False
    for rel in HISTORY_FILES:
        path = os.path.expanduser(rel)
        exists = os.path.isfile(path)
        readable = False
        size = 0
        mtime_iso = ""
        reason = ""
        if not exists:
            reason = "absent"
        else:
            readable = os.access(path, os.R_OK)
            if not readable:
                reason = "unreadable"
            else:
                try:
                    st = os.stat(path)
                    size = st.st_size
                    mtime_iso = iso_date(st.st_mtime)
                    any_present = True
                except OSError as exc:
                    readable = False
                    reason = "stat failed: " + str(exc)[:80]
        rows.append((path, exists, readable, size, mtime_iso, reason))

    packed = RS.join(
        FS.join([
            sanitize(path), "1" if exists else "0", "1" if readable else "0",
            str(size), mtime_iso, sanitize(reason),
        ])
        for path, exists, readable, size, mtime_iso, reason in rows
    )

    result = {
        "ok": True,
        "count": len(HISTORY_FILES),
        "found": sum(1 for row in rows if row[2]),
        "packed": packed,
        "warning": None if any_present else "none of the 5 known shell-history files were found or readable on this machine",
    }
    print(json.dumps(result))


# ---------------------------------------------------------------------------
# --scan
# ---------------------------------------------------------------------------

def unpack_locate(packed):
    rows = []
    if not packed:
        return rows
    for raw_row in packed.split(RS):
        if not raw_row:
            continue
        parts = raw_row.split(FS)
        if len(parts) != 6:
            continue  # malformed row from a degraded upstream step; skip it
        path, exists_s, readable_s, size_s, mtime_iso, reason = parts
        rows.append({
            "path": path,
            "label": redact_home(path),
            "exists": exists_s == "1",
            "readable": readable_s == "1",
            "size_bytes": int(size_s) if size_s.isdigit() else 0,
            "mtime_iso": mtime_iso or None,
            "reason": reason or None,
        })
    return rows


def parse_max_findings(raw):
    try:
        value = int(raw)
    except (TypeError, ValueError):
        fail("max_findings must be an integer, got: " + str(raw))
    return max(MIN_FINDINGS, min(MAX_FINDINGS, value))


def cmd_scan(argv):
    if len(argv) < 2:
        fail("--scan requires <locate_packed> <max_findings>")
    packed, max_findings_raw = argv[0], argv[1]
    max_findings = parse_max_findings(max_findings_raw)

    rows = unpack_locate(packed)

    all_findings = []
    file_reports = []
    total_lines = 0
    total_findings = 0
    oldest_iso = None
    oldest_label = None
    budget_exceeded_any = False

    scan_start = time.monotonic()
    overall_deadline = scan_start + SCAN_BUDGET_SECONDS

    for i, row in enumerate(rows):
        label = row["label"]
        if not row["exists"]:
            file_reports.append({"file": label, "status": "absent", "lines_scanned": 0})
            continue
        if not row["readable"]:
            file_reports.append({"file": label, "status": "unreadable", "lines_scanned": 0, "reason": row["reason"]})
            continue

        now = time.monotonic()
        if now >= overall_deadline:
            file_reports.append({"file": label, "status": "budget-exceeded", "lines_scanned": 0})
            budget_exceeded_any = True
            continue

        # Slice the time still left fairly across every readable file that
        # hasn't had its turn yet, so one huge file early in the fixed
        # order cannot silently starve every file after it of any turn at
        # all -- each still gets a bounded, proportional shot, all within
        # the same overall SCAN_BUDGET_SECONDS envelope.
        remaining_files = sum(1 for r in rows[i:] if r["exists"] and r["readable"])
        slice_seconds = max(1.0, (overall_deadline - now) / max(1, remaining_files))
        file_deadline = min(overall_deadline, now + slice_seconds)

        remaining_slots = max(0, max_findings - len(all_findings))
        findings_shown, total_in_file, lines_scanned, error, cut_off = scan_file(
            row["path"], remaining_slots, _allow_spaced_assignment(row["path"]), file_deadline,
        )
        total_lines += lines_scanned
        total_findings += total_in_file

        if cut_off:
            budget_exceeded_any = True
            file_reports.append({"file": label, "status": "budget-exceeded", "lines_scanned": lines_scanned})
        elif error:
            file_reports.append({"file": label, "status": "error", "lines_scanned": lines_scanned, "error": error})
        else:
            file_reports.append({"file": label, "status": "scanned", "lines_scanned": lines_scanned})

        for f in findings_shown:
            all_findings.append({"file": label, **f})

        if row["mtime_iso"] and (oldest_iso is None or row["mtime_iso"] < oldest_iso):
            oldest_iso = row["mtime_iso"]
            oldest_label = label

    files_scanned = sum(1 for r in file_reports if r["status"] == "scanned")

    warning = None
    if not rows:
        warning = "locate_histories output was unavailable or malformed; nothing was scanned"
    elif budget_exceeded_any:
        warning = (
            f"scan wall-clock budget ({SCAN_BUDGET_SECONDS}s) reached before every file finished; "
            f"{files_scanned} of {len(rows)} file(s) fully scanned -- rerun to check the rest"
        )

    result = {
        "ok": True,
        "findings": all_findings,
        "files": file_reports,
        "totals": {
            "files_checked": len(rows),
            "files_scanned": files_scanned,
            "total_lines_scanned": total_lines,
            "total_findings": total_findings,
            "findings_shown": len(all_findings),
            "findings_truncated": total_findings - len(all_findings),
            "max_findings": max_findings,
        },
        "oldest_file": oldest_label,
        "oldest_iso": oldest_iso,
        "warning": warning,
    }
    print(json.dumps(result))


def main():
    if len(sys.argv) < 2:
        fail("usage: scan_history.py --locate | --scan <locate_packed> <max_findings>")
    mode = sys.argv[1]
    if mode == "--locate":
        cmd_locate()
    elif mode == "--scan":
        cmd_scan(sys.argv[2:])
    else:
        fail("unknown mode: " + mode)


main()
