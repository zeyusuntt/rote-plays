"""Scan recent commit messages for AI-attribution marks. Reads commit
metadata only -- subjects, bodies, and trailers -- never touches code,
diffs, or file contents. Identity hygiene for commit metadata, not a repo
audit.

argv[1]  repo_abs  -- absolute path to the git repository (already
                       validated by validate_repo)
argv[2]  depth     -- how many recent commits to scan (already validated)

Detection is two-class, and the split is the whole point of this play:

  TRAILER    a Co-Authored-By or Signed-off-by trailer, recognized by
             delegating the FULL raw commit message (subject included) to
             `git interpret-trailers --parse` -- the actual authority on
             trailer-block eligibility (which final-paragraph shapes
             count at all, and specifically that a trailer paragraph
             needs the natural subject-then-blank-line context in front
             of it, even when there is no other body prose), folded/
             continuation lines (an indented continuation line is part of
             the previous trailer's value, not a separate line), and the
             "whole block, not one matching line in a paragraph that also
             has prose" rule -- whose value names an AI tool, or an AI
             vendor's noreply-style email address.

  BODY-MARK  a "Generated with/by <AI tool>" phrase where the tool is the
             direct object (not merely present somewhere else on the same
             line, and not inside quote marks -- prose DISCUSSING the
             phrase, like `explains why "Generated with Claude" is
             forbidden`, is not the phrase), or a robot emoji sharing a
             line with an AI tool name, anywhere in the commit BODY only
             (never the subject).

A commit message that merely DISCUSSES AI in prose ("remove claude
co-author trailer", "fix GPT prompt in docs") must NOT match either class:
both classes require one of the exact structural shapes above, never a
bare tool-name mention anywhere in the message. Only the commit BODY
(`%b`) is ever scanned for BODY-MARK; a no-body subject that happens to
look like a "Generated with" phrase is never flagged, the way Git itself
never treats a subject line as a trailer either -- which is also why
TRAILER recognition, despite reading the full message, still correctly
finds no trailer in a subject-only message: git's own parser applies that
same subject-is-never-a-trailer rule to the paragraph it is given.

Text is Unicode-normalized (NFKC) and stripped of zero-width/
default-ignorable characters before any pattern is applied, so a
zero-width-joined obfuscation like "Cl<ZWSP>aude" still reads as "Claude".
Emoji SHORTCODES such as ":robot:" are explicitly OUT OF SCOPE: that is
prose describing an emoji, not the literal Unicode robot-emoji body mark
tools actually emit, and a shortcode is never treated as equivalent to it.

Emits one JSON object on stdout, always exit 0 once git itself succeeds
(git failing outright against a repo validate_repo already confirmed is an
unexpected essential failure -- this step's whole job is reading that
output, so there is nothing honest left to degrade to):
    {"ok": true, "scanned": N,
     "findings": [{"sha7": "...", "class": "trailer"|"body-mark",
                    "pattern": "...", "line_redacted": "..."}, ...],
     "warning": "..." (only if some commit's content was not valid UTF-8)}
Every finding carries exactly these four fields -- sha7, class, pattern,
line_redacted -- and nothing else; there is no subject or full-message
field anywhere in this output.
"""

import json
import re
import subprocess
import sys
import unicodedata

GIT_TIMEOUT_S = 25
INTERPRET_TIMEOUT_S = 10
LINE_MAX = 200

AI_TOOL_RE = re.compile(
    r"(?i)\b(claude|chatgpt|gpt|openai|copilot|codex|gemini|aider|cursor|devin|windsurf|opencode|anthropic)\b"
)
TRAILER_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z-]*)\s*:\s*(.+?)\s*$")
TRAILER_KEYS = ("co-authored-by", "signed-off-by")
# The tool must be the direct object of "generated with/by" -- optionally
# through "the" or a markdown-link bracket, the shape Claude Code's own
# footer uses ("Generated with [Claude Code](...)") -- never merely
# present somewhere else on the same line.
GENERATED_MARK_RE = re.compile(
    r"(?i)\bgenerated\s+(?:with|by)\s+(?:the\s+)?\[?"
    r"(claude|chatgpt|gpt|openai|copilot|codex|gemini|aider|cursor|devin|windsurf|opencode|anthropic)\b"
)
ROBOT_EMOJI = "\U0001F916"  # the literal robot-emoji body mark this play looks for
QUOTE_CHARS = "\"'\u201c\u201d\u2018\u2019`"

# Zero-width and other default-ignorable characters an obfuscator could
# splice into a tool name without changing how it renders: soft hyphen,
# zero-width space through right-to-left mark, bidi embedding/override,
# word joiner and invisible math operators, bidi isolates, BOM/zero-width
# no-break space.
DEFAULT_IGNORABLE_RE = re.compile(
    "[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(2)


def normalize_for_matching(text):
    """NFKC-normalize and strip zero-width/default-ignorable characters
    before any pattern match. See the module docstring for why emoji
    shortcodes are deliberately NOT normalized into their emoji."""
    text = unicodedata.normalize("NFKC", text)
    return DEFAULT_IGNORABLE_RE.sub("", text)


def repo_has_head(repo_abs):
    """Locale-independent emptiness probe. `-q` suppresses git's
    (English, locale-dependent) error text and turns "HEAD does not
    resolve" into a silent, well-defined exit code 1 -- distinct from
    every other fatal git error, which exits with something else (128 in
    practice). No stderr string is ever pattern-matched to decide this."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo_abs, "rev-parse", "--verify", "-q", "HEAD"],
            capture_output=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        fail("git rev-parse failed to run: " + str(exc))
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    fail("git rev-parse HEAD failed unexpectedly: " + stderr[:200])


def run_git_log_records(repo_abs, depth):
    """Returns a list of (sha_bytes, body_bytes, full_message_bytes)
    triples straight off git log's NUL-delimited output. NUL is the one
    byte git never lets a valid commit's content smuggle -- it strips
    embedded NULs when a commit is written -- unlike the RS/FS
    control-picture bytes this parser used to rely on (git accepts those
    in commit content). `-z` entry termination plus `%x00` field
    separation gives an unambiguous, self-validating frame: split the
    whole capture on NUL, require the trailing empty token `-z` always
    appends, and require what remains is an exact multiple of three
    fields. Anything else is fail-closed malformed history, never a
    silently truncated or silently clean scan.

    Both %b (body only) and %B (the full raw message, subject included)
    are fetched: %b is the only text find_body_marks ever sees, so a
    no-body subject never becomes a body mark; %B is what
    git_interpret_trailers is fed, because git's own trailer parser needs
    the natural subject-then-blank-line shape to correctly decide
    eligibility -- feeding it %b alone loses that context and makes git
    silently refuse to recognize a trailer paragraph that has no other
    body prose in front of it."""
    if not repo_has_head(repo_abs):
        return []
    argv = [
        "git",
        "-C",
        repo_abs,
        "log",
        "-z",
        "-n",
        str(depth),
        "--no-color",
        "--format=%H%x00%b%x00%B",
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=GIT_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as exc:
        fail("git log failed to run: " + str(exc))
    if proc.returncode != 0:
        stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        fail("git log exited " + str(proc.returncode) + ": " + stderr[:200])

    raw = proc.stdout
    if raw == b"":
        return []
    tokens = raw.split(b"\x00")
    if tokens[-1] != b"":
        fail("malformed git log output: missing trailing NUL terminator")
    tokens = tokens[:-1]
    if len(tokens) % 3 != 0:
        fail(
            "malformed git log output: expected sha/body/message triples, got "
            + str(len(tokens))
            + " field(s)"
        )
    return [(tokens[i], tokens[i + 1], tokens[i + 2]) for i in range(0, len(tokens), 3)]


def decode_field(raw_bytes):
    """Best-effort UTF-8 decode of one field. Never raises: a non-UTF-8 or
    mismatched-encoding commit degrades that one field to
    replacement-character text instead of a blanket text=True subprocess
    decode aborting the whole scan on one bad commit."""
    try:
        return raw_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw_bytes.decode("utf-8", errors="replace"), True


def redact_line(line):
    stripped = line.strip()
    if len(stripped) > LINE_MAX:
        stripped = stripped[: LINE_MAX - 1] + "…"
    return stripped


def _is_quoted_span(line, start, end):
    """True when the matched phrase is immediately wrapped in quote marks
    on the line -- the structural shape of prose DISCUSSING a footer
    ('...explains why "Generated with Claude" is forbidden...'), not the
    footer itself. A real tool-emitted footer is never quoted like this."""
    before = line[start - 1 : start] if start > 0 else ""
    after = line[end : end + 1]
    # An empty slice ("" at line start/end) is a substring of every string
    # in Python, so a bare `in QUOTE_CHARS` on it would always be True --
    # guard explicitly rather than silently treating start/end-of-line as
    # quoted.
    return (before != "" and before in QUOTE_CHARS) or (after != "" and after in QUOTE_CHARS)


def candidate_trailer_lines(full_message):
    """The final paragraph of the full commit message, split into
    non-blank lines. Used only as a cheap pre-filter -- authority on
    whether it is actually a trailer block belongs to
    git_interpret_trailers below."""
    paragraphs = re.split(r"\n\s*\n", full_message.strip())
    if not paragraphs:
        return []
    return [line for line in paragraphs[-1].splitlines() if line.strip()]


def git_interpret_trailers(repo_abs, full_message):
    """Delegate trailer-BLOCK recognition -- paragraph eligibility, folded
    continuation lines, and the "whole block must look like trailers, not
    one matching line in a prose paragraph" rule -- to git's own parser,
    the actual authority on these rules rather than a reimplementation of
    them. Takes the FULL raw message (subject included), not the body
    alone: git's parser needs the natural subject-then-blank-line shape
    to decide eligibility, and a trailer paragraph with no other body
    prose in front of it (subject, blank line, trailer -- nothing else)
    is only recognized when that leading context is present. Returns a
    list of (key, value) pairs; never raises, degrades to an empty list
    on any subprocess problem since the caller only reaches here when the
    cheap pre-filter already found a candidate line."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo_abs, "interpret-trailers", "--parse"],
            input=full_message.encode("utf-8", errors="replace"),
            capture_output=True,
            timeout=INTERPRET_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    out = proc.stdout.decode("utf-8", errors="replace")
    trailers = []
    for line in out.splitlines():
        m = TRAILER_LINE_RE.match(line)
        if not m:
            continue
        trailers.append((m.group(1), m.group(2)))
    return trailers


def find_trailer_marks(repo_abs, full_message):
    marks = []
    if not any(TRAILER_LINE_RE.match(line) for line in candidate_trailer_lines(full_message)):
        return marks
    for key, value in git_interpret_trailers(repo_abs, full_message):
        if key.lower() not in TRAILER_KEYS:
            continue
        tool_match = AI_TOOL_RE.search(value)
        if not tool_match:
            continue
        marks.append((key.lower(), tool_match.group(1).lower(), key + ": " + value))
    return marks


def find_body_marks(body):
    marks = []
    for line in body.splitlines():
        m = GENERATED_MARK_RE.search(line)
        if m and not _is_quoted_span(line, m.start(), m.end()):
            marks.append(("generated-with", m.group(1).lower(), line))
            continue
        if ROBOT_EMOJI in line:
            tool_match = AI_TOOL_RE.search(line)
            if tool_match:
                marks.append(("robot-emoji", tool_match.group(1).lower(), line))
    return marks


def main():
    repo_abs = arg(1, "")
    depth_raw = arg(2, "50")
    if not repo_abs:
        # validate_repo emits an empty repo_abs for the "no repository given"
        # case, which is a normal first run, not a wiring bug. scan_config
        # already degrades here; this step used to fail closed and take the
        # whole run red with it.
        print(json.dumps({
            "ok": True,
            "no_repo": True,
            "scanned": 0,
            "findings": [],
            "warning": "no repository given; nothing scanned",
        }))
        return
    try:
        depth = int(depth_raw)
    except ValueError:
        fail("depth must be an integer, got: " + depth_raw)

    records = run_git_log_records(repo_abs, depth)

    findings = []
    decode_degraded = 0
    for sha_bytes, body_bytes, full_message_bytes in records:
        sha, sha_degraded = decode_field(sha_bytes)
        body_raw, body_degraded = decode_field(body_bytes)
        full_message_raw, message_degraded = decode_field(full_message_bytes)
        if sha_degraded or body_degraded or message_degraded:
            decode_degraded += 1
        sha7 = sha.strip()[:7]
        body = normalize_for_matching(body_raw)
        full_message = normalize_for_matching(full_message_raw)

        for key, tool, line in find_trailer_marks(repo_abs, full_message):
            findings.append(
                {
                    "sha7": sha7,
                    "class": "trailer",
                    "pattern": key + ":" + tool,
                    "line_redacted": redact_line(line),
                }
            )
        for kind, tool, line in find_body_marks(body):
            findings.append(
                {
                    "sha7": sha7,
                    "class": "body-mark",
                    "pattern": kind + ":" + tool,
                    "line_redacted": redact_line(line),
                }
            )

    result = {"ok": True, "scanned": len(records), "findings": findings}
    if decode_degraded:
        result["warning"] = (
            str(decode_degraded)
            + " commit(s) had non-UTF-8 content; decoded with replacement characters"
        )
    print(json.dumps(result))


main()
