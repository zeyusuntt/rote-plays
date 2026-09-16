"""Digest Claude Code session transcripts into counts only.

Read-only: opens each transcript for a single streamed read, line by line
-- a transcript can run to tens of megabytes, so this never loads a whole
file into memory. Nothing here quotes message text, prompt content, or
command argv back out; see the module-level PRIVACY note in main.ts for
the full trust line.

Each JSONL record is parsed defensively. Claude Code's own transcript
schema carries well over a dozen top-level "type" values across versions
(user, assistant, queue-operation, attachment, file-history-delta,
file-history-snapshot, ai-title, last-prompt, mode, system, cost-state,
permission-mode, atis-latch, bridge-session, summary, ...); only "user"
and "assistant" carry the signals this digest counts (tool calls, token
usage, tool-result errors). Every other well-formed type is simply
uninformative for this job, not a parse failure, and is not treated as
one. A record that fails to parse as JSON, or parses to something that
isn't a JSON object, is skipped and tallied -- if any occur in a file,
that file's session row carries a "warning" saying how many lines were
skipped (see module docstring "Per-file degrade" below), but the file is
never abandoned over it.

argv[1]  packed session file paths from locate_sessions (chr(31)/chr(30) --
         see locate.py); empty string is a valid "nothing in window" input,
         not a fault.

Per-session fields:
    dir              project directory basename, taken from the first
                     "cwd" field seen in the file; falls back to the
                     basename of the transcript's own parent directory
                     (Claude Code's project-slug folder) if no record in
                     the file carries "cwd"
    start / end      earliest/latest ISO-8601 "timestamp" string seen
                     (compared lexicographically -- valid for this
                     fixed-width, zero-padded, always-UTC-"Z" format,
                     and sidesteps needing a full ISO-8601 parser for
                     ordering); null if no record carried one
    duration_min     end - start in minutes, rounded to 1 decimal; null
                     if either endpoint didn't parse as a timestamp
    tool_calls       {tool name: count}, from assistant message content
                     blocks of type "tool_use"
    files_touched    {"count": n, "paths": [<=10 home-redacted paths]},
                     from Edit/Write tool_use blocks' input.file_path
    commands_run     count of Bash tool_use blocks (COUNT only -- the
                     command text itself is never read out of .input)
    errors           count of tool_result content blocks with
                     is_error == true
    tokens           {"in": n, "out": n}; "in" sums input_tokens,
                     cache_creation_input_tokens, and
                     cache_read_input_tokens across assistant messages
                     (the total tokens the model was billed to read);
                     "out" sums output_tokens
    model            the most-used assistant message model id in the
                     session (ties broken by first-seen); null if none

Per-file degrade: any exception while opening/streaming a file (permission
error, decode disaster, etc.) degrades just that file to a session row
with every count at its zero/empty default and a "warning" explaining why,
rather than aborting the whole digest.

Emits one JSON object on stdout, always exit 0:
    {"ok": true,
     "sessions": [...],
     "totals": {"sessions": n, "tool_calls": {name: count},
                 "files_touched": n, "commands_run": n, "errors": n,
                 "tokens": {"in": n, "out": n}},
     "warning": "<optional -- N session file(s) degraded>"}
"""

import json
import os
import sys
from datetime import datetime, timezone


def clean_display(text, cap=60):
    """Sanitize a transcript-derived string before it can reach any report.

    Transcript content is untrusted input: a corrupt or hostile transcript
    could carry ANSI escapes (terminal injection into the human report) or
    multi-KB strings (table blowup). Keep printable characters only, cap
    length with a declared ellipsis. Codex blocker #3.
    """
    if not isinstance(text, str):
        return ""
    cleaned = "".join(ch for ch in text if ch.isprintable()).strip()
    return cleaned[: cap - 1] + "\u2026" if len(cleaned) > cap else cleaned

HOME = os.path.expanduser("~")
RS = chr(30)

TOOL_USE_FILE_NAMES = ("Edit", "Write")
MAX_FILES_SHOWN = 10


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def safe_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def home_redact(path):
    """Redact a path for output. An absolute path outside $HOME can still
    embed the same identifying directory names $HOME redaction exists to
    hide -- e.g. an agent tool's own scratch sandbox (a typical macOS
    /private/tmp/claude-<uid>/<slugged-home>/<session>/... convention slugs
    the user's home path right back into the sandbox root) -- so any
    absolute path that isn't under $HOME is collapsed to a generic marker
    plus its basename rather than ever leaving the full path intact."""
    if not isinstance(path, str):
        return path
    if path.startswith(HOME):
        return "~" + path[len(HOME):]
    if path.startswith("/"):
        return "<outside-home>/" + os.path.basename(path)
    return path


def parse_iso(ts):
    """Best-effort ISO-8601 -> epoch seconds; returns None rather than
    raising on any format this play doesn't recognize."""
    if not isinstance(ts, str) or not ts:
        return None
    text = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def empty_session(path, warning):
    return {
        "dir": os.path.basename(os.path.dirname(path)) or path,
        "start": None,
        "end": None,
        "duration_min": None,
        "tool_calls": {},
        "files_touched": {"count": 0, "paths": []},
        "commands_run": 0,
        "errors": 0,
        "tokens": {"in": 0, "out": 0},
        "model": None,
        "warning": warning,
    }


def digest_one(path):
    project_dir = None
    start_ts = None
    end_ts = None
    tool_calls = {}
    files_touched = set()
    commands_run = 0
    errors = 0
    tokens_in = 0
    tokens_out = 0
    model_counts = {}
    skipped_lines = 0

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped)
            except ValueError:
                skipped_lines += 1
                continue
            if not isinstance(rec, dict):
                skipped_lines += 1
                continue

            if project_dir is None:
                cwd_val = rec.get("cwd")
                if isinstance(cwd_val, str) and cwd_val:
                    project_dir = os.path.basename(cwd_val.rstrip("/")) or cwd_val

            ts = rec.get("timestamp")
            if isinstance(ts, str) and ts:
                if start_ts is None or ts < start_ts:
                    start_ts = ts
                if end_ts is None or ts > end_ts:
                    end_ts = ts

            rec_type = rec.get("type")
            message = rec.get("message")
            if not isinstance(message, dict):
                continue

            if rec_type == "assistant":
                model = message.get("model")
                if isinstance(model, str) and model:
                    model = clean_display(model)
                    if model:
                        model_counts[model] = model_counts.get(model, 0) + 1

                usage = message.get("usage")
                if isinstance(usage, dict):
                    tokens_in += (
                        safe_int(usage.get("input_tokens"))
                        + safe_int(usage.get("cache_creation_input_tokens"))
                        + safe_int(usage.get("cache_read_input_tokens"))
                    )
                    tokens_out += safe_int(usage.get("output_tokens"))

                content = message.get("content")
                if isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict) or block.get("type") != "tool_use":
                            continue
                        name = block.get("name")
                        if not isinstance(name, str) or not name:
                            name = "unknown"
                        name = clean_display(name)
                        if name:
                            tool_calls[name] = tool_calls.get(name, 0) + 1
                        if name == "Bash":
                            commands_run += 1
                        if name in TOOL_USE_FILE_NAMES:
                            block_input = block.get("input")
                            if isinstance(block_input, dict):
                                file_path = block_input.get("file_path")
                                if isinstance(file_path, str) and file_path:
                                    files_touched.add(file_path)

            elif rec_type == "user":
                content = message.get("content")
                if isinstance(content, list):
                    for block in content:
                        if (
                            isinstance(block, dict)
                            and block.get("type") == "tool_result"
                            and block.get("is_error") is True
                        ):
                            errors += 1

    if project_dir is None:
        project_dir = os.path.basename(os.path.dirname(path)) or path

    duration_min = None
    start_epoch, end_epoch = parse_iso(start_ts), parse_iso(end_ts)
    if start_epoch is not None and end_epoch is not None:
        duration_min = round((end_epoch - start_epoch) / 60.0, 1)

    model = None
    if model_counts:
        model = max(model_counts.items(), key=lambda pair: pair[1])[0]

    shown_paths = [home_redact(p) for p in sorted(files_touched)[:MAX_FILES_SHOWN]]

    session = {
        "dir": project_dir,
        "start": start_ts,
        "end": end_ts,
        "duration_min": duration_min,
        "tool_calls": tool_calls,
        "files_touched": {"count": len(files_touched), "paths": shown_paths},
        "commands_run": commands_run,
        "errors": errors,
        "tokens": {"in": tokens_in, "out": tokens_out},
        "model": model,
    }
    if skipped_lines > 0:
        session["warning"] = str(skipped_lines) + " line(s) could not be parsed as JSON and were skipped"
    return session


def aggregate(sessions):
    tool_calls = {}
    files_touched = 0
    commands_run = 0
    errors = 0
    tokens_in = 0
    tokens_out = 0
    for session in sessions:
        for name, count in session.get("tool_calls", {}).items():
            tool_calls[name] = tool_calls.get(name, 0) + count
        files_touched += session.get("files_touched", {}).get("count", 0)
        commands_run += session.get("commands_run", 0)
        errors += session.get("errors", 0)
        tokens_in += session.get("tokens", {}).get("in", 0)
        tokens_out += session.get("tokens", {}).get("out", 0)
    return {
        "sessions": len(sessions),
        "tool_calls": tool_calls,
        "files_touched": files_touched,
        "commands_run": commands_run,
        "errors": errors,
        "tokens": {"in": tokens_in, "out": tokens_out},
    }


def main():
    packed = arg(1, "")
    paths = [p for p in packed.split(RS) if p] if packed else []

    sessions = []
    degraded_files = 0
    for path in paths:
        try:
            sessions.append(digest_one(path))
        except OSError as exc:
            degraded_files += 1
            # exc.strerror is the plain OS reason ("No such file or
            # directory"); str(exc)/exc.filename would embed the raw,
            # un-redacted absolute path in output -- never use those here.
            reason = getattr(exc, "strerror", None) or type(exc).__name__
            sessions.append(empty_session(path, "could not open/read " + home_redact(path) + ": " + reason))
        except Exception as exc:  # noqa: BLE001 -- a parse disaster degrades this file, never the run
            degraded_files += 1
            # Same rationale: only the exception's type name is reported,
            # never str(exc), which could echo file content in some future
            # code path this defensive branch wasn't written to expect.
            sessions.append(empty_session(path, "unexpected parse error (" + type(exc).__name__ + ") in " + home_redact(path)))

    output = {"ok": True, "sessions": sessions, "totals": aggregate(sessions)}
    if degraded_files > 0:
        output["warning"] = str(degraded_files) + " session file(s) could not be fully parsed and were degraded"

    print(json.dumps(output))


main()
