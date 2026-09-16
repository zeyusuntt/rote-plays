"""Digest Codex session transcripts into counts only.

Read-only, streamed line by line -- see digest_claude.py's module
docstring for the shared streaming/privacy rationale; this script mirrors
its shape and field names so the presentation body can render both
sources through one table.

Codex's on-disk transcript schema is its own thing, and has visibly
changed shape across the versions on this machine: every record is
{"timestamp", "type", "payload": {...}}, but "type" here is only ever
session_meta | turn_context | response_item | event_msg | compacted |
world_state, and the SIGNAL this digest wants -- an actual tool
invocation -- lives one level down, in payload.type, which itself varies
by version and by which Codex-family tool wrote the file (plain
"function_call"/"function_call_output" pairs in some transcripts,
"custom_tool_call"/"custom_tool_call_output" plus a "local_shell_call"
shape in others, "mcp_tool_call_end" for MCP-routed calls). This script
recognizes every payload.type it has seen and tallies only those; a
payload.type it doesn't recognize (reasoning, message, agent_message,
*_output pairs -- these are conversation/result content, not a distinct
tool invocation) is simply not tallied, not a parse failure. A record
that fails to parse as JSON, or parses to something that isn't a JSON
object, is skipped and tallied toward that file's "warning" (see
digest_claude.py's "Per-file degrade" note -- identical policy here).

Tool-call tallying, one source per family, no double counting:
  - response_item payload.type in (function_call, custom_tool_call) ->
    name = payload.name
  - response_item payload.type == local_shell_call -> name = "shell"
    (older/standard Codex CLI shape; not seen on this machine, handled
    defensively since the play spec calls out schema drift across
    versions)
  - response_item payload.type in (web_search_call, tool_search_call) ->
    name = "web_search" / "tool_search"
  - event_msg payload.type == mcp_tool_call_end -> name =
    "mcp:<payload.invocation.tool>" (there is no response_item
    counterpart for MCP calls in the transcripts on this machine, so this
    is the only source for them and cannot double count)
commands_run counts whichever of the above resolved to a shell-like name
(exec_command, exec, shell, run, bash, sh) -- a COUNT only, never the
command text itself, which for the custom_tool_call shape lives in a free
-form input string this play never reads.

files_touched comes from event_msg payload.type == patch_apply_end's
payload.changes dict keys -- the one place file paths appear as
structured data rather than embedded in free-form output text.

errors is a structural lower bound, deliberately: event_msg
payload.type == turn_aborted, plus patch_apply_end records with
payload.success == false. Tool output text elsewhere sometimes embeds an
"exit code" or similar, but that lives inside free-form output content
this play does not scan (see the trust line in main.ts) -- so a codex
session's errors count can under-report failures that never triggered one
of these two structural signals. This is documented, not hidden.

tokens takes the LAST token_count event_msg seen in the file
(payload.info.total_token_usage), because Codex reports that field as a
running total for the whole session already -- summing every event would
massively over-count. "in" adds input_tokens + cached_input_tokens; "out"
is output_tokens.

argv[1]  packed session file paths from locate_sessions (chr(31)/chr(30) --
         see locate.py). Empty string covers both real absences this play
         must not treat as a fault: no ~/.codex/sessions directory at all,
         and a directory that exists but had nothing in the look-back
         window -- either way there is nothing to digest, so this exits
         {"ok": true, "warning": "codex transcripts not found/unrecognized",
         "sessions": []} rather than guessing which case it was from an
         empty string alone.

Session fields are identical in shape to digest_claude.py's, with "dir"
taken from the session's own session_meta.payload.cwd (falling back to
the transcript's own filename stem when absent).

Emits one JSON object on stdout, always exit 0:
    {"ok": true,
     "sessions": [...],
     "totals": {"sessions": n, "tool_calls": {name: count},
                 "files_touched": n, "commands_run": n, "errors": n,
                 "tokens": {"in": n, "out": n}},
     "warning": "<optional -- N session file(s) degraded, or the
                  not-found/empty-input message above>"}
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

CALL_PAYLOAD_TYPES = ("function_call", "custom_tool_call")
SHELL_LIKE_NAMES = {"exec_command", "exec", "shell", "local_shell_call", "run", "bash", "sh"}
MAX_FILES_SHOWN = 10


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def safe_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def home_redact(path):
    """Redact a path for output. An absolute path outside $HOME can still
    embed the same identifying directory names $HOME redaction exists to
    hide -- e.g. an agent tool's own scratch sandbox (this machine's
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
    raising on any format this play doesn't recognize. Codex timestamps
    use the same fixed-width "...Z" shape as Claude Code's."""
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


def resolved_tool_name(payload):
    """Returns a tool-call name for a response_item/event_msg payload this
    script recognizes as an actual invocation, or None if this payload
    isn't one (conversation content, a *_output pair, or an unrecognized
    shape -- none of those are tallied, none are parse failures)."""
    ptype = payload.get("type")
    if ptype in CALL_PAYLOAD_TYPES:
        name = payload.get("name")
        return name if isinstance(name, str) and name else "unknown"
    if ptype == "local_shell_call":
        return "shell"
    if ptype == "web_search_call":
        return "web_search"
    if ptype == "tool_search_call":
        return "tool_search"
    return None


def empty_session(path, warning):
    return {
        "dir": os.path.splitext(os.path.basename(path))[0],
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

            ts = rec.get("timestamp")
            if isinstance(ts, str) and ts:
                if start_ts is None or ts < start_ts:
                    start_ts = ts
                if end_ts is None or ts > end_ts:
                    end_ts = ts

            rec_type = rec.get("type")
            payload = rec.get("payload")
            if not isinstance(payload, dict):
                continue

            if rec_type == "session_meta" and project_dir is None:
                cwd_val = payload.get("cwd")
                if isinstance(cwd_val, str) and cwd_val:
                    project_dir = os.path.basename(cwd_val.rstrip("/")) or cwd_val

            if rec_type == "turn_context":
                model = payload.get("model")
                if isinstance(model, str) and model:
                    model = clean_display(model)
                    if model:
                        model_counts[model] = model_counts.get(model, 0) + 1

            if rec_type == "response_item":
                name = resolved_tool_name(payload)
                if name is not None:
                    name = clean_display(name)
                    if name:
                        tool_calls[name] = tool_calls.get(name, 0) + 1
                    if name.lower() in SHELL_LIKE_NAMES:
                        commands_run += 1

            elif rec_type == "event_msg":
                ptype = payload.get("type")
                if ptype == "mcp_tool_call_end":
                    invocation = payload.get("invocation")
                    tool = invocation.get("tool") if isinstance(invocation, dict) else None
                    name = "mcp:" + tool if isinstance(tool, str) and tool else "mcp"
                    name = clean_display(name)
                    if name:
                        tool_calls[name] = tool_calls.get(name, 0) + 1
                elif ptype == "patch_apply_end":
                    changes = payload.get("changes")
                    if isinstance(changes, dict):
                        for file_path in changes.keys():
                            if isinstance(file_path, str) and file_path:
                                files_touched.add(file_path)
                    if payload.get("success") is False:
                        errors += 1
                elif ptype == "turn_aborted":
                    errors += 1
                elif ptype == "token_count":
                    info = payload.get("info")
                    total = info.get("total_token_usage") if isinstance(info, dict) else None
                    if isinstance(total, dict):
                        tokens_in = safe_int(total.get("input_tokens")) + safe_int(total.get("cached_input_tokens"))
                        tokens_out = safe_int(total.get("output_tokens"))

    if project_dir is None:
        project_dir = os.path.splitext(os.path.basename(path))[0]

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
    if not packed:
        print(json.dumps({"ok": True, "warning": "codex transcripts not found/unrecognized", "sessions": []}))
        return

    paths = [p for p in packed.split(RS) if p]

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
