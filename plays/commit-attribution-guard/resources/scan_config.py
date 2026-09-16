"""Read-only checks of attribution SOURCES that could re-inject AI marks
into a future commit: a configured commit.template file, and
prepare-commit-msg/commit-msg hooks. scan_log.py already covers what has
already been written into history; this step checks what could write it
again.

This script's one narrow, explicitly-scoped exception to "reads commit
messages only, never code": it reads a commit.template file's and a
hook script's bytes to test them for a structural attribution match --
never their behavior, never their execution. What it returns is never
that source text: a match is reported only as a "class:tool" pattern
identifier (the same identifier shape scan_log.py's findings use), the
same way a fingerprint is reported without the object it was taken from.
No hook or template source line ever reaches this script's stdout.

A bare tool-name mention is not a match: a hook comment like
`# remove Claude trailers`, or template prose explaining GPT usage, has
neither the Key: Value trailer shape nor the "Generated with/by <tool>"
direct-object shape, so it is not flagged -- the same structural-match
requirement scan_log.py's commit-history detectors apply, reused here
against source text instead of commit bodies.

Explicitly out of scope: user-level ~/.claude settings. This play stays
inside the repository it was asked to look at. A configured
commit.template or core.hooksPath that resolves outside the repository's
real (symlink-resolved) working directory is treated as out of scope and
is never opened -- only its configured path and an "outside repository"
warning are reported, honoring the "stays inside the repository" promise
for values git itself would happily read from anywhere on disk.

argv[1]  repo_abs  -- absolute path to the git repository (already
                       validated by validate_repo)

Every source degrades independently and this step never fails -- a
missing template, an unreadable hook, or git config itself being
unavailable are all reported as absent/degraded, never a nonzero exit.
There is nothing here as essential as validate_repo's job: this is
read-only inspection of optional, possibly-absent files.

Emits one JSON object on stdout, always exit 0:
    {"ok": true,
     "commit_template": {"configured": bool, "path": "..."|null,
                          "readable": bool|null, "flagged": bool,
                          "pattern": "..."|null,
                          "warning": "..." (only if degraded)},
     "hooks": [{"name": "prepare-commit-msg"|"commit-msg",
                 "path": "...", "exists": bool|null, "flagged": bool,
                 "pattern": "..."|null,
                 "warning": "..." (only if degraded)}, ...]}
"""

import json
import os
import re
import subprocess
import sys

GIT_TIMEOUT_S = 8
READ_MAX_BYTES = 65536
HOOK_NAMES = ("prepare-commit-msg", "commit-msg")

AI_TOOL_RE = re.compile(
    r"(?i)\b(claude|chatgpt|gpt|openai|copilot|codex|gemini|aider|cursor|devin|windsurf|opencode|anthropic)\b"
)
TRAILER_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z-]*)\s*:\s*(.+?)\s*$")
TRAILER_KEYS = ("co-authored-by", "signed-off-by")
GENERATED_MARK_RE = re.compile(
    r"(?i)\bgenerated\s+(?:with|by)\s+(?:the\s+)?\[?"
    r"(claude|chatgpt|gpt|openai|copilot|codex|gemini|aider|cursor|devin|windsurf|opencode|anthropic)\b"
)
ROBOT_EMOJI = "\U0001F916"

OUTSIDE_REPO_WARNING = "path is outside the repository; not read (out of scope)"


def arg(index, fallback=""):
    return sys.argv[index] if len(sys.argv) > index else fallback


def git_config_get(repo_abs, key):
    """Returns (value_or_None, warning_or_None). Never raises; an
    unavailable git or a config read failure degrades to (None, warning)
    rather than failing this step."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo_abs, "config", "--get", key],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "git config failed to run: " + str(exc)
    if proc.returncode == 0:
        value = proc.stdout.strip()
        return (value or None), None
    if proc.returncode == 1:
        # key not set -- the normal, expected "absent" case, not a warning
        return None, None
    return None, "git config exited " + str(proc.returncode) + ": " + (proc.stderr or "").strip()[:200]


def resolve_config_path(repo_abs, raw_path):
    """git expands ~ itself and, for a relative path, resolves it relative
    to the repository's top-level working directory. Mirrored here without
    another git call."""
    expanded = os.path.expanduser(raw_path)
    if os.path.isabs(expanded):
        return expanded
    return os.path.normpath(os.path.join(repo_abs, expanded))


def is_contained(repo_abs, candidate):
    """True when `candidate` resolves (symlinks included) to a path inside
    `repo_abs`'s own real path. An absolute or `~`-expanded config value
    that escapes the worktree fails this, honoring "stays inside the
    repository" for paths git itself would follow anywhere."""
    repo_real = os.path.realpath(repo_abs)
    cand_real = os.path.realpath(candidate)
    if cand_real == repo_real:
        return True
    return os.path.commonpath([repo_real, cand_real]) == repo_real


def find_structural_pattern(text):
    """Scan arbitrary source text (a commit.template file or a hook
    script) for a line that already has one of the exact structural
    shapes scan_log.py flags in real commit history: a Co-authored-by/
    Signed-off-by Key: Value line naming an AI tool, a "Generated with/by
    <tool>" direct-object phrase, or a robot emoji sharing a line with a
    tool name. A bare tool-name mention -- a comment like `# remove
    Claude trailers`, prose explaining GPT usage -- matches none of these
    shapes and returns None. Returns a "class:tool" identifier, never the
    matched line itself.

    Unlike scan_log.py's find_body_marks, this does NOT exclude a
    quote-wrapped match: scan_log.py's quote check exists to skip prose
    DISCUSSING a footer in a commit message, but here the text under scan
    is source code, where `echo "Generated with Claude Code" >> "$1"`
    wraps its payload in quotes as ordinary shell syntax -- that quoting
    is exactly the emission evidence this scan is looking for, not a
    reason to ignore it."""
    for line in text.splitlines():
        m = TRAILER_LINE_RE.match(line)
        if m and m.group(1).lower() in TRAILER_KEYS:
            tool_match = AI_TOOL_RE.search(m.group(2))
            if tool_match:
                return "trailer:" + tool_match.group(1).lower()
        gm = GENERATED_MARK_RE.search(line)
        if gm:
            return "generated-with:" + gm.group(1).lower()
        if ROBOT_EMOJI in line:
            tool_match = AI_TOOL_RE.search(line)
            if tool_match:
                return "robot-emoji:" + tool_match.group(1).lower()
    return None


def read_text_best_effort(path):
    """Returns (text_or_None, warning_or_None). Never raises."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(READ_MAX_BYTES)
    except OSError as exc:
        return None, "could not read " + path + ": " + str(exc)
    return raw.decode("utf-8", errors="replace"), None


def check_commit_template(repo_abs):
    raw_path, warning = git_config_get(repo_abs, "commit.template")
    if warning:
        return {
            "configured": False,
            "path": None,
            "readable": None,
            "flagged": False,
            "pattern": None,
            "warning": warning,
        }
    if not raw_path:
        return {
            "configured": False,
            "path": None,
            "readable": None,
            "flagged": False,
            "pattern": None,
        }

    resolved = resolve_config_path(repo_abs, raw_path)
    if not is_contained(repo_abs, resolved):
        return {
            "configured": True,
            "path": resolved,
            "readable": None,
            "flagged": False,
            "pattern": None,
            "warning": OUTSIDE_REPO_WARNING,
        }

    text, read_warning = read_text_best_effort(resolved)
    if read_warning:
        return {
            "configured": True,
            "path": resolved,
            "readable": False,
            "flagged": False,
            "pattern": None,
            "warning": read_warning,
        }

    pattern = find_structural_pattern(text)
    return {
        "configured": True,
        "path": resolved,
        "readable": True,
        "flagged": pattern is not None,
        "pattern": pattern,
    }


def check_hooks(repo_abs):
    hooks_dir_raw, warning = git_config_get(repo_abs, "core.hooksPath")
    if warning:
        hooks_dir = os.path.join(repo_abs, ".git", "hooks")
        base_warning = warning
    elif hooks_dir_raw:
        resolved_hooks_dir = resolve_config_path(repo_abs, hooks_dir_raw)
        if is_contained(repo_abs, resolved_hooks_dir):
            hooks_dir = resolved_hooks_dir
            base_warning = None
        else:
            hooks_dir = resolved_hooks_dir
            base_warning = OUTSIDE_REPO_WARNING
    else:
        hooks_dir = os.path.join(repo_abs, ".git", "hooks")
        base_warning = None

    results = []
    for name in HOOK_NAMES:
        path = os.path.join(hooks_dir, name)
        if base_warning == OUTSIDE_REPO_WARNING:
            # An out-of-scope hooks directory is never even stat-ed --
            # this script reports nothing about paths it was told to stay
            # out of, not even whether a file exists there.
            entry = {
                "name": name,
                "path": path,
                "exists": None,
                "flagged": False,
                "pattern": None,
                "warning": base_warning,
            }
            results.append(entry)
            continue

        exists = os.path.isfile(path)
        entry = {"name": name, "path": path, "exists": exists, "flagged": False, "pattern": None}
        if base_warning:
            entry["warning"] = base_warning
        elif exists:
            text, read_warning = read_text_best_effort(path)
            if read_warning:
                entry["warning"] = read_warning
            else:
                pattern = find_structural_pattern(text)
                entry["flagged"] = pattern is not None
                entry["pattern"] = pattern
        results.append(entry)
    return results


def main():
    repo_abs = arg(1, "")
    if not repo_abs:
        # Missing wiring from validate_repo, not an absent source -- but
        # this step's contract is "degrades per-source, never fails", so
        # even this reports as a degraded source rather than exiting
        # nonzero.
        print(
            json.dumps(
                {
                    "ok": True,
                    "commit_template": {
                        "configured": False,
                        "path": None,
                        "readable": None,
                        "flagged": False,
                        "pattern": None,
                        "warning": "repo_abs argument missing",
                    },
                    "hooks": [],
                }
            )
        )
        return

    print(
        json.dumps(
            {
                "ok": True,
                "commit_template": check_commit_template(repo_abs),
                "hooks": check_hooks(repo_abs),
            }
        )
    )


main()
