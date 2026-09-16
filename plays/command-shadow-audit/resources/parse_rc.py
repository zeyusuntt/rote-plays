"""Statically parse a fixed list of shell rc files for alias, function, and
PATH-export definitions -- WITHOUT ever executing them.

HARD SAFETY LINE: this script never calls subprocess, never uses os.system,
never uses eval/exec, and never spawns a shell of any kind. It only ever
calls Python's own open()/read() on plain text files and applies regular
expressions to the lines. Every alias/function/export-PATH it reports comes
from reading the rc files' own text, not from running them. This is the
whole trust story of the play this script is a step of; do not add any
subprocess call here, ever -- version probing (the only place this play
ever executes anything) lives entirely in resolve.py, gated to a fixed
allowlist of binaries.

ROOT FILES (a fixed list, always all seven, tilde-expanded against this
process's own $HOME -- never read from a running shell):
    ~/.zshrc ~/.zprofile ~/.zshenv ~/.bashrc ~/.bash_profile ~/.profile
    ~/.bash_aliases
A missing root file is normal (most machines do not have all seven) and is
not an error; an unreadable one (permission denied, decode error) degrades
only that one file. Root files are parsed in the fixed order above -- see
FILE_SEQ / "last one wins" below.

ONE-LEVEL SOURCE FOLLOW: within each root file only (never within a
sourced file's own body -- exactly one hop), a line containing a `source X`
or `. X` / `\\. X` directive is detected by regex, no matter where on the
line it sits (`[ -f ~/.rote/shell/init.sh ] && source ~/.rote/shell/init.sh`
is a real-world rc line this pattern needs to handle). X is only ever
FOLLOWED when it is LITERAL after tilde-expansion: an absolute path (starts
with "/" once ~ is expanded) containing no "$", backtick, "(" or ")" --
i.e. no shell variable or command substitution this script would have to
evaluate to resolve. `$NVM_DIR/nvm.sh`-style targets are a common shape in
real rc files and are deliberately NOT followed for exactly this reason; they
are counted and reported as skipped, not silently dropped. This script does
not evaluate the `[ -f X ] &&` / `[ -s X ] &&` guards a source line may sit
behind -- it reports "this rc file contains a source directive for this
literal path", not "this line definitely ran on your last shell start".
That gap is disclosed by the play's own CHECKED/UNVERIFIED footer. Whether
the directive line itself sits inside an unresolved if/case branch is
tracked and disclosed the same way a definition's own conditional context
is (see CONDITIONAL CANDIDATES below) -- the directive is still followed
either way, since evaluating the guard is out of scope regardless.

LEXICAL SCAN, not a shell parser -- three deliberate, disclosed layers on
top of plain per-line regex matching, added because a shell script's real
structure can otherwise fool a line-blind scanner:
  comments   -- a '#' is only ever treated as a comment start when it is
                unquoted (not inside '...'/"..." -- best-effort quote
                tracking, escapes inside "..." are skipped over, not
                expanded) AND at a word boundary (line start or preceded by
                whitespace), matching real shell comment rules. This is
                what keeps `alias good=ok # y=bad` from ever yielding a
                phantom `y=bad` alias, and keeps a `source X` mentioned only
                in a trailing comment from ever being followed as a real
                directive.
  heredocs   -- an unquoted `<<[-]DELIM` (DELIM optionally single- or
                double-quoted) opens a heredoc; every line from there up to
                and including the line that is exactly DELIM (leading tabs
                stripped first when the operator was `<<-`) is heredoc BODY
                -- data, never shell syntax -- and is never scanned for a
                definition or a source directive. Heredoc detection itself
                is quote-aware (an unquoted `<<` only), so a literal `<<`
                inside an alias's own quoted value is never mistaken for a
                real heredoc redirect.
  CONDITIONAL CANDIDATES -- a best-effort if/case nesting depth (tracked
                per physical line by leading keyword: `if`/`case` opens,
                `fi`/`esac` closes; a conditional opened and closed on one
                physical line is not detected as conditional -- this is a
                per-line tracker, not a per-token one). A definition found
                while that depth is > 0 is still recorded -- this script
                cannot evaluate the branch condition any more than it can
                evaluate a `[ -f X ] &&` source guard -- but is marked
                conditional=true, an honest "candidate, not confirmed live"
                label carried all the way to resolve.py's output and this
                play's own presentation, rather than either silently
                dropping it (a false negative) or silently reporting it as
                certain (a false positive).
This is still a best-effort lexical match, not a full shell parser -- it
does not handle every quoting/escaping edge case a real shell would.

DEFINITIONS CAPTURED per non-comment, non-blank line:
  alias    -- `alias name=value` (POSIX shells also allow more than one
              name=value pair per `alias` line); value may be single- or
              double-quoted or bare.
  function -- `function name { ... }`, `function name() { ... }`,
              `name() { ... }`, INCLUDING a one-line body on the same
              physical line (`curl() { command curl "$@"; }`) -- the
              function's BODY is never parsed or captured beyond that,
              only its name and the file:line it starts at; parsing
              arbitrary multi-line shell bodies safely is out of scope, the
              winner/shadow story this play tells only needs the name and
              where it was defined.
  export_path -- a line assigning the PATH variable itself, with or
              without a leading `export` keyword (`PATH="...":${PATH}"`
              followed by a separate bare `export PATH` line is a real
              pattern in practice -- so the `export`
              keyword is optional in the match). Only PATH is matched,
              never any other environment variable, and never a variable
              VALUE beyond the PATH assignment's own right-hand side --
              this script never reports any other exported variable, which
              is deliberate: a real .zshrc can carry real API
              key exports, and this parser's regex is scoped narrowly
              enough that it structurally cannot capture them.

FILE_SEQ / "last one wins": each definition record carries a `file_seq`
integer from ONE counter shared across the entire run, incremented once per
definition found, IN TRUE DOCUMENT ORDER -- a root file's own lines and its
one-level-sourced children are interleaved at the exact lexical position of
the `source`/`.` directive that names each child, not appended in bulk
after the whole root file. This is what lets a root definition occurring
AFTER its own source line correctly outrank whatever the sourced child
defines, and lets a child definition correctly outrank only what came
BEFORE the source line in its root -- exactly what a real top-to-bottom
sourcing of these files would produce. Root files themselves are still
walked in the fixed order above. resolve.py uses (file_seq, line) to decide
which same-named alias/function definition is the one that would actually
be live if all these files were sourced top to bottom in this order --
which is a real, disclosed simplification: a live shell only ever sources
ONE real combination of these files depending on login/interactive nature,
never literally all seven every session. That is exactly the kind of gap
the play's CHECKED/UNVERIFIED footer states plainly rather than implying a
precision this script cannot actually deliver.

Emits one JSON object on stdout, always exit 0 (no essential capability is
being requested here -- an rc file simply not existing is a normal,
expected outcome, not a degrade-worthy fault):
    {"ok": true,
     "warning": "<optional -- N file(s) unreadable, listed>",
     "count": <definitions found>,
     "files_total": 7,
     "files_parsed": <root files successfully opened>,
     "files_missing": <root files not found>,
     "files_unreadable": <root files that exist but could not be read>,
     "sourced_files_found": <literal one-level source targets detected>,
     "sourced_files_parsed": <of those, successfully opened>,
     "sourced_files_skipped_nonliteral": <source targets skipped because
         they were not a literal absolute path after tilde-expansion>,
     "packed": "<records>"}
Each record packs kind|name|value|file|line|file_seq|conditional,
FS-joined (chr(31)); records are RS-joined (chr(30)). conditional is "1"
when the definition was found inside an unresolved if/case branch (see
CONDITIONAL CANDIDATES above), else "0". value is stripped of any embedded
FS/RS bytes and truncated, the same packing hygiene every modiqo play
resource script applies before a scalar collection crosses a value edge.
"""

import json
import os
import re
import sys

FS, RS = chr(31), chr(30)
VALUE_MAX = 300

ROOT_FILES = [
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.bash_aliases",
]

# Matches `alias name=value [name2=value2 ...]` -- value may be double-quoted
# (with backslash escapes), single-quoted (no escapes, standard shell), or a
# bare unquoted token. Best-effort lexical match, not a full shell parser.
_ALIAS_LINE_RE = re.compile(r"^\s*alias\s+(.*)$")
_ALIAS_PAIR_RE = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)"""
)

# Two function-definition shapes: `function name`, or a bare name followed
# by `()`. The optional trailing `(\{.*)?` allows -- but never parses -- a
# one-line body after the opening brace (`curl() { command curl "$@"; }`);
# it is equally happy leaving the brace for a following line (the common
# multi-line style). The name-only branch is guarded below to reject a
# plain identifier or a `case` label like `darwin) ...` that happens to
# have no literal "(" and no brace on this line at all.
_FUNC_RE = re.compile(
    r"^\s*(?:function\s+([A-Za-z_][A-Za-z0-9_.:-]*)|([A-Za-z_][A-Za-z0-9_.:-]*))"
    r"\s*(?:\(\s*\))?\s*(\{.*)?$"
)

# PATH assignment, `export` keyword optional (a real pattern on this
# machine's .zprofile: `PATH="...:${PATH}"` on one line, bare `export PATH`
# on the next). Anchored to true line start so e.g. `MYPATH=...` never
# matches. Only PATH -- no other variable is ever captured.
_EXPORT_PATH_RE = re.compile(r"^\s*(?:export\s+)?PATH=(.*)$")

# A `source X` or (possibly backslash-escaped) lone `. X` directive,
# anywhere on the line, preceded by line-start or a shell separator/space,
# so it is found even sitting behind `[ -f X ] && source X`. The lone-dot
# form requires the dot be its own whitespace-bounded token, which is what
# keeps this from ever matching a "." inside an ordinary word.
_SOURCE_RE = re.compile(
    r"""(?:^|[;&|]|\s)(?:source|\\?\.)\s+("[^"]*"|'[^']*'|\S+)"""
)

# Quote-aware heredoc-delimiter probe, applied only to text already known to
# start right after an unquoted `<<[-]` (see lex_line()) -- an optionally
# quoted word token, the same pairing lex_line() itself checks.
_HEREDOC_DELIM_RE = re.compile(r"""(['"]?)(\w+)\1""")

_COND_OPEN = ("if", "case")
_COND_CLOSE = ("fi", "esac")


def strip_quotes(text):
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def sanitize_value(text):
    """Strip the packing separators themselves (defensive -- see every other
    resource script's sanitize_for_packing()), collapse embedded newlines,
    truncate."""
    text = text.replace(FS, "?").replace(RS, "?").replace("\n", " ").replace("\r", " ")
    return text[:VALUE_MAX]


def is_comment_or_blank(stripped):
    return not stripped or stripped.startswith("#")


def lex_line(line):
    """One quote-aware pass over an already whitespace-stripped shell line.
    Returns (comment_stripped_text, heredoc_delim_or_None,
    heredoc_strip_tabs) -- a '#' or a `<<[-]DELIM` heredoc operator is only
    ever recognized OUTSIDE single/double quotes, so a literal '#' or '<<'
    inside a quoted alias value is never mistaken for either. Best-effort:
    escapes inside "..." are skipped over, not expanded -- this script never
    needs the expanded value, only to not lose quote-state tracking."""
    in_single = in_double = False
    out = []
    heredoc_delim = None
    heredoc_strip_tabs = False
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if in_single:
            out.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            break  # unquoted, word-boundary comment -- rest of line is dropped
        if heredoc_delim is None and ch == "<" and i + 1 < n and line[i + 1] == "<":
            j = i + 2
            strip_tabs = False
            if j < n and line[j] == "-":
                strip_tabs = True
                j += 1
            while j < n and line[j] == " ":
                j += 1
            m = _HEREDOC_DELIM_RE.match(line[j:])
            if m:
                heredoc_delim = m.group(2)
                heredoc_strip_tabs = strip_tabs
        out.append(ch)
        i += 1
    return "".join(out).rstrip(), heredoc_delim, heredoc_strip_tabs


def lex_shell_lines(text):
    """Non-executing, line-oriented shell lexer shared by every scan in this
    script: strips unquoted trailing comments, skips heredoc BODY lines
    entirely (a heredoc body is data, never shell syntax -- neither a
    definition nor a source directive inside one is ever real), and tracks
    the best-effort if/case nesting depth described in the module docstring
    under CONDITIONAL CANDIDATES.

    Yields (line_no, comment_stripped_text, in_conditional) for every
    non-blank, non-comment-only, non-heredoc-body line."""
    in_heredoc = False
    heredoc_delim = None
    heredoc_strip_tabs = False
    cond_depth = 0

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if in_heredoc:
            probe = raw_line.lstrip("\t") if heredoc_strip_tabs else raw_line
            if probe == heredoc_delim:
                in_heredoc = False
                heredoc_delim = None
            continue  # heredoc body (and its own terminator line) is data, never scanned

        stripped = raw_line.strip()
        if is_comment_or_blank(stripped):
            continue

        no_comment, new_delim, strip_tabs = lex_line(stripped)
        no_comment = no_comment.strip()
        if not no_comment:
            continue

        first_token = no_comment.split(None, 1)[0].rstrip(";")
        if first_token in _COND_CLOSE and cond_depth > 0:
            cond_depth -= 1
        in_conditional = cond_depth > 0
        if first_token in _COND_OPEN:
            cond_depth += 1

        if new_delim is not None:
            in_heredoc = True
            heredoc_delim = new_delim
            heredoc_strip_tabs = strip_tabs

        yield line_no, no_comment, in_conditional


def match_definitions(no_comment):
    """Returns a list of (kind, name, value) definitions found on one
    already-lexed (comment-stripped) line, or [] if it defines nothing.
    A single `alias` line may yield more than one pair."""
    alias_match = _ALIAS_LINE_RE.match(no_comment)
    if alias_match:
        pairs = _ALIAS_PAIR_RE.findall(alias_match.group(1))
        if pairs:
            return [("alias", name, strip_quotes(value)) for name, value in pairs]

    export_match = _EXPORT_PATH_RE.match(no_comment)
    if export_match:
        return [("export_path", "PATH", strip_quotes(export_match.group(1).strip()))]

    func_match = _FUNC_RE.match(no_comment)
    if func_match:
        name = func_match.group(1) or func_match.group(2)
        # Reject the degenerate case where FUNC_RE's bare-name branch
        # matched a line with no parens and no brace at all on this line
        # (e.g. a plain "true" or a lone identifier, or a `case` label) --
        # a real function definition needs either the `function` keyword,
        # `()`, or a brace already visible on this same line.
        if func_match.group(2) and "(" not in no_comment and func_match.group(3) is None:
            return []
        return [("function", name, "")]

    return []


def read_file(path):
    """Returns (text_or_None, status) where status is "ok", "missing", or
    "unreadable: <reason>". Each file's failure is independent -- never
    raised, always returned."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(), "ok"
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, "unreadable: " + str(exc)


def parse_file(text, file_label, depth, all_defs, visited, stats, seq_counter):
    """Single interleaved pass over one file's lines, in true document
    order: every definition is appended to all_defs with a seq number from
    the ONE counter shared across the whole run, and -- only at depth 0 (a
    root file; a sourced child is depth 1, and never has its own source
    directives followed -- exactly one hop) -- a literal source directive
    is followed the MOMENT its line is reached, splicing the child file's
    own defs in right there before this file's remaining lines continue.
    See FILE_SEQ / "last one wins" in the module docstring for why this
    interleaving (rather than parsing all of a root's own defs first, then
    all of its children's) is what makes a root definition occurring AFTER
    its own source line correctly outrank the sourced child."""
    for line_no, no_comment, in_conditional in lex_shell_lines(text):
        for kind, name, value in match_definitions(no_comment):
            seq_counter[0] += 1
            all_defs.append(
                (kind, name, sanitize_value(value), file_label, line_no, seq_counter[0], in_conditional)
            )

        if depth != 0:
            continue  # one-level-only: a sourced child's own source lines are never followed

        match = _SOURCE_RE.search(no_comment)
        if not match:
            continue
        target = strip_quotes(match.group(1))
        expanded = os.path.expanduser(target)
        if not (expanded.startswith("/") and not any(c in expanded for c in "$`()")):
            stats["sourced_skipped_nonliteral"] += 1
            continue
        stats["sourced_found"] += 1
        real_t = os.path.realpath(expanded)
        if real_t in visited:
            continue  # cycle-safe: already parsed (a root, or already sourced once)
        visited.add(real_t)

        child_text, child_status = read_file(expanded)
        if child_status == "missing":
            continue  # a source line pointing at a file that isn't there; not an error
        if child_status != "ok":
            stats["unreadable_notes"].append(expanded + ": " + child_status)
            continue
        stats["sourced_parsed"] += 1
        parse_file(child_text, expanded, depth + 1, all_defs, visited, stats, seq_counter)


def main():
    all_defs = []  # (kind, name, value, file, line, seq, conditional)
    visited = set()
    seq_counter = [0]
    stats = {
        "sourced_found": 0,
        "sourced_parsed": 0,
        "sourced_skipped_nonliteral": 0,
        "unreadable_notes": [],
    }

    files_parsed = files_missing = files_unreadable = 0

    for root_rel in ROOT_FILES:
        root_abs = os.path.expanduser(root_rel)
        real = os.path.realpath(root_abs)
        if real in visited:
            continue
        visited.add(real)

        text, status = read_file(root_abs)
        if status == "missing":
            files_missing += 1
            continue
        if status != "ok":
            files_unreadable += 1
            stats["unreadable_notes"].append(root_rel + ": " + status)
            continue
        files_parsed += 1

        parse_file(text, root_abs, 0, all_defs, visited, stats, seq_counter)

    packed = RS.join(
        FS.join([kind, name, value, file, str(line), str(seq), "1" if conditional else "0"])
        for kind, name, value, file, line, seq, conditional in all_defs
    )

    output = {
        "ok": True,
        "count": len(all_defs),
        "files_total": len(ROOT_FILES),
        "files_parsed": files_parsed,
        "files_missing": files_missing,
        "files_unreadable": files_unreadable,
        "sourced_files_found": stats["sourced_found"],
        "sourced_files_parsed": stats["sourced_parsed"],
        "sourced_files_skipped_nonliteral": stats["sourced_skipped_nonliteral"],
        "packed": packed,
    }
    if stats["unreadable_notes"]:
        output["warning"] = (
            str(len(stats["unreadable_notes"])) + " file(s) unreadable: " + "; ".join(stats["unreadable_notes"])[:VALUE_MAX]
        )

    print(json.dumps(output))


main()
