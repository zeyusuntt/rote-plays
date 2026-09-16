#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: command-shadow-audit
 * description: 'When you type python3, what ACTUALLY runs -- and what did it silently replace? Statically parses your shell rc files (~/.zshrc, ~/.zprofile, ~/.bashrc, ~/.bash_profile, ~/.profile, and what they `source` one level deep) for alias, function, and PATH-export definitions, and walks this process''s own $PATH for a watchlist of common commands, recording each hit''s directory, symlink status, and version-manager convention (asdf, nvm, pyenv, rbenv, conda, brew, or plain system). You get, per command, the winner by the shell''s own precedence (function > alias > first PATH hit) and everything that decision silently shadows. Optionally reads --version from duplicates for a small fixed runtime allowlist, one 3-second-capped call each, only when probe_versions=1. Severity: a function shadowing a real binary is worst, a PATH duplicate with a different feature version is next, a same-version duplicate is informational. This play never executes your shell rc files and never opens an interactive shell -- every alias and function it reports comes from statically reading the rc files'' own text, never from running them. Read-only, no credentials, no network; the only things this play ever executes are those fixed, capped version probes (python3, python, node, git, curl, ruby, go, rustc, java); needs only python3.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/command-shadow-audit
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: command-shadow-audit
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   parse_rc: resources/presentation-fixtures/parse_rc/fixture.yaml
 *   walk_path: resources/presentation-fixtures/walk_path/fixture.yaml
 *   resolve: resources/presentation-fixtures/resolve/fixture.yaml
 * tags:
 * - domain-developer-workflow
 * - job-command-resolution
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-developer-workflow
 *   - job-command-resolution
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       ok:
 *         type: boolean
 *       commands:
 *         type: array
 *       path_exports:
 *         type: array
 *       totals:
 *         type: object
 *       parse_rc:
 *         type: object
 *       walk_path:
 *         type: object
 *       representations:
 *         type: object
 * parameters:
 * - name: commands
 *   param_type: string
 *   required: false
 *   default: ''
 *   description: Extra commands to audit, comma-separated, added to the built-in watchlist (letters, digits, dash, underscore, dot only -- anything else is ignored with a note)
 *   example: python3,node
 * - name: probe_versions
 *   param_type: integer
 *   required: false
 *   default: '0'
 *   description: 1 = read --version from the safe allowlist binaries (opt-in; each candidate is realpath/ownership/write-permission trust-checked before it is ever run -- see resolve.py PROBE SAFETY), 0 = pure path analysis, no execution at all (0-1)
 *   example: '1'
 * steps:
 *   parse_rc:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{parse_rc.py}'
 *   walk_path:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{walk_path.py}'
 *     - $commands
 *   resolve:
 *     type: process.exec
 *     timeout_ms: 25000
 *     depends_on:
 *     - parse_rc
 *     - walk_path
 *     argv:
 *     - python3
 *     - '@resource{resolve.py}'
 *     - '@parse_rc{$.stdout.text | fromjson | .packed}'
 *     - '@walk_path{$.stdout.text | fromjson | .watchlist_packed}'
 *     - '@walk_path{$.stdout.text | fromjson | .packed}'
 *     - $probe_versions
 * ---
 */

const presentationSdk = await import("__ROTE_PRESENTATION_SDK__").catch((cause) => {
  throw new Error(
    "This is a rote steps presentation program. Run it with `rote play run <name>`.",
    { cause },
  );
});
const { FlowOutput, loadPresentationContext, stepName } = presentationSdk;

const out = new FlowOutput();
const ctx = await loadPresentationContext();

type StdoutResult =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

function bodyOf(step: ReturnType<typeof ctx.step>): any {
  const o = step.outcome;
  if (o.status === "completed" || o.status === "restored") return o.output.body;
  return null;
}

// Truncation is read as a first-class, named outcome -- never inferred
// from a JSON.parse failure. `stdout.truncated === true` (strict) is the
// only signal trusted; a missing field is not truncation. A truncated
// capture is reported as truncated even on the off chance its partial
// text still happens to parse as valid JSON -- truncated wins over
// unparseable, since truncation is the cause and a parse failure is only
// ever its symptom.
function parsedStdout(step: ReturnType<typeof ctx.step>): StdoutResult {
  const body = bodyOf(step);
  const s = body?.stdout;
  if (!s) return { kind: "absent" };
  if (s.truncated === true) {
    return { kind: "truncated", bytes: typeof s.bytes === "number" ? s.bytes : null };
  }
  const text = s.text ?? "";
  try { return { kind: "ok", data: JSON.parse(text) }; } catch { return { kind: "unparseable" }; }
}

/** Human-readable reason a step's data is unavailable, truncation-aware --
 * a truncated capture is a fact about rote's capture cap, never described
 * merely as "unavailable" or "did not parse". */
function unavailableReason(step: ReturnType<typeof ctx.step>, result: StdoutResult): string {
  if (result.kind === "truncated") {
    const bytesNote = result.bytes != null ? `${result.bytes} byte(s) captured` : "rote's capture cap reached";
    return `output was truncated at rote's capture cap (${bytesNote}) -- this report covers only part of what the step produced`;
  }
  const status = step.outcome.status;
  if (status !== "completed" && status !== "restored") return `step ${status}`;
  return result.kind === "unparseable" ? "output did not parse as JSON" : `step ${status}`;
}

const parseRcStep = ctx.step(stepName("parse_rc"));
const walkPathStep = ctx.step(stepName("walk_path"));
const resolveStep = ctx.step(stepName("resolve"));

const parseRcResult = parsedStdout(parseRcStep);
const walkPathResult = parsedStdout(walkPathStep);
const resolveResult = parsedStdout(resolveStep);

// resolve depends_on BOTH parse_rc and walk_path, consuming each one's own
// $.stdout.text directly via the DAG's own templating -- a truncated
// parse_rc/walk_path capture is therefore expected to already cascade into
// resolve never completing, but each step's own truncation is still
// detected and reported independently here rather than assumed from the
// others. A truncated capture is never trusted as data either --
// parseRcData/walkPathData/data stay null exactly as they would for any
// other unusable read, so no count or `ok: true` is ever built on a
// partial capture (the truncation FACT itself is still surfaced,
// distinctly, via unavailableReason below and in CHECKED/UNVERIFIED).
const parseRcData = parseRcResult.kind === "ok" ? parseRcResult.data : null;
const walkPathData = walkPathResult.kind === "ok" ? walkPathResult.data : null;
const data = resolveResult.kind === "ok" ? resolveResult.data : null;
const parseRcTruncated = parseRcResult.kind === "truncated";
const walkPathTruncated = walkPathResult.kind === "truncated";
const resolveTruncated = resolveResult.kind === "truncated";
const upstreamTruncated = parseRcTruncated || walkPathTruncated;

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, result: StdoutResult, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  const parsed = result.kind === "ok" ? result.data : null;
  if (parsed?.warning) return `  degraded  ${label}  ${parsed.warning}`;
  if (parsed && parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (!parsed) return `  degraded  ${label}  ${unavailableReason(step, result)}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** What-wins + source text for the per-command table, tolerant of a
 * missing/degraded fingerprint or version field on a "path" winner. A
 * function winner marked shell_precedence_ambiguous gets a trailing "*"
 * (a same-named alias exists too -- bash would run that alias instead;
 * see the SHADOWS DETAIL note and resolve.py's own WINNER docstring). */
function winnerLabel(winner: any): string {
  if (!winner || typeof winner !== "object") return "degraded";
  switch (winner.type) {
    case "function": return winner.shell_precedence_ambiguous ? "function*" : "function";
    case "alias": return "alias";
    case "path": return winner.fingerprint ? `PATH (${winner.fingerprint})` : "PATH";
    case "none": return "not found";
    default: return String(winner.type ?? "unknown");
  }
}

function winnerSource(winner: any): string {
  if (!winner || typeof winner !== "object") return "-";
  return winner.source ?? "-";
}

function shadowCount(shadows: any): number {
  if (!shadows || typeof shadows !== "object") return 0;
  const aliases = Array.isArray(shadows.aliases) ? shadows.aliases.length : 0;
  const pathHits = Array.isArray(shadows.path_hits) ? shadows.path_hits.length : 0;
  return aliases + pathHits;
}

/** Distinct probed versions among a winner + its shadowed PATH hits, for
 * the table's "versions read" column -- empty when nothing was probed.
 * A probe that was attempted but skipped/failed (including a probe-safety
 * rejection -- see resolve.py PROBE SAFETY) surfaces its version_error
 * here too, prominently, right in the main table, not only buried in
 * SHADOWS DETAIL below. */
function versionsRead(cmd: any): string {
  const versions = new Set<string>();
  if (cmd?.winner?.type === "path") {
    if (cmd.winner.version) versions.add(cmd.winner.version);
    else if (cmd.winner.version_error) versions.add(`unread: ${cmd.winner.version_error}`);
  }
  const hits = Array.isArray(cmd?.shadows?.path_hits) ? cmd.shadows.path_hits : [];
  hits.forEach((h: any) => {
    if (h?.version) versions.add(h.version);
    else if (h?.version_error) versions.add(`unread: ${h.version_error}`);
  });
  if (versions.size === 0) return "-";
  return truncate([...versions].join(","), 28);
}

const SEVERITY_ORDER: Record<string, number> = { highest: 0, high: 1, medium: 2, info: 3, none: 4 };

const lines: string[] = [];
lines.push("COMMAND SHADOW AUDIT");
lines.push("");

if (!data) {
  lines.push(`audit unavailable — ${unavailableReason(resolveStep, resolveResult)}`);
} else if (!data.ok) {
  lines.push(`audit degraded — ${data.error ?? "unknown reason"}`);
} else {
  const commands = Array.isArray(data.commands) ? data.commands : [];
  const totals = data.totals && typeof data.totals === "object" ? data.totals : {};
  const total = totals.total_commands ?? commands.length;
  const clean = totals.clean ?? 0;
  const notWhatTheySeem = total - clean;
  const byFunction = totals.shadowed_by_function ?? 0;
  const byAlias = totals.shadowed_by_alias ?? 0;
  const byPathDup = totals.shadowed_by_path_dup ?? 0;

  lines.push(
    `${notWhatTheySeem} of ${total} commands are not what they seem: ` +
    `${byFunction} shadowed by functions, ${byAlias} by aliases, ${byPathDup} by PATH duplicates`,
  );
  if (upstreamTruncated) {
    const names = [parseRcTruncated ? "parse_rc" : null, walkPathTruncated ? "walk_path" : null].filter(Boolean).join(" and ");
    lines.push(`coverage incomplete — ${names} output was truncated at rote's capture cap; this report covers only part of what ${parseRcTruncated && walkPathTruncated ? "they" : "it"} produced — no clean bill until coverage is complete.`);
  }
  lines.push("");

  if (!Array.isArray(data.commands)) {
    lines.push("degraded — commands was not a list; nothing to show");
  } else {
    const sorted = [...commands].sort(
      (a, b) => (SEVERITY_ORDER[a?.severity] ?? 9) - (SEVERITY_ORDER[b?.severity] ?? 9),
    );
    lines.push(
      `${"COMMAND".padEnd(10)}${"WINS".padEnd(16)}${"SOURCE".padEnd(30)}${"SHADOWS".padEnd(9)}${"VERSIONS READ".padEnd(30)}SEVERITY`,
    );
    sorted.forEach((c: any) => {
      lines.push(
        `${String(c?.name ?? "?").padEnd(10)}` +
        `${winnerLabel(c?.winner).padEnd(16)}` +
        `${truncate(winnerSource(c?.winner), 29).padEnd(30)}` +
        `${String(shadowCount(c?.shadows)).padEnd(9)}` +
        `${versionsRead(c).padEnd(30)}` +
        `${String(c?.severity ?? "unknown")}`,
      );
    });
    lines.push("");

    const nonClean = sorted.filter((c: any) => c?.severity && c.severity !== "none");
    lines.push(`SHADOWS DETAIL (${nonClean.length})`);
    if (nonClean.length === 0) {
      lines.push("  none — every watched command resolved cleanly to a single, unambiguous PATH hit (or was not found)");
    } else {
      nonClean.forEach((c: any) => {
        const winnerCond = (c?.winner?.type === "function" || c?.winner?.type === "alias") && c.winner.conditional
          ? " [conditional -- found inside an if/case branch this play never evaluates]"
          : "";
        lines.push(`  ${c.name} — ${winnerLabel(c.winner)} at ${winnerSource(c.winner)} (severity ${c.severity})${winnerCond}`);
        if (c?.winner?.shell_precedence_ambiguous) {
          lines.push("      NOTE  zsh runs this function; bash's alias-expansion would run the alias below instead (shell-dependent precedence)");
        }
        const aliases = Array.isArray(c?.shadows?.aliases) ? c.shadows.aliases : [];
        aliases.forEach((a: any) => {
          const cond = a?.conditional ? " [conditional]" : "";
          lines.push(`      shadowed alias   ${a?.file}:${a?.line}  ${truncate(String(a?.value ?? ""), 60)}${cond}`);
        });
        const pathHits = Array.isArray(c?.shadows?.path_hits) ? c.shadows.path_hits : [];
        pathHits.forEach((h: any) => {
          const link = h?.is_symlink ? ` -> ${h.link_target}` : "";
          const ver = h?.version ? ` [${h.version}]` : h?.version_error ? ` [unread: ${h.version_error}]` : "";
          lines.push(`      shadowed PATH    ${h?.dir}${link}  (${h?.fingerprint})${ver}`);
        });
      });
    }
    lines.push("");

    const exports = Array.isArray(data.path_exports) ? data.path_exports : [];
    if (exports.length > 0) {
      lines.push(`PATH EXPORTS FOUND IN YOUR RC FILES (${exports.length}) — why your PATH looks the way it does`);
      exports.forEach((e: any) => {
        const cond = e?.conditional ? " [conditional]" : "";
        lines.push(`  ${e?.file}:${e?.line}  PATH=${truncate(String(e?.value ?? ""), 70)}${cond}`);
      });
      lines.push("");
    }
  }
}

lines.push("STAGES");
lines.push(
  stageLine("parse rc files    ", parseRcStep, parseRcResult, (p) =>
    `${p.count} definition(s) across ${p.files_parsed}/${p.files_total} root file(s) + ${p.sourced_files_parsed} sourced`,
  ),
);
lines.push(
  stageLine("walk $PATH        ", walkPathStep, walkPathResult, (p) =>
    `${p.hit_count} hit(s) across ${p.path_dirs_existing}/${p.path_dirs_walked} dir(s) for ${p.watchlist_count} command(s)`,
  ),
);
lines.push(
  stageLine("resolve & grade   ", resolveStep, resolveResult, (p) =>
    `${(p.commands ?? []).length} command(s) resolved, ${p.totals?.total_commands - (p.totals?.clean ?? 0) || 0} not clean`,
  ),
);
lines.push("");

const pFiles = parseRcData ?? {};
const pWalk = walkPathData ?? {};
lines.push("CHECKED — what this run actually read");
if (!parseRcTruncated) {
  lines.push(
    `  ${pFiles.files_total ?? "?"} root rc file(s) checked (${pFiles.files_parsed ?? 0} parsed, ` +
    `${pFiles.files_missing ?? 0} missing, ${pFiles.files_unreadable ?? 0} unreadable); ` +
    `${pFiles.sourced_files_found ?? 0} one-level source target(s) found (${pFiles.sourced_files_parsed ?? 0} parsed, ` +
    `${pFiles.sourced_files_skipped_nonliteral ?? 0} skipped as non-literal)`,
  );
}
if (!walkPathTruncated) {
  lines.push(
    `  ${pWalk.path_dirs_existing ?? "?"}/${pWalk.path_dirs_walked ?? "?"} PATH director(ies) existed and were scanned, ` +
    `for ${pWalk.watchlist_count ?? "?"} watched command(s)` +
    (pWalk.extra_ignored_note ? `; ${pWalk.extra_ignored_note}` : ""),
  );
}
lines.push("UNVERIFIED — what this play cannot tell you");
if (parseRcTruncated) {
  lines.push(`  parse_rc: ${unavailableReason(parseRcStep, parseRcResult)} — nothing from this step is CHECKED above`);
}
if (walkPathTruncated) {
  lines.push(`  walk_path: ${unavailableReason(walkPathStep, walkPathResult)} — nothing from this step is CHECKED above`);
}
if (resolveTruncated) {
  lines.push(`  resolve: ${unavailableReason(resolveStep, resolveResult)} — nothing from this step is CHECKED above`);
}
lines.push("  runtime-defined functions/aliases in a LIVE shell session (only static rc text is read, nothing is sourced)");
lines.push("  whether a `source`/`.` line's own guard (e.g. `[ -f X ] &&`) actually evaluates true -- the directive is detected and followed, the guard is not evaluated");
lines.push("  whether an alias/function marked [conditional] above actually lands in a real shell -- it was found inside an if/case branch this play cannot evaluate, so it is reported as a candidate, not a confirmed live definition");
lines.push("  alias/function definitions more than one `source` hop deep");
lines.push("  unalias/unfunction directives that undo an earlier definition (a real line on the machine this play was built on removes several guard functions right after defining them)");
lines.push("  which single combination of these rc files a real login/interactive shell actually sources on start -- this play reads all seven, always, as a static superset");
lines.push("  which shell (bash vs zsh) will actually read these rc files -- a command marked function* above has a same-named alias too, and the two disagree on which wins (see the NOTE in SHADOWS DETAIL)");
lines.push("  the trust of the python3 interpreter that runs this play's own three steps -- like every play on this host, rote's own Process Portability Contract requires invoking installed tools by bare PATH name (never a pinned absolute path; see `rote grammar steps`), so `python3` here is resolved from this process's own inherited $PATH once, before any of this play's own PATH-shadow analysis above has even started; a play running as a rote step has no way to verify that bootstrapping step about itself");

out.human(lines.join("\n"));

const totalsForSummary = data?.ok && !upstreamTruncated && data.totals && typeof data.totals === "object" ? data.totals : null;
out.summary(
  totalsForSummary
    ? `${(totalsForSummary.total_commands ?? 0) - (totalsForSummary.clean ?? 0)} of ${totalsForSummary.total_commands ?? 0} watched commands are not what they seem ` +
      `(${totalsForSummary.shadowed_by_function ?? 0} function, ${totalsForSummary.shadowed_by_alias ?? 0} alias, ${totalsForSummary.shadowed_by_path_dup ?? 0} PATH-dup)`
    : upstreamTruncated
      ? "command shadow audit unavailable — parse_rc/walk_path output truncated at rote's capture cap"
      : "command shadow audit unavailable (degraded)",
);

out.result({
  ok: (data?.ok ?? false) && !upstreamTruncated,
  commands: data?.commands ?? null,
  path_exports: data?.path_exports ?? null,
  totals: data?.totals ?? null,
  parse_rc: {
    status: parseRcStep.outcome.status,
    truncated: parseRcTruncated,
    count: parseRcData?.count ?? null,
    warning: parseRcData?.warning ?? (parseRcTruncated ? unavailableReason(parseRcStep, parseRcResult) : null),
  },
  walk_path: {
    status: walkPathStep.outcome.status,
    truncated: walkPathTruncated,
    watchlist_count: walkPathData?.watchlist_count ?? null,
    hit_count: walkPathData?.hit_count ?? null,
    ignored_note: walkPathData?.extra_ignored_note ?? null,
    warning: walkPathTruncated ? unavailableReason(walkPathStep, walkPathResult) : null,
  },
  representations: {
    human: "complete — headline, per-command table sorted by severity, shadows detail, rc PATH exports, stage ledger, CHECKED/UNVERIFIED footer",
    json: "canonical — every watched command's winner and full shadow list, covers the whole watchlist even when the table above is easy to scan",
    summary: "intentionally lossy — counts only",
  },
});
