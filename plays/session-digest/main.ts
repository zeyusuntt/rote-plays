#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: session-digest
 * description: 'You stepped away and your agents kept working. What did they actually do? Digests your recent LOCAL agent session transcripts into "what happened while you were away" -- Claude Code transcripts under ~/.claude/projects, plus Codex transcripts under ~/.codex/sessions when present -- into counts only: sessions, duration, tool calls by tool, files edited/written, shell commands run, errors, and token usage totals where the transcript records them. Claude Code and Codex use different JSONL record shapes across versions, so each source gets its own defensive parser that treats an unrecognized record shape as uninformative rather than fatal, degrading just that one file, never the whole run, on a genuine parse disaster -- degraded rows are rendered honestly rather than hidden. The trust line is literal: message text, prompt content, and command argv are never read into the output -- shell commands run are a COUNT only, file paths are reported home-redacted, and nothing here is ever quoted back to you, only counted. Independent implementation sharing no code with Anthropics Apache-2.0 receipts plugin that inspired it. Read-only, no credentials, no network; needs only python3.'
 * version: 0.1.5
 * source_url: https://play.modiqo.ai/dotisacat/session-digest
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: session-digest
 * metadata:
 *   version: 0.1.5
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   locate_sessions: resources/presentation-fixtures/locate_sessions/fixture.yaml
 *   digest_claude: resources/presentation-fixtures/digest_claude/fixture.yaml
 *   digest_codex: resources/presentation-fixtures/digest_codex/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-session-digest
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-session-digest
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       locate:
 *         type: object
 *       claude:
 *         type: object
 *       codex:
 *         type: object
 *       sessions:
 *         type: object
 *       totals:
 *         type: object
 *       window_hours:
 *         type: object
 *       representations:
 *         type: object
 *       privacy:
 *         type: string
 * parameters:
 * - name: window_hours
 *   param_type: integer
 *   required: false
 *   default: '24'
 *   description: Look-back window (1-168)
 *   example: '24'
 * - name: max_sessions
 *   param_type: integer
 *   required: false
 *   default: '12'
 *   description: Digest at most this many sessions, newest first (1-50)
 *   example: '12'
 * steps:
 *   locate_sessions:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{locate.py}'
 *     - $window_hours
 *     - $max_sessions
 *   digest_claude:
 *     type: process.exec
 *     timeout_ms: 60000
 *     depends_on:
 *     - locate_sessions
 *     argv:
 *     - python3
 *     - '@resource{digest_claude.py}'
 *     - '@locate_sessions{$.stdout.text | fromjson | .claude_packed}'
 *   digest_codex:
 *     type: process.exec
 *     timeout_ms: 45000
 *     depends_on:
 *     - locate_sessions
 *     argv:
 *     - python3
 *     - '@resource{digest_codex.py}'
 *     - '@locate_sessions{$.stdout.text | fromjson | .codex_packed}'
 * ---
 */

const presentationSdk = await import("__ROTE_PRESENTATION_SDK__").catch((cause) => {
  throw new Error(
    "This is a rote steps presentation program. Run it with `rote play run`.",
    { cause },
  );
});
const { FlowOutput, loadPresentationContext, stepName } = presentationSdk;

const out = new FlowOutput();
const ctx = await loadPresentationContext();

function bodyOf(step: ReturnType<typeof ctx.step>): any {
  const o = step.outcome;
  if (o.status === "completed" || o.status === "restored") return o.output.body;
  return null;
}

// Reading a step's stdout has four distinct outcomes, and callers must not
// conflate them: a truncated capture is not the same failure as invalid
// JSON, and both are different from a step that never produced a body at
// all. "truncated" wins over "unparseable" when both apply -- truncation is
// the cause, an unparseable partial payload is only its symptom.
type StdoutRead =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

function parsedStdout(step: ReturnType<typeof ctx.step>): StdoutRead {
  const body = bodyOf(step);
  const stdout = body?.stdout;
  if (!stdout) return { kind: "absent" };
  if (stdout.truncated === true) {
    return { kind: "truncated", bytes: typeof stdout.bytes === "number" ? stdout.bytes : null };
  }
  try {
    return { kind: "ok", data: JSON.parse(stdout.text ?? "") };
  } catch {
    return { kind: "unparseable" };
  }
}

function dataOf(result: StdoutRead): any {
  return result.kind === "ok" ? result.data : null;
}

function truncationNote(bytes: number | null): string {
  const capturedLabel = bytes != null ? `${bytes} bytes captured` : "capture size unknown";
  return `output was truncated at rote's capture cap (${capturedLabel}) -- this report covers only part of what the step produced`;
}

const locateStep = ctx.step(stepName("locate_sessions"));
const claudeStep = ctx.step(stepName("digest_claude"));
const codexStep = ctx.step(stepName("digest_codex"));

const locateResult = parsedStdout(locateStep);
const claudeResult = parsedStdout(claudeStep);
const codexResult = parsedStdout(codexStep);

const locateData = dataOf(locateResult);
const claudeData = dataOf(claudeResult);
const codexData = dataOf(codexResult);

const locateTruncated = locateResult.kind === "truncated";
const claudeTruncated = claudeResult.kind === "truncated";
const codexTruncated = codexResult.kind === "truncated";

// Prefer the effective (clamped) window locate_sessions actually used to
// select files over the raw parameter -- a caller passing window_hours=1000
// gets files from the last 168h (locate_sessions' own 1-168 clamp), and this
// digest should say "168h", not "1000h". Falls back to the raw param only
// when locate_sessions didn't run or its output didn't parse.
const windowHours = typeof locateData?.window_hours === "number"
  ? locateData.window_hours
  : Number(ctx.params.window_hours ?? 24) || 24;

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, result: StdoutRead, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (result.kind === "truncated") {
    return `  truncated ${label}  ${truncationNote(result.bytes)}`;
  }
  const parsed = dataOf(result);
  if (parsed?.warning) return `  degraded  ${label}  ${parsed.warning}`;
  if (parsed && parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

// A degraded/absent digest still contributes an empty-shaped sessions list and
// totals so every downstream sum/loop below can stay Array.isArray-guarded
// instead of branching on which source is present.
function sessionsOf(data: any): any[] {
  return Array.isArray(data?.sessions) ? data.sessions : [];
}

function totalsOf(data: any) {
  const t = data?.totals ?? {};
  return {
    sessions: typeof t.sessions === "number" ? t.sessions : 0,
    tool_calls: t.tool_calls && typeof t.tool_calls === "object" ? t.tool_calls : {},
    files_touched: typeof t.files_touched === "number" ? t.files_touched : 0,
    commands_run: typeof t.commands_run === "number" ? t.commands_run : 0,
    errors: typeof t.errors === "number" ? t.errors : 0,
    tokens: {
      in: typeof t.tokens?.in === "number" ? t.tokens.in : 0,
      out: typeof t.tokens?.out === "number" ? t.tokens.out : 0,
    },
  };
}

const claudeSessions = sessionsOf(claudeData).map((s: any) => ({ ...s, source: "claude" }));
const codexSessions = sessionsOf(codexData).map((s: any) => ({ ...s, source: "codex" }));
const allSessions = [...claudeSessions, ...codexSessions].sort((a, b) =>
  String(b.start ?? "").localeCompare(String(a.start ?? "")),
);

const claudeTotals = totalsOf(claudeData);
const codexTotals = totalsOf(codexData);

const mergedToolCalls: Record<string, number> = {};
for (const totals of [claudeTotals, codexTotals]) {
  for (const [name, count] of Object.entries(totals.tool_calls)) {
    mergedToolCalls[name] = (mergedToolCalls[name] ?? 0) + (typeof count === "number" ? count : 0);
  }
}
const rankedTools = Object.entries(mergedToolCalls).sort((a, b) => b[1] - a[1]);

const totalSessions = claudeTotals.sessions + codexTotals.sessions;
const totalToolCalls = rankedTools.reduce((sum, [, n]) => sum + n, 0);
const totalFilesTouched = claudeTotals.files_touched + codexTotals.files_touched;
const totalCommandsRun = claudeTotals.commands_run + codexTotals.commands_run;
const totalErrors = claudeTotals.errors + codexTotals.errors;
const totalTokensIn = claudeTotals.tokens.in + codexTotals.tokens.in;
const totalTokensOut = claudeTotals.tokens.out + codexTotals.tokens.out;
const totalTokens = totalTokensIn + totalTokensOut;

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

const lines: string[] = [];
lines.push("SESSION DIGEST — while you were away");
lines.push("");

if (locateTruncated) {
  lines.push(`digest unavailable — locate_sessions: ${truncationNote(locateResult.bytes)}`);
} else if (!locateData) {
  lines.push(`digest unavailable — locate_sessions step ${locateStep.outcome.status}`);
} else if (locateData.ok === false) {
  lines.push(`digest degraded — ${locateData.error ?? "unknown reason"}`);
} else {
  lines.push(
    `${totalSessions} session(s), ${totalToolCalls} tool call(s), ${totalFilesTouched} file(s) touched, ` +
    `~${formatCount(totalTokens)} tokens in the last ${windowHours} hour(s)`,
  );
  if (claudeTruncated || codexTruncated) {
    const which = [claudeTruncated ? "claude" : null, codexTruncated ? "codex" : null].filter(Boolean).join(" and ");
    lines.push(`(${which} output was truncated at rote's capture cap; totals above are partial -- see STAGES)`);
  }
  lines.push("");

  lines.push(`SESSIONS (${allSessions.length})`);
  if (allSessions.length === 0) {
    lines.push("  none — nothing in this look-back window");
  } else {
    allSessions.forEach((s: any) => {
      const toolCallCount = s.tool_calls && typeof s.tool_calls === "object"
        ? Object.values(s.tool_calls).reduce((sum: number, n: any) => sum + (typeof n === "number" ? n : 0), 0)
        : 0;
      const filesCount = s.files_touched?.count ?? 0;
      const tokensIn = s.tokens?.in ?? 0;
      const tokensOut = s.tokens?.out ?? 0;
      const degradedFlag = s.warning ? "DEGRADED" : "";
      lines.push(
        `  [${String(s.source).padEnd(6)}] ${String(s.dir ?? "unknown").slice(0, 28).padEnd(28)} ` +
        `${String(s.start ?? "-").slice(0, 19).padEnd(19)}  dur ${String(s.duration_min ?? "-").padStart(8)}m  ` +
        `${String(toolCallCount).padStart(4)} calls  ${String(filesCount).padStart(3)} files  ` +
        `${String(s.commands_run ?? 0).padStart(4)} cmds  ${String(s.errors ?? 0).padStart(2)} err  ` +
        `~${formatCount(tokensIn + tokensOut).padStart(6)} tok  ${String(s.model ?? "-").padEnd(16)} ${degradedFlag}`,
      );
      if (s.warning) lines.push(`           ⚠ ${s.warning}`);
    });
  }
  lines.push("");

  lines.push(`TOOL CALLS BY TOOL (${rankedTools.length} distinct)`);
  if (rankedTools.length === 0) {
    lines.push("  none");
  } else {
    rankedTools.forEach(([name, count]) => {
      lines.push(`  ${String(count).padStart(6)}  ${name}`);
    });
  }
  lines.push("");

  lines.push("SOURCE TOTALS");
  lines.push(
    `  claude   ${claudeTotals.sessions} session(s)  ${claudeTotals.commands_run} command(s)  ` +
    `${claudeTotals.errors} error(s)  ~${formatCount(claudeTotals.tokens.in + claudeTotals.tokens.out)} tokens`,
  );
  lines.push(
    `  codex    ${codexTotals.sessions} session(s)  ${codexTotals.commands_run} command(s)  ` +
    `${codexTotals.errors} error(s)  ~${formatCount(codexTotals.tokens.in + codexTotals.tokens.out)} tokens`,
  );
}

lines.push("");
lines.push("STAGES");
lines.push(
  stageLine("locate sessions      ", locateStep, locateResult, (p) =>
    `${p.counts?.claude_selected ?? 0} claude + ${p.counts?.codex_selected ?? 0} codex selected`,
  ),
);
lines.push(
  stageLine("digest claude        ", claudeStep, claudeResult, (p) => `${p.totals?.sessions ?? 0} session(s)`),
);
lines.push(
  stageLine("digest codex         ", codexStep, codexResult, (p) => `${p.totals?.sessions ?? 0} session(s)`),
);
lines.push("");
lines.push(
  "PRIVACY — counts, tool names, file paths (home-redacted), durations, and token totals only. " +
  "Message text, prompt content, and command argv are never read; shell commands are a count only.",
);

out.human(lines.join("\n"));

out.summary(
  locateTruncated
    ? `session digest unavailable (locate_sessions output truncated at rote's capture cap)`
    : locateData && locateData.ok !== false
      ? `${totalSessions} sessions, ${totalToolCalls} tool calls, ${totalFilesTouched} files touched, ~${formatCount(totalTokens)} tokens in the last ${windowHours}h` +
        (claudeTruncated || codexTruncated ? " (partial -- source output truncated)" : "")
      : "session digest unavailable (degraded)",
);

out.result({
  locate: {
    status: locateStep.outcome.status,
    counts: locateData?.counts ?? null,
    warning: locateTruncated ? truncationNote(locateResult.bytes) : locateData?.warning ?? null,
  },
  claude: {
    status: claudeStep.outcome.status,
    totals: claudeTotals,
    warning: claudeTruncated ? truncationNote(claudeResult.bytes) : claudeData?.warning ?? null,
  },
  codex: {
    status: codexStep.outcome.status,
    totals: codexTotals,
    warning: codexTruncated ? truncationNote(codexResult.bytes) : codexData?.warning ?? null,
  },
  sessions: allSessions,
  totals: {
    sessions: totalSessions,
    tool_calls: mergedToolCalls,
    files_touched: totalFilesTouched,
    commands_run: totalCommandsRun,
    errors: totalErrors,
    tokens: { in: totalTokensIn, out: totalTokensOut },
  },
  window_hours: windowHours,
  representations: {
    human: "complete — headline, per-session table, per-tool tally, source totals, stage ledger, privacy note",
    json: "canonical — full digest object the human view renders, covers every digested session even when the table above is long",
    summary: "intentionally lossy — counts and total tokens only",
  },
  privacy: "counts, tool names, file paths (home-redacted), durations, and token totals only — never message text, prompt content, or command argv",
});
