#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: agent-resource-audit
 * description: 'Your agents keep running after you stop typing, and what they hold is invisible until the fans come on. You get every agent-related process on this machine right now -- Claude Code, Codex, Cursor, Windsurf, Copilot, Aider, opencode, gemini-cli, MCP servers, and their companion processes -- grouped by kind and ranked by memory, the total agent footprint measured against your system RAM, and every Claude Code or Codex session file on disk, matched to a live process where one exists. A process is flagged orphan-suspect only when it is reparented to launchd, agent-shaped, and has run more than ten minutes -- a suspicion, never a certainty; known daemons and desktop-app helpers are excluded outright. Codex sessions can''t be matched to a process the way Claude Code''s can, so every one is reported as resumable, with a separate note when a codex process is actually running. Session files are read by filesystem metadata only, never opened. Kill commands and resume commands are printed as text for you to read and run yourself; nothing here is ever executed on your behalf. Read-only, no credentials, no network, never reads environment variables or file contents; needs only python3.'
 * version: 0.2.11
 * source_url: https://play.modiqo.ai/dotisacat/agent-resource-audit
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: agent-resource-audit
 * metadata:
 *   version: 0.2.11
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   enumerate_processes: resources/presentation-fixtures/enumerate_processes/fixture.yaml
 *   system_memory: resources/presentation-fixtures/system_memory/fixture.yaml
 *   scan_sessions: resources/presentation-fixtures/scan_sessions/fixture.yaml
 *   classify_and_rank: resources/presentation-fixtures/classify_and_rank/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-resource-audit
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-resource-audit
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       enumerate:
 *         type: object
 *       system_memory:
 *         type: object
 *       scan_sessions:
 *         type: object
 *       audit:
 *         type: object
 *       representations:
 *         type: object
 * parameters:
 * - name: top
 *   param_type: integer
 *   required: false
 *   default: '15'
 *   description: How many processes to show, ranked by memory (1-100)
 *   example: '15'
 * - name: min_rss_mb
 *   param_type: integer
 *   required: false
 *   default: '25'
 *   description: Only report processes holding at least this many MB of resident memory (0-4096)
 *   example: '25'
 * - name: idle_minutes
 *   param_type: integer
 *   required: false
 *   default: '20'
 *   description: A running session with no transcript activity for this many minutes counts as idle (1-1440)
 *   example: '20'
 * - name: max_age_days
 *   param_type: integer
 *   required: false
 *   default: '30'
 *   description: List on-disk sessions newer than this (1-365)
 *   example: '30'
 * - name: harness
 *   param_type: string
 *   required: false
 *   default: 'all'
 *   description: Which harness sessions to scan -- valid values are all, claude, or codex
 *   example: 'all'
 * steps:
 *   enumerate_processes:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{enumerate.py}'
 *   system_memory:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{sysmem.py}'
 *   scan_sessions:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{sessions.py}'
 *     - $max_age_days
 *     - $harness
 *   classify_and_rank:
 *     type: process.exec
 *     timeout_ms: 20000
 *     depends_on:
 *     - enumerate_processes
 *     - system_memory
 *     - scan_sessions
 *     argv:
 *     - python3
 *     - '@resource{classify.py}'
 *     - '@enumerate_processes{$.stdout.text | fromjson | .packed}'
 *     - '@system_memory{$.stdout.text | fromjson | .packed}'
 *     - $top
 *     - $min_rss_mb
 *     - '@scan_sessions{$.stdout.text | fromjson | .packed}'
 *     - $idle_minutes
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

function bodyOf(step: ReturnType<typeof ctx.step>): any {
  const o = step.outcome;
  if (o.status === "completed" || o.status === "restored") return o.output.body;
  return null;
}

/** Discriminated read of a step's captured stdout. rote caps a step's
 * captured stdout and sets stdout.truncated when that cap was hit -- a
 * truncated payload must never be conflated with a clean parse failure
 * (the capture cap is the CAUSE, an unparseable/partial payload is only
 * its symptom), so truncated === true is checked, and wins, before any
 * JSON.parse is even attempted -- a partial payload that would happen to
 * still parse is never read as "ok" either. */
type StdoutResult =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

function readStdout(step: ReturnType<typeof ctx.step>): StdoutResult {
  const s = bodyOf(step)?.stdout;
  if (!s) return { kind: "absent" };
  if (s.truncated === true) return { kind: "truncated", bytes: s.bytes ?? null };
  const text = s.text ?? "";
  try { return { kind: "ok", data: JSON.parse(text) }; } catch { return { kind: "unparseable" }; }
}

/** Unwraps a StdoutResult to the parsed value or null, for call sites that
 * only need "do we have usable data" -- truncation-awareness for those
 * call sites lives in stageLine and the clean-bill gates below, which read
 * the StdoutResult directly instead of going through this. */
function parsedStdout(step: ReturnType<typeof ctx.step>): any {
  const r = readStdout(step);
  return r.kind === "ok" ? r.data : null;
}

const enumerateStep = ctx.step(stepName("enumerate_processes"));
const sysmemStep = ctx.step(stepName("system_memory"));
const scanSessionsStep = ctx.step(stepName("scan_sessions"));
const classifyStep = ctx.step(stepName("classify_and_rank"));

const enumerateResult = readStdout(enumerateStep);
const sysmemResult = readStdout(sysmemStep);
const scanResult = readStdout(scanSessionsStep);
const classifyResult = readStdout(classifyStep);

const enumerateData = enumerateResult.kind === "ok" ? enumerateResult.data : null;
const sysmemData = sysmemResult.kind === "ok" ? sysmemResult.data : null;
const scanData = scanResult.kind === "ok" ? scanResult.data : null;
const data = classifyResult.kind === "ok" ? classifyResult.data : null;

// A truncated step never gets to claim "0 findings" for the parts of the
// report it feeds -- this machine's whole capture-truncated payload could
// be hiding the finding that would have flipped the verdict.
const anyStepTruncated = [enumerateResult, sysmemResult, scanResult, classifyResult]
  .some((r) => r.kind === "truncated");

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, result: StdoutResult, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (result.kind === "truncated") {
    const bytesNote = result.bytes != null ? `${result.bytes} bytes captured` : "capture cap reached";
    return `  ${"truncated".padEnd(8)}  ${label}  output was truncated at rote's capture cap (${bytesNote}) — this report covers only part of what the step produced`;
  }
  const parsed = result.kind === "ok" ? result.data : null;
  if (parsed?.warning) return `  degraded  ${label}  ${parsed.warning}`;
  if (parsed && parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const lines: string[] = [];
lines.push("AGENT RESOURCE AUDIT");
lines.push("");

// Set below, in priority order (orphan-suspect first, then the top ranked
// advisory), for the "reader's next action" closing line -- see the ending
// block after STAGES. Left null when this run has nothing actionable to
// offer, in which case the ending falls back to a single clean-bill or
// withheld-verdict sentence instead.
let nextActionLine: string | null = null;

if (classifyResult.kind === "truncated") {
  const bytesNote = classifyResult.bytes != null ? `${classifyResult.bytes} bytes captured` : "capture cap reached";
  lines.push(`audit unavailable — classify_and_rank output was truncated at rote's capture cap (${bytesNote}); this report covers only part of what the step produced`);
} else if (!data) {
  lines.push(`audit unavailable — classify step ${classifyStep.outcome.status}`);
} else if (!data.ok) {
  lines.push(`audit degraded — ${data.error ?? "unknown reason"}`);
} else {
  const totals = data.totals ?? {};

  // Pulls the sessions totals forward from the SESSIONS section below so the
  // most retellable fact in this report -- how many sessions are sitting on
  // disk with no process behind them -- leads the headline instead of being
  // buried in a parenthetical past the ranked table.
  const sessionsForHeadline = data.sessions && typeof data.sessions === "object" ? data.sessions : null;
  const headlineTotals = sessionsForHeadline?.totals && typeof sessionsForHeadline.totals === "object"
    ? sessionsForHeadline.totals
    : null;
  if (headlineTotals && typeof headlineTotals.resumable === "number" && typeof headlineTotals.running === "number") {
    const runningMbText = typeof headlineTotals.running_rss_mb === "number" ? `${headlineTotals.running_rss_mb} MB` : "an unknown amount of memory";
    lines.push(
      `${headlineTotals.resumable} agent sessions are sitting on this disk. ${headlineTotals.running} are still running and holding ${runningMbText}.`,
    );
  } else {
    lines.push("session count unavailable -- see SESSIONS below");
  }

  const matched = totals.matched ?? 0;
  const agentRssMb = totals.agent_rss_mb ?? 0;
  const ramGb = typeof totals.system_ram_gb === "number" ? totals.system_ram_gb : null;
  if (ramGb != null && ramGb > 0) {
    const agentGb = agentRssMb / 1024;
    const agentDisplay = agentGb >= 0.05 ? `${agentGb.toFixed(1)} GB` : `${Math.round(agentRssMb)} MB`;
    const percentRaw = (agentGb / ramGb) * 100;
    const percent = Math.round(percentRaw);
    // A non-zero footprint must never round down to a bare "0 percent" --
    // that reads as "no footprint" when the honest story is "a small one".
    const percentText = agentRssMb === 0 ? "0 percent" : percent === 0 ? "under 1 percent" : `${percent} percent`;
    lines.push(`${matched} agent processes are using ${agentDisplay} of your ${ramGb} GB -- ${percentText} of this machine's RAM.`);
  } else {
    lines.push(`${matched} agent processes are using ${agentRssMb} MB; total system RAM is unknown, so no percentage is shown.`);
  }
  if ((totals.filtered_below_min ?? 0) > 0) {
    lines.push(`(${totals.filtered_below_min} more agent process(es) below the memory floor, not shown; lower min_rss_mb to see them)`);
  }
  lines.push("");

  // Degraded JSON can carry a truthy value here that isn't an array (a
  // string, an object); guard every collection so a shape mismatch renders
  // a degradation note instead of crashing the presentation on .forEach().
  const processes = Array.isArray(data.processes) ? data.processes : [];
  lines.push(`RANKED BY MEMORY (top ${totals.shown ?? processes.length} of ${totals.matched ?? 0})`);
  if (!Array.isArray(data.processes)) {
    lines.push("  degraded — processes was not a list; nothing to rank");
  }
  processes.forEach((p: any, i: number) => {
    const flag = p.orphan_suspect ? "ORPHAN?" : "";
    lines.push(
      `  ${String(i + 1).padStart(2)}. pid ${String(p.pid).padStart(6)}  ${String(p.category).padEnd(11)} ` +
      `${String(p.rss_mb).padStart(7)} MB  ${String(p.pcpu).padStart(5)}%  ${String(p.age).padEnd(13)} ${p.cmd_short}  ${flag}`,
    );
  });
  lines.push("");

  const suspects = Array.isArray(data.orphan_suspects) ? data.orphan_suspects : [];
  lines.push(`ORPHAN-SUSPECTS -- looks abandoned, not confirmed (${suspects.length})`);
  if (!Array.isArray(data.orphan_suspects)) {
    lines.push("  degraded — orphan_suspects was not a list; treating as none");
  } else if (suspects.length === 0) {
    lines.push(
      anyStepTruncated
        ? "  0 shown — but one or more steps above were truncated (see STAGES); not a verified clean result"
        : "  none — nothing shown looked reparented, agent-shaped, and long-running enough to flag",
    );
  } else {
    suspects.forEach((p: any) => {
      lines.push(`  pid ${p.pid}  ${p.category}  ${p.rss_mb} MB  age ${p.age}  ${p.cmd_short}`);
    });
    lines.push("");
    lines.push("  suggested commands — nothing was executed. Snapshot pids can be reused:");
    lines.push("  verify each one is still the process named below before running its kill command.");
    const hints = Array.isArray(data.kill_hints) ? data.kill_hints : [];
    hints.forEach((hint: string) => lines.push(`    ${hint}`));

    // The reader's next action, picked by the largest suspect by memory --
    // kill_hints is built index-aligned with orphan_suspects in classify.py,
    // so the same index into both arrays names and verifies the same pid.
    if (hints.length === suspects.length && suspects.length > 0) {
      let topIdx = 0;
      for (let i = 1; i < suspects.length; i++) {
        if ((suspects[i].rss_mb ?? 0) > (suspects[topIdx].rss_mb ?? 0)) topIdx = i;
      }
      nextActionLine =
        `Next: the largest orphan-suspect is pid ${suspects[topIdx].pid} (${suspects[topIdx].rss_mb} MB, ${suspects[topIdx].cmd_short}) --\n` +
        `  ${hints[topIdx]}`;
    }
  }
  lines.push("");

  // sessions is its own nested object inside the classify_and_rank output
  // (see classify.py); guarded the same way every other collection above
  // is, so a shape mismatch degrades this section instead of throwing.
  const sessionsRaw = data.sessions;
  const sessions = sessionsRaw && typeof sessionsRaw === "object" ? sessionsRaw : null;
  if (!sessions) {
    lines.push("SESSIONS");
    lines.push("  degraded — sessions was not an object; nothing to show");
  } else {
    const sTotals = sessions.totals && typeof sessions.totals === "object" ? sessions.totals : {};
    const running = sTotals.running ?? 0;
    const runningIdle = sTotals.running_idle ?? 0;
    const resumable = sTotals.resumable ?? 0;
    const runningMb = sTotals.running_rss_mb ?? 0;
    lines.push(
      `SESSIONS — ${running} running (${runningIdle} idle, no recent activity) holding ${runningMb} MB; ` +
      `${resumable} resumable (file on disk, no live process found)`,
    );
    const resumableShown = sTotals.resumable_shown ?? resumable;
    if (resumable > resumableShown) {
      lines.push(`(${resumable - resumableShown} more resumable session(s) not shown; narrow max_age_days or harness to see them)`);
    }
    const sessionRows = Array.isArray(sessions.rows) ? sessions.rows : [];
    if (!Array.isArray(sessions.rows)) {
      lines.push("  degraded — sessions.rows was not a list; nothing to show");
    } else if (sessionRows.length === 0) {
      lines.push(
        anyStepTruncated
          ? "  0 shown — but one or more steps above were truncated (see STAGES); not a verified clean result"
          : "  none — no session files found within max_age_days on this machine",
      );
    } else {
      const truncate = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);
      sessionRows.forEach((s: any) => {
        const rss = s.rss_mb != null ? `${s.rss_mb} MB` : "";
        const started = s.started_approx ? `~${s.started}` : `${s.started} `;
        lines.push(
          `  ${String(s.harness).padEnd(7)}${String(s.id_short).padEnd(10)}${truncate(String(s.project ?? ""), 28).padEnd(29)}` +
          `${String(started).padEnd(18)}${String(s.last_active).padEnd(17)} ${String(s.state).padEnd(15)}${rss}`,
        );
      });

      // sessionRows already arrives ranked most-useful-first (running before
      // resumable, most-recently-active first within each -- see classify.py's
      // state_order sort), so slicing here keeps that ranking rather than
      // imposing a new one. Unranked, fifty-plus equal-weight suggestions is
      // zero suggestions; the full set still travels in out.result() below.
      const ADVISORY_SHOWN_MAX = 8;
      const advisories = sessionRows.filter((s: any) => s.advisory);
      const advisoriesShown = advisories.slice(0, ADVISORY_SHOWN_MAX);
      lines.push("");
      lines.push("  advisories — nothing was executed. Text only, for you to run yourself:");
      if (advisories.length === 0) {
        lines.push("  none");
      } else {
        advisoriesShown.forEach((s: any) => {
          lines.push(`    ${s.harness} ${s.id_short}: ${s.advisory}`);
        });
        if (advisories.length > advisoriesShown.length) {
          lines.push(`    (top ${advisoriesShown.length} of ${advisories.length} — full list in the JSON result)`);
        }
        // Falls back to the top-ranked session advisory only when no
        // orphan-suspect action was already found above -- an abandoned
        // process is the more concrete win, so it keeps priority.
        if (!nextActionLine) {
          const top = advisoriesShown[0];
          nextActionLine = `Next: the most relevant session is ${top.harness} ${top.id_short} --\n  ${top.advisory}`;
        }
      }
      if (sessions.codex_process_detected && sessions.codex_running_unmatched_note) {
        lines.push(`    codex: ${sessions.codex_running_unmatched_note}`);
      }
    }
  }
}

lines.push("");
lines.push("STAGES");
lines.push(
  stageLine("enumerate processes  ", enumerateStep, enumerateResult, (p) => `${p.count} matched`),
);
lines.push(
  stageLine("system memory        ", sysmemStep, sysmemResult, (p) =>
    p.packed && p.packed !== "unknown" ? `${(Number(p.packed) / 1024 ** 3).toFixed(1)} GB` : "unknown",
  ),
);
lines.push(
  stageLine("scan sessions        ", scanSessionsStep, scanResult, (p) =>
    `${p.counts?.claude_listed ?? 0} claude, ${p.counts?.codex_listed ?? 0} codex listed`,
  ),
);
lines.push(
  stageLine("classify & rank      ", classifyStep, classifyResult, (p) =>
    `${p.totals?.shown ?? 0} shown, ${(p.orphan_suspects ?? []).length} orphan-suspect(s)`,
  ),
);

// The report ends on the reader's next action, not on this ledger -- see
// nextActionLine above. A truncated step must still withhold the clean-bill
// reading here, the same gate every "none" line above already honors.
lines.push("");
if (nextActionLine) {
  lines.push(nextActionLine);
  lines.push("");
  lines.push("Nothing above was executed — every kill and resume command is text only, for you to run yourself.");
} else if (data?.ok && anyStepTruncated) {
  lines.push("One or more steps above were truncated (see STAGES) — not a verified clean result, so no action is suggested here.");
} else if (data?.ok) {
  lines.push("Nothing looked abandoned or idle enough to act on right now. Nothing was executed and nothing was changed.");
} else {
  lines.push("Nothing was executed and nothing was changed.");
}

out.human(lines.join("\n"));

const sessionTotalsForSummary = data?.ok && data.sessions && typeof data.sessions === "object"
  ? data.sessions.totals ?? {}
  : null;

const baseSummary = data?.ok
  ? `${data.totals?.matched ?? 0} agent processes, ${data.totals?.agent_rss_mb ?? 0} MB total, ` +
    `${(data.orphan_suspects ?? []).length} orphan-suspects, ` +
    `${sessionTotalsForSummary ? `${sessionTotalsForSummary.running ?? 0} running / ${sessionTotalsForSummary.resumable ?? 0} resumable sessions` : "sessions unavailable"}`
  : "agent resource audit unavailable (degraded)";

out.summary(
  anyStepTruncated ? `${baseSummary} — partial: one or more steps were truncated at the capture cap` : baseSummary,
);

out.result({
  enumerate: {
    status: enumerateStep.outcome.status,
    truncated: enumerateResult.kind === "truncated",
    count: enumerateData?.count ?? null,
  },
  system_memory: {
    status: sysmemStep.outcome.status,
    truncated: sysmemResult.kind === "truncated",
    warning: sysmemData?.warning ?? null,
  },
  scan_sessions: {
    status: scanSessionsStep.outcome.status,
    truncated: scanResult.kind === "truncated",
    warning: scanData?.warning ?? null,
    counts: scanData?.counts ?? null,
  },
  audit: data,
  representations: {
    human: "complete — context line, ranked table, orphan-suspects with kill hints, sessions table with advisories, stage ledger",
    json: "canonical — full audit object the human view renders, covers every matched process and every scanned session in totals even when only the top N are listed",
    summary: "intentionally lossy — counts and total MB only",
  },
});
