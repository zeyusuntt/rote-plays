#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: commit-attribution-guard
 * description: 'Scans your recent commit messages for AI-attribution marks you may not have meant to publish -- Co-Authored-By trailers naming an AI tool, "Generated with/by" footers, robot-emoji-plus-tool-name body marks -- before that history goes public. Identity hygiene for commit metadata, NOT a repo audit: reads commit messages only, never code. The one narrow exception reads a configured commit.template file and commit hooks to test for the same structural match, but returns only a "class:tool" pattern identifier, never the source text -- no hook or template code line ever leaves this play. A match is either a TRAILER (a Co-Authored-By or Signed-off-by trailer whose value names an AI tool, via git''s own trailer parser) or a BODY-MARK (a "Generated with/by <tool>" phrase or a robot emoji sharing a line with a tool name) -- a commit that merely discusses AI in prose is never flagged. The same check covers attribution SOURCES that could re-inject a mark into a future commit -- your commit.template and commit hooks -- staying inside the repository; a path resolving outside it is reported out of scope and never opened. You get a clean bill when nothing is found, or a findings table naming only the sha, the class, and the single matched line -- never the full commit message and never any code. Read-only, no credentials, no network; needs python3 and git.'
 * version: 0.1.5
 * source_url: https://play.modiqo.ai/dotisacat/commit-attribution-guard
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: commit-attribution-guard
 * metadata:
 *   version: 0.1.5
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   validate_repo: resources/presentation-fixtures/validate_repo/fixture.yaml
 *   scan_log: resources/presentation-fixtures/scan_log/fixture.yaml
 *   scan_config: resources/presentation-fixtures/scan_config/fixture.yaml
 * tags:
 * - domain-developer-workflow
 * - job-identity-hygiene
 * - audience-developers
 * - effect-read-only
 * - tool-git
 * discoverability:
 *   tags:
 *   - domain-developer-workflow
 *   - job-identity-hygiene
 *   - audience-developers
 *   - effect-read-only
 *   - tool-git
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       validate:
 *         type: object
 *       scan_log:
 *         type: object
 *       scan_config:
 *         type: object
 *       totals:
 *         type: object
 *       representations:
 *         type: object
 * parameters:
 * - name: repo
 *   param_type: string
 *   required: false
 *   default: .
 *   description: Path to the git repository. Steps run in the play workspace, so a relative path resolves somewhere you did not mean — prefer absolute paths.
 *   example: ~/my-project
 * - name: depth
 *   param_type: integer
 *   required: false
 *   default: '50'
 *   description: How many recent commits to scan (1-1000)
 *   example: '50'
 * steps:
 *   validate_repo:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{validate.py}'
 *     - $repo
 *     - $depth
 *   scan_log:
 *     type: process.exec
 *     timeout_ms: 30000
 *     depends_on:
 *     - validate_repo
 *     argv:
 *     - python3
 *     - '@resource{scan_log.py}'
 *     - '@validate_repo{$.stdout.text | fromjson | .repo_abs}'
 *     - '@validate_repo{$.stdout.text | fromjson | .depth}'
 *   scan_config:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on:
 *     - validate_repo
 *     argv:
 *     - python3
 *     - '@resource{scan_config.py}'
 *     - '@validate_repo{$.stdout.text | fromjson | .repo_abs}'
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

const validateStep = ctx.step(stepName("validate_repo"));
const scanLogStep = ctx.step(stepName("scan_log"));
const scanConfigStep = ctx.step(stepName("scan_config"));

const validateResult = parsedStdout(validateStep);
const logResult = parsedStdout(scanLogStep);
const configResult = parsedStdout(scanConfigStep);

const validateData = dataOf(validateResult);
const logData = dataOf(logResult);
const configData = dataOf(configResult);

const validateTruncated = validateResult.kind === "truncated";
const logTruncated = logResult.kind === "truncated";
const configTruncated = configResult.kind === "truncated";

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
  // A step that completed cleanly over an unread repository is not "ok" from
  // the reader's side, whatever its exit code was. Keep the whole ledger on
  // one story rather than showing an ok row next to a note saying nothing
  // was scanned.
  if (validateData?.no_repo_given) return `  degraded  ${label}  ${okNote(parsed)}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

// Zero findings is the daily-habit hook: a clean bill must read as a
// positive result, not an absence of data, so every collection below is
// Array.isArray-guarded and defaults to "none" rather than throwing.
//
// Defensive field projection: every finding is re-shaped to exactly these
// four fields regardless of what the producer emits, so a future producer
// regression (an extra field, a full commit message) can never leak past
// this line into any output representation below.
const findings = (Array.isArray(logData?.findings) ? logData.findings : []).map((f: any) => ({
  sha7: f?.sha7 ?? null,
  class: f?.class ?? null,
  pattern: f?.pattern ?? null,
  line_redacted: f?.line_redacted ?? null,
}));
const scanned = typeof logData?.scanned === "number" ? logData.scanned : 0;
const flaggedShas = new Set(findings.map((f: any) => f?.sha7).filter(Boolean));
const flaggedCount = flaggedShas.size;

const lines: string[] = [];
lines.push("COMMIT ATTRIBUTION GUARD");
lines.push("");

if (validateData?.no_repo_given) {
  // The default invocation. Not a failure and NOT a clean bill: nothing was
  // read, so the report says what to type instead of reporting zero findings.
  lines.push("no repository given — nothing was scanned");
  lines.push("");
  lines.push("  point it at a repository with an ABSOLUTE path:");
  lines.push("    rote play run https://play.modiqo.ai/dotisacat/commit-attribution-guard --yes repo=/path/to/your/repo");
  lines.push("");
  lines.push("  a relative path resolves inside this play's own workspace, not where you ran the command,");
  lines.push("  which is why there is no useful default here.");
} else if (logTruncated) {
  lines.push(`scan unavailable — scan_log: ${truncationNote(logResult.bytes)}`);
} else if (!logData) {
  lines.push(`scan unavailable — scan_log step ${scanLogStep.outcome.status}`);
} else {
  if (flaggedCount === 0) {
    lines.push(`0 of ${scanned} — your history is clean`);
  } else {
    lines.push(`${flaggedCount} of your last ${scanned} commits carry AI attribution marks`);
  }
  if (validateData?.empty_repo) {
    lines.push("(repository has no commits yet)");
  }
  if (!Array.isArray(logData.findings)) {
    lines.push("(findings did not parse as a list; treating as none)");
  }
  lines.push("");

  lines.push(`FINDINGS (${findings.length})`);
  if (findings.length === 0) {
    lines.push("  none — no AI-attribution trailers or body marks in the scanned range");
  } else {
    findings.forEach((f: any) => {
      const sha = String(f?.sha7 ?? "???????").padEnd(9);
      const cls = String(f?.class ?? "?").padEnd(11);
      const pattern = String(f?.pattern ?? "?").padEnd(24);
      const line = String(f?.line_redacted ?? "");
      lines.push(`  ${sha} ${cls} ${pattern} ${line}`);
    });
  }
}

lines.push("");
lines.push("SOURCES (could re-inject a mark into a future commit)");
if (validateData?.no_repo_given) {
  // Nothing was read, so nothing here is "clean". Saying so is the whole
  // point: a source section that reports clean over an unread repository is
  // the same defect as a clean bill over a truncated step.
  lines.push("  not scanned — no repository given");
} else if (configTruncated) {
  lines.push(`  unavailable — scan_config: ${truncationNote(configResult.bytes)}`);
} else if (!configData) {
  lines.push(`  unavailable — scan_config step ${scanConfigStep.outcome.status}`);
} else {
  const tmpl = configData.commit_template;
  if (!tmpl) {
    lines.push("  commit.template: unavailable");
  } else if (tmpl.warning) {
    lines.push(`  commit.template: degraded — ${tmpl.warning}`);
  } else if (!tmpl.configured) {
    lines.push("  commit.template: not configured");
  } else if (tmpl.readable === false) {
    lines.push(`  commit.template: ${tmpl.path} — configured but unreadable`);
  } else if (tmpl.flagged) {
    lines.push(`  commit.template: ${tmpl.path} — FLAGGED: ${tmpl.pattern}`);
  } else {
    lines.push(`  commit.template: ${tmpl.path} — clean`);
  }

  const hooks = Array.isArray(configData.hooks) ? configData.hooks : [];
  if (!Array.isArray(configData.hooks)) {
    lines.push("  hooks: degraded — hooks was not a list");
  } else if (hooks.length === 0) {
    lines.push("  hooks: none reported");
  } else {
    hooks.forEach((h: any) => {
      if (h?.warning) {
        lines.push(`  hook ${h.name}: degraded — ${h.warning}`);
      } else if (!h?.exists) {
        lines.push(`  hook ${h?.name}: not present`);
      } else if (h.flagged) {
        lines.push(`  hook ${h.name}: FLAGGED: ${h.pattern}`);
      } else {
        lines.push(`  hook ${h.name}: present, clean`);
      }
    });
  }
}

lines.push("");
lines.push("STAGES");
lines.push(
  stageLine("validate repo   ", validateStep, validateResult, (p) =>
    p.empty_repo ? `${p.repo_abs} (empty repo)` : `${p.repo_abs} @ depth ${p.depth}`,
  ),
);
lines.push(
  stageLine("scan commit log ", scanLogStep, logResult, (p) =>
    `${p.scanned} commit(s) scanned, ${(Array.isArray(p.findings) ? p.findings.length : 0)} finding(s)`,
  ),
);
lines.push(
  stageLine("scan sources    ", scanConfigStep, configResult, (p) => {
    if (validateData?.no_repo_given) return "no repository given; nothing scanned";
    const tmplNote = p.commit_template?.flagged ? "template flagged" : "template clean";
    const hookFlags = Array.isArray(p.hooks) ? p.hooks.filter((h: any) => h.flagged).length : 0;
    return `${tmplNote}, ${hookFlags} hook(s) flagged`;
  }),
);

out.human(lines.join("\n"));

out.summary(
  logTruncated
    ? `commit attribution scan unavailable (scan_log output truncated at rote's capture cap)`
    : logData
      ? (flaggedCount === 0
          ? `0 of ${scanned} commits carry AI attribution marks`
          : `${flaggedCount} of ${scanned} commits carry AI attribution marks`)
      : "commit attribution scan unavailable (degraded)",
);

out.result({
  validate: {
    status: validateStep.outcome.status,
    repo_abs: validateData?.repo_abs ?? null,
    depth: validateData?.depth ?? null,
    empty_repo: validateData?.empty_repo ?? null,
    warning: validateTruncated ? truncationNote(validateResult.bytes) : validateData?.warning ?? null,
  },
  scan_log: {
    status: scanLogStep.outcome.status,
    scanned,
    findings,
    warning: logTruncated ? truncationNote(logResult.bytes) : null,
  },
  scan_config: {
    status: scanConfigStep.outcome.status,
    sources: configData ?? null,
    warning: configTruncated ? truncationNote(configResult.bytes) : null,
  },
  totals: { flagged_commits: flaggedCount, scanned },
  representations: {
    human: "complete — headline, findings table (sha, class, pattern, matched line), sources section, stage ledger",
    json: "canonical — full validate/scan_log/scan_config objects the human view renders, plus totals",
    summary: "intentionally lossy — flagged-commit count and scanned count only",
  },
});
