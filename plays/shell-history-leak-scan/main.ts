#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: shell-history-leak-scan
 * description: 'A git-history scanner reads what got committed. It never reads what got TYPED: an export or curl invocation carrying a raw credential at a shell prompt lands in ~/.zsh_history, ~/.bash_history, ~/.local/share/fish/fish_history, ~/.python_history, or ~/.psql_history instead -- files no commit-scanner ever opens. Classifies what it finds as secret-shaped: export/declare/set (bash, zsh, fish) or a bare VAR=value where the NAME looks secret-related (key, token, secret, password, credential, auth) AND the value is a literal, never a $VAR indirection (export KEY=$FROM_ENV is the deliberately SAFE case, never flagged); a Bearer auth header or token; a --password/--token flag with a literal value; and known token shapes (sk-, ghp_, gho_, xox[bp]-, AKIA, an eyJ-led JWT). Every finding is reduced, including in its own JSON, to file, line number, a short SHAPE label, the variable/flag name, and the first 4 characters plus total length of the matched value -- NEVER the full value, never the full line. The report closes with a remediation note (rotate first, then scrub -- a still-open shell can silently rewrite it back over your edit) and a CHECKED/UNVERIFIED coverage ledger, never a clean bill unless at least one file was actually scanned. Nothing is ever executed on your behalf, and no history file is ever written, moved, or truncated. Read-only, no credentials, no network; needs only python3.'
 * version: 0.1.3
 * source_url: https://play.modiqo.ai/dotisacat/shell-history-leak-scan
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: shell-history-leak-scan
 * metadata:
 *   version: 0.1.3
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   locate_histories: resources/presentation-fixtures/locate_histories/fixture.yaml
 *   scan: resources/presentation-fixtures/scan/fixture.yaml
 * tags:
 * - domain-security
 * - job-secret-hygiene
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-security
 *   - job-secret-hygiene
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       ok:
 *         type: boolean
 *       headline:
 *         type: string
 *       findings:
 *         type: array
 *       totals:
 *         type: object
 *       files:
 *         type: array
 *       locate:
 *         type: object
 *       scan:
 *         type: object
 *       checked:
 *         type: array
 *       unverified:
 *         type: array
 *       representations:
 *         type: object
 * parameters:
 * - name: max_findings
 *   param_type: integer
 *   required: false
 *   default: '50'
 *   description: Maximum number of findings to list individually (1-500), the rest summarized as a count
 *   example: '50'
 * steps:
 *   locate_histories:
 *     type: process.exec
 *     timeout_ms: 10000
 *     argv:
 *     - python3
 *     - '@resource{scan_history.py}'
 *     - --locate
 *   scan:
 *     type: process.exec
 *     timeout_ms: 35000
 *     depends_on:
 *     - locate_histories
 *     argv:
 *     - python3
 *     - '@resource{scan_history.py}'
 *     - --scan
 *     - '@locate_histories{$.stdout.text | fromjson | .packed}'
 *     - $max_findings
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

type StdoutResult =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

/** Read a step's stdout, distinguishing WHY it isn't usable JSON: absent
 * (step didn't complete, or stdout was empty), truncated at rote's capture
 * cap, or unparseable (present, not truncated, but not valid JSON).
 * Truncation is read directly off the stdout.truncated flag -- strict ===
 * true, never inferred from a JSON.parse failure -- so a truncated payload
 * is never misdiagnosed as merely malformed. When both apply, truncated
 * wins: it is the cause, unparseable only its symptom. This distinction
 * matters most for a play like this one, which streams and classifies its
 * own input line by line internally -- a truncated JSON envelope from this
 * step must never be read as a smaller-but-complete scan. */
function readStdout(step: ReturnType<typeof ctx.step>): StdoutResult {
  const body = bodyOf(step);
  const s = body?.stdout;
  const truncated = s?.truncated === true;
  const text = typeof s?.text === "string" ? s.text : "";
  if (truncated) return { kind: "truncated", bytes: typeof s?.bytes === "number" ? s.bytes : null };
  if (!text.trim()) return { kind: "absent" };
  try {
    const data = JSON.parse(text);
    return data && typeof data === "object" ? { kind: "ok", data } : { kind: "unparseable" };
  } catch {
    return { kind: "unparseable" };
  }
}

function parsedStdout(step: ReturnType<typeof ctx.step>): any {
  const r = readStdout(step);
  return r.kind === "ok" ? r.data : null;
}

function bytesLabel(n: number | null): string {
  if (typeof n !== "number") return "an unknown number of bytes";
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

/** One STAGES ledger row, tolerant of every outcome status the runner can
 * hand back. A step that completed but was truncated at rote's capture cap
 * is reported as truncated, never silently folded into "degraded" (which
 * this play uses for a genuinely malformed or self-reported-bad result). */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, result: StdoutResult, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (result.kind === "truncated") {
    return `  truncated ${label}  output truncated at rote's capture cap (${bytesLabel(result.bytes)} captured) -- this report covers only part of what the step produced`;
  }
  const parsed = result.kind === "ok" ? result.data : null;
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const locateStep = ctx.step(stepName("locate_histories"));
const scanStep = ctx.step(stepName("scan"));

const locateResult = readStdout(locateStep);
const scanResult = readStdout(scanStep);
const locateTruncated = locateResult.kind === "truncated";
const scanTruncated = scanResult.kind === "truncated";

const locateData = locateResult.kind === "ok" ? locateResult.data : null;
const scanData = scanResult.kind === "ok" ? scanResult.data : null;

const totals = scanData?.totals && typeof scanData.totals === "object" ? scanData.totals : {};
const filesChecked = typeof totals.files_checked === "number" ? totals.files_checked : (locateData?.count ?? 0);
const filesScanned = typeof totals.files_scanned === "number" ? totals.files_scanned : 0;
const totalLines = typeof totals.total_lines_scanned === "number" ? totals.total_lines_scanned : 0;
const totalFindings = typeof totals.total_findings === "number" ? totals.total_findings : 0;
const findingsShown = typeof totals.findings_shown === "number" ? totals.findings_shown : 0;
const findingsTruncated = typeof totals.findings_truncated === "number" ? totals.findings_truncated : 0;

// Guarded the same way every collection-bearing field in this fleet is: a
// shape mismatch from a degraded/malformed producer renders as an empty
// list rather than throwing on .forEach()/.map() below.
const findings: any[] = Array.isArray(scanData?.findings) ? scanData.findings : [];
const files: any[] = Array.isArray(scanData?.files) ? scanData.files : [];

const plural = (n: number, word: string) => `${word}${n === 1 ? "" : "s"}`;

// A missing/malformed locate_histories output must never read the same as
// "checked all 5, found none" (a legitimate, unremarkable outcome) -- same
// distinction this fleet already draws for its own base_dir sweeps.
const locateUnavailable = !locateData || locateData.ok === false;
const scanUnavailable = !scanData || scanData.ok === false;

function headlineLine(): string {
  if (scanTruncated) {
    return `scan unavailable -- scan step output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured); this report covers only part of what the step produced`;
  }
  if (scanUnavailable) return `scan unavailable -- scan step ${scanStep.outcome.status}`;
  const oldest = scanData.oldest_iso ? ` (oldest from ${scanData.oldest_iso})` : "";
  const entryWord = totalFindings === 1 ? "entry" : "entries";
  return `${totalFindings} secret-shaped ${entryWord} across ${filesScanned} history ${plural(filesScanned, "file")}${oldest}`;
}

// A clean bill (or an honest "nothing to scan") requires every step behind
// it to have been read in full -- a step truncated at rote's capture cap
// means this play did not finish looking, and "0 findings" or "nothing to
// scan" must never be reported as if it had.
const earnedCleanBill = !scanUnavailable && !locateTruncated && !scanTruncated && totalFindings === 0 && filesScanned > 0;
const nothingToScan = !scanUnavailable && !locateTruncated && !scanTruncated && filesScanned === 0;

// ---- human view -------------------------------------------------------------
const lines: string[] = [];
lines.push("SHELL HISTORY LEAK SCAN");
lines.push("");

lines.push(headlineLine());
if (earnedCleanBill) {
  lines.push("clean -- nothing secret-shaped found in any scanned file.");
} else if (nothingToScan) {
  lines.push("nothing to scan -- none of the 5 known shell-history files were found and readable on this machine.");
}
lines.push("");

lines.push("FINDINGS");
if (scanTruncated) {
  lines.push(`  unavailable -- scan step output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured); this report covers only part of what the step produced`);
} else if (!Array.isArray(scanData?.findings)) {
  lines.push("  degraded -- findings was not a list; nothing to show");
} else if (findings.length === 0) {
  lines.push("  none");
} else {
  findings.forEach((f: any) => {
    lines.push(
      `  ${String(f?.file ?? "?").padEnd(40)} line ${String(f?.line ?? "?").padStart(6)}  ` +
      `${String(f?.shape ?? "?").padEnd(20)} ${String(f?.name ?? "?").padEnd(20)} ${f?.value_preview ?? "?"}`,
    );
  });
  if (findingsTruncated > 0) {
    lines.push(`  (${findingsTruncated} more finding(s) not shown; raise max_findings to see them, up to 500)`);
  }
}
lines.push("");

lines.push("ADVISORY");
if (scanTruncated) {
  lines.push(`  unknown -- scan step output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured); rotate/scrub advice withheld until a complete scan is available.`);
} else if (totalFindings > 0) {
  lines.push("  rotate first -- if any finding above is a real, still-valid credential, rotate or revoke it");
  lines.push("  before doing anything else. A history file can be re-read faster than you can scrub it.");
  lines.push("  to scrub a line: delete it from your shell's own in-memory history, then persist that --");
  lines.push("  bash: `history -d <event_num>` then `history -w`; zsh: delete the line, then `fc -W`.");
  lines.push("  editing HISTFILE on disk alone is not enough: every OTHER shell session with this file");
  lines.push("  still open keeps its own in-memory copy, and can atomically REWRITE the file back to that");
  lines.push("  stale copy on exit or the next `history -a`/`fc -A`, silently undoing a disk-only edit.");
  lines.push("  close (or `unset HISTFILE` in) every other open session with this file first.");
} else {
  lines.push("  none needed -- nothing was found to rotate or scrub.");
}
lines.push("");

lines.push("CHECKED (what this report is actually based on)");
if (locateTruncated) {
  lines.push(`  - locate_histories: output was truncated at rote's capture cap (${bytesLabel(locateResult.bytes)} captured) -- this report covers only part of what the step produced, see UNVERIFIED`);
} else if (locateUnavailable) {
  lines.push(`  - locate_histories unavailable -- ${locateData?.warning ?? `step ${locateStep.outcome.status}`}`);
} else if (scanTruncated) {
  lines.push(`  - ${filesChecked} of 5 known history files were located; scan step output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured) -- per-file scan detail unavailable this run, see UNVERIFIED`);
} else if (!Array.isArray(scanData?.files) || files.length === 0) {
  lines.push(`  - ${filesChecked} of 5 known history files were located; per-file detail unavailable`);
} else {
  files.forEach((f: any) => {
    const status = f?.status ?? "unknown";
    const detail = status === "scanned" || status === "error" || status === "budget-exceeded"
      ? `, ${f?.lines_scanned ?? 0} line(s)` : "";
    lines.push(`  - ${f?.file ?? "?"}: ${status}${detail}`);
  });
}
lines.push(`  - ${totalLines} line(s) streamed across ${filesScanned} file(s), one entry at a time`);
lines.push("  - zsh EXTENDED_HISTORY multi-line entries and fish's cmd: block form were parsed, not just split on newlines");
lines.push("");

lines.push("UNVERIFIED (this scan cannot tell you)");
if (locateTruncated) {
  lines.push(`  - locate_histories: output was truncated at rote's capture cap (${bytesLabel(locateResult.bytes)} captured) -- this report covers only part of what the step produced`);
}
if (scanTruncated) {
  lines.push(`  - scan: output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured) -- this report covers only part of what the step produced`);
}
lines.push("  - whether any matched value is still live -- a shape match is not proof");
lines.push("  - secrets in a format none of the known patterns describe");
lines.push("  - history kept outside these 5 known files (a custom HISTFILE, another shell, another tool)");
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine("locate histories", locateStep, locateResult, (p) => `${p.found ?? 0} of ${p.count ?? 5} file(s) found`),
);
lines.push(
  stageLine("scan            ", scanStep, scanResult, (p) => `${p.totals?.files_scanned ?? 0} file(s) scanned, ${p.totals?.total_findings ?? 0} finding(s)`),
);

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
out.summary(
  scanTruncated
    ? `shell history leak scan unavailable -- scan step output truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured)`
    : scanUnavailable
      ? `shell history leak scan unavailable (degraded)`
      : `${totalFindings} secret-shaped entries across ${filesScanned} history files` +
        (earnedCleanBill ? " (clean)" : "") +
        (locateTruncated ? "; locate_histories truncated, coverage incomplete" : ""),
);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: !locateUnavailable && !scanUnavailable && !locateTruncated && !scanTruncated,
  headline: headlineLine(),
  findings,
  totals: {
    files_checked: filesChecked,
    files_scanned: filesScanned,
    total_lines_scanned: totalLines,
    total_findings: totalFindings,
    findings_shown: findingsShown,
    findings_truncated: findingsTruncated,
    earned_clean_bill: earnedCleanBill,
    nothing_to_scan: nothingToScan,
  },
  files,
  locate: {
    status: locateStep.outcome.status,
    warning: locateData?.warning ?? null,
    truncated: locateTruncated,
    truncated_bytes: locateTruncated ? locateResult.bytes : null,
  },
  scan: {
    status: scanStep.outcome.status,
    warning: scanData?.warning ?? null,
    truncated: scanTruncated,
    truncated_bytes: scanTruncated ? scanResult.bytes : null,
  },
  checked: [
    locateTruncated
      ? `locate_histories: output was truncated at rote's capture cap (${bytesLabel(locateResult.bytes)} captured) -- this report covers only part of what the step produced`
      : locateUnavailable
        ? `locate_histories unavailable -- ${locateData?.warning ?? `step ${locateStep.outcome.status}`}`
        : scanTruncated
          ? `${filesChecked} of 5 known history files located; scan step output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured) -- per-file scan detail unavailable this run`
          : `${filesChecked} of 5 known history files located, ${filesScanned} scanned`,
    `${totalLines} line(s) streamed across ${filesScanned} file(s)`,
    "zsh EXTENDED_HISTORY multi-line entries and fish's cmd: block form were parsed",
  ],
  unverified: [
    ...(locateTruncated
      ? [`locate_histories: output was truncated at rote's capture cap (${bytesLabel(locateResult.bytes)} captured) -- this report covers only part of what the step produced`]
      : []),
    ...(scanTruncated
      ? [`scan: output was truncated at rote's capture cap (${bytesLabel(scanResult.bytes)} captured) -- this report covers only part of what the step produced`]
      : []),
    "whether any matched value is still live -- a shape match is not proof",
    "secrets in a format none of the known patterns describe",
    "history kept outside these 5 known files (a custom HISTFILE, another shell, another tool)",
  ],
  representations: {
    human: "complete -- headline, FINDINGS table, text-only ADVISORY, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- full totals and every finding up to max_findings, plus per-file status even when the human view only lists a subset",
    summary: "intentionally lossy -- counts and files only",
  },
});
