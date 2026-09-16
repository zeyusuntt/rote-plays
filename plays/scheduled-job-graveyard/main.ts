#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: scheduled-job-graveyard
 * description: 'Reports the scheduled jobs on THIS machine you have probably forgotten exist: your user crontab, LaunchAgents plists, launchd''s own live status for them (pid, last-exit code), and -- names only, content never opened, no sudo -- /etc/crontab, /etc/cron.d, and the system LaunchDaemons directories. On Linux, systemd user timers stand in for LaunchAgents. Every source degrades on its own, and an absent source is reported as a plain, honest absence, never a warning. Each job is classified healthy, target-missing (target no longer exists on disk), stale-suspect (target untouched in stale_days with no recent-run evidence), silent-failure-suspect (launchd''s own last exit status is nonzero -- exit 127 often means macOS TCC silently denied folder access), or opaque (command could not be parsed). Only the first absolute-path token in a command is tested, so an interpreter-wrapped job like /bin/zsh script.sh is checked against the interpreter, not the script -- a disclosed blind spot, not a bug. Every label carries -suspect wording, never a certainty, and a nonzero exit is reported as literally "last exit N -- check it", never "broken" or "dead". Nothing here edits a crontab, rewrites a plist, or loads/unloads/signals any job; every fix is printed as text only, for you to act on yourself. Read-only, no sudo, no credentials, no network; needs only python3.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/scheduled-job-graveyard
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: scheduled-job-graveyard
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   enum_jobs: resources/presentation-fixtures/enum_jobs/fixture.yaml
 *   classify_jobs: resources/presentation-fixtures/classify_jobs/fixture.yaml
 * tags:
 * - domain-developer-workflow
 * - job-scheduler-audit
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-developer-workflow
 *   - job-scheduler-audit
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       enum:
 *         type: object
 *       classify:
 *         type: object
 *       graveyard:
 *         type: object
 *       representations:
 *         type: object
 * parameters:
 * - name: stale_days
 *   param_type: integer
 *   required: false
 *   default: '365'
 *   description: A target script untouched this long is flagged stale-suspect (30-3650)
 *   example: '365'
 * steps:
 *   enum_jobs:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{enum_jobs.py}'
 *   classify_jobs:
 *     type: process.exec
 *     timeout_ms: 20000
 *     depends_on:
 *     - enum_jobs
 *     argv:
 *     - python3
 *     - '@resource{classify_jobs.py}'
 *     - '@enum_jobs{$.stdout.text | fromjson | .packed_jobs}'
 *     - '@enum_jobs{$.stdout.text | fromjson | .packed_status}'
 *     - $stale_days
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
 * wins: it is the cause, unparseable only its symptom. */
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

const enumStep = ctx.step(stepName("enum_jobs"));
const classifyStep = ctx.step(stepName("classify_jobs"));

const enumResult = readStdout(enumStep);
const classifyResult = readStdout(classifyStep);
const enumTruncated = enumResult.kind === "truncated";
const classifyTruncated = classifyResult.kind === "truncated";

const enumData = enumResult.kind === "ok" ? enumResult.data : null;
const data = classifyResult.kind === "ok" ? classifyResult.data : null;

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
  if (parsed?.warning) return `  degraded  ${label}  ${parsed.warning}`;
  if (parsed && parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const lines: string[] = [];
lines.push("SCHEDULED JOB GRAVEYARD");
lines.push("");

if (classifyTruncated) {
  lines.push(
    `graveyard unavailable — classify step output was truncated at rote's capture cap (${bytesLabel(classifyResult.bytes)} captured); ` +
      "this report covers only part of what the step produced",
  );
} else if (!data) {
  lines.push(`graveyard unavailable — classify step ${classifyStep.outcome.status}`);
} else if (!data.ok) {
  lines.push(`graveyard degraded — ${data.error ?? "unknown reason"}`);
} else {
  const counts = data.counts ?? {};
  const total = counts.total ?? 0;
  const healthy = counts.healthy ?? 0;
  const missing = counts["target-missing"] ?? 0;
  const suspects = counts["silent-failure-suspect"] ?? 0;
  const stale = counts["stale-suspect"] ?? 0;
  const opaque = counts.opaque ?? 0;
  // A zero-warning, non-truncated enum step is required before any "clean
  // bill" sentence is allowed to print: a degraded source (a source that
  // could not be read at all) must never be conflated with "nothing found
  // there" -- see MAJOR #3 in the hardening log. A truncated enum step is
  // the same category of problem as a degraded one: this play cannot claim
  // a clean bill on input it did not see in full.
  const enumWarning: string | null = enumData?.warning ?? null;

  lines.push(
    `${total} scheduled jobs: ${healthy} healthy, ${missing} target-missing, ${suspects} silent-failure-suspects`,
  );
  if (stale > 0 || opaque > 0) {
    lines.push(`(+ ${stale} stale-suspect, ${opaque} opaque -- see the table below)`);
  }
  if (total > 0 && missing === 0 && suspects === 0 && stale === 0 && opaque === 0) {
    if (enumTruncated) {
      lines.push(
        `incomplete, not a clean bill: no problems in the ${total} job(s) actually enumerated, but enum_jobs output was ` +
          `truncated at rote's capture cap (${bytesLabel(enumResult.bytes)} captured) -- see UNVERIFIED`,
      );
    } else if (!enumWarning) {
      lines.push("clean bill: every job's target exists, none show a nonzero launchd exit, and none are stale-suspect or opaque.");
    } else {
      lines.push(`incomplete, not a clean bill: no problems in the ${total} job(s) actually enumerated, but enumeration was degraded -- ${enumWarning}`);
    }
  } else if (total === 0) {
    if (enumTruncated) {
      lines.push(
        `incomplete, not a clean bill: zero jobs classified, but enum_jobs output was truncated at rote's capture cap ` +
          `(${bytesLabel(enumResult.bytes)} captured) -- see UNVERIFIED`,
      );
    } else if (!enumWarning) {
      lines.push("clean bill: no user crontab entries and no LaunchAgents (or systemd user timers) found on this machine.");
    } else {
      lines.push(`incomplete, not a clean bill: zero jobs classified, but enumeration was degraded -- ${enumWarning}`);
    }
  }
  lines.push("");

  // Degraded JSON can carry a truthy value here that isn't an array; guard
  // every collection so a shape mismatch renders a degradation note
  // instead of crashing the presentation on .forEach().
  const jobs = Array.isArray(data.jobs) ? data.jobs : [];
  const truncate = (s: string, max: number) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);
  lines.push(`JOBS (${jobs.length})`);
  lines.push(
    `  ${"SOURCE".padEnd(14)} ${"LABEL".padEnd(36)} ${"SCHEDULE".padEnd(24)} ${"STATE".padEnd(22)} EVIDENCE`,
  );
  if (!Array.isArray(data.jobs)) {
    lines.push("  degraded — jobs was not a list; nothing to show");
  } else if (jobs.length === 0) {
    lines.push("  none found");
  } else {
    jobs.forEach((j: any) => {
      lines.push(
        `  ${truncate(String(j.source), 14).padEnd(14)} ${truncate(String(j.label), 35).padEnd(36)} ` +
        `${truncate(String(j.schedule_summary), 23).padEnd(24)} ${String(j.state).padEnd(22)} ${j.evidence}`,
      );
    });
  }
  lines.push("");

  const advisories = Array.isArray(data.advisories) ? data.advisories : [];
  lines.push("ADVISORIES — text only, nothing here is executed on your behalf:");
  if (!Array.isArray(data.advisories)) {
    lines.push("  degraded — advisories was not a list; nothing to show");
  } else if (advisories.length === 0) {
    lines.push("  none");
  } else {
    advisories.forEach((a: any) => lines.push(`  ${a.label}: ${a.text}`));
  }
}

lines.push("");
lines.push("SYSTEM (list-only — content never read, no sudo)");
const sys = enumData?.system;
if (sys && typeof sys === "object") {
  lines.push(`  /etc/crontab: ${sys.etc_crontab_present ? "present" : "absent"}`);
  // null (as opposed to []) means the directory exists but could not be
  // listed -- an honest "unknown", never conflated with a confirmed-empty
  // listing; see MAJOR #11 in the hardening log.
  if (sys.etc_cron_d_names === null) {
    lines.push("  /etc/cron.d: unknown -- listing failed, see warning above");
  } else {
    const cronD = Array.isArray(sys.etc_cron_d_names) ? sys.etc_cron_d_names : [];
    lines.push(`  /etc/cron.d: ${cronD.length} entr${cronD.length === 1 ? "y" : "ies"}`);
    cronD.forEach((n: string) => lines.push(`    ${n}`));
  }
  if (sys.launchdaemons_library_names === null) {
    lines.push("  /Library/LaunchDaemons: unknown -- listing failed, see warning above");
  } else {
    const libNames = Array.isArray(sys.launchdaemons_library_names) ? sys.launchdaemons_library_names : [];
    lines.push(`  /Library/LaunchDaemons: ${libNames.length} label(s)`);
    libNames.forEach((n: string) => lines.push(`    ${n}`));
  }
  const appleCount = sys.launchdaemons_apple_count;
  lines.push(
    `  /System/Library/LaunchDaemons: ${appleCount ?? "unknown"} plist(s) -- Apple built-in, counted only, never listed by name`,
  );
} else if (enumTruncated) {
  lines.push(
    `  unavailable — enum step output was truncated at rote's capture cap (${bytesLabel(enumResult.bytes)} captured); ` +
      "this report covers only part of what the step produced",
  );
} else {
  lines.push("  unavailable — enum step did not report a system inventory");
}

lines.push("");
lines.push("STAGES");
lines.push(
  stageLine("enum jobs   ", enumStep, enumResult, (p) =>
    `${p.counts?.user_crontab ?? 0} crontab, ${p.counts?.user_launchagents ?? 0} LaunchAgent(s), ` +
    `${p.counts?.systemd_timers ?? 0} systemd timer(s), ${p.counts?.launchctl_status_rows ?? 0} loaded launchd job(s)`,
  ),
);
lines.push(
  stageLine("classify    ", classifyStep, classifyResult, (p) => `${p.counts?.total ?? 0} classified`),
);

lines.push("");
lines.push("CHECKED");
lines.push("  - your user crontab via `crontab -l`");
lines.push("  - your ~/Library/LaunchAgents plists via plutil -convert json (per-file degrade on a bad plist)");
lines.push("  - launchd's own last-exit status for loaded jobs via `launchctl list`");
lines.push("  - /etc/crontab presence, /etc/cron.d filenames, and system LaunchDaemons filenames (names only, no content, no sudo)");
lines.push("  - on Linux: your user crontab, plus systemd user timers via `systemctl --user list-timers` and each unit's own ExecStart");
lines.push("UNVERIFIED");
if (enumTruncated) {
  lines.push(
    `  - enum_jobs: output was truncated at rote's capture cap (${bytesLabel(enumResult.bytes)} captured) -- ` +
      "this report covers only part of what the step produced, see STAGES",
  );
}
if (classifyTruncated) {
  lines.push(
    `  - classify_jobs: output was truncated at rote's capture cap (${bytesLabel(classifyResult.bytes)} captured) -- ` +
      "this report covers only part of what the step produced, see STAGES",
  );
}
lines.push("  - whether a job SHOULD exist that doesn't -- this play only reports what it found, never what's missing entirely");
lines.push("  - the content of any system LaunchDaemons plist or /etc/crontab (list-only by design; no sudo is ever used)");
lines.push("  - whether a launchd last-exit status reflects the newest run or an older one -- `launchctl list` discloses no run timestamp");
lines.push("  - the actual script behind an interpreter-wrapped command (e.g. `/bin/zsh script.sh`) -- only the first absolute-path token, the interpreter here, is checked; see this play's description");

out.human(lines.join("\n"));

out.summary(
  classifyTruncated
    ? `scheduled job graveyard unavailable — classify step output truncated at rote's capture cap (${bytesLabel(classifyResult.bytes)} captured)`
    : data?.ok
      ? `${data.counts?.total ?? 0} scheduled jobs, ${data.counts?.["target-missing"] ?? 0} target-missing, ` +
        `${data.counts?.["silent-failure-suspect"] ?? 0} silent-failure-suspect(s), ${data.counts?.["stale-suspect"] ?? 0} stale-suspect, ` +
        `${data.counts?.opaque ?? 0} opaque` +
        (enumTruncated ? `; enum_jobs truncated at rote's capture cap, coverage incomplete` : "")
      : "scheduled job graveyard unavailable (degraded)",
);

out.result({
  enum: {
    status: enumStep.outcome.status,
    counts: enumData?.counts ?? null,
    warning: enumData?.warning ?? null,
    truncated: enumTruncated,
    truncated_bytes: enumTruncated ? enumResult.bytes : null,
  },
  classify: {
    status: classifyStep.outcome.status,
    warning: data?.warning ?? null,
    truncated: classifyTruncated,
    truncated_bytes: classifyTruncated ? classifyResult.bytes : null,
  },
  graveyard: data,
  representations: {
    human: "complete — headline, per-job table, text-only advisories, list-only system inventory, stage ledger, checked/unverified footer",
    json: "canonical — full graveyard object the human view renders (every classified job, no truncation) plus enum's system list-only inventory",
    summary: "intentionally lossy — state counts only",
  },
});
