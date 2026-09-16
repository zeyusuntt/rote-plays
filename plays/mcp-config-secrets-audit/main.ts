#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: mcp-config-secrets-audit
 * description: 'An API key written straight into an MCP config file is readable by anything that can read your home directory. Reads the same harness-owned config files as our other MCP plays (Claude Code, Claude Desktop, Cursor, Codex, Windsurf) and classifies every env var value each declared server carries by SHAPE, at the moment it is read off disk: a literal secret-shape (an OpenAI-style sk- key, a GitHub ghp_ token, an AWS AKIA key, a JWT, or a high-entropy token) versus safe indirection ($VAR, ${VAR}, or empty) versus a plain literal. You get per-file counts, and the single combination that matters most flagged as the top finding: a file that is world- or group-readable AND holds at least one inline secret-shaped value. A NEVER EXECUTED text advisory appears when a secret-shaped value is found: move it to your OS keychain or a local env manager -- MCP configs travel in backups and dotfile repos. Disabled server blocks are still audited -- an ignored config block can still hold a secret in cleartext. The raw value itself never survives past that one read: never packed into this play''s own data, never printed, including in its own JSON result -- only a var NAME, shape, 4-character preview, and length are kept. Read-only, no credentials transmitted, no network calls, no server spawned, no handshake or probe -- only files and their permission bits are read; needs only python3.'
 * version: 0.1.5
 * source_url: https://play.modiqo.ai/dotisacat/mcp-config-secrets-audit
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: mcp-config-secrets-audit
 * metadata:
 *   version: 0.1.5
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   discover_configs: resources/presentation-fixtures/discover_configs/fixture.yaml
 *   audit: resources/presentation-fixtures/audit/fixture.yaml
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
 *       generated_at:
 *         type: string
 *       totals:
 *         type: object
 *       files:
 *         type: array
 *       findings:
 *         type: array
 *       verbose_rows:
 *         type: array
 *       advisory:
 *         type: string
 *       discover:
 *         type: object
 *       audit:
 *         type: object
 *       checked:
 *         type: array
 *       unverified:
 *         type: array
 *       representations:
 *         type: object
 * parameters:
 * - name: verbose
 *   param_type: integer
 *   required: false
 *   default: '0'
 *   description: (0-1) include a per-entry detail row for every env var examined, not only the secret-shaped ones
 *   example: '0'
 * steps:
 *   discover_configs:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{discover_configs.py}'
 *   audit:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on:
 *     - discover_configs
 *     argv:
 *     - python3
 *     - '@resource{audit_configs.py}'
 *     - '@discover_configs{$.stdout.text | fromjson | .sources_packed}'
 *     - '@discover_configs{$.stdout.text | fromjson | .entries_packed}'
 *     - $verbose
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

/** Read a step's stdout as a discriminated result rather than data | null,
 * so a caller cannot conflate "the payload didn't parse" with "rote never
 * captured all of it". truncated is read off stdout.truncated with a
 * strict === true check -- a missing field is never treated as truncation
 * -- and truncated wins over unparseable when both apply: truncation is
 * the cause, an unparseable payload is only its symptom. */
function parsedStdout(step: ReturnType<typeof ctx.step>): StdoutResult {
  const body = bodyOf(step);
  const stdout = body?.stdout;
  if (stdout?.truncated === true) {
    return { kind: "truncated", bytes: typeof stdout?.bytes === "number" ? stdout.bytes : null };
  }
  const text = stdout?.text ?? "";
  if (typeof text !== "string" || !text.trim()) return { kind: "absent" };
  try {
    const data = JSON.parse(text);
    return data && typeof data === "object" ? { kind: "ok", data } : { kind: "unparseable" };
  } catch {
    return { kind: "unparseable" };
  }
}

/** One STAGES ledger row, tolerant of every outcome status the runner can
 * hand back. A truncated payload gets its own labeled row -- never folded
 * into "degraded" (which reports a payload that parsed but was unusable)
 * or "ok" (which would present a partial read as a complete one). */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, parsed: any, truncatedNote: string | null, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (truncatedNote) {
    return `  ${"truncated".padEnd(8)}  ${label}  ${truncatedNote}`;
  }
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? parsed.warning ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function fmtBytes(n: unknown): string {
  return typeof n === "number" ? `${n.toLocaleString("en-US")} bytes` : "an unknown number of bytes";
}

// "4-character preview = max exposure anywhere" is enforced upstream in
// discover_configs.py and re-enforced one step downstream in
// audit_configs.py -- re-enforced a third time here, at the last boundary
// before human rendering and this play's own JSON result, so a corrupted
// or regressed producer can never surface a longer value in either
// representation this play emits.
const PREVIEW_MAX = 4;
function capPreview(v: unknown): string {
  return typeof v === "string" ? v.slice(0, PREVIEW_MAX) : "";
}

const discoverStep = ctx.step(stepName("discover_configs"));
const auditStep = ctx.step(stepName("audit"));

const discoverResult = parsedStdout(discoverStep);
const discoverData = discoverResult.kind === "ok" ? discoverResult.data : null;
const discoverTruncated = discoverResult.kind === "truncated";

const auditResult = parsedStdout(auditStep);
const auditData = auditResult.kind === "ok" ? auditResult.data : null;
const auditTruncated = auditResult.kind === "truncated";

const anyTruncated = discoverTruncated || auditTruncated;

const totals = auditData?.totals && typeof auditData.totals === "object" ? auditData.totals : {};
const filesFound = typeof totals.config_files_found === "number" ? totals.config_files_found : 0;
const filesParsed = typeof totals.config_files_parsed === "number" ? totals.config_files_parsed : 0;
const secretCount = typeof totals.inline_secret_count === "number" ? totals.inline_secret_count : 0;
const worldReadableCount = typeof totals.world_readable_count === "number" ? totals.world_readable_count : 0;
const groupReadableCount = typeof totals.group_readable_count === "number" ? totals.group_readable_count : 0;
const flaggedCount = typeof totals.flagged_file_count === "number" ? totals.flagged_file_count : 0;
const envEntriesTotal = typeof totals.env_entries_total === "number" ? totals.env_entries_total : 0;
const serversTotal = typeof totals.servers_total === "number" ? totals.servers_total : 0;

// Array.isArray-guarded the same way every collection-bearing field in
// this fleet is: a degraded/malformed producer renders as an empty list
// downstream rather than throwing.
const files: any[] = Array.isArray(auditData?.files) ? auditData.files : [];
// preview re-capped defensively (see capPreview) -- this same array feeds
// both the human FINDINGS DETAIL table below and out.result()'s findings.
const findings: any[] = (Array.isArray(auditData?.findings) ? auditData.findings : []).map(
  (f: any) => ({ ...f, preview: capPreview(f?.preview) }),
);
const verboseRows: any[] = Array.isArray(auditData?.verbose_rows) ? auditData.verbose_rows : [];
const checked: string[] = Array.isArray(auditData?.checked) ? auditData.checked : [];
const unverified: string[] = Array.isArray(auditData?.unverified) ? auditData.unverified : [];
const advisory: string | null = typeof auditData?.advisory === "string" ? auditData.advisory : null;

const plural = (n: number, word: string) => `${word}${n === 1 ? "" : "s"}`;

function headlineLine(): string {
  if (secretCount === 0) {
    return `${filesFound} config ${plural(filesFound, "file")} checked (${filesParsed} parsed): no inline secret-shaped values found`;
  }
  return (
    `${filesFound} config ${plural(filesFound, "file")}: ${secretCount} inline secret-shaped ` +
    `${plural(secretCount, "value")}, ${worldReadableCount} world-readable`
  );
}

const lines: string[] = [];
lines.push("MCP CONFIG SECRETS AUDIT");
lines.push("");

if (auditTruncated) {
  lines.push(
    `audit step output was truncated at rote's capture cap (${fmtBytes(auditResult.kind === "truncated" ? auditResult.bytes : null)} captured) -- this report covers only part of what the step produced`,
  );
} else if (discoverTruncated) {
  lines.push(
    `discover_configs step output was truncated at rote's capture cap (${fmtBytes(discoverResult.kind === "truncated" ? discoverResult.bytes : null)} captured) -- this report covers only part of what the step produced`,
  );
} else if (!auditData) {
  lines.push(`audit unavailable -- audit step ${auditStep.outcome.status}`);
} else if (auditData.ok === false) {
  lines.push(`audit degraded -- ${auditData.error ?? "unknown reason"}`);
} else {
  lines.push(headlineLine());
  if (flaggedCount > 0) {
    lines.push(
      `  ⚠ ${flaggedCount} ${plural(flaggedCount, "file")} world- or group-readable AND holding an inline secret -- the top flag`,
    );
  } else if (secretCount > 0) {
    lines.push("  none of those secret-holding files are readable by group or world -- permissions look locked down");
  }
  if (secretCount === 0) {
    lines.push("  clean bill: every env value examined is either a plain literal, an empty value, or a $VAR/${VAR} indirection");
  }
  lines.push("");

  lines.push(`PER-FILE (${files.length})`);
  if (files.length === 0) {
    lines.push("  none -- no fixed harness config path exists on this machine");
  } else {
    lines.push(
      `  ${"CONFIG".padEnd(52)}${"HARNESS".padEnd(16)}${"ENV".padStart(4)}  ${"SECRETS".padStart(7)}  ${"PERMS".padEnd(11)}FLAG`,
    );
    files.forEach((f: any) => {
      const cfg = truncate(String(f?.path_display ?? "?"), 51).padEnd(52);
      const harness = String(f?.harness ?? "?").padEnd(16);
      const env = String(f?.env_entries ?? 0).padStart(4);
      const secrets = String(f?.inline_secret_count ?? 0).padStart(7);
      const permsRaw = f?.mode_octal ? String(f.mode_octal) : String(f?.status ?? "?");
      const perms = truncate(permsRaw, 10).padEnd(11);
      const flag = f?.flagged
        ? "WORLD/GROUP-READABLE + SECRET"
        : f?.world_readable || f?.group_readable
          ? "readable, no secret"
          : "-";
      lines.push(`  ${cfg}${harness}${env}  ${secrets}  ${perms}${flag}`);
    });
  }
  lines.push("");

  lines.push(`FINDINGS DETAIL (${findings.length}) -- var NAME, shape, 4-char preview + length, file (never the value)`);
  if (findings.length === 0) {
    lines.push("  none -- no env value matched a secret shape");
  } else {
    findings.forEach((f: any) => {
      const disabledNote = f?.enabled === false ? " [disabled block]" : "";
      lines.push(
        `  ${String(f?.var_name ?? "?").padEnd(28)} [${String(f?.shape ?? "?").padEnd(18)}] ` +
        `${String(f?.preview ?? "")}… (len ${f?.length ?? "?"})  ` +
        `${f?.harness ?? "?"}/${f?.server ?? "?"} in ${f?.path_display ?? "?"}${disabledNote}`,
      );
    });
  }
  lines.push("");

  if (verboseRows.length > 0) {
    lines.push(`PER-ENTRY DETAIL (verbose=1) -- every env var examined, all shapes (${verboseRows.length})`);
    verboseRows.forEach((r: any) => {
      const disabledNote = r?.enabled === false ? " [disabled block]" : "";
      lines.push(
        `  ${String(r?.var_name ?? "?").padEnd(28)} [${String(r?.shape ?? "?").padEnd(18)}] ` +
        `${r?.harness ?? "?"}/${r?.server ?? "?"} in ${r?.path_display ?? "?"}${disabledNote}`,
      );
    });
    lines.push("");
  }

  lines.push("ADVISORY -- text only, nothing here was executed");
  lines.push(advisory ? `  ${advisory}` : "  none -- no inline secret-shaped value was found, nothing to move");
  lines.push("");

  lines.push("CHECKED -- what this run actually read");
  checked.forEach((c) => lines.push(`  - ${c}`));
  lines.push("");

  lines.push("UNVERIFIED -- what this play cannot tell you");
  unverified.forEach((u) => lines.push(`  - ${u}`));
  lines.push("");
}

lines.push("STAGES");
lines.push(
  stageLine(
    "discover configs  ",
    discoverStep,
    discoverData,
    discoverTruncated
      ? `output was truncated at rote's capture cap (${fmtBytes(discoverResult.kind === "truncated" ? discoverResult.bytes : null)} captured) -- this report covers only part of what the step produced`
      : null,
    (p) => `${p.sources_count ?? 0} source(s), ${p.servers_total ?? 0} server(s), ${p.env_vars_total ?? 0} env var(s) classified`,
  ),
);
lines.push(
  stageLine(
    "audit             ",
    auditStep,
    auditData,
    auditTruncated
      ? `output was truncated at rote's capture cap (${fmtBytes(auditResult.kind === "truncated" ? auditResult.bytes : null)} captured) -- this report covers only part of what the step produced`
      : null,
    (p) => `${p.files?.length ?? 0} file(s) reported, ${p.findings?.length ?? 0} finding(s)`,
  ),
);
lines.push("");
lines.push("This play never spawns a server -- discovery and static file analysis only, no probe step at all.");
lines.push("A 4-character preview and a length are the most this play ever shows of an env value, anywhere -- never the value.");

out.human(lines.join("\n"));

out.summary(
  auditTruncated
    ? "mcp-config-secrets-audit unavailable (audit output truncated at rote's capture cap)"
    : discoverTruncated
      ? "mcp-config-secrets-audit unavailable (discover_configs output truncated at rote's capture cap)"
      : auditData && auditData.ok !== false
        ? `mcp-config-secrets-audit: ${headlineLine()}` + (flaggedCount > 0 ? `, ${flaggedCount} readable+secret (top flag)` : "")
        : "mcp-config-secrets-audit unavailable (degraded)",
);

out.result({
  ok: Boolean(discoverData && auditData && auditData.ok !== false && !anyTruncated),
  generated_at: new Date().toISOString(),
  totals: {
    config_files_found: filesFound,
    config_files_parsed: filesParsed,
    servers_total: serversTotal,
    env_entries_total: envEntriesTotal,
    inline_secret_count: secretCount,
    world_readable_count: worldReadableCount,
    group_readable_count: groupReadableCount,
    flagged_file_count: flaggedCount,
  },
  files,
  findings,
  verbose_rows: verboseRows,
  advisory,
  discover: {
    status: discoverStep.outcome.status,
    sources_count: discoverData?.sources_count ?? null,
    warning: discoverData?.warning ?? null,
    truncated: discoverTruncated,
    truncated_bytes: discoverTruncated && discoverResult.kind === "truncated" ? discoverResult.bytes : null,
  },
  audit: {
    status: auditStep.outcome.status,
    warning: auditData?.warning ?? null,
    truncated: auditTruncated,
    truncated_bytes: auditTruncated && auditResult.kind === "truncated" ? auditResult.bytes : null,
  },
  checked,
  unverified,
  representations: {
    human: "complete -- headline, top-flag callout, per-file table, findings detail, optional per-entry verbose detail, advisory, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- every reported file row and every secret-shaped finding this run produced, still capped to a 4-char preview + length, never the value",
    summary: "intentionally lossy -- headline counts only",
  },
});
