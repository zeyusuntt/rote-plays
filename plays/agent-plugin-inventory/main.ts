#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: agent-plugin-inventory
 * description: 'Your harness extensions accumulate like browser toolbars -- this inventories them. Covers Claude Code plugins (name, version, scope, marketplace, timestamps, cross-referenced against enabledPlugins, measured on disk as present/missing/empty/inaccessible with a byte size), personal skills (name, description first line truncated to 80 characters, mtime -- no other file content is ever read), known marketplaces (name, last-sync when actually recorded), and Codex plugin-equivalents from ~/.codex/config.toml when present -- each source degrades alone, never the rest of the report, when unreadable or unparseable. FOUR FLAGS, always "-suspect", never a certainty: name-collision (a skill name found under more than one owner); broken-install (an installed plugin''s own cache directory missing or empty); stale (a marketplace not refreshed in stale_days or more); and disabled-but-cached (a disabled plugin whose cache directory is still present -- a disk note, not a security finding). Every skill description is truncated to 80 characters before this play ever holds it, and no path survives into a diagnostic -- an OS error is reduced to a short, non-secret reason instead. Read-only throughout: edits, deletes, installs, enables, disables, and moves nothing, kills no process, makes no network call of its own; needs only python3.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/agent-plugin-inventory
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: agent-plugin-inventory
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   inventory: resources/presentation-fixtures/inventory/fixture.yaml
 *   assess: resources/presentation-fixtures/assess/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-plugin-inventory
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-plugin-inventory
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
 *       headline:
 *         type: string
 *       totals:
 *         type: object
 *       plugins:
 *         type: array
 *       codex:
 *         type: array
 *       personal_skills:
 *         type: array
 *       plugin_skills:
 *         type: array
 *       marketplaces:
 *         type: array
 *       flags:
 *         type: object
 *       checked:
 *         type: array
 *       unverified:
 *         type: array
 *       note:
 *         type: string
 *       representations:
 *         type: object
 * parameters:
 * - name: stale_days
 *   param_type: integer
 *   required: false
 *   default: '30'
 *   description: (1-365) marketplace sync older than this is stale-flagged
 *   example: '30'
 * steps:
 *   inventory:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{inventory_plugins.py}'
 *   assess:
 *     type: process.exec
 *     timeout_ms: 15000
 *     depends_on:
 *     - inventory
 *     argv:
 *     - python3
 *     - '@resource{assess.py}'
 *     - '@inventory{$.stdout.text | fromjson | .packed_plugins}'
 *     - '@inventory{$.stdout.text | fromjson | .plugin_count}'
 *     - '@inventory{$.stdout.text | fromjson | .packed_skills}'
 *     - '@inventory{$.stdout.text | fromjson | .skill_count}'
 *     - '@inventory{$.stdout.text | fromjson | .packed_marketplaces}'
 *     - '@inventory{$.stdout.text | fromjson | .marketplace_count}'
 *     - '@inventory{$.stdout.text | fromjson | .packed_codex}'
 *     - '@inventory{$.stdout.text | fromjson | .codex_count}'
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
  try {
    return { kind: "ok", data: JSON.parse(text) };
  } catch {
    return { kind: "unparseable" };
  }
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

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, result: StdoutResult, okNote: (p: any) => string): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (result.kind !== "ok") return `  degraded  ${label}  ${unavailableReason(step, result)}`;
  const parsed = result.data;
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? parsed.warning ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const inventoryStep = ctx.step(stepName("inventory"));
const assessStep = ctx.step(stepName("assess"));

const inventoryResult = parsedStdout(inventoryStep);
const assessResult = parsedStdout(assessStep);

// assess depends_on inventory (it consumes inventory's own $.stdout.text
// via the DAG's own templating) -- a truncated inventory capture is
// therefore expected to already cascade into assess never completing, but
// each step's own truncation is still detected and reported independently
// here rather than assumed from the other. A truncated capture is never
// trusted as data either -- inventoryData/assessData stay null exactly as
// they would for any other unusable read, so no count or `ok: true` is
// ever built on a partial capture (the truncation FACT itself is still
// surfaced, distinctly, via unavailableReason below and in
// CHECKED/UNVERIFIED).
const inventoryData = inventoryResult.kind === "ok" ? inventoryResult.data : null;
const assessData = assessResult.kind === "ok" ? assessResult.data : null;
const inventoryTruncated = inventoryResult.kind === "truncated";
const assessTruncated = assessResult.kind === "truncated";
const anyStepTruncated = inventoryTruncated || assessTruncated;

const totals = assessData?.totals && typeof assessData.totals === "object" ? assessData.totals : {};
const pluginCount = typeof totals.plugin_count === "number" ? totals.plugin_count : 0;
const pluginEnabledCount = typeof totals.plugin_enabled_count === "number" ? totals.plugin_enabled_count : 0;
const pluginDisabledCount = typeof totals.plugin_disabled_count === "number" ? totals.plugin_disabled_count : 0;
const pluginEnabledUnknownCount =
  typeof totals.plugin_enabled_unknown_count === "number" ? totals.plugin_enabled_unknown_count : 0;
const pluginCacheInaccessibleCount =
  typeof totals.plugin_cache_inaccessible_count === "number" ? totals.plugin_cache_inaccessible_count : 0;
const pluginCacheNotApplicableCount =
  typeof totals.plugin_cache_not_applicable_count === "number" ? totals.plugin_cache_not_applicable_count : 0;
const personalSkillCount = typeof totals.personal_skill_count === "number" ? totals.personal_skill_count : 0;
const pluginSkillCount = typeof totals.plugin_skill_count === "number" ? totals.plugin_skill_count : 0;
const marketplaceCount = typeof totals.marketplace_count === "number" ? totals.marketplace_count : 0;
const marketplaceUnknownStalenessCount =
  typeof totals.marketplace_unknown_staleness_count === "number" ? totals.marketplace_unknown_staleness_count : 0;
const codexCount = typeof totals.codex_count === "number" ? totals.codex_count : 0;
const codexEnabledCount = typeof totals.codex_enabled_count === "number" ? totals.codex_enabled_count : 0;
const staleDays = typeof totals.stale_days === "number" ? totals.stale_days : 30;

// Guarded the same way every collection-bearing field in this fleet is: a
// shape mismatch from a degraded/malformed producer renders as an empty
// list rather than throwing on .forEach()/.map() below.
const plugins: any[] = Array.isArray(assessData?.plugins) ? assessData.plugins : [];
const personalSkills: any[] = Array.isArray(assessData?.personal_skills) ? assessData.personal_skills : [];
const pluginSkills: any[] = Array.isArray(assessData?.plugin_skills) ? assessData.plugin_skills : [];
const marketplaces: any[] = Array.isArray(assessData?.marketplaces) ? assessData.marketplaces : [];
const codexPlugins: any[] = Array.isArray(assessData?.codex) ? assessData.codex : [];
const flagsRaw = assessData?.flags && typeof assessData.flags === "object" ? assessData.flags : {};
const flagBuckets: Record<string, any[]> = {
  name_collision_suspect: Array.isArray(flagsRaw.name_collision_suspect) ? flagsRaw.name_collision_suspect : [],
  broken_install_suspect: Array.isArray(flagsRaw.broken_install_suspect) ? flagsRaw.broken_install_suspect : [],
  stale_suspect: Array.isArray(flagsRaw.stale_suspect) ? flagsRaw.stale_suspect : [],
  disabled_but_cached: Array.isArray(flagsRaw.disabled_but_cached) ? flagsRaw.disabled_but_cached : [],
};
const flagTotal = Object.values(flagBuckets).reduce((sum, bucket) => sum + bucket.length, 0);

const claudePluginsStatus: string = typeof inventoryData?.claude_plugins_status === "string" ? inventoryData.claude_plugins_status : "unknown";
const claudeSettingsStatus: string = typeof inventoryData?.claude_settings_status === "string" ? inventoryData.claude_settings_status : "unknown";
const claudeSkillsStatus: string = typeof inventoryData?.claude_skills_status === "string" ? inventoryData.claude_skills_status : "unknown";
const claudeMarketplacesStatus: string = typeof inventoryData?.claude_marketplaces_status === "string" ? inventoryData.claude_marketplaces_status : "unknown";
const codexConfigStatus: string = typeof inventoryData?.codex_config_status === "string" ? inventoryData.codex_config_status : "unknown";
const codexTomlReader: string | null = typeof inventoryData?.codex_toml_reader === "string" ? inventoryData.codex_toml_reader : null;

const claudePresent = claudePluginsStatus === "ok" || claudeSkillsStatus === "ok";
const codexPresent = codexCount > 0;
const harnessCount = (claudePresent ? 1 : 0) + (codexPresent ? 1 : 0);

const totalPluginsAcrossHarnesses = pluginCount + codexCount;
// A Claude Code plugin absent from the enabledPlugins map is treated as
// enabled by Claude Code's OWN default (see CHECKED footer below and the
// plugin_enabled_unknown_count disclosure) -- so the headline/total enabled
// figure must include those default-enabled plugins, not just the
// explicitly-enabled ones, or the count would contradict the very sentence
// that explains it. pluginEnabledUnknownCount itself remains separately
// disclosed so "explicit" and "defaulted" stay distinguishable.
const pluginEnabledOrDefaultCount = pluginEnabledCount + pluginEnabledUnknownCount;
const totalEnabledAcrossHarnesses = pluginEnabledOrDefaultCount + codexEnabledCount;

const nothingFound =
  Boolean(inventoryData) &&
  Boolean(assessData) &&
  totalPluginsAcrossHarnesses === 0 &&
  personalSkillCount === 0 &&
  marketplaceCount === 0;

function headlineLine(): string {
  return (
    `${totalPluginsAcrossHarnesses} plugin${totalPluginsAcrossHarnesses === 1 ? "" : "s"} ` +
    `(${totalEnabledAcrossHarnesses} enabled) + ${personalSkillCount} personal skill${personalSkillCount === 1 ? "" : "s"} ` +
    `across ${harnessCount} harness${harnessCount === 1 ? "" : "es"}; ${flagTotal} flag${flagTotal === 1 ? "" : "s"}`
  );
}

function topLine(): string {
  if (!inventoryData) return `inventory unavailable -- ${unavailableReason(inventoryStep, inventoryResult)}`;
  if (!assessData) return `assessment unavailable -- ${unavailableReason(assessStep, assessResult)}`;
  if (nothingFound) return "no Claude Code plugins, personal skills, or marketplaces found on this machine";
  return headlineLine();
}

function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let value = n;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const digits = unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

function fmtDate(isoText: string | null | undefined): string {
  if (!isoText) return "unknown";
  const d = new Date(isoText);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toISOString().slice(0, 10);
}

function fmtAgeDays(days: number | null | undefined): string {
  if (typeof days !== "number" || Number.isNaN(days)) return "unknown";
  if (days < 1) return "<1d";
  if (days < 365) return `${Math.round(days)}d`;
  return `${(days / 365.25).toFixed(1)}y`;
}

function triLabel(v: boolean | null | undefined): string {
  if (v === true) return "yes";
  if (v === false) return "no";
  return "unknown";
}

const FLAG_META: { key: string; label: string }[] = [
  {
    key: "name_collision_suspect",
    label: "same skill name from more than one source -- which one wins is harness-defined",
  },
  {
    key: "broken_install_suspect",
    label: "cache directory missing or empty for an installed plugin (never a plugin with no cache to check at all -- see CHECKED)",
  },
  {
    key: "stale_suspect",
    label: `marketplace not synced in ${staleDays}+ day(s)`,
  },
  {
    key: "disabled_but_cached",
    label: "disabled but its cache directory is still on disk (disk note -- see agent-disk-tax for the actual cost)",
  },
];

// ---- human view -------------------------------------------------------------
const lines: string[] = [];
lines.push("AGENT PLUGIN INVENTORY");
lines.push("");
lines.push(topLine());
lines.push("");

if (inventoryData && assessData && !nothingFound) {
  if (plugins.length > 0) {
    lines.push(`CLAUDE CODE PLUGINS (${plugins.length})`);
    lines.push(
      `  ${"name".padEnd(22)} ${"marketplace".padEnd(26)} ${"version".padEnd(12)} ${"scope".padEnd(8)} ${"enabled".padEnd(9)} ${"cache".padEnd(16)} size`,
    );
    plugins.forEach((p) => {
      lines.push(
        `  ${String(p.name ?? "?").padEnd(22)} ${String(p.marketplace ?? "?").padEnd(26)} ${String(p.version ?? "?").padEnd(12)} ` +
          `${String(p.scope ?? "?").padEnd(8)} ${triLabel(p.enabled).padEnd(9)} ${String(p.cache_dir_status ?? "?").padEnd(16)} ${fmtBytes(p.cache_size_bytes)}${p.cache_partial ? " (partial)" : ""}`,
      );
    });
    lines.push("");
  }

  if (codexPlugins.length > 0) {
    lines.push(`CODEX PLUGIN-EQUIVALENTS (${codexPlugins.length})`);
    lines.push(`  reader: ${codexTomlReader ?? "unknown"}`);
    lines.push(`  ${"name".padEnd(22)} ${"marketplace".padEnd(26)} ${"enabled".padEnd(9)} cache`);
    codexPlugins.forEach((c) => {
      lines.push(
        `  ${String(c.name ?? "?").padEnd(22)} ${String(c.marketplace ?? "?").padEnd(26)} ${triLabel(c.enabled).padEnd(9)} ${String(c.cache_dir_status ?? "?")}`,
      );
    });
    lines.push("");
  } else if (codexConfigStatus === "ok") {
    lines.push("CODEX PLUGIN-EQUIVALENTS (0)");
    lines.push("  ~/.codex/config.toml was read but declared no [plugins.\"...\"] tables");
    lines.push("");
  }

  lines.push(`PERSONAL SKILLS (${personalSkills.length})`);
  if (personalSkills.length === 0) {
    lines.push("  none found under ~/.claude/skills");
  } else {
    personalSkills.forEach((s) => {
      const age = s.mtime_epoch ? fmtAgeDays((Date.now() / 1000 - s.mtime_epoch) / 86400) : "unknown";
      lines.push(`  ${String(s.name ?? "?").padEnd(28)} ${String(s.description ?? "(no description)").padEnd(60)} age ${age}`);
    });
  }
  lines.push(`  + ${pluginSkillCount} skill(s) bundled inside installed plugins (not listed individually; see FLAGS for any name collision)`);
  lines.push("");

  if (marketplaces.length > 0) {
    lines.push(`MARKETPLACES (${marketplaces.length})`);
    lines.push(`  ${"name".padEnd(28)} ${"repo".padEnd(38)} ${"last synced".padEnd(12)} age`);
    marketplaces.forEach((m) => {
      lines.push(
        `  ${String(m.name ?? "?").padEnd(28)} ${String(m.repo ?? "unknown").padEnd(38)} ${fmtDate(m.last_updated).padEnd(12)} ${fmtAgeDays(m.age_days)}`,
      );
    });
    lines.push("");
  }

  lines.push("FLAGS -- each conservative, none a certainty");
  let anyFlag = false;
  FLAG_META.forEach((meta) => {
    const bucket = flagBuckets[meta.key] ?? [];
    lines.push(`  ${meta.label} (${bucket.length})`);
    if (bucket.length === 0) {
      lines.push("    none");
    } else {
      anyFlag = true;
      bucket.forEach((f: any) => {
        lines.push(`    ${f?.name ?? f?.key ?? "?"}  --  ${f?.detail ?? "flagged"}`);
      });
    }
  });
  if (!anyFlag) {
    lines.push("");
    lines.push("  nothing flagged -- no name collision, no broken cache directory, no stale marketplace, nothing disabled-but-cached");
  }
  lines.push("");
}

lines.push("CHECKED (what this report is actually based on)");
if (inventoryData) {
  lines.push(`  - Claude Code plugins: installed_plugins.json (${claudePluginsStatus}), enabledPlugins map (${claudeSettingsStatus})`);
  lines.push(`  - Claude Code personal skills: ~/.claude/skills/* (${claudeSkillsStatus}) -- description first line only, no other file content`);
  lines.push(`  - Claude Code marketplaces: known_marketplaces.json (${claudeMarketplacesStatus})`);
  lines.push(
    `  - Codex plugin-equivalents: ~/.codex/config.toml (${codexConfigStatus})${codexTomlReader ? ` via ${codexTomlReader} reader` : ""}`,
  );
  if (pluginCacheInaccessibleCount > 0) {
    lines.push(`  - ${pluginCacheInaccessibleCount} plugin cache director(y/ies) were inaccessible (permission) -- not counted toward broken-install-suspect`);
  }
  if (pluginCacheNotApplicableCount > 0) {
    lines.push(`  - ${pluginCacheNotApplicableCount} plugin(s) had no installPath recorded, or one outside Claude's own plugin cache root -- cache not evaluated, not counted toward broken-install-suspect`);
  }
  if (marketplaceUnknownStalenessCount > 0) {
    lines.push(`  - ${marketplaceUnknownStalenessCount} marketplace(s) have no recorded last-sync time -- staleness not evaluated for those`);
  }
  if (pluginEnabledUnknownCount > 0) {
    lines.push(`  - ${pluginEnabledUnknownCount} plugin(s) absent from the enabledPlugins map -- treated as enabled (Claude Code's own default), never guessed disabled`);
  }
}
lines.push("");

lines.push("UNVERIFIED (this play cannot tell you)");
if (inventoryTruncated) {
  lines.push(`  - inventory: ${unavailableReason(inventoryStep, inventoryResult)} -- nothing from this step is CHECKED above`);
}
if (assessTruncated) {
  lines.push(`  - assess: ${unavailableReason(assessStep, assessResult)} -- nothing from this step is CHECKED above`);
}
lines.push("  - whether any plugin's hooks, commands, or skills actually fire correctly -- config presence is checked, not runtime behavior");
lines.push("  - whether a flagged name collision actually shadows anything at runtime -- harness precedence rules vary and are not evaluated");
lines.push("  - Codex's own marketplace sync recency -- only Claude Code's known_marketplaces.json feeds stale-suspect");
lines.push("  - project-scoped plugin/skill configuration (a repo's own .claude/settings.local.json) -- only the well-known user-level paths are read");
lines.push("  - cache directory sizes are POSIX apparent size (st_size), not on-disk block size; Codex cache presence is a bare directory check, size not measured");
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine("inventory  ", inventoryStep, inventoryResult, (p) =>
    `${p.plugin_count} plugin(s), ${p.skill_count} skill(s), ${p.marketplace_count} marketplace(s), ${p.codex_count} codex plugin(s)`,
  ),
);
lines.push(
  stageLine("assess     ", assessStep, assessResult, (p) => `${flagTotal} flag(s) across 4 categories`),
);

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
out.summary(
  anyStepTruncated
    ? `agent plugin inventory: ${topLine()} — partial: one or more steps were truncated at the capture cap`
    : `agent plugin inventory: ${topLine()}`,
);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: Boolean(inventoryData) && Boolean(assessData),
  generated_at: inventoryData?.generated_at ?? new Date().toISOString(),
  headline: topLine(),
  totals: {
    plugin_count_claude: pluginCount,
    plugin_count_codex: codexCount,
    plugin_count_total: totalPluginsAcrossHarnesses,
    plugin_enabled_count_total: totalEnabledAcrossHarnesses,
    plugin_disabled_count_claude: pluginDisabledCount,
    plugin_enabled_unknown_count_claude: pluginEnabledUnknownCount,
    plugin_cache_inaccessible_count_claude: pluginCacheInaccessibleCount,
    plugin_cache_not_applicable_count_claude: pluginCacheNotApplicableCount,
    personal_skill_count: personalSkillCount,
    plugin_skill_count: pluginSkillCount,
    marketplace_count: marketplaceCount,
    marketplace_unknown_staleness_count: marketplaceUnknownStalenessCount,
    harness_count: harnessCount,
    stale_days: staleDays,
    flags_total: flagTotal,
  },
  plugins,
  codex: codexPlugins,
  personal_skills: personalSkills,
  plugin_skills: pluginSkills,
  marketplaces,
  flags: flagBuckets,
  checked: [
    ...(inventoryTruncated ? [] : [
      `Claude Code plugins: installed_plugins.json (${claudePluginsStatus}), enabledPlugins map (${claudeSettingsStatus})`,
      `Claude Code personal skills: ~/.claude/skills/* (${claudeSkillsStatus})`,
      `Claude Code marketplaces: known_marketplaces.json (${claudeMarketplacesStatus})`,
      `Codex plugin-equivalents: ~/.codex/config.toml (${codexConfigStatus})${codexTomlReader ? `, ${codexTomlReader} reader` : ""}`,
    ]),
    ...(assessTruncated ? [] : [
      `${pluginSkillCount} plugin-bundled skill(s) read (frontmatter description first line, never the body) -- every row is in this JSON under plugin_skills, not shown individually in the human view, not just when flagged`,
    ]),
  ],
  unverified: [
    ...(inventoryTruncated ? [`inventory: ${unavailableReason(inventoryStep, inventoryResult)}`] : []),
    ...(assessTruncated ? [`assess: ${unavailableReason(assessStep, assessResult)}`] : []),
    "whether any plugin's hooks, commands, or skills actually fire correctly at runtime",
    "whether a flagged name collision actually shadows anything -- harness precedence rules vary",
    "Codex's own marketplace sync recency -- only known_marketplaces.json feeds stale-suspect",
    "project-scoped plugin/skill configuration outside the well-known user-level paths",
    "on-disk block-allocated size -- cache sizes are POSIX apparent size (st_size) only, and Codex cache presence is a bare directory check with no size measured",
  ],
  note:
    "Every skill description is truncated to 80 characters before this play holds onto it; no file content beyond that one frontmatter line is ever read. Cache directory sizes are POSIX apparent size (st_size), no `du` dependency.",
  representations: {
    human: "complete -- headline, per-source tables (plugins, Codex plugin-equivalents, personal skills, marketplaces), FLAGS with conservative wording, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- every plugin/skill/marketplace row and every flag, even when the human view only summarizes",
    summary: "intentionally lossy -- the headline line only",
  },
});
