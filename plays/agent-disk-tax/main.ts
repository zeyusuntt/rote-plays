#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: agent-disk-tax
 * description: 'What does your agent tooling cost you in DISK, right now, by category, with the single largest offenders named? You get one table of known agent-tooling locations ranked by size, a merged, exact largest-files list across every category, and a judgment-free worktree listing that states only calendar facts like "untouched 14+ days", never a removal recommendation. A category that cannot finish walking in its time budget is labeled PARTIAL and its size stated as at least what is shown, never a silent truncation. Every path shown -- category roots, largest files, worktrees -- has your home directory replaced with "~"; Claude transcript paths default to filename-only. This is the disk half of our tax family (context-tax covers token cost). Read-only: nothing is ever written, moved, or deleted, not even a cache file of its own; no network calls, no credentials read or transmitted; needs only python3.'
 * version: 0.1.3
 * source_url: https://play.modiqo.ai/dotisacat/agent-disk-tax
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: agent-disk-tax
 * metadata:
 *   version: 0.1.3
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   discover_cats: resources/presentation-fixtures/discover_cats/fixture.yaml
 *   measure_cat: resources/presentation-fixtures/measure_cat/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-disk-audit
 * - audience-developers
 * - effect-read-only
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-disk-audit
 *   - audience-developers
 *   - effect-read-only
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
 *       categories:
 *         type: array
 *       largest_files:
 *         type: array
 *       worktrees:
 *         type: object
 *       checked:
 *         type: object
 *       unverified:
 *         type: object
 *       note:
 *         type: string
 *       representations:
 *         type: object
 * parameters:
 * - name: per_category_seconds
 *   param_type: integer
 *   required: false
 *   default: '20'
 *   description: Time budget per category walk (5-120); partial results are labeled, never silent
 *   example: '20'
 * - name: top_files
 *   param_type: integer
 *   required: false
 *   default: '3'
 *   description: How many of each category's largest files to report (1-10)
 *   example: '3'
 * - name: show_full_transcript_paths
 *   param_type: boolean
 *   required: false
 *   default: 'false'
 *   description: Show full per-project Claude transcript paths in the largest-files list instead of filename-only (opt-in -- Claude Code's transcript folder naming embeds the original project/client path)
 *   example: 'false'
 * steps:
 *   discover_cats:
 *     type: process.exec
 *     timeout_ms: 10000
 *     argv:
 *     - python3
 *     - '@resource{discover_cats.py}'
 *   measure_cat:
 *     type: process.exec
 *     timeout_ms: 130000
 *     depends_on:
 *     - discover_cats
 *     for_each: $.stdout.text | fromjson | .items
 *     max_concurrency: 3
 *     argv:
 *     - python3
 *     - '@resource{measure_cat.py}'
 *     - $item
 *     - $per_category_seconds
 *     - $top_files
 *     - $show_full_transcript_paths
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

/** Read a single (non fan-out) step's stdout, distinguishing WHY it isn't
 * usable JSON: absent (step didn't complete, or stdout was empty), truncated
 * at rote's capture cap, or unparseable (present, not truncated, but not
 * valid JSON). Truncation is read directly off the stdout.truncated flag --
 * strict === true, never inferred from a JSON.parse failure -- so a
 * truncated payload is never misdiagnosed as merely malformed. When both
 * apply, truncated wins: it is the cause, unparseable only its symptom. */
function readStepJson(step) {
  const outcome = step?.outcome;
  if (outcome?.status !== "completed" && outcome?.status !== "restored") return { kind: "absent" };
  const s = outcome?.output?.body?.stdout;
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

/** Same distinction as readStepJson, applied to one fan-out item's stdout. */
function readItemJson(item) {
  const s = item?.body?.stdout;
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

/** Best-effort category label for a fan-out item whose stdout did not parse
 * -- read from the item's own invocation args (the $item payload measure_cat
 * was invoked with), never from its output, so a degraded item can still be
 * named accurately in the report instead of only counted. */
function itemCategoryHint(item) {
  try {
    const args = item?.body?.invocation?.args;
    const itemArg = Array.isArray(args) ? args[1] : null;
    const parsed = typeof itemArg === "string" ? JSON.parse(itemArg) : null;
    return typeof parsed?.category === "string" ? parsed.category : null;
  } catch {
    return null;
  }
}

/** Read a for_each fan-out step: one { category, result } observation per
 * item, result being the same discriminated shape readStepJson returns.
 * Deliberately does NOT gate on the aggregate step status the way a single
 * (non fan-out) step read would -- if the runner ever promotes one item's
 * failure/timeout to an aggregate status other than completed/restored
 * while still populating output.items with the observations that DID come
 * back, gating on the aggregate status here would silently discard every
 * successful peer along with the bad one. Array.isArray-guarded so a shape
 * mismatch (items absent, e.g. a genuine pre-fan-out failure) degrades to
 * an empty list instead of throwing, and one malformed item's JSON never
 * sinks the rest of the report; every category missing a row still gets an
 * explicit "no measurement result" or "truncated" line below, whichever way
 * this comes back empty or degraded. */
function readFanOutResults(step) {
  const items = step?.outcome?.output?.items;
  if (!Array.isArray(items)) return [];
  return items.map((item) => {
    const result = readItemJson(item);
    const category = result.kind === "ok" && typeof result.data?.category === "string"
      ? result.data.category
      : itemCategoryHint(item);
    return { category, result };
  });
}

const discoverStep = ctx.step(stepName("discover_cats"));
const measureStep = ctx.step(stepName("measure_cat"));

const discoverResult = readStepJson(discoverStep);
const discoverTruncated = discoverResult.kind === "truncated";
const discovery = discoverResult.kind === "ok" ? discoverResult.data : null;

const measureResults = readFanOutResults(measureStep);
const measuredRows = measureResults.filter((m) => m.result.kind === "ok").map((m) => m.result.data);
const truncatedMeasureItems = measureResults.filter((m) => m.result.kind === "truncated");

const discoveredCategories = Array.isArray(discovery?.items) ? discovery.items : [];
const checked = Array.isArray(discovery?.checked) ? discovery.checked : [];
const skipped = Array.isArray(discovery?.skipped) ? discovery.skipped : [];
const overlapRejections = Array.isArray(discovery?.overlap_rejections) ? discovery.overlap_rejections : [];

const measuredByCategory = new Map();
for (const row of measuredRows) {
  if (row && typeof row.category === "string" && row.category) measuredByCategory.set(row.category, row);
}

// Every discovered category normally gets back exactly one measurement row
// (measure_cat.py always emits JSON, even on its own internal degrade --
// see its module docstring). A row missing entirely is a defensive
// fallback that should not happen (the underlying process.exec item failed
// outright rather than measure_cat.py degrading to JSON on its own) --
// labeled honestly rather than silently dropped. A category whose item WAS
// truncated at rote's capture cap gets its own named bucket, never folded
// into "no measurement result returned" -- that message is for a genuinely
// missing/malformed result, not a capped-but-real one.
const rows = [];
const missingRows = [];
const truncatedRows = []; // { category, bytes }
for (const dc of discoveredCategories) {
  const row = measuredByCategory.get(dc?.category);
  if (row) {
    rows.push(row);
    continue;
  }
  const truncatedItem = dc?.category
    ? truncatedMeasureItems.find((t) => t.category === dc.category)
    : undefined;
  if (truncatedItem) {
    truncatedRows.push({ category: dc.category, bytes: truncatedItem.result.bytes });
  } else if (dc?.category) {
    missingRows.push(dc.category);
  }
}

const okRows = rows.filter((r) => r && r.ok === true);
const errorRows = rows.filter((r) => r && r.ok !== true);
const ranked = [...okRows].sort((a, b) => (b.size_bytes ?? 0) - (a.size_bytes ?? 0));
const topCategory = ranked[0] ?? null;

const totalBytes = okRows.reduce((sum, r) => sum + (r.size_bytes ?? 0), 0);
const totalFiles = okRows.reduce((sum, r) => sum + (r.file_count ?? 0), 0);
const totalIoErrors = okRows.reduce((sum, r) => sum + (r.io_errors ?? 0), 0);
const totalHardlinksDeduped = okRows.reduce((sum, r) => sum + (r.hardlinks_deduped_within_category ?? 0), 0);
const partialCategories = okRows.filter((r) => r.partial === true);

function fmtBytes(n) {
  const bytes = Number(n) || 0;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const digits = unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

function fmtInt(n) {
  return (n ?? 0).toLocaleString("en-US");
}

function fmtBytesOrUnknown(n) {
  return typeof n === "number" ? fmtBytes(n) : "an unknown number of bytes";
}

function fmtDate(isoText) {
  if (!isoText) return "unknown";
  const d = new Date(isoText);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toISOString().slice(0, 10);
}

function daysSince(isoText) {
  if (!isoText) return null;
  const t = new Date(isoText).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24));
}

function catWord(n) {
  return n === 1 ? "category" : "categories";
}

// Global "largest files" merge. Each okRow's largest_files is already that
// category's own top `top_files_requested` (see measure_cat.py's module
// docstring for why merging per-category top-N and re-sorting is an EXACT
// global top-N, not an approximation, for categories that finished
// walking). All rows share the same top_files param, so any row's own
// top_files_requested is the effective value for this run.
const globalTopN = okRows.length > 0 ? (okRows[0].top_files_requested || 3) : 3;
const allFiles = [];
for (const r of okRows) {
  const files = Array.isArray(r.largest_files) ? r.largest_files : [];
  for (const f of files) {
    if (f && typeof f.size_bytes === "number" && typeof f.path_redacted === "string") {
      allFiles.push({ ...f, category: r.category });
    }
  }
}
allFiles.sort((a, b) => (b.size_bytes ?? 0) - (a.size_bytes ?? 0));
const largestFilesGlobal = allFiles.slice(0, globalTopN);

// Worktrees: a special, judgment-free listing -- see measure_cat.py's
// module docstring for why root_details already carries per-worktree size
// and mtime with no aggregation needed beyond what is already in the row.
const STALE_DAYS = 14;
const worktreesRow = okRows.find((r) => r.category === "agent-worktrees") ?? null;
const worktreeEntries = worktreesRow && Array.isArray(worktreesRow.root_details) ? worktreesRow.root_details : [];
const worktreeEntriesWithAge = worktreeEntries.map((e) => {
  const age = daysSince(e?.newest_mtime);
  return { ...e, days_since_activity: age, untouched_14d: age !== null && age >= STALE_DAYS };
});
let oldestUntouched = null;
for (const e of worktreeEntriesWithAge) {
  if (e.days_since_activity === null) continue;
  if (!oldestUntouched || e.days_since_activity > oldestUntouched.days_since_activity) oldestUntouched = e;
}

/** One STAGES ledger row, tolerant of every outcome status the runner can
 * hand back. truncatedNote, when supplied and non-null, takes precedence
 * over okNote -- a step that completed but was truncated at rote's capture
 * cap is reported as truncated, never silently folded into "ok". */
function stageLine(label, step, okNote, truncatedNote) {
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(10)}  ${label}  step ${status}`;
  }
  const truncMsg = truncatedNote ? truncatedNote() : null;
  if (truncMsg) {
    return `  truncated   ${label}  ${truncMsg}`;
  }
  return `  ok          ${label}  ${okNote()}`;
}

const lines = [];
lines.push("AGENT DISK TAX");
lines.push("");

if (discoverTruncated) {
  lines.push(
    `discover_cats output was truncated at rote's capture cap (${fmtBytesOrUnknown(discoverResult.bytes)} captured) -- ` +
      "category discovery could not be read in full, so no category or measurement below can be trusted this run",
  );
  lines.push("");
} else if (!discovery || discovery.ok !== true) {
  lines.push(`discovery unavailable -- discover_cats step ${discoverStep?.outcome?.status ?? "unknown"}`);
  lines.push("");
} else {
  const topShare = topCategory && totalBytes > 0 ? Math.round((topCategory.size_bytes / totalBytes) * 100) : null;
  const headline = topCategory
    ? `Your agent tooling holds ${fmtBytes(totalBytes)} across ${ranked.length} ${catWord(ranked.length)}. ` +
      `The ${topCategory.category} category alone is ${fmtBytes(topCategory.size_bytes)} in ${fmtInt(topCategory.file_count)} files` +
      (topShare !== null ? ` -- ${topShare} percent of the total.` : ".")
    : `Your agent tooling holds ${fmtBytes(totalBytes)} across ${ranked.length} ${catWord(ranked.length)}.`;
  lines.push(headline);
  if (partialCategories.length > 0) {
    lines.push(
      `  ${partialCategories.length} ${catWord(partialCategories.length)} PARTIAL -- true size is AT LEAST what is shown, see CHECKED below`,
    );
  }
  if (errorRows.length > 0) {
    lines.push(`  + ${errorRows.length} ${catWord(errorRows.length)} degraded during measurement -- see CHECKED`);
  }
  if (missingRows.length > 0) {
    lines.push(`  + ${missingRows.length} ${catWord(missingRows.length)} discovered but never returned a measurement -- see CHECKED`);
  }
  if (truncatedRows.length > 0) {
    lines.push(`  + ${truncatedRows.length} ${catWord(truncatedRows.length)} truncated at rote's capture cap during measurement -- see UNVERIFIED`);
  }
  lines.push("");

  lines.push(`RANKED BY SIZE (${ranked.length})`);
  if (ranked.length === 0) {
    lines.push("  none -- no category root exists on this machine, or every measurement degraded");
  } else {
    ranked.forEach((r, i) => {
      const rank = `${i + 1}.`.padEnd(4);
      const name = String(r.category ?? "?").padEnd(22);
      const size = fmtBytes(r.size_bytes).padStart(10);
      const files = `${fmtInt(r.file_count)} files`.padStart(14);
      const oldest = fmtDate(r.oldest_mtime).padStart(12);
      const flag = r.partial ? "  PARTIAL" : "";
      lines.push(`  ${rank}${name} ${size}  ${files}  oldest ${oldest}${flag}`);
    });
  }
  lines.push("");

  lines.push(`LARGEST FILES (${largestFilesGlobal.length})`);
  if (largestFilesGlobal.length === 0) {
    lines.push("  none found");
  } else {
    largestFilesGlobal.forEach((f, i) => {
      const rank = `${i + 1}.`.padEnd(4);
      lines.push(`  ${rank}${fmtBytes(f.size_bytes).padStart(10)}  ${f.path_redacted}  (${f.category})`);
    });
    if (partialCategories.length > 0) {
      lines.push("  note: categories marked PARTIAL above may hold larger files than shown here -- their walk did not finish");
    }
  }
  lines.push("");

  if (worktreesRow) {
    lines.push("WORKTREES");
    lines.push(
      `  ${worktreeEntriesWithAge.length} worktree director${worktreeEntriesWithAge.length === 1 ? "y" : "ies"}, ` +
        `${fmtBytes(worktreesRow.size_bytes)} total`,
    );
    if (oldestUntouched) {
      lines.push(
        `  oldest untouched: ${oldestUntouched.root_redacted} -- last touched ${fmtDate(oldestUntouched.newest_mtime)} ` +
          `(${oldestUntouched.days_since_activity} days ago)`,
      );
    }
    if (worktreeEntriesWithAge.length === 0) {
      lines.push("  no worktree directories found");
    } else {
      worktreeEntriesWithAge.forEach((e) => {
        const staleNote = e.untouched_14d ? "  [untouched 14+ days]" : "";
        lines.push(
          `  - ${e.root_redacted}  ${fmtBytes(e.size_bytes)}  last touched ${fmtDate(e.newest_mtime)}${staleNote}`,
        );
      });
    }
    lines.push("");
  }
}

lines.push("CHECKED");
if (discoverTruncated) {
  lines.push(
    `  discover_cats: output was truncated at rote's capture cap (${fmtBytesOrUnknown(discoverResult.bytes)} captured) -- ` +
      "no category table could be evaluated this run, see UNVERIFIED",
  );
} else if (checked.length === 0) {
  lines.push("  no category table was evaluated -- discover_cats step did not return usable output");
} else {
  checked.forEach((c) => {
    const candidateCount = Array.isArray(c?.candidate_roots) ? c.candidate_roots.length : 0;
    const existingCount = Array.isArray(c?.existing_roots) ? c.existing_roots.length : 0;
    const inaccessibleCount = Array.isArray(c?.inaccessible_roots) ? c.inaccessible_roots.length : 0;
    const rejectedSymlinkCount = Array.isArray(c?.rejected_symlink_roots) ? c.rejected_symlink_roots.length : 0;
    const flags = [];
    if (inaccessibleCount > 0) flags.push(`${inaccessibleCount} inaccessible`);
    if (rejectedSymlinkCount > 0) flags.push(`${rejectedSymlinkCount} rejected as symlink`);
    const flagNote = flags.length > 0 ? ` (${flags.join(", ")})` : "";
    const status = c?.included
      ? `walked -- ${existingCount}/${candidateCount} root(s) found${flagNote}`
      : `checked -- not present on this machine${flagNote}`;
    lines.push(`  ${String(c?.category ?? "?").padEnd(22)} ${status}`);
  });
}
if (overlapRejections.length > 0) {
  lines.push("  cross-category overlap rejected:");
  overlapRejections.forEach((r) =>
    lines.push(`    ${r?.category ?? "?"}: ${r?.root ?? "?"} -- ${r?.reason ?? "overlap"}`),
  );
}
if (errorRows.length > 0 || missingRows.length > 0) {
  lines.push("  measurement issues:");
  errorRows.forEach((r) => lines.push(`    ${r.category ?? "?"}: degraded -- ${r.error ?? "unknown reason"}`));
  missingRows.forEach((cat) => lines.push(`    ${cat}: no measurement result returned`));
}
if (partialCategories.length > 0) {
  lines.push("  budget hits / unreadable roots:");
  partialCategories.forEach((r) => lines.push(`    ${r.category}: ${r.partial_note}`));
}
if (totalHardlinksDeduped > 0) {
  lines.push(
    `  hard-link dedup: ${fmtInt(totalHardlinksDeduped)} duplicate path(s) collapsed to their first-seen inode within their own category`,
  );
}
lines.push("");

lines.push("UNVERIFIED");
if (discoverTruncated) {
  lines.push(
    `  discover_cats: output was truncated at rote's capture cap (${fmtBytesOrUnknown(discoverResult.bytes)} captured) -- ` +
      "this report covers only part of what the step produced; nothing above this line was evaluated this run.",
  );
}
if (truncatedRows.length > 0) {
  lines.push(
    `  measure_cat: output truncated at rote's capture cap for ${truncatedRows.length} categor${truncatedRows.length === 1 ? "y" : "ies"} -- ` +
      `${truncatedRows.map((t) => `${t.category} (${fmtBytesOrUnknown(t.bytes)} captured)`).join(", ")}; each covers only part of what that item produced.`,
  );
}
lines.push(
  "  any directory outside the fixed category table above was never checked -- this play does not walk your " +
    "whole disk, only the known agent-tooling locations listed under CHECKED.",
);
lines.push(
  "  whether any specific file or category shown above is safe to delete is not evaluated by this play -- " +
    "review it yourself; this play deletes nothing and recommends only review, never an rm command.",
);
lines.push(
  "  a file hard-linked into TWO DIFFERENT categories is deduplicated within each category but not across " +
    "them -- each category's own number stays honest, but the grand total can still double-count that file.",
);
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine(
    "discover categories",
    discoverStep,
    () =>
      discovery
        ? `${discoveredCategories.length} of ${checked.length} checked ${catWord(discoveredCategories.length)} exist (${skipped.length} skipped)`
        : "output did not parse as JSON",
    () =>
      discoverTruncated
        ? `output truncated at rote's capture cap (${fmtBytesOrUnknown(discoverResult.bytes)} captured) -- see UNVERIFIED`
        : null,
  ),
);
lines.push(
  stageLine("measure categories ", measureStep, () =>
    `${measuredRows.length} measured, ${fmtBytes(totalBytes)} total` +
    (truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated -- see UNVERIFIED` : ""),
  ),
);
lines.push("");

lines.push("Sizes are POSIX apparent size (st_size), not on-disk block-allocated size -- this play makes no `du` calls of its own.");
if (okRows.some((r) => r.category === "claude-transcripts")) {
  lines.push(
    "Claude transcript file paths above are shown as filename-only by default (project/client names are embedded " +
      "in the folder name) -- pass show_full_transcript_paths=true to see full paths.",
  );
}
lines.push("");

if (topCategory) {
  lines.push(
    `Start with ${topCategory.category}, the largest category above at ${fmtBytes(topCategory.size_bytes)} across ${fmtInt(topCategory.file_count)} files` +
      (topCategory.partial ? " (PARTIAL -- see CHECKED for what didn't finish)" : "") +
      " -- check what in it is still needed before deleting anything.",
  );
} else {
  lines.push("No category was measured this run -- rerun once discovery and measurement complete before deciding what to review.");
}
lines.push("This play deletes nothing itself; review before removing anything yourself.");

out.human(lines.join("\n"));

out.summary(
  discoverTruncated
    ? `agent-disk-tax unavailable -- discover_cats output truncated at rote's capture cap (${fmtBytesOrUnknown(discoverResult.bytes)} captured)`
    : discovery && discovery.ok === true
      ? `agent-disk-tax: ${fmtBytes(totalBytes)} across ${ranked.length} categories; largest: ` +
        `${largestFilesGlobal[0] ? `${fmtBytes(largestFilesGlobal[0].size_bytes)} ${largestFilesGlobal[0].path_redacted}` : "n/a"}; ` +
        `${partialCategories.length} partial, ${errorRows.length + missingRows.length} degraded` +
        (truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated` : "")
      : "agent-disk-tax unavailable (discovery degraded)",
);

out.result({
  ok: Boolean(discovery && discovery.ok === true) && !discoverTruncated && truncatedRows.length === 0,
  generated_at: new Date().toISOString(),
  totals: {
    total_bytes: totalBytes,
    total_files: totalFiles,
    categories_checked: checked.length,
    categories_included: discoveredCategories.length,
    categories_skipped: skipped.length,
    categories_measured: okRows.length,
    categories_partial: partialCategories.length,
    categories_degraded: errorRows.length,
    categories_missing_result: missingRows.length,
    categories_truncated: truncatedRows.length,
    io_errors: totalIoErrors,
    hardlinks_deduped_within_category: totalHardlinksDeduped,
  },
  categories: ranked.map((r) => ({
    category: r.category,
    size_bytes: r.size_bytes ?? 0,
    file_count: r.file_count ?? 0,
    oldest_mtime: r.oldest_mtime ?? null,
    newest_mtime: r.newest_mtime ?? null,
    partial: Boolean(r.partial),
    partial_note: r.partial_note ?? null,
    path_projection: r.path_projection ?? "full",
    io_errors: r.io_errors ?? 0,
    hardlinks_deduped_within_category: r.hardlinks_deduped_within_category ?? 0,
    roots_vanished: Array.isArray(r.roots_vanished) ? r.roots_vanished : [],
    roots_inaccessible: Array.isArray(r.roots_inaccessible) ? r.roots_inaccessible : [],
    roots_rejected_symlink: Array.isArray(r.roots_rejected_symlink) ? r.roots_rejected_symlink : [],
    roots: Array.isArray(r.roots_redacted) ? r.roots_redacted : [],
  })),
  largest_files: largestFilesGlobal,
  worktrees: worktreesRow
    ? {
        present: true,
        count: worktreeEntriesWithAge.length,
        total_bytes: worktreesRow.size_bytes ?? 0,
        oldest_untouched: oldestUntouched
          ? {
              root: oldestUntouched.root_redacted,
              newest_mtime: oldestUntouched.newest_mtime ?? null,
              days_since_activity: oldestUntouched.days_since_activity,
            }
          : null,
        entries: worktreeEntriesWithAge.map((e) => ({
          root: e.root_redacted,
          size_bytes: e.size_bytes ?? 0,
          file_count: e.file_count ?? 0,
          newest_mtime: e.newest_mtime ?? null,
          untouched_14d_plus: Boolean(e.untouched_14d),
        })),
      }
    : { present: false, count: 0, total_bytes: 0, oldest_untouched: null, entries: [] },
  checked: {
    categories: checked,
    skipped,
    overlap_rejections: overlapRejections,
  },
  unverified: {
    note:
      "Only the fixed category roots listed under checked.categories were examined; nothing outside them was " +
      "walked. This play deletes nothing and does not evaluate delete-safety -- review manually. A file " +
      "hard-linked into two different categories is deduplicated within each category but not across them.",
    categories_degraded: errorRows.map((r) => ({ category: r.category ?? null, error: r.error ?? null })),
    categories_missing_result: missingRows,
    categories_truncated: truncatedRows.map((t) => ({ category: t.category, bytes: t.bytes })),
    discover_cats_truncated: discoverTruncated ? { bytes: discoverResult.bytes } : null,
  },
  note: "Sizes are POSIX apparent size (st_size), not on-disk block-allocated size; this play makes no `du` calls of its own. Claude transcript file paths default to filename-only; see show_full_transcript_paths.",
  representations: {
    human: "complete -- headline, ranked category table, largest-files list, worktrees section when present, checked/unverified footer, stage ledger",
    json: "canonical -- every discovered/measured category, full largest-files merge, full worktree entries, degrade detail",
    summary: "intentionally lossy -- totals and counts only",
  },
});
