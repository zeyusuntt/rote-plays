#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: timemachine-exclusions-audit
 * description: 'Time Machine exclusions are invisible until restore day. Companion to laptop-loss-drill -- that play answers whether there is a backup at all and what git work is unique; this one answers whether your backup even COVERS the paths you think it does, no shared state between them. Five jobs, in order: (1) discover_paths builds the path list, depth-bounded under base_dir: every "project dir" (a directory that directly contains .git, package.json, pyproject.toml, Cargo.toml, go.mod, pom.xml, Gemfile, or composer.json -- the walk stops the moment one is found, never descending into it) PLUS a fixed list of high-value roots (~/Documents, ~/Desktop, ~/.ssh, ~/.claude) PLUS "dev dirs found" -- a presence-only probe of common developer-root names (~/Developer, ~/dev, ~/Projects, ~/src, ~/Code, ~/repos, ~/workspace and a couple more), included only when they exist on this machine; (2) check_exclusions asks `tmutil isexcluded` about every discovered path, batched several paths per invocation with bounded concurrency across batches (never one process per path), a per-batch timeout, and a batch failure degrading only the paths in THAT batch to a labeled unknown row, never the whole step; (3) it separately reads the sticky per-item xattr Time Machine''s own "Exclude these items" UI (and some third-party tools -- node_modules is sometimes auto-excluded this way) sets on an excluded directory, com.apple.metadata:com_apple_backup_excludeItem, one read per path, no sudo; (4) it separately reads the SYSTEM-wide SkipPaths list from /Library/Preferences/com.apple.TimeMachine via `defaults export` (readable without sudo through cfprefsd even though the backing file itself is root-owned and SIP-guarded against a direct read), once per run, and matches each excluded path against it; when tmutil reports a path excluded, the sticky xattr and the SkipPaths match are consulted, in that order, only to LABEL why -- sticky-xattr vs system -- and a path excluded by neither of those two readable-without-sudo channels is still reported excluded, just with exclusion_source "unknown", never silently reattributed to look more complete than it is; (5) on any platform other than macOS this play degrades instantly and honestly to one line -- "Time Machine is a macOS system" -- still exit 0, no crash, nothing else attempted, a Linux runner learns in under a second. Read-only, no credentials, no network, no sudo anywhere in this play, ever; write-shaped calls (tmutil addexclusion/removeexclusion, xattr -w/-d, defaults write) do not appear anywhere in it -- this play never sets or removes an exclusion on any real path it discovers on its own; its own live-bed proof of sticky-xattr detection sets that attribute only on a scratch directory it creates and deletes for the purpose. Every helper call is bounded by a timeout, though, and a call that overruns it IS terminated (Python enforces a subprocess timeout by killing the child) -- that termination only ever degrades the one call, or every path in one tmutil batch, to a labeled unknown row, never the whole step, and it is only ever aimed at a helper process this play itself spawned and is still waiting on. Needs only python3; on macOS it also consults tmutil, xattr, and defaults, none of them with sudo; on Linux none of the three exist and none are invoked.'
 * version: 0.1.2
 * source_url: https://play.modiqo.ai/dotisacat/timemachine-exclusions-audit
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: timemachine-exclusions-audit
 * metadata:
 *   version: 0.1.2
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * tags:
 * - domain-security
 * - job-backup-audit
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-security
 *   - job-backup-audit
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       ok:
 *         type: boolean
 *         description: True whenever both steps produced a readable report, even a degraded one.
 *       platform:
 *         type: string
 *         description: darwin, linux, or another platform name; only darwin ever runs a real check.
 *       headline:
 *         type: string
 *         description: The one-line verdict this play was built to give.
 *       totals:
 *         type: object
 *         description: paths_total, paths_checked, excluded_count, unknown_count.
 *       excluded:
 *         type: array
 *         description: Every path reported excluded, redacted, with its exclusion source when known.
 *       unknown:
 *         type: array
 *         description: Every path this run could not determine, redacted, with a reason.
 *       discover:
 *         type: object
 *       check:
 *         type: object
 *       checked:
 *         type: array
 *         description: What a clean result above is actually based on, with counts.
 *       unverified:
 *         type: array
 *         description: What this play deliberately does not check.
 *       representations:
 *         type: object
 *         description: Parity notes for the human, summary, and json views.
 * presentation_fixtures:
 *   discover_paths: resources/presentation-fixtures/discover_paths/fixture.yaml
 *   check_exclusions: resources/presentation-fixtures/check_exclusions/fixture.yaml
 * parameters:
 * - name: base_dir
 *   param_type: string
 *   required: false
 *   default: ~/Documents
 *   description: Folder to sweep for project directories. Tilde expands to your home directory; relative paths resolve against the run workspace, so prefer absolute paths.
 *   example: ~/Documents
 * - name: max_depth
 *   param_type: integer
 *   required: false
 *   default: '2'
 *   description: How many directory levels below base_dir to search for project directories (1-4), tmutil per-path calls add up -- keep small.
 *   example: '2'
 * steps:
 *   discover_paths:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{audit_exclusions.py}'
 *     - discover
 *     - $base_dir
 *     - $max_depth
 *   check_exclusions:
 *     type: process.exec
 *     timeout_ms: 90000
 *     depends_on:
 *     - discover_paths
 *     argv:
 *     - python3
 *     - '@resource{audit_exclusions.py}'
 *     - check
 *     - '@discover_paths{$.stdout.text | fromjson | .paths_packed}'
 *     - '@discover_paths{$.stdout.text | fromjson | .paths_total}'
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
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.warning ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const discoverStep = ctx.step(stepName("discover_paths"));
const checkStep = ctx.step(stepName("check_exclusions"));

const discoverResult = parsedStdout(discoverStep);
const checkResult = parsedStdout(checkStep);

const discover = dataOf(discoverResult);
const check = dataOf(checkResult);

const discoverTruncated = discoverResult.kind === "truncated";
const checkTruncated = checkResult.kind === "truncated";

const plural = (n: number, word: string) => `${word}${n === 1 ? "" : "s"}`;

// Array.isArray-guarded the same way every collection-bearing field in this
// fleet is: a degraded/malformed producer renders as an empty list
// downstream rather than throwing.
const excludedRows: any[] = Array.isArray(check?.excluded_rows) ? check.excluded_rows : [];
const unknownRows: any[] = Array.isArray(check?.unknown_rows) ? check.unknown_rows : [];
const checkedList: string[] = Array.isArray(check?.checked) ? check.checked : [];
const unverifiedList: string[] = Array.isArray(check?.unverified) ? check.unverified : [];

const platform: string = check?.platform ?? discover?.platform ?? "unknown";
const macosNote: string | null = check?.note ?? discover?.note ?? null;

const pathsTotal = typeof check?.paths_total === "number" ? check.paths_total : 0;
const pathsChecked = typeof check?.paths_checked === "number" ? check.paths_checked : 0;
const excludedCount = typeof check?.excluded_count === "number" ? check.excluded_count : 0;
const unknownCount = typeof check?.unknown_count === "number" ? check.unknown_count : 0;
const tmutilUnavailable = check?.tmutil_unavailable === true;

function headlineLine(): string {
  // A cut capture is never trusted downstream, so truncation is checked
  // before any other "no data" explanation -- discover_paths first, since
  // check_exclusions' own input is derived from its output.
  if (discoverTruncated) return `paths unavailable -- discover_paths: ${truncationNote(discoverResult.bytes)}`;
  if (checkTruncated) return `check unavailable -- check_exclusions: ${truncationNote(checkResult.bytes)}`;
  if (macosNote) return macosNote;
  if (!check) return "check_exclusions unavailable -- no exclusion status to report";
  if (tmutilUnavailable) {
    return (
      `tmutil isexcluded did not return a usable answer for any of the ${pathsChecked} path(s) asked -- ` +
      `Time Machine's exclusion index may be unavailable on this Mac. Run laptop-loss-drill to check whether ` +
      `Time Machine is even configured (cross-reference by name).`
    );
  }
  // A "clean bill" is a claim about EVERY path this run asked about, so it
  // may only be issued when every path got a usable answer -- 0 excluded
  // among a set that also contains unresolved paths is a partial result,
  // not a clean one, even though the detailed UNKNOWN section discloses the
  // uncertainty further down; the headline itself must not overstate it.
  if (excludedCount === 0 && unknownCount === 0) {
    return `0 of ${pathsChecked} checked ${plural(pathsChecked, "path")} are excluded from backup -- clean bill.`;
  }
  if (excludedCount === 0) {
    return (
      `0 of ${pathsChecked} checked ${plural(pathsChecked, "path")} are excluded from backup, but ` +
      `${unknownCount} could not be determined -- partial result, not a clean bill.`
    );
  }
  return (
    `${excludedCount} of ${pathsChecked} checked ${plural(pathsChecked, "path")} are EXCLUDED from backup` +
    (unknownCount > 0 ? `, ${unknownCount} ${plural(unknownCount, "path")} unknown` : "") +
    `.`
  );
}

// ---- human view -------------------------------------------------------------
const lines: string[] = [];
lines.push("TIME MACHINE EXCLUSIONS AUDIT");
lines.push("");
lines.push(headlineLine());
lines.push("");

if (discoverTruncated) {
  lines.push(`unavailable -- discover_paths: ${truncationNote(discoverResult.bytes)}`);
} else if (checkTruncated) {
  lines.push(`unavailable -- check_exclusions: ${truncationNote(checkResult.bytes)}`);
} else if (macosNote) {
  lines.push(`This host reports platform "${platform}" -- nothing else to check here.`);
} else if (!check) {
  lines.push(`unavailable -- check_exclusions step ${checkStep.outcome.status}`);
} else {
  lines.push(`EXCLUDED PATHS (${excludedRows.length})`);
  if (excludedRows.length === 0) {
    lines.push("  none");
  } else {
    lines.push(`  ${"PATH".padEnd(56)}${"SOURCE".padEnd(24)}KIND`);
    excludedRows.forEach((r: any) => {
      const path = String(r?.path_display ?? "?").padEnd(56);
      const source = String(r?.exclusion_source ?? "unknown").padEnd(24);
      const kind = String(r?.kind ?? "?");
      // exclusion_source counts an AFFECTED path, not an independent rule,
      // when it is inherited-sticky-xattr -- name the ancestor that
      // actually carries the exclusion rather than leaving it implicit.
      const inherited = r?.inherited_from ? `  (inherited from ${r.inherited_from})` : "";
      lines.push(`  ${path}${source}${kind}${inherited}`);
    });
  }
  lines.push("");

  if (unknownRows.length > 0) {
    lines.push(`UNKNOWN (${unknownRows.length}) -- could not be determined this run, never counted as included or excluded`);
    unknownRows.forEach((r: any) => {
      lines.push(`  ${String(r?.path_display ?? "?").padEnd(56)}${String(r?.reason ?? "unknown reason")}`);
    });
    lines.push("");
  }

  if (discover?.warning) {
    lines.push(`DISCOVERY NOTE -- ${discover.warning}`);
    lines.push("");
  }
  if (check?.warning) {
    lines.push(`CHECK NOTE -- ${check.warning}`);
    lines.push("");
  }

  lines.push("CHECKED (what this report is actually based on)");
  if (discover) {
    lines.push(
      `  - ${discover.paths_total ?? 0} path(s) discovered under ${discover.base_display ?? "(unknown base)"} (depth ${discover.max_depth ?? "?"}): ` +
        `${discover.fixed_roots_found ?? 0} fixed root(s), ${discover.dev_dirs_found ?? 0} dev dir(s) found, ${discover.projects_found ?? 0} project(s)`,
    );
  }
  checkedList.forEach((c) => lines.push(`  - ${c}`));
  lines.push("");

  lines.push("UNVERIFIED (this audit cannot tell you)");
  unverifiedList.forEach((u) => lines.push(`  - ${u}`));
  lines.push("");
}

lines.push("STAGES");
lines.push(
  stageLine("discover paths  ", discoverStep, discoverResult, (p) =>
    macosNote ? macosNote : `${p.paths_total ?? 0} path(s) discovered under ${p.base_display ?? "?"}`,
  ),
);
lines.push(
  stageLine("check exclusions", checkStep, checkResult, (p) =>
    macosNote ? macosNote : `${p.paths_checked ?? 0} path(s) asked of tmutil, ${p.excluded_count ?? 0} excluded`,
  ),
);

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
out.summary(
  discoverTruncated
    ? `timemachine-exclusions-audit: discover_paths unavailable (${truncationNote(discoverResult.bytes)})`
    : checkTruncated
      ? `timemachine-exclusions-audit: check_exclusions unavailable (${truncationNote(checkResult.bytes)})`
      : macosNote
        ? `timemachine-exclusions-audit: ${macosNote}`
        : !check
          ? "timemachine-exclusions-audit: check_exclusions unavailable"
          : tmutilUnavailable
            ? "timemachine-exclusions-audit: tmutil isexcluded unavailable, no usable answer this run"
            : `timemachine-exclusions-audit: ${excludedCount} of ${pathsChecked} checked paths excluded` +
              (unknownCount > 0 ? `, ${unknownCount} unknown` : ""),
);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: Boolean(discover) && Boolean(check),
  platform,
  headline: headlineLine(),
  totals: {
    paths_total: pathsTotal,
    paths_checked: pathsChecked,
    excluded_count: excludedCount,
    unknown_count: unknownCount,
  },
  excluded: excludedRows,
  unknown: unknownRows,
  discover: {
    status: discoverStep.outcome.status,
    warning: discoverTruncated ? truncationNote(discoverResult.bytes) : discover?.warning ?? null,
    base_display: discover?.base_display ?? null,
    max_depth: discover?.max_depth ?? null,
    fixed_roots_found: discover?.fixed_roots_found ?? null,
    dev_dirs_found: discover?.dev_dirs_found ?? null,
    projects_found: discover?.projects_found ?? null,
    // discover.truncated (above/below) is the WALK's own deadline/repo-cap
    // signal, self-reported by discover_paths.py -- a different concept
    // from rote's capture cap, named separately here so the two are never
    // conflated.
    truncated: discover?.truncated ?? null,
    capture_truncated: discoverTruncated,
    capture_truncated_bytes: discoverTruncated ? discoverResult.bytes : null,
  },
  check: {
    status: checkStep.outcome.status,
    warning: checkTruncated ? truncationNote(checkResult.bytes) : check?.warning ?? null,
    tmutil_unavailable: tmutilUnavailable,
    system_skip_paths_state: check?.system_skip_paths_state ?? null,
    system_skip_paths_count: check?.system_skip_paths_count ?? null,
    capture_truncated: checkTruncated,
    capture_truncated_bytes: checkTruncated ? checkResult.bytes : null,
  },
  checked: checkedList,
  unverified: [
    ...(discoverTruncated ? [`discover_paths: ${truncationNote(discoverResult.bytes)}`] : []),
    ...(checkTruncated ? [`check_exclusions: ${truncationNote(checkResult.bytes)}`] : []),
    ...unverifiedList,
  ],
  representations: {
    human: "complete -- headline, excluded-paths table, unknown list, discovery/check notes, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- every excluded and unknown path this run produced, plus discover/check step detail",
    summary: "intentionally lossy -- headline counts only",
  },
});
