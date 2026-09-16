#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: commit-identity-check
 * description: 'The wrong-email commit everyone has pushed -- a work email landing on a personal repo, or a personal email landing on a work one -- is easiest to catch BEFORE it happens, not after: this play resolves the EXACT identity your next commit in each repo would actually use, so the mistake is visible before you commit it, not after you have already pushed it. Five jobs: discover_repos walks base_dir up to max_depth levels (pruning node_modules and the same conservative noise list laptop-loss-drill''s sweep already established, never descending into a found repository''s own .git internals), bounded by one wall-clock deadline and a repository cap; for every discovered repo, scan_identities resolves user.name/user.email the exact way git itself would -- one unscoped `git config --show-origin --show-scope --get`, so git''s own local > includeIf > global precedence decides the winner, never re-derived by hand -- and reports the WINNING SOURCE (its scope and origin file) alongside the value, never guessed; once per run, not per repo, it separately lists every includeIf.gitdir CONDITION configured in your global config, names only -- the file each condition points at is only ever read indirectly, when some discovered repo''s own path actually matches it, never opened proactively here; every repo whose resolved email differs from the DOMINANT email among its SIBLINGS -- every other discovered repo sharing its immediate parent directory, and only when one email strictly outnumbers every other email in that group -- is flagged suspect (conservative "-suspect" language, never a certainty; a tie flags nothing, since there is no dominant email to disagree with); and for every repo with commits, the one narrow exception to this play''s otherwise forward-looking job, the last up to 5 commits'' author emails on this branch''s own first-parent line of descent -- never a merged-in side branch, never the subject line, never the body -- none of them matching is the just-changed-jobs trap made visible: recent history was written under one email while the next commit would silently use another. commit-attribution-guard, this play''s identity-hygiene sibling, audits what already landed in your commit messages; this play never looks at what already happened except for that one disclosed drift check, and its whole job is the commit that has not happened yet. A repo with no user.name or no user.email resolved at ANY scope is flagged separately from all three checks above: the next commit there would either fail outright (with user.useConfigOnly set) or fall back to git''s own guessed login@hostname identity with a warning -- neither is a configured identity this play can vouch for. Read-only, no credentials, no network; every git call is --no-optional-locks with a scrubbed environment (GIT_TERMINAL_PROMPT=0, LC_ALL=C, inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE stripped); needs python3 and git 2.26+ (the floor for --show-scope).'
 * version: 0.1.1
 * source_url: https://play.modiqo.ai/dotisacat/commit-identity-check
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: commit-identity-check
 * metadata:
 *   version: 0.1.1
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   discover_repos: resources/presentation-fixtures/discover_repos/fixture.yaml
 *   scan_identities: resources/presentation-fixtures/scan_identities/fixture.yaml
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
 *       ok:
 *         type: boolean
 *       headline:
 *         type: string
 *       totals:
 *         type: object
 *       identity_groups:
 *         type: array
 *       flags:
 *         type: object
 *       includeif_patterns:
 *         type: array
 *       discover:
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
 * - name: base_dir
 *   param_type: string
 *   required: false
 *   default: ~/Documents
 *   description: Folder to sweep for git repositories. Tilde expands to your home directory; relative paths resolve against the run workspace, not wherever you were thinking of -- prefer absolute paths.
 *   example: ~/Documents
 * - name: max_depth
 *   param_type: integer
 *   required: false
 *   default: '3'
 *   description: How many directory levels below base_dir to search for repositories (1-6)
 *   example: '3'
 * steps:
 *   discover_repos:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{discover_repos.py}'
 *     - $base_dir
 *     - $max_depth
 *   scan_identities:
 *     type: process.exec
 *     timeout_ms: 60000
 *     depends_on:
 *     - discover_repos
 *     argv:
 *     - python3
 *     - '@resource{scan_identities.py}'
 *     - '@discover_repos{$.stdout.text | fromjson | .packed}'
 *     - '@discover_repos{$.stdout.text | fromjson | .repos_total}'
 *     - $base_dir
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
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? parsed.warning ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const discoverStep = ctx.step(stepName("discover_repos"));
const scanStep = ctx.step(stepName("scan_identities"));

const discoverResult = parsedStdout(discoverStep);
const scanResult = parsedStdout(scanStep);

const discoverData = dataOf(discoverResult);
const scanData = dataOf(scanResult);

const discoverTruncated = discoverResult.kind === "truncated";
const scanTruncated = scanResult.kind === "truncated";

const totals = scanData?.totals && typeof scanData.totals === "object" ? scanData.totals : {};
const reposTotal = typeof totals.repos_total === "number" ? totals.repos_total : (discoverData?.repos_total ?? 0);
const distinctEmails = typeof totals.distinct_emails === "number" ? totals.distinct_emails : 0;
const suspectCount = typeof totals.suspect_count === "number" ? totals.suspect_count : 0;
const noIdentityCount = typeof totals.no_identity_count === "number" ? totals.no_identity_count : 0;
const driftCount = typeof totals.drift_count === "number" ? totals.drift_count : 0;
const driftUnverifiedCount = typeof totals.drift_unverified_count === "number" ? totals.drift_unverified_count : 0;
const unknownCount = typeof totals.unknown_count === "number" ? totals.unknown_count : 0;

// Guarded the same way every collection-bearing field in this fleet is: a
// shape mismatch from a degraded/malformed producer renders as an empty
// list rather than throwing on .forEach()/.map() below.
const identityGroups: any[] = Array.isArray(scanData?.identity_groups) ? scanData.identity_groups : [];
const flagsRaw = scanData?.flags && typeof scanData.flags === "object" ? scanData.flags : {};
const noIdentityFlags: any[] = Array.isArray(flagsRaw.no_identity) ? flagsRaw.no_identity : [];
const suspectFlags: any[] = Array.isArray(flagsRaw.suspect) ? flagsRaw.suspect : [];
const driftFlags: any[] = Array.isArray(flagsRaw.drift) ? flagsRaw.drift : [];
const driftUnverifiedFlags: any[] = Array.isArray(flagsRaw.drift_unverified) ? flagsRaw.drift_unverified : [];
const unknownFlags: any[] = Array.isArray(flagsRaw.unknown) ? flagsRaw.unknown : [];
const includeifPatterns: string[] = Array.isArray(scanData?.includeif_patterns) ? scanData.includeif_patterns : [];

const plural = (n: number, word: string) => `${word}${n === 1 ? "" : "s"}`;

function headlineLine(): string {
  const identityWord = distinctEmails === 1 ? "identity" : "identities";
  return (
    `${reposTotal} ${plural(reposTotal, "repo")}, ${distinctEmails} distinct ${identityWord}; ` +
    `${suspectCount} ${plural(suspectCount, "repo")} would commit with a suspect identity, ${noIdentityCount} have none configured`
  );
}

const allConsistent =
  Boolean(scanData) &&
  reposTotal > 0 &&
  suspectCount === 0 &&
  noIdentityCount === 0 &&
  driftCount === 0 &&
  driftUnverifiedCount === 0 &&
  unknownCount === 0;

// A missing/unreadable base_dir reports repos_total: 0 with a warning; that
// must never read the same as "swept everything, found zero repos" (a valid,
// unremarkable outcome with no warning) -- same distinction laptop-loss-drill
// draws for the identical base_dir/max_depth sweep.
const sweepUnavailable = Boolean(discoverData) && reposTotal === 0 && Boolean(discoverData.warning);
const noReposFound = Boolean(scanData) && !sweepUnavailable && reposTotal === 0;

function repoWord(n: number): string {
  return n === 1 ? "repository" : "repositories";
}

function topLine(): string {
  // A cut capture is never trusted downstream, so truncation is checked
  // before any other "no data" explanation -- discover_repos first, since
  // scan_identities' own input is derived from its output.
  if (discoverTruncated) return `discovery unavailable -- discover_repos: ${truncationNote(discoverResult.bytes)}`;
  if (scanTruncated) return `scan unavailable -- scan_identities: ${truncationNote(scanResult.bytes)}`;
  if (!scanData) return `scan unavailable -- scan_identities step ${scanStep.outcome.status}`;
  if (sweepUnavailable) return `base_dir sweep unavailable -- ${discoverData.warning}`;
  if (noReposFound) return `no git repositories found under ${discoverData?.base ?? "base_dir"} (depth ${discoverData?.max_depth ?? "?"}) -- nothing to check`;
  return headlineLine();
}

// ---- human view -------------------------------------------------------------
const lines: string[] = [];
lines.push("COMMIT IDENTITY CHECK");
lines.push("");

lines.push(topLine());

if (scanData && !discoverTruncated && !sweepUnavailable && !noReposFound) {
  if (allConsistent) {
    lines.push(
      "all consistent -- no suspect identities, nothing unconfigured, no past-vs-future drift in the repositories scanned",
    );
  }
  if (unknownCount > 0) {
    lines.push(`(${unknownCount} ${plural(unknownCount, "repo")} could not be read; see FLAGS below)`);
  }
  lines.push("");

  lines.push("IDENTITY GROUPS");
  if (identityGroups.length === 0) {
    lines.push("  none -- no repo resolved an email");
  } else {
    identityGroups.forEach((g: any) => {
      const email = String(g?.email ?? "?");
      const count = typeof g?.repo_count === "number" ? g.repo_count : 0;
      const scopes = Array.isArray(g?.scopes) ? g.scopes.join(", ") : "?";
      lines.push(`  ${email.padEnd(36)} ${String(count).padStart(3)} ${plural(count, "repo").padEnd(6)} scope: ${scopes}`);
    });
  }
  lines.push("");

  lines.push("FLAGS");

  lines.push(`  no identity configured (${noIdentityCount})`);
  if (noIdentityFlags.length === 0) {
    lines.push("    none -- every scanned repo resolved both user.name and user.email");
  } else {
    noIdentityFlags.forEach((r: any) => {
      lines.push(`    ${r?.repo ?? "?"}  --  next commit would fail (user.useConfigOnly) or fall back to a guessed identity`);
    });
    if (totals.no_identity_shown != null && totals.no_identity_shown < noIdentityCount) {
      lines.push(`    (showing ${totals.no_identity_shown} of ${noIdentityCount})`);
    }
  }

  lines.push(`  suspect identity (${suspectCount})`);
  if (suspectFlags.length === 0) {
    lines.push("    none -- no repo's resolved email disagreed with its sibling group's dominant email");
  } else {
    suspectFlags.forEach((r: any) => {
      lines.push(`    ${r?.repo ?? "?"}  resolved: ${r?.email ?? "?"}  -- ${r?.suspect_reason ?? "differs from sibling group"}`);
    });
    if (totals.suspect_shown != null && totals.suspect_shown < suspectCount) {
      lines.push(`    (showing ${totals.suspect_shown} of ${suspectCount})`);
    }
  }

  lines.push(`  past-vs-future drift (${driftCount})`);
  if (driftFlags.length === 0) {
    lines.push("    none -- last 5 commits (where present) match the identity the next commit would use");
  } else {
    driftFlags.forEach((r: any) => {
      const recent = Array.isArray(r?.recent_emails) ? r.recent_emails.join(", ") : "?";
      lines.push(`    ${r?.repo ?? "?"}  next: ${r?.email ?? "?"}  recent commits: ${recent}`);
    });
    if (totals.drift_shown != null && totals.drift_shown < driftCount) {
      lines.push(`    (showing ${totals.drift_shown} of ${driftCount})`);
    }
  }

  if (driftUnverifiedCount > 0) {
    lines.push(`  drift check unavailable (${driftUnverifiedCount})`);
    driftUnverifiedFlags.forEach((r: any) => {
      lines.push(`    ${r?.repo ?? "?"}  -- ${r?.drift_warning ?? "drift could not be checked"}`);
    });
    if (totals.drift_unverified_shown != null && totals.drift_unverified_shown < driftUnverifiedCount) {
      lines.push(`    (showing ${totals.drift_unverified_shown} of ${driftUnverifiedCount})`);
    }
  }

  if (unknownCount > 0) {
    lines.push(`  could not be read (${unknownCount})`);
    unknownFlags.forEach((r: any) => {
      lines.push(`    ${r?.repo ?? "?"}  ${r?.unknown ?? "unknown reason"}`);
    });
    if (totals.unknown_shown != null && totals.unknown_shown < unknownCount) {
      lines.push(`    (showing ${totals.unknown_shown} of ${unknownCount})`);
    }
  }
  lines.push("");

  lines.push("CONDITIONAL INCLUDES (names only -- from your global config)");
  if (includeifPatterns.length === 0) {
    lines.push("  none configured");
  } else {
    includeifPatterns.forEach((p: string) => lines.push(`  ${p}`));
  }
  if (scanData.includeif_warning) {
    lines.push(`  degraded -- ${scanData.includeif_warning}`);
  }
}
lines.push("");

lines.push("CHECKED (what this report is actually based on)");
if (!discoverTruncated && discoverData) {
  const base = discoverData.base ?? "(unknown base)";
  const depth = discoverData.max_depth ?? "?";
  lines.push(`  - ${reposTotal} ${repoWord(reposTotal)} discovered under ${base} (depth ${depth})`);
  if (discoverData.truncated_by_deadline) lines.push("  - discovery hit its time budget before finishing the walk; not every repository under base_dir was found");
  if (discoverData.truncated_by_repo_cap) lines.push("  - discovery hit its repository cap before finishing the walk; not every repository under base_dir was found");
}
// A truncated scan_identities capture never earns this methodology line --
// it names what was VERIFIED this run, and a cut capture verified nothing.
if (!scanTruncated) {
  lines.push("  - each repo's identity read via `git config --show-origin --show-scope --get`, honoring git's own local > includeIf > global precedence -- never re-derived by hand");
}
if (unknownCount > 0) {
  lines.push(`  - ${unknownCount} ${plural(unknownCount, "repo")} could not be read within the scan's time/permission budget and are reported UNKNOWN, never counted as configured or unconfigured`);
}
lines.push("");

lines.push("UNVERIFIED (this play cannot tell you)");
// A truncated step's line moves out of CHECKED and into here, named --
// never left asserting a fact that a partial capture cannot back up.
if (discoverTruncated) {
  lines.push(`  - discover_repos: ${truncationNote(discoverResult.bytes)}`);
}
if (scanTruncated) {
  lines.push(`  - scan_identities: ${truncationNote(scanResult.bytes)}`);
}
lines.push("  - which identity is RIGHT for any given repo -- only you know that; this play reports what would be used next, and what its siblings are doing, nothing more");
lines.push("  - commit templates, hooks, or CI steps that could rewrite authorship after the fact -- see commit-attribution-guard for what already landed in history");
lines.push("  - shell environment variables (GIT_AUTHOR_EMAIL, GIT_COMMITTER_EMAIL, EMAIL) that could override the configured identity at commit time -- this reports the CONFIG resolution only");
lines.push("  - repositories outside base_dir/max_depth, and anything pruned as node_modules or similar during the walk");
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine("discover repos  ", discoverStep, discoverResult, (p) => `${p.repos_total ?? 0} repo(s) found under ${p.base ?? "?"}`),
);
lines.push(
  stageLine("scan identities ", scanStep, scanResult, (p) => `${p.totals?.repos_scanned ?? 0} repo(s) scanned, ${p.totals?.distinct_emails ?? 0} distinct email(s)`),
);

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
out.summary(`commit identity check: ${topLine()}`);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: Boolean(discoverData) && Boolean(scanData),
  headline: topLine(),
  totals: {
    repos_total: reposTotal,
    distinct_emails: distinctEmails,
    suspect_count: suspectCount,
    no_identity_count: noIdentityCount,
    drift_count: driftCount,
    drift_unverified_count: driftUnverifiedCount,
    unknown_count: unknownCount,
    all_consistent: allConsistent,
    sweep_unavailable: sweepUnavailable,
    no_repos_found: noReposFound,
  },
  identity_groups: identityGroups,
  flags: {
    no_identity: noIdentityFlags,
    suspect: suspectFlags,
    drift: driftFlags,
    drift_unverified: driftUnverifiedFlags,
    unknown: unknownFlags,
  },
  includeif_patterns: includeifPatterns,
  discover: {
    status: discoverStep.outcome.status,
    base: discoverData?.base ?? null,
    max_depth: discoverData?.max_depth ?? null,
    warning: discoverTruncated ? truncationNote(discoverResult.bytes) : discoverData?.warning ?? null,
  },
  scan: {
    status: scanStep.outcome.status,
    warning: scanTruncated ? truncationNote(scanResult.bytes) : scanData?.warning ?? null,
  },
  checked: [
    discoverTruncated
      ? `discover_repos truncated -- ${truncationNote(discoverResult.bytes)}`
      : discoverData
        ? `${reposTotal} ${repoWord(reposTotal)} discovered under ${discoverData.base ?? "?"} (depth ${discoverData.max_depth ?? "?"})`
        : "discover_repos unavailable",
    scanTruncated
      ? `scan_identities truncated -- ${truncationNote(scanResult.bytes)}`
      : "identity resolved via git config --show-origin --show-scope --get, honoring local > includeIf > global precedence",
    scanTruncated
      ? "unread/unknown-repo accounting unavailable -- scan_identities was truncated"
      : unknownCount > 0
        ? `${unknownCount} repo(s) unread, reported unknown`
        : "every discovered repo was read",
    scanTruncated
      ? "drift accounting unavailable -- scan_identities was truncated"
      : driftUnverifiedCount > 0
        ? `${driftUnverifiedCount} repo(s) had identity resolved but drift could not be checked, reported drift_unverified`
        : "drift was checked for every repo with commits",
  ],
  unverified: [
    ...(discoverTruncated ? [`discover_repos: ${truncationNote(discoverResult.bytes)}`] : []),
    ...(scanTruncated ? [`scan_identities: ${truncationNote(scanResult.bytes)}`] : []),
    "which identity is RIGHT for any given repo -- only you know that",
    "commit templates/hooks/CI steps that could rewrite authorship after the fact",
    "shell environment variables (GIT_AUTHOR_EMAIL, GIT_COMMITTER_EMAIL, EMAIL) that could override the configured identity at commit time",
    "repositories outside base_dir/max_depth, and anything pruned (node_modules or similar) during the walk",
  ],
  representations: {
    human: "complete -- headline, IDENTITY GROUPS table, FLAGS (no-identity/suspect/drift/drift-unverified/unknown), conditional includes, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- full totals, identity_groups, and every flagged repo row (no-identity/suspect/drift/drift-unverified/unknown), even when the human view only shows a subset",
    summary: "intentionally lossy -- the headline line only",
  },
});
