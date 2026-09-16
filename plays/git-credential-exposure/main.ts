#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: git-credential-exposure
 * description: 'The three places git authentication leaks in cleartext, all covered in one sweep: your ~/.git-credentials file, your credential.helper config, and every repo''s remote URLs. Every embedded user:token pair found is reduced to HOST, a token SHAPE (sk-, ghp_, gho_, xox[bp]-, AKIA, an eyJ-led JWT, else a generic "stored-credential" bucket), and a 4-character-plus-length preview -- NEVER the token itself, and never the username either. Its permission bits are flagged whenever group- or world-readable. credential.helper is resolved at every scope (system, global, per-repo local/worktree); only a coarse KIND is reported (store, cache, osxkeychain, ...), never the raw value, which can itself be an arbitrary shell command. helper=store is flagged with an advisory to switch to your platform''s credential manager (osxkeychain on macOS). A bounded repo sweep also reads each remote URL for an embedded user:token or x-access-token:token credential. Every git call runs with a scrubbed, non-interactive environment; git missing from PATH fails the scan closed, never a silent clean. Never claims a clean bill unless everything was actually scanned and fully undegraded, and discloses upfront: credentials already sitting in your OS keychain -- the SAFE place -- are exactly what this play does NOT scan. Read-only, no credentials transmitted, no network; needs python3 and git.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/git-credential-exposure
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: git-credential-exposure
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   scan_global: resources/presentation-fixtures/scan_global/fixture.yaml
 *   scan_repos: resources/presentation-fixtures/scan_repos/fixture.yaml
 * tags:
 * - domain-security
 * - job-secret-hygiene
 * - audience-developers
 * - effect-read-only
 * - tool-git
 * discoverability:
 *   tags:
 *   - domain-security
 *   - job-secret-hygiene
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
 *       credentials_file:
 *         type: object
 *       global_helper:
 *         type: object
 *       repos:
 *         type: object
 *       totals:
 *         type: object
 *       scan_global:
 *         type: object
 *       scan_repos:
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
 *   description: Folder to sweep for git repositories whose local credential.helper and remotes get checked. Tilde expands to your home directory; relative paths resolve against the run workspace, not wherever you were thinking of -- prefer absolute paths.
 *   example: ~/Documents
 * - name: max_depth
 *   param_type: integer
 *   required: false
 *   default: '3'
 *   description: How many directory levels below base_dir to search for repositories (1-6)
 *   example: '3'
 * steps:
 *   scan_global:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{scan_exposure.py}'
 *     - --global
 *   scan_repos:
 *     type: process.exec
 *     timeout_ms: 60000
 *     argv:
 *     - python3
 *     - '@resource{scan_exposure.py}'
 *     - --repos
 *     - $base_dir
 *     - $max_depth
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
  try { return { kind: "ok", data: JSON.parse(text) }; } catch { return { kind: "unparseable" }; }
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
  if (parsed.ok === false) return `  degraded  ${label}  ${parsed.error ?? "unknown reason"}`;
  if (parsed.warning) return `  degraded  ${label}  ${parsed.warning}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const scanGlobalStep = ctx.step(stepName("scan_global"));
const scanReposStep = ctx.step(stepName("scan_repos"));

const scanGlobalResult = parsedStdout(scanGlobalStep);
const scanReposResult = parsedStdout(scanReposStep);

const globalData = scanGlobalResult.kind === "ok" ? scanGlobalResult.data : null;
const reposData = scanReposResult.kind === "ok" ? scanReposResult.data : null;
const globalTruncated = scanGlobalResult.kind === "truncated";
const reposTruncated = scanReposResult.kind === "truncated";

// scan_global and scan_repos are two INDEPENDENT root steps -- either can
// be truncated while the other completes cleanly, so anything that
// summarizes across both (the one-line summary below) must check both
// independently rather than trusting either alone.
const anyStepTruncated = globalTruncated || reposTruncated;

// scan_global and scan_repos are two INDEPENDENT root steps (no depends_on
// between them) -- either can succeed while the other degrades or fails, so
// every section below is gated on its OWN source's availability, never a
// combined all-or-nothing gate. A truncated capture is never trusted as
// data either -- globalData/reposData stay null exactly as they would for
// any other unusable read, so no count, clean bill, or `ok: true` is ever
// built on a partial capture (the truncation FACT itself is still
// surfaced, distinctly, via unavailableReason below and in
// CHECKED/UNVERIFIED).
const globalUnavailable = !globalData || globalData.ok === false;
const reposUnavailable = !reposData || reposData.ok === false;

const credFile = globalUnavailable ? null : (globalData.credentials_file ?? {});
const globalHelper = globalUnavailable ? null : (globalData.global_helper ?? {});
const findings: any[] = Array.isArray(credFile?.findings) ? credFile.findings : [];
const platform: string | null = globalUnavailable ? null : (globalData.platform ?? null);

const reposTotals = reposUnavailable ? {} : (reposData.totals && typeof reposData.totals === "object" ? reposData.totals : {});
const helperStoreRepos: any[] = reposUnavailable ? [] : (Array.isArray(reposData.helper_store_repos) ? reposData.helper_store_repos : []);
const embeddedFindings: any[] = reposUnavailable ? [] : (Array.isArray(reposData.embedded_cred_findings) ? reposData.embedded_cred_findings : []);
const unknownRepos: any[] = reposUnavailable ? [] : (Array.isArray(reposData.unknown_repos) ? reposData.unknown_repos : []);

const plural = (n: number, word: string) => `${word}${n === 1 ? "" : "s"}`;
const repoWord = (n: number) => (n === 1 ? "repository" : "repositories");

const credCount = globalUnavailable ? null : ((credFile.entry_count ?? 0) - (credFile.parse_error_count ?? 0));
const repoCredCount = reposUnavailable ? null : (reposTotals.embedded_cred_repo_count ?? 0);
const helperStoreAnywhere = Boolean(globalHelper?.is_store) || (reposTotals.helper_store_count ?? 0) > 0;

// ---- coverage gating -- an unreadable/stat-failed credentials file, any
// parse error, a failed/timed-out helper check, an unknown repository, or a
// deadline/repo-cap truncation all mean "not everything was actually
// scanned" -- none of these are allowed to still yield ok:true or a clean
// bill (see gotcha: "unknown repositories are never counted as clean").
const credFileReadIssue = !globalUnavailable && Boolean(credFile.exists) && (!credFile.readable || Boolean(credFile.reason));
const credFileParseIssue = !globalUnavailable && Boolean(credFile.exists) && Boolean(credFile.readable) && (credFile.parse_error_count ?? 0) > 0;
const globalHelperIssue = !globalUnavailable && Boolean(globalHelper?.warning);
const reposCoverageIssue = !reposUnavailable && (
  (reposTotals.unknown_count ?? 0) > 0 ||
  Boolean(reposData.truncated_by_deadline) ||
  Boolean(reposData.truncated_by_repo_cap)
);
const fullyCovered =
  !globalUnavailable && !reposUnavailable &&
  !credFileReadIssue && !credFileParseIssue && !globalHelperIssue && !reposCoverageIssue;

function headlineLine(): string {
  const credPart = credCount === null
    ? "credentials file unavailable"
    : `${credCount} plaintext ${plural(credCount, "credential")} on disk`;
  const repoPart = repoCredCount === null
    ? "repo remotes unavailable"
    : `${repoCredCount} ${plural(repoCredCount, "repo")} with embedded-credential remotes`;
  const helperPart = (globalUnavailable && reposUnavailable)
    ? "helper=store: unknown"
    : `helper=store: ${helperStoreAnywhere ? "yes" : "no"}`;
  return `${credPart}, ${repoPart}, ${helperPart}`;
}

const somethingScanned =
  (!globalUnavailable && credFile?.exists) ||
  (!reposUnavailable && (reposTotals.repos_total ?? 0) > 0);
const earnedCleanBill =
  fullyCovered &&
  credCount === 0 && repoCredCount === 0 && !helperStoreAnywhere &&
  somethingScanned;

// ---- human view -------------------------------------------------------------
const lines: string[] = [];
lines.push("GIT CREDENTIAL EXPOSURE");
lines.push("");

lines.push(headlineLine());
if (earnedCleanBill) {
  lines.push("clean -- no plaintext credentials on disk, no embedded-credential remotes, credential.helper is never store.");
} else if (!globalUnavailable && !reposUnavailable) {
  const coverageGaps: string[] = [];
  if (credFileReadIssue) coverageGaps.push("~/.git-credentials could not be fully read");
  if (credFileParseIssue) coverageGaps.push(`${credFile.parse_error_count} line(s) in ~/.git-credentials did not parse`);
  if (globalHelperIssue) coverageGaps.push("global credential.helper check failed");
  if ((reposTotals.unknown_count ?? 0) > 0) coverageGaps.push(`${reposTotals.unknown_count} ${plural(reposTotals.unknown_count, "repo")} unknown`);
  if (reposData.truncated_by_deadline) coverageGaps.push("repo walk truncated by time budget");
  if (reposData.truncated_by_repo_cap) coverageGaps.push("repo walk truncated by repo cap");
  if (coverageGaps.length > 0) {
    lines.push(`coverage incomplete -- ${coverageGaps.join("; ")} -- no clean bill until coverage is complete.`);
  }
}
lines.push("");

lines.push("GIT-CREDENTIALS FILE (~/.git-credentials)");
if (globalUnavailable) {
  lines.push(`  unavailable -- ${unavailableReason(scanGlobalStep, scanGlobalResult)}`);
} else if (!credFile.exists) {
  lines.push("  not present on this machine");
} else {
  const permNote = credFile.perm_flagged
    ? `FLAGGED -- mode ${credFile.mode_octal}, readable by group/others (should be 600, owner only)`
    : `mode ${credFile.mode_octal}, owner-only`;
  lines.push(`  present, ${permNote}`);
  if (!credFile.readable) {
    lines.push("  unreadable -- content could not be scanned");
  } else if (findings.length === 0) {
    lines.push(`  none of ${credFile.entry_count} stored line(s) carried a readable embedded credential`);
  } else {
    findings.forEach((f: any) => {
      lines.push(`  line ${String(f?.line ?? "?").padStart(4)}  ${String(f?.host ?? "?").padEnd(28)} ${String(f?.shape ?? "?").padEnd(20)} ${f?.value_preview ?? "?"}`);
    });
    if ((credFile.findings_truncated ?? 0) > 0) {
      lines.push(`  (${credFile.findings_truncated} more finding(s) not shown)`);
    }
  }
}
lines.push("");

// Helper values are never rendered here -- only the classified KIND (store,
// cache, osxkeychain, ...); a helper value can be an arbitrary `!` shell
// command or an absolute path carrying arguments, either of which could
// embed a token this play has no business repeating (see scan_exposure.py's
// classify_helper_kind). active_kinds is the final list surviving replay of
// git's own reset semantics -- system, then global, in effective order.
const kindsLabel = (kinds: any) => (Array.isArray(kinds) && kinds.length > 0 ? kinds.join(", ") : "none");

lines.push("CREDENTIAL HELPER");
if (globalUnavailable) {
  lines.push(`  global: unavailable -- ${unavailableReason(scanGlobalStep, scanGlobalResult)}`);
} else if (globalHelper.warning) {
  lines.push(`  global: unavailable -- ${globalHelper.warning}`);
} else if (globalHelper.is_store) {
  lines.push(`  global: FLAGGED -- store is active (system+global, effective order: ${kindsLabel(globalHelper.active_kinds)})`);
} else if (globalHelper.configured) {
  lines.push(`  global: ${kindsLabel(globalHelper.active_kinds)}`);
} else {
  lines.push(`  global: not configured${globalHelper.note ? " -- " + globalHelper.note : ""}`);
}
if (reposUnavailable) {
  lines.push(`  per-repo: unavailable -- ${unavailableReason(scanReposStep, scanReposResult)}`);
} else if (helperStoreRepos.length === 0) {
  lines.push("  per-repo: none of the scanned repositories effectively use credential.helper=store");
} else {
  helperStoreRepos.forEach((r: any) => {
    const sourceNote = r?.source === "local"
      ? "local override"
      : r?.source === "inherited"
        ? "inherited from global/system"
        : "store";
    lines.push(`  per-repo: FLAGGED -- ${r?.repo ?? "?"}  (${sourceNote})`);
  });
  if ((reposTotals.helper_store_count ?? 0) > helperStoreRepos.length) {
    lines.push(`  (${reposTotals.helper_store_count - helperStoreRepos.length} more repo(s) not shown)`);
  }
}
lines.push("");

lines.push("REMOTE URLS WITH EMBEDDED CREDENTIALS");
if (reposUnavailable) {
  lines.push(`  unavailable -- ${unavailableReason(scanReposStep, scanReposResult)}`);
} else if (embeddedFindings.length === 0) {
  lines.push(`  none found across ${reposTotals.repos_scanned ?? 0} scanned ${plural(reposTotals.repos_scanned ?? 0, "repo")}`);
} else {
  embeddedFindings.forEach((f: any) => {
    lines.push(`  ${String(f?.repo ?? "?").padEnd(24)} ${String(f?.remote ?? "?").padEnd(10)} ${String(f?.host ?? "?").padEnd(24)} ${String(f?.shape ?? "?").padEnd(20)} ${f?.value_preview ?? "?"}`);
  });
  if ((reposTotals.embedded_cred_finding_count ?? 0) > embeddedFindings.length) {
    lines.push(`  (${reposTotals.embedded_cred_finding_count - embeddedFindings.length} more finding(s) not shown)`);
  }
}
if (!reposUnavailable && unknownRepos.length > 0) {
  lines.push(`  (${reposTotals.unknown_count ?? unknownRepos.length} repo(s) could not be read; see CHECKED below)`);
}
lines.push("");

lines.push("ADVISORIES (text only -- nothing here is ever executed on your behalf)");
const advisories: string[] = [];
if ((credCount ?? 0) > 0) {
  advisories.push("rotate every credential listed above first -- a plaintext value already on disk should be treated as compromised regardless of file permissions.");
}
if (helperStoreAnywhere) {
  // credential.helper is cumulative -- a bare `git config credential.helper
  // <name>` errors out ("multiple values") the moment more than one is
  // already configured at that scope, which is common (e.g. store plus
  // anything else). --unset-all first, then --add, is the only sequence
  // that reliably lands on exactly one helper regardless of what was there
  // before. The helper name itself is platform-appropriate, not always
  // osxkeychain.
  const helperName = platform === "darwin" ? "osxkeychain" : platform === "win32" ? "manager" : "libsecret";
  const altNote = platform === "darwin"
    ? ""
    : platform === "win32"
      ? " (git for Windows ships `manager` by default -- the standard recommendation there)"
      : " (libsecret needs building from git's own contrib/credential/libsecret on most distros; substitute your distro's git-credential-manager package if that is already installed instead)";
  advisories.push(
    `git config --global --unset-all credential.helper && git config --global --add credential.helper ${helperName}${altNote}, then delete ~/.git-credentials after rotating. For any repo flagged above as a local override, repeat the same --unset-all/--add pair with \`--local\` in place of \`--global\` inside that repo -- a repo flagged as inherited already gets fixed by the global command above and needs no repo-local change.`,
  );
}
if ((repoCredCount ?? 0) > 0) {
  advisories.push("reset every flagged remote to drop the embedded credential -- `git remote set-url <name> <url-without-credential>` -- and let credential.helper authenticate instead of the URL itself.");
}
if (!globalUnavailable && credFile.perm_flagged) {
  advisories.push(
    platform === "win32"
      ? "restrict ~/.git-credentials to your own account via Windows ACLs (Properties > Security) -- though removing the file entirely once helper=store is replaced is the real fix."
      : "tighten ~/.git-credentials to 600 (owner read/write only) -- `chmod 600 ~/.git-credentials` -- though removing the file entirely once helper=store is replaced is the real fix.",
  );
}
if (advisories.length === 0) {
  lines.push("  none needed -- nothing above was flagged.");
} else {
  advisories.forEach((a) => lines.push(`  - ${a}`));
}
lines.push("");

lines.push("CHECKED (what this report is actually based on)");
if (!globalUnavailable) {
  lines.push(`  - ~/.git-credentials: ${credFile.exists ? "present" : "absent"}${credFile.exists ? `, permission bits read` : ""}`);
  lines.push("  - system+global credential.helper resolved via `git config <scope> --get-all credential.helper`, in effective order, empty (reset) entries preserved and replayed");
} else if (!globalTruncated) {
  lines.push(`  - scan_global unavailable -- ${globalData?.warning ?? unavailableReason(scanGlobalStep, scanGlobalResult)}`);
}
if (!reposUnavailable) {
  lines.push(`  - ${reposTotals.repos_total ?? 0} ${repoWord(reposTotals.repos_total ?? 0)} discovered under ${reposData.base ?? "base_dir"} (depth ${reposData.max_depth ?? "?"})`);
  lines.push("  - each repo's EFFECTIVE credential.helper (system+global+local+worktree, in effective order) and `git remote -v` read with --no-optional-locks and a scrubbed environment");
  if ((reposTotals.unknown_count ?? 0) > 0) {
    lines.push(`  - ${reposTotals.unknown_count} ${plural(reposTotals.unknown_count, "repo")} could not be read within the scan's time/permission budget and are reported unknown, never counted as clean`);
  }
} else if (!reposTruncated) {
  lines.push(`  - scan_repos unavailable -- ${reposData?.warning ?? unavailableReason(scanReposStep, scanReposResult)}`);
}
lines.push("");

lines.push("UNVERIFIED (this play cannot tell you)");
if (globalTruncated) {
  lines.push(`  - scan_global: ${unavailableReason(scanGlobalStep, scanGlobalResult)} -- nothing from this step is CHECKED above`);
}
if (reposTruncated) {
  lines.push(`  - scan_repos: ${unavailableReason(scanReposStep, scanReposResult)} -- nothing from this step is CHECKED above`);
}
lines.push("  - whether any matched token is still live -- a shape match is not proof");
lines.push("  - credentials already stored in your OS keychain (osxkeychain, Windows Credential Manager, libsecret) -- the SAFE place this play deliberately does not scan");
lines.push("  - repositories outside base_dir/max_depth, and anything pruned (node_modules or similar) during the walk");
lines.push("  - custom credential.helper values that are themselves shell commands -- their own content is not inspected for embedded secrets");
lines.push("  - ~/.netrc and any other credential store git can also read -- out of scope for this play");
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine("scan global ", scanGlobalStep, scanGlobalResult, (p) =>
    `${p.credentials_file?.exists ? "present" : "absent"}, ${(p.credentials_file?.findings ?? []).length} finding(s), helper ${p.global_helper?.is_store ? "store" : (p.global_helper?.configured ? "configured" : "unset")}`),
);
lines.push(
  stageLine("scan repos  ", scanReposStep, scanReposResult, (p) =>
    `${p.totals?.repos_scanned ?? 0} repo(s) scanned, ${p.totals?.embedded_cred_finding_count ?? 0} embedded finding(s)`),
);

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
const baseSummary = (globalUnavailable && reposUnavailable)
  ? "git credential exposure scan unavailable (degraded)"
  : `${headlineLine()}${earnedCleanBill ? " (clean)" : ""}`;
out.summary(
  anyStepTruncated ? `${baseSummary} — partial: one or more steps were truncated at the capture cap` : baseSummary,
);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: fullyCovered,
  headline: headlineLine(),
  credentials_file: credFile,
  global_helper: globalHelper,
  repos: {
    base: reposUnavailable ? null : (reposData.base ?? null),
    max_depth: reposUnavailable ? null : (reposData.max_depth ?? null),
    helper_store_repos: helperStoreRepos,
    embedded_cred_findings: embeddedFindings,
    unknown_repos: unknownRepos,
  },
  totals: {
    plaintext_credential_count: credCount,
    embedded_cred_repo_count: repoCredCount,
    helper_store_anywhere: helperStoreAnywhere,
    fully_covered: fullyCovered,
    earned_clean_bill: earnedCleanBill,
    ...reposTotals,
  },
  scan_global: {
    status: scanGlobalStep.outcome.status,
    truncated: globalTruncated,
    warning: globalData?.warning ?? (globalTruncated ? unavailableReason(scanGlobalStep, scanGlobalResult) : null),
  },
  scan_repos: {
    status: scanReposStep.outcome.status,
    truncated: reposTruncated,
    warning: reposData?.warning ?? (reposTruncated ? unavailableReason(scanReposStep, scanReposResult) : null),
  },
  checked: [
    globalUnavailable
      ? (globalTruncated ? null : `scan_global unavailable -- ${globalData?.warning ?? unavailableReason(scanGlobalStep, scanGlobalResult)}`)
      : `~/.git-credentials ${credFile.exists ? "present" : "absent"}; system+global credential.helper resolved via git config <scope> --get-all, effective order, resets replayed`,
    reposUnavailable
      ? (reposTruncated ? null : `scan_repos unavailable -- ${reposData?.warning ?? unavailableReason(scanReposStep, scanReposResult)}`)
      : `${reposTotals.repos_total ?? 0} repo(s) discovered under ${reposData.base ?? "base_dir"} (depth ${reposData.max_depth ?? "?"}), effective (system+global+local+worktree) credential.helper and remote -v read per repo`,
  ].filter((line): line is string => line !== null),
  unverified: [
    ...(globalTruncated ? [`scan_global: ${unavailableReason(scanGlobalStep, scanGlobalResult)}`] : []),
    ...(reposTruncated ? [`scan_repos: ${unavailableReason(scanReposStep, scanReposResult)}`] : []),
    "whether any matched token is still live -- a shape match is not proof",
    "credentials already stored in your OS keychain -- the SAFE place this play deliberately does not scan",
    "repositories outside base_dir/max_depth, and anything pruned (node_modules or similar) during the walk",
    "custom credential.helper values that are themselves shell commands -- their own content is not inspected",
    "~/.netrc and any other credential store git can also read -- out of scope for this play",
  ],
  representations: {
    human: "complete -- headline, per-surface sections (file, helper, remotes), text-only advisories, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- full credentials_file/global_helper/repos objects and every finding up to the display cap, even when the human view only shows a subset",
    summary: "intentionally lossy -- the headline line only",
  },
});
