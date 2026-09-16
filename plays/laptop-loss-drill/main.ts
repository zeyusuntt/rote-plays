#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: laptop-loss-drill
 * description: 'One question, answered with evidence: if this laptop died right now, what would you lose? Two readings joined into a verdict: your last backup (Time Machine consulted read-only via tmutil; unreachable or unconfigured states reported honestly, never papered over) and the work that exists NOWHERE but this disk -- unpushed commits counted against every remote-tracking ref, branches with no upstream at all, stashes, and dirty files, from a bounded sweep of the git repositories under base_dir. Loss claims are conservative: a commit reachable from any pushed ref is never counted as lost. This is loss exposure, not work triage -- it answers what is unrecoverable, not what needs attention. Every git read uses --no-optional-locks with a scrubbed environment; one unreadable repo degrades to a labeled unknown, never a crash. Zero loss renders a positive verdict: backed up and pushed means this laptop is replaceable. Read-only, no credentials, no network; needs only python3 and git.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/laptop-loss-drill
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: laptop-loss-drill
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * tags:
 * - domain-developer-workflow
 * - job-loss-exposure
 * - audience-developers
 * - effect-read-only
 * - tool-git
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       ok:
 *         type: boolean
 *         description: True whenever both roots produced a readable report, even a degraded one.
 *       verdict:
 *         type: object
 *         description: The one-line answer plus the counts it was built from.
 *       backup:
 *         type: object
 *         description: The last-backup reading -- age, destination, or a labeled unknown.
 *       repos:
 *         type: object
 *         description: Sweep scope and every nonzero-exposure or unknown repository row.
 *       checked:
 *         type: array
 *         description: What a clean result above is actually based on, with counts.
 *       unverified:
 *         type: array
 *         description: What this play deliberately does not check.
 *     representations:
 *       type: object
 *       description: Parity notes for the human, summary, and json views.
 * presentation_fixtures:
 *   backup_status: resources/presentation-fixtures/backup_status/fixture.yaml
 *   sweep_loss: resources/presentation-fixtures/sweep_loss/fixture.yaml
 * parameters:
 * - name: base_dir
 *   param_type: string
 *   required: false
 *   default: ~/Documents
 *   description: Folder to sweep for git repositories. Tilde expands to your home directory; relative paths resolve against the run workspace, so prefer absolute paths.
 *   example: ~/Documents
 * - name: max_depth
 *   param_type: integer
 *   required: false
 *   default: '3'
 *   description: How many directory levels below base_dir to search for repositories (1-6), keep small; large trees get slow.
 *   example: '3'
 * steps:
 *   backup_status:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - python3
 *     - '@resource{backup_status.py}'
 *   sweep_loss:
 *     type: process.exec
 *     timeout_ms: 90000
 *     argv:
 *     - python3
 *     - '@resource{sweep_loss.py}'
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

/** Trims to maxLen on a word or punctuation boundary, never mid-word, and
 * marks the cut with an explicit ellipsis -- used only for the short STAGES
 * reference; the full text still belongs in its own section (BACKUP). */
function shortNote(raw: string, maxLen = 70): string {
  if (raw.length <= maxLen) return raw;
  const clipped = raw.slice(0, maxLen);
  const boundary = Math.max(clipped.lastIndexOf(" "), clipped.lastIndexOf(","), clipped.lastIndexOf(";"), clipped.lastIndexOf("."));
  const cut = boundary > maxLen / 2 ? clipped.slice(0, boundary) : clipped;
  return `${cut.replace(/[.,;\s]+$/, "")}...`;
}

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(
  label: string,
  step: ReturnType<typeof ctx.step>,
  result: StdoutRead,
  okNote: (p: any) => string,
  warningNote: (raw: string) => string = (raw) => raw,
): string {
  const status = step.outcome.status; // completed | restored | skipped | blocked | failed
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(8)}  ${label}  step ${status}`;
  }
  if (result.kind === "truncated") {
    return `  truncated ${label}  ${truncationNote(result.bytes)}`;
  }
  const parsed = dataOf(result);
  if (!parsed) return `  degraded  ${label}  output did not parse as JSON`;
  if (parsed.ok === false) return `  degraded  ${label}  ${warningNote(parsed.reason ?? parsed.warning ?? "unknown reason")}`;
  if (parsed.warning) return `  degraded  ${label}  ${warningNote(parsed.warning)}`;
  return `  ok        ${label}  ${okNote(parsed)}`;
}

const backupStep = ctx.step(stepName("backup_status"));
const sweepStep = ctx.step(stepName("sweep_loss"));

const backupResult = parsedStdout(backupStep);
const sweepResult = parsedStdout(sweepStep);

const backup = dataOf(backupResult);
const sweep = dataOf(sweepResult);

const backupTruncated = backupResult.kind === "truncated";
const sweepTruncated = sweepResult.kind === "truncated";

// ---- shape a backup age humans can read -----------------------------------
function formatAge(hours: number | null | undefined): string | null {
  if (typeof hours !== "number" || Number.isNaN(hours)) return null;
  if (hours < 1) return `${Math.max(0, Math.round(hours * 60))}m ago`;
  if (hours < 48) return `${hours.toFixed(1)}h ago`;
  return `${(hours / 24).toFixed(1)} days ago`;
}

const backupAgeHours: number | null = typeof backup?.age_hours === "number" ? backup.age_hours : null;
const backupAgeStr = formatAge(backupAgeHours);
const backupKnown = backupAgeHours != null;

// ---- shape the sweep's rows -------------------------------------------------
// Guarded the same way every other collection-bearing step in this fleet is:
// a shape mismatch degrades to an empty list instead of throwing on .forEach().
const rows: any[] = Array.isArray(sweep?.rows) ? sweep.rows : [];

const count = (v: any) => (typeof v === "number" ? v : 0);

function exposureScore(row: any): number {
  if (row.unknown) return 1; // unknown repos are never "clean"; kept out of that bucket
  return count(row.unpushed) * 5 + count(row.local_only_branch_count) * 3 + count(row.stashes) * 2 + count(row.dirty);
}

const known = rows.filter((r) => !r.unknown);
const unknownRows = rows.filter((r) => r.unknown);
const exposed = known.filter((r) => exposureScore(r) > 0);
const cleanRows = known.filter((r) => exposureScore(r) === 0);

const totalUnpushed = known.reduce((sum, r) => sum + count(r.unpushed), 0);
const reposWithUnpushed = known.filter((r) => count(r.unpushed) > 0).length;
const totalLocalOnlyBranches = known.reduce((sum, r) => sum + count(r.local_only_branch_count), 0);
const totalStashes = known.reduce((sum, r) => sum + count(r.stashes), 0);
const totalDirty = known.reduce((sum, r) => sum + count(r.dirty), 0);

// A repository this play could not read might be hiding anything; a clean
// bill of health is only honest when every discovered repo was actually read
// AND the sweep itself reconciles cleanly: no repo left out by the wall-clock
// deadline or the repository cap, and no repo's branch list itself truncated
// (a repo with >50 branches could have an undiscovered local-only branch
// past the cap). Any of those makes "zero loss" a claim this play cannot
// back up, so the result degrades to the itemized (possibly all-zero, but
// explicitly non-certifying) line below instead.
const sweepReconciled =
  Boolean(sweep) &&
  (sweep.repos_swept ?? -1) === (sweep.repos_total ?? -2) &&
  sweep.truncated_by_deadline !== true &&
  sweep.truncated_by_repo_cap !== true &&
  !known.some((r) => r.branches_truncated);

const zeroGitLoss =
  totalUnpushed === 0 &&
  totalLocalOnlyBranches === 0 &&
  totalStashes === 0 &&
  totalDirty === 0 &&
  unknownRows.length === 0 &&
  rows.length > 0 &&
  sweepReconciled;

// A missing/unreadable base_dir reports repos_total: 0 with a warning; that
// must never read the same as "swept everything, found zero repos" (a valid,
// unremarkable outcome with no warning). "0 across 0" is not a clean bill.
const sweepUnavailable = Boolean(sweep) && (sweep.repos_total ?? 0) === 0 && Boolean(sweep.warning);

// A valid sweep that simply found no git repositories under base_dir is
// neither "unavailable" (no warning was raised) nor "zero loss" (there was
// nothing to certify as clean) -- it needs its own honest state, or the
// verdict line silently renders "0 across 0 repos" as if that were a
// finding rather than an unassessed scope.
const noReposFound = Boolean(sweep) && !sweepUnavailable && rows.length === 0;

// A short backup clause that never carries the raw tmutil/OS error text --
// that text belongs once, in full, in the BACKUP section below; everywhere
// else in the report either states the age plainly or points there.
function backupClause(): string {
  if (backupTruncated) return `Backup status unavailable this run (${truncationNote(backupResult.bytes)})`;
  if (backupKnown) return `Backed up ${backupAgeStr}`;
  if (backup?.platform === "darwin") return "Time Machine could not be asked when it last backed any of this up -- see BACKUP below";
  if (backup?.platform === "linux") return "Backup age is not available on Linux -- see BACKUP below";
  return "Backup status unknown -- see BACKUP below";
}

type WorstOffender = { repo: string; metric: string; category: "commits" | "branches" | "stashes" | "dirty" };

// The single highest-exposure known repo, ranked the same way the UNIQUE
// WORK table is ranked, reported by whichever of its own counts is largest
// -- so "Worst: <repo>, 73 commits" names the actual dominant loss for that
// repo rather than always defaulting to one column.
function worstOffender(): WorstOffender | null {
  const top = exposed.slice().sort((a, b) => exposureScore(b) - exposureScore(a))[0];
  if (!top) return null;
  const repo = String(top.repo);
  const u = count(top.unpushed);
  const b = count(top.local_only_branch_count);
  const s = count(top.stashes);
  const d = count(top.dirty);
  if (u > 0 && u >= b && u >= s && u >= d) return { repo, metric: `${u} commit${u === 1 ? "" : "s"}`, category: "commits" };
  if (b > 0 && b >= s && b >= d) return { repo, metric: `${b} branch${b === 1 ? "" : "es"}`, category: "branches" };
  if (s > 0 && s >= d) return { repo, metric: `${s} stash${s === 1 ? "" : "es"}`, category: "stashes" };
  return { repo, metric: `${d} dirty file${d === 1 ? "" : "s"}`, category: "dirty" };
}

const ACTION_BY_CATEGORY: Record<WorstOffender["category"], string> = {
  commits: "push its unpushed commits to a remote",
  branches: "push its local-only branches to a remote (or delete the ones you no longer need)",
  stashes: "commit or drop its stashes",
  dirty: "commit or stash its uncommitted changes",
};

// The reader's next action, computed last so it can point at whatever the
// rest of this report actually found -- real exposure first, then whatever
// is standing between this drill and a verified clean bill, in the order a
// reader would actually need to clear them.
function nextActionLine(): string {
  const worst = worstOffender();
  if (worst) {
    return `NEXT: start with ${worst.repo} -- it holds the most exposure here (${worst.metric}). ${ACTION_BY_CATEGORY[worst.category]}.`;
  }
  if (sweepTruncated) {
    return "NEXT: rerun this drill -- the unique-work sweep above was truncated at rote's capture cap before it could finish.";
  }
  if (sweepUnavailable) {
    return "NEXT: point base_dir at a directory this drill can actually read (see UNIQUE WORK above), then rerun -- git exposure has not been assessed yet.";
  }
  if (noReposFound) {
    return `NEXT: point base_dir at wherever your repositories actually live (see UNIQUE WORK above) -- none were found under ${sweep?.base ?? "the configured path"}.`;
  }
  if (unknownRows.length > 0) {
    return `NEXT: ${unknownRows.length} repo${unknownRows.length === 1 ? "" : "s"} above could not be read -- check ${unknownRows.length === 1 ? "it" : "them"} by hand before trusting a clean bill.`;
  }
  if (backupTruncated) {
    return "NEXT: rerun this drill -- the backup reading above was truncated at rote's capture cap, so backup status is unknown this run.";
  }
  if (!backupKnown) {
    return "NEXT: sort out Time Machine (see BACKUP above) -- your git work checks out clean, but nothing here is confirmed backed up right now.";
  }
  return "This laptop checks out clean: everything swept here is pushed, and your last backup was recent -- no action needed.";
}

function buildVerdict(): { headline: string; sub: string | null; oneLine: string } {
  if (sweepTruncated) {
    const headline = `${backupClause()}. Unique-work sweep unavailable: ${truncationNote(sweepResult.bytes)}`;
    return { headline, sub: null, oneLine: headline };
  }
  if (sweepUnavailable) {
    const headline = `${backupClause()}. Unique-work sweep unavailable: ${sweep.warning}`;
    return { headline, sub: null, oneLine: headline };
  }
  if (noReposFound) {
    const headline = `${backupClause()}. No git repositories found under ${sweep.base}; git loss exposure was not assessed.`;
    return { headline, sub: null, oneLine: headline };
  }
  if (zeroGitLoss && backupKnown) {
    const headline = (
      `Backed up ${backupAgeStr}. No git exposure found in the ${sweep.repos_swept} repositories scanned ` +
      `under ${sweep.base} -- that does not by itself make this laptop replaceable (non-git files and ` +
      `restore verification are unchecked; see UNVERIFIED).`
    );
    return { headline, sub: null, oneLine: headline };
  }
  if (zeroGitLoss && !backupKnown) {
    const headline = (
      `${backupClause()}. No git exposure found in the ${sweep.repos_swept} repositories ` +
      `scanned under ${sweep.base} -- the backup question is still open.`
    );
    return { headline, sub: null, oneLine: headline };
  }
  // Real exposure: loss first, in the play's own voice, then the backup
  // condition as its own plain sentence -- never the raw error inline here.
  const worst = worstOffender();
  const headline =
    `If this laptop died right now you would lose ${totalUnpushed} commit${totalUnpushed === 1 ? "" : "s"} ` +
    `across ${reposWithUnpushed} repo${reposWithUnpushed === 1 ? "" : "s"}, ${totalLocalOnlyBranches} ` +
    `branch${totalLocalOnlyBranches === 1 ? "" : "es"} that exist${totalLocalOnlyBranches === 1 ? "s" : ""} nowhere else, ` +
    `${totalStashes} stash${totalStashes === 1 ? "" : "es"} and ${totalDirty} uncommitted file${totalDirty === 1 ? "" : "s"}.` +
    (worst ? ` Worst: ${worst.repo}, ${worst.metric}.` : "");
  const sub = `${backupClause()}.`;
  return { headline, sub, oneLine: `${headline} ${sub}` };
}

// ---- human view -------------------------------------------------------------
const verdict = buildVerdict();

const lines: string[] = [];
lines.push("LAPTOP LOSS DRILL");
lines.push("");
lines.push(verdict.headline);
if (verdict.sub) lines.push(verdict.sub);
lines.push("");

lines.push("BACKUP");
if (backupTruncated) {
  lines.push(`  unknown -- ${truncationNote(backupResult.bytes)}`);
} else if (backup?.platform === "darwin") {
  if (backupKnown) {
    const dest = backup.destination_kind ? ` (${backup.destination_kind} destination)` : "";
    lines.push(`  last Time Machine backup: ${backupAgeStr}${dest}`);
  } else {
    lines.push(`  unknown -- ${backup?.reason ?? "tmutil did not return a usable result"}`);
  }
} else if (backup?.platform === "linux") {
  lines.push(`  unknown -- Time Machine is macOS-only; ${backup?.reason ?? "no backup markers found"}`);
} else if (backup) {
  lines.push(`  unknown -- ${backup?.reason ?? `unsupported platform: ${backup?.platform}`}`);
} else {
  lines.push(`  unknown -- backup_status step ${backupStep.outcome.status}`);
}
lines.push("");

lines.push("UNIQUE WORK");
if (sweepTruncated) {
  lines.push(`  unavailable -- ${truncationNote(sweepResult.bytes)}`);
} else if (!sweep) {
  lines.push(`  unavailable -- sweep_loss step ${sweepStep.outcome.status}`);
} else if (!Array.isArray(sweep?.rows)) {
  lines.push("  degraded -- rows was not a list; nothing to show");
} else if (sweepUnavailable) {
  lines.push(`  not swept -- ${sweep.warning}`);
} else if (noReposFound) {
  lines.push(`  no git repositories found under ${sweep.base} (depth ${sweep.max_depth ?? "?"}) -- git loss exposure was not assessed`);
} else {
  const table = [...exposed, ...unknownRows].sort((a, b) => exposureScore(b) - exposureScore(a));
  if (table.length === 0) {
    lines.push("  none -- nothing swept had unreachable commits, local-only branches, stashes, or dirty files");
  } else {
    const TABLE_CAP = 8;
    const shownRows = table.slice(0, TABLE_CAP);
    lines.push(
      `  ${"#".padStart(2)} ${"repo".padEnd(33)} ${"unreachable".padStart(11)} ${"local-only".padStart(10)} ${"stashes".padStart(7)} ${"dirty".padStart(5)}`,
    );
    shownRows.forEach((row, i) => {
      const rank = `${i + 1}.`.padStart(2);
      if (row.unknown) {
        lines.push(`  ${rank} ${String(row.repo).padEnd(33)} ${"?".padStart(11)} ${"?".padStart(10)} ${"?".padStart(7)} ${"?".padStart(5)}  UNREAD: ${row.unknown}`);
        return;
      }
      const truncatedFlag = row.branches_truncated ? " (branch list truncated)" : "";
      lines.push(
        `  ${rank} ${String(row.repo).padEnd(33)} ${String(count(row.unpushed)).padStart(11)} ` +
          `${String(count(row.local_only_branch_count)).padStart(10)} ${String(count(row.stashes)).padStart(7)} ${String(count(row.dirty)).padStart(5)}${truncatedFlag}`,
      );
    });
    if (table.length > TABLE_CAP) {
      lines.push(`  (${table.length - TABLE_CAP} more repo(s) not shown, all lower exposure than row ${TABLE_CAP} above)`);
    }
  }
  lines.push("");
  lines.push(
    `clean: ${cleanRows.length} repo${cleanRows.length === 1 ? "" : "s"} with nothing unreachable, nothing stashed, nothing dirty` +
      (sweepReconciled ? "" : " (sweep did not fully reconcile -- see CHECKED; this count is not a certified clean bill)"),
  );
}
lines.push("");

lines.push("CHECKED (what this report is actually based on)");
if (sweep) {
  const base = sweep.base ?? "(unknown base)";
  const depth = sweep.max_depth ?? "?";
  lines.push(`  - ${sweep.repos_swept ?? 0} of ${sweep.repos_total ?? 0} repositories found under ${base} (depth ${depth}) were checked`);
  if (sweep.truncated_by_deadline) lines.push("  - the sweep hit its time budget before finishing every repository; see the count above");
  if (sweep.truncated_by_repo_cap) lines.push("  - discovery hit its repository cap before finishing the walk; not every repository under base_dir was found");
  if (known.some((r) => r.branches_truncated)) {
    lines.push("  - at least one repository has more branches than this sweep enumerates; its local-only-branch count may be incomplete");
  }
}
if (backup?.platform === "darwin") {
  lines.push("  - tmutil consulted read-only, no sudo: latestbackup -t, destinationinfo -X");
} else if (backup?.platform === "linux") {
  lines.push("  - Time Machine does not apply on Linux; checked only for a borg/restic/timeshift binary or state path, no repository was opened");
}
if (unknownRows.length > 0) {
  lines.push(`  - ${unknownRows.length} repo(s) could not be read within the per-repo timeout and are reported UNKNOWN, never counted as clean`);
}
lines.push("");

lines.push("STAGES");
lines.push(
  stageLine(
    "backup status  ",
    backupStep,
    backupResult,
    (p) => (backupKnown ? `${backupAgeStr}` : p.reason ?? "unknown"),
    (raw) => shortNote(raw),
  ),
);
lines.push(
  stageLine("sweep loss     ", sweepStep, sweepResult, (p) => `${p.repos_swept ?? 0}/${p.repos_total ?? 0} repos checked`),
);
lines.push("");

lines.push("UNVERIFIED (this drill cannot tell you)");
if (sweepTruncated) {
  lines.push(`  - sweep_loss: ${truncationNote(sweepResult.bytes)} -- unique-work exposure across your repositories was not assessed this run`);
}
if (backupTruncated) {
  lines.push(`  - backup_status: ${truncationNote(backupResult.bytes)} -- backup age could not be read this run`);
}
lines.push("  - any file or directory that is not inside a git repository -- non-git files are never inventoried");
lines.push("  - whether any swept directory is itself cloud-synced (iCloud Drive, Dropbox, etc.) and backed up that way instead");
lines.push("  - whether the last Time Machine backup actually restores -- only that tmutil reports one exists, and how old it is");
lines.push("  - whether tmutil itself touched the network on macOS: querying it can mount an already-configured network backup destination; this play makes no zero-network guarantee there");
lines.push("");

lines.push(nextActionLine());
lines.push("Nothing above was executed -- every read here is read-only; push, commit, delete, or back up only if and when you choose to.");

out.human(lines.join("\n"));

// ---- summary view -- intentionally lossy ------------------------------------
out.summary(
  sweepTruncated
    ? `laptop loss drill: unique-work sweep unavailable (${truncationNote(sweepResult.bytes)}), backup ${backupTruncated ? "unknown (capture truncated)" : backupKnown ? backupAgeStr : "unknown"}`
    : sweepUnavailable
      ? `laptop loss drill: unique-work sweep unavailable (${sweep.warning}), backup ${backupTruncated ? "unknown (capture truncated)" : backupKnown ? backupAgeStr : "unknown"}`
      : noReposFound
        ? `laptop loss drill: no git repositories found under ${sweep.base}, git exposure not assessed, backup ${backupTruncated ? "unknown (capture truncated)" : backupKnown ? backupAgeStr : "unknown"}`
        : zeroGitLoss
          ? `laptop loss drill: no git exposure found -- backup ${backupTruncated ? "unknown (capture truncated)" : backupKnown ? backupAgeStr : "unknown"}, ${rows.length} repos all pushed`
          : `laptop loss drill: ${totalUnpushed} unreachable commit(s) across ${reposWithUnpushed} repo(s), ` +
            `${totalLocalOnlyBranches} local-only branch(es), ${totalStashes} stash(es), ${totalDirty} dirty file(s), ` +
            `backup ${backupTruncated ? "unknown (capture truncated)" : backupKnown ? backupAgeStr : "unknown"}` +
            (unknownRows.length > 0 ? `, ${unknownRows.length} repo(s) unread` : "") +
            (!sweepReconciled ? ", sweep not fully reconciled" : ""),
);

// ---- result view -- canonical JSON superset ---------------------------------
out.result({
  ok: Boolean(backup) && Boolean(sweep),
  verdict: {
    line: verdict.oneLine,
    zero_loss: zeroGitLoss,
    sweep_unavailable: sweepUnavailable,
    no_repos_found: noReposFound,
    sweep_reconciled: sweepReconciled,
    backup_age_days: backup?.age_days ?? null,
    unpushed_commits: totalUnpushed,
    unpushed_repo_count: reposWithUnpushed,
    local_only_branches: totalLocalOnlyBranches,
    stashes: totalStashes,
    dirty_files: totalDirty,
  },
  backup: backup ?? {
    ok: false,
    reason: backupTruncated ? truncationNote(backupResult.bytes) : `backup_status step ${backupStep.outcome.status}`,
  },
  repos: {
    base: sweep?.base ?? null,
    max_depth: sweep?.max_depth ?? null,
    repos_total: sweep?.repos_total ?? 0,
    repos_swept: sweep?.repos_swept ?? 0,
    warning: sweepTruncated ? truncationNote(sweepResult.bytes) : sweep?.warning ?? null,
    clean_count: cleanRows.length,
    exposed: exposed
      .slice()
      .sort((a, b) => exposureScore(b) - exposureScore(a))
      .map((r) => ({
        repo: r.repo,
        unpushed: count(r.unpushed),
        local_only_branches: count(r.local_only_branch_count),
        stashes: count(r.stashes),
        dirty: count(r.dirty),
        branches_truncated: Boolean(r.branches_truncated),
      })),
    unknown: unknownRows.map((r) => ({ repo: r.repo, reason: r.unknown })),
  },
  checked: [
    sweepTruncated
      ? null
      : sweep
        ? `${sweep.repos_swept ?? 0} of ${sweep.repos_total ?? 0} repositories swept at depth ${sweep.max_depth ?? "?"}`
        : "sweep_loss unavailable",
    backupTruncated
      ? null
      : backup?.platform === "darwin"
        ? "tmutil consulted read-only (latestbackup -t, destinationinfo -X), no sudo"
        : `backup detection on platform: ${backup?.platform ?? "unknown"}`,
  ].filter(Boolean),
  unverified: [
    ...(sweepTruncated ? [`sweep_loss: ${truncationNote(sweepResult.bytes)} -- unique-work exposure across your repositories was not assessed this run`] : []),
    ...(backupTruncated ? [`backup_status: ${truncationNote(backupResult.bytes)} -- backup age could not be read this run`] : []),
    "files and directories outside git",
    "whether a swept directory is itself cloud-synced",
    "whether the last backup actually restores",
    "whether tmutil itself touched the network on macOS (querying it can mount an already-configured network destination)",
  ],
  representations: {
    human: "complete -- loss-first verdict (worst offender named, raw errors kept out of the headline), BACKUP section (full error text, once), UNIQUE WORK table (top 8 by exposure, ranked, omitted count noted, clean count on one line), CHECKED section, stage ledger, UNVERIFIED footer, closing next-action + read-only line",
    json: "canonical -- full verdict, backup reading, and every nonzero-exposure or unknown repo row, even when the human view only shows a subset",
    summary: "intentionally lossy -- counts and backup age only",
  },
});
