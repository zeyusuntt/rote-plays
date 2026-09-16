#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: playoffs-standings
 * description: 'Where does your Play actually stand, and what shipped while you were building? Live standings for the Modiqo public Play registry: total plays and owners, top-N by lifetime downloads, everything published in the last H hours, and per-owner aggregates. Every run also compares itself against your last run and shows what changed since then -- plays that newly appeared (with age), the biggest download gainers, and any references that vanished; the first run just saves a baseline. Set author to track one publisher''s own plays with rank, downloads, and delta. Fetches the live endpoint with retry and falls back to the cached feed with a labeled warning instead of failing. Read-only against the registry; saves only a small snapshot under its own run workspace so the next run can show you what changed. Plays are tracked by owner/name across version bumps: a bump shows as UPDATED, never as one play GONE plus one NEW, and the saved baseline keeps each play''s high-water download count so the registry''s cache can never fake a gain. No credentials, no browser; needs only python3 and curl.'
 * version: 0.2.8
 * source_url: https://play.modiqo.ai/dotisacat/playoffs-standings
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: playoffs-standings
 * metadata:
 *   version: 0.2.8
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   probe_endpoint: resources/presentation-fixtures/probe_endpoint/fixture.yaml
 *   compute_standings: resources/presentation-fixtures/compute_standings/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-registry-standings
 * - audience-developers
 * - effect-read-only
 * - tool-registry
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-registry-standings
 *   - audience-developers
 *   - effect-read-only
 *   - tool-registry
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       probe:
 *         type: object
 *       standings:
 *         type: object
 *       representations:
 *         type: object
 * parameters:
 * - name: limit
 *   param_type: integer
 *   required: false
 *   default: '15'
 *   description: How many Plays to show in the downloads ranking (1-100)
 *   example: '15'
 * - name: recent_hours
 *   param_type: integer
 *   required: false
 *   default: '48'
 *   description: Look-back window in hours for the recently-published list
 *   example: '48'
 * - name: author
 *   param_type: string
 *   required: false
 *   default: ''
 *   description: 'Track one author: their plays get a YOUR PLAYS section with rank + downloads + delta. Empty string means off.'
 *   example: 'dotisacat'
 * steps:
 *   probe_endpoint:
 *     type: process.exec
 *     timeout_ms: 20000
 *     argv:
 *     - curl
 *     - -sI
 *     - --max-time
 *     - '15'
 *     - https://www.modiqo.ai/api/public-registry
 *   compute_standings:
 *     type: process.exec
 *     timeout_ms: 90000
 *     argv:
 *     - python3
 *     - '@resource{standings.py}'
 *     - $limit
 *     - $recent_hours
 *     - $author
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

/** Discriminated read of a step's captured stdout. rote caps a step's
 * captured stdout and sets stdout.truncated when that cap was hit -- a
 * truncated payload must never be conflated with a clean parse failure
 * (the capture cap is the CAUSE, an unparseable/partial payload is only
 * its symptom), so truncated === true is checked, and wins, before any
 * JSON.parse is even attempted -- a partial payload that would happen to
 * still parse is never read as "ok" either. */
type StdoutResult =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

function readStdout(step: ReturnType<typeof ctx.step>): StdoutResult {
  const s = bodyOf(step)?.stdout;
  if (!s) return { kind: "absent" };
  if (s.truncated === true) return { kind: "truncated", bytes: s.bytes ?? null };
  const text = s.text ?? "";
  try { return { kind: "ok", data: JSON.parse(text) }; } catch { return { kind: "unparseable" }; }
}

/** Unwraps a StdoutResult to the parsed value or null, for call sites that
 * only need "do we have usable data" -- truncation-awareness for those
 * call sites lives in the STAGES row and the clean-bill gate below, which
 * read the StdoutResult directly instead of going through this. */
function parsedStdout(step: ReturnType<typeof ctx.step>): any {
  const r = readStdout(step);
  return r.kind === "ok" ? r.data : null;
}

/** Array.isArray guard so one malformed field degrades a section, never the run. */
function asArray(value: any): any[] {
  return Array.isArray(value) ? value : [];
}

/** Compact duration since a timestamp — 39m, 5h, 3d, "just now" — for table columns. Never throws on garbage input. */
function ageToken(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "unknown";
  const ms = Date.now() - then;
  if (ms < 60_000) return "just now";
  const mins = Math.floor(ms / 60_000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

/** ageToken() wrapped for a sentence — "39m ago", "just now", "unknown time". */
function agoPhrase(iso: string | null | undefined): string {
  const token = ageToken(iso);
  if (token === "unknown") return "unknown time";
  if (token === "just now") return token;
  return `${token} ago`;
}

const probe = ctx.step(stepName("probe_endpoint"));
const compute = ctx.step(stepName("compute_standings"));

// probe_endpoint's own report reads its captured stdout line-wise, never
// via JSON.parse -- a truncated header blob still reads as a syntactically
// fine first line, so this is the dangerous case: without checking
// truncated first, a capture cut mid-headers (but after "200" already
// appeared) would read as a normal, verified "200" response. truncated is
// checked before probeLine is trusted for anything, and probeOk is gated
// on !probeTruncated so a truncated probe can never report the endpoint
// as ok.
const probeStdoutMeta = bodyOf(probe)?.stdout;
const probeTruncated = probeStdoutMeta?.truncated === true;
const probeBytes = probeStdoutMeta?.bytes ?? null;
const probeLine = (probeStdoutMeta?.text ?? "").split("\n")[0].trim() || "no response";
const probeOk = !probeTruncated && probe.outcome.status === "completed" && probeLine.includes("200");

const computeResult = readStdout(compute);
const data = computeResult.kind === "ok" ? computeResult.data : null;
// Neither root step depends on the other -- probe_endpoint can be
// truncated while compute_standings completes cleanly (or vice versa),
// so the summary below must never trust a clean-looking count from one
// step without also checking its independent sibling.
const anyStepTruncated = probeTruncated || computeResult.kind === "truncated";
const delta = data?.ok ? (data.delta ?? null) : null;
const authorWatch = data?.ok ? (data.author ?? null) : null;
const lines: string[] = [];
lines.push("PLAYOFFS REGISTRY STANDINGS");
lines.push("");

if (computeResult.kind === "truncated") {
  const bytesNote = computeResult.bytes != null ? `${computeResult.bytes} bytes captured` : "capture cap reached";
  lines.push(`standings unavailable — compute_standings output was truncated at rote's capture cap (${bytesNote}); this report covers only part of what the step produced`);
} else if (!data) {
  lines.push(`standings unavailable — compute step ${compute.outcome.status}`);
} else if (!data.ok) {
  lines.push(`standings degraded — ${data.error ?? "unknown reason"}`);
} else {
  lines.push(`feed generated: ${data.feed_generated_at}   plays: ${data.totals.plays}   owners: ${data.totals.owners}`);
  if (data.warning) lines.push(`note: ${data.warning}`);
  lines.push("");

  // ---- delta since last run — the daily-habit headline -------------------
  if (!delta || delta.first_run) {
    lines.push(
      delta?.first_run_reason === "previous_snapshot_unreadable"
        ? "CHANGED: first run (previous snapshot was unreadable/corrupt -- discarded), baseline saved"
        : "CHANGED: first run, baseline saved",
    );
  } else {
    const newSince = asArray(delta.new_since_last);
    const movers = asArray(delta.movers);
    const gone = asArray(delta.gone);
    const parts: string[] = [];
    if (newSince.length) parts.push(`${newSince.length} new`);
    if (movers.length) parts.push(`${movers.length} movers`);
    if (gone.length) parts.push(`${gone.length} gone`);
    lines.push(`CHANGED: ${parts.length ? parts.join(", ") : "nothing"} since ${agoPhrase(delta.as_of)}`);
    if (delta.stale_note) lines.push(`note: ${delta.stale_note}`);
    lines.push("");
    if (newSince.length) {
      lines.push(`NEW SINCE LAST RUN (${newSince.length})`);
      newSince.forEach((r: any) => {
        lines.push(`  ${ageToken(r?.published_at).padStart(8)} old  ${String(r?.downloads ?? 0).padStart(4)} dl  ${r?.reference}`);
      });
      lines.push("");
    }
    if (movers.length) {
      lines.push(`MOVERS (${movers.length})`);
      movers.forEach((m: any) => {
        lines.push(`  +${String(m?.delta ?? 0).padStart(3)} dl  ${String(m?.downloads ?? 0).padStart(4)} now  ${m?.reference}`);
      });
      lines.push("");
    }
    const updatedRows = asArray(delta.updated);
    if (updatedRows.length) {
      lines.push(`UPDATED (${updatedRows.length}) — version bumps, tracked as the same play`);
      updatedRows.forEach((u: any) => {
        lines.push(`  ${String(u?.reference ?? "?")}  ${String(u?.from_version ?? "?")} -> ${String(u?.to_version ?? "?")}${u?.delta ? `  (+${u.delta} dl)` : ""}`);
      });
      lines.push("");
    }
    if (gone.length) {
      lines.push(`GONE (${gone.length})`);
      gone.forEach((g: any) => {
        lines.push(`  was ${String(g?.last_downloads ?? 0).padStart(4)} dl  ${g?.reference}`);
      });
      lines.push("");
    }
  }

  // ---- optional author watch ----------------------------------------------
  if (authorWatch) {
    const plays = asArray(authorWatch.plays);
    lines.push(`YOUR PLAYS (${authorWatch.name})`);
    if (!plays.length) {
      lines.push(`  no plays found for owner "${authorWatch.name}"`);
    } else {
      plays.forEach((p: any) => {
        const d = p?.delta;
        const deltaStr = d === null || d === undefined ? "" : `  (${d >= 0 ? "+" : ""}${d} since last run)`;
        lines.push(`  #${String(p?.rank ?? "?").padStart(3)}  ${String(p?.downloads ?? 0).padStart(4)} dl${deltaStr}  ${p?.reference}`);
      });
    }
    lines.push("");
  }

  lines.push("TOP BY LIFETIME DOWNLOADS");
  const top = data.top_by_downloads ?? [];
  top.forEach((r: any, i: number) => {
    lines.push(`  ${String(i + 1).padStart(2)}. ${String(r.downloads).padStart(4)} dl  ${r.reference}`);
  });
  lines.push("");
  const recent = Array.isArray(data.recent) ? data.recent : [];
  // recent_total is what the window really held; recent is what fit inside the
  // step's output budget. Headline the TRUE count so a trimmed list can never
  // read as the whole window, and name the omission rather than implying it.
  const recentTotal = typeof data.recent_total === "number" ? data.recent_total : recent.length;
  const recentOmitted = typeof data.recent_omitted === "number" ? data.recent_omitted : 0;
  lines.push(`PUBLISHED IN THE WINDOW (${recentTotal})`);
  recent.forEach((r: any) => {
    lines.push(`  ${(r.published_at ?? "").slice(0, 16)}  ${String(r.downloads).padStart(3)} dl  ${r.reference}`);
  });
  if (recentOmitted > 0) {
    lines.push(
      `  … ${recentOmitted} more not listed — the window held more than one step's output can carry;` +
        ` narrow recent_hours to see them all`,
    );
  }
}
lines.push("");
lines.push("STAGES");
{
  const probeStatus = probeTruncated ? "truncated" : probeOk ? "ok      " : "degraded";
  const probeNote = probeTruncated
    ? `output was truncated at rote's capture cap (${probeBytes != null ? `${probeBytes} bytes captured` : "capture cap reached"}) — this report covers only part of what the step produced`
    : probeLine;
  lines.push(`  ${probeStatus}  endpoint probe   ${probeNote}`);
}
{
  const standingsStatus = computeResult.kind === "truncated" ? "truncated" : data?.ok ? "ok      " : "degraded";
  const standingsNote = computeResult.kind === "truncated"
    ? `output was truncated at rote's capture cap (${computeResult.bytes != null ? `${computeResult.bytes} bytes captured` : "capture cap reached"}) — this report covers only part of what the step produced`
    : data?.ok
      ? `${(data.top_by_downloads ?? []).length} ranked, ${(data.recent ?? []).length} recent`
      : "see note above";
  lines.push(`  ${standingsStatus}  standings        ${standingsNote}`);
}
{
  const snapshotOk = Boolean(data?.ok) && Boolean(data?.snapshot?.saved);
  // Label must never claim a save happened when it didn't -- checked first, independent of
  // which delta phase (first-run vs. steady-state) produced it, so "degraded" in the status
  // column never sits next to a label that still says "saved".
  const snapshotLabel = !data?.ok
    ? "n/a — see note above"
    : !snapshotOk
      ? `save failed${data?.snapshot?.error ? ` (${data.snapshot.error})` : ""}`
      : !delta || delta.first_run
        ? delta?.first_run_reason === "previous_snapshot_unreadable"
          ? "baseline saved (previous snapshot discarded)"
          : "baseline saved"
        : `delta vs ${agoPhrase(delta.as_of)}`;
  lines.push(`  ${snapshotOk ? "ok      " : "degraded"}  ${"snapshot".padEnd(15)}  ${snapshotLabel}`);
}

out.human(lines.join("\n"));

const deltaSummary = !delta
  ? ""
  : delta.first_run
    ? "; first run, baseline saved"
    : `; ${asArray(delta.new_since_last).length} new, ${asArray(delta.movers).length} movers, ${asArray(delta.updated).length} updated since last run`;
const baseSummary = data?.ok
  ? `registry: ${data.totals.plays} plays / ${data.totals.owners} owners; top ${(data.top_by_downloads ?? []).length} ranked; ${(data.recent ?? []).length} new in window${deltaSummary}`
  : "registry standings unavailable (degraded)";
out.summary(
  anyStepTruncated ? `${baseSummary} — partial: one or more steps were truncated at the capture cap` : baseSummary,
);
out.result({
  probe: { status: probe.outcome.status, truncated: probeTruncated, first_line: probeLine },
  standings: data,
  representations: {
    human: "complete — delta since last run (new/movers/gone), optional author watch, ranking, recent list, stage ledger",
    json: "canonical — full standings object the human view renders, including delta and author watch",
    summary: "intentionally lossy — totals, counts, and delta headline only",
  },
});
