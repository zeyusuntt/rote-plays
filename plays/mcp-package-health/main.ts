#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: mcp-package-health
 * description: 'Are the npm and PyPI packages behind your MCP servers still maintained? Reads the same harness-owned configs as our other MCP plays (Claude Code, Claude Desktop, Cursor, Codex, Windsurf), resolves each stdio server''s command to a package identity (npx, npm exec, uvx, uv tool run, pipx run, including --from and --spec; a trailing @version is read as a pin, never merged into the name; a python -m module is reported unresolvable rather than guessed at), then asks registry.npmjs.org and pypi.org about it. Deprecated and yanked rank first, being the registries'' own words; then pin drift; then days since the last release as a FACT, never a verdict -- a finished package can go years without one, and this play never says abandoned or unmaintained. A 404 reads as not found in the public registry, never as does not exist. The ONLY thing that leaves your machine is a package NAME, allowlist-checked before the request, which does reveal which MCP servers you run. Never spawns a server, never installs or upgrades anything. Read-only, no credentials; needs python3 and curl.'
 * version: 0.1.2
 * source_url: https://play.modiqo.ai/dotisacat/mcp-package-health
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: mcp-package-health
 * metadata:
 *   version: 0.1.2
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   discover_packages: resources/presentation-fixtures/discover_packages/fixture.yaml
 *   fetch_registry: resources/presentation-fixtures/fetch_registry/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-dependency-health
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-dependency-health
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
 *       counts:
 *         type: object
 *       packages:
 *         type: array
 *       unresolvable:
 *         type: array
 *       not_registry:
 *         type: array
 *       remote:
 *         type: array
 *       sources:
 *         type: array
 *       warnings:
 *         type: array
 *       checked:
 *         type: array
 *       unverified:
 *         type: array
 *       representations:
 *         type: object
 * parameters:
 * - name: stale_release_days
 *   param_type: integer
 *   required: false
 *   default: '365'
 *   description: Days since the latest release above which a package is reported as "no recent release" (30-3650); a fact only, never a verdict of abandonment -- a finished package can go years without one
 *   example: '365'
 * - name: per_request_timeout_s
 *   param_type: integer
 *   required: false
 *   default: '10'
 *   description: Seconds curl is given for each registry GET (1-60); a request exceeding this degrades that one package to a labeled unknown, never the whole run
 *   example: '10'
 * steps:
 *   discover_packages:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{discover_packages.py}'
 *   fetch_registry:
 *     type: process.exec
 *     timeout_ms: 75000
 *     depends_on:
 *     - discover_packages
 *     for_each: $.stdout.text | fromjson | .packages
 *     max_concurrency: 5
 *     argv:
 *     - python3
 *     - '@resource{fetch_registry.py}'
 *     - $item
 *     - $item_index
 *     - $per_request_timeout_s
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

/** Read a for_each fan-out step: one process observation per item -> one
 * discriminated result per item (same shape as parsedStdout, plus its
 * index in the fan-out list -- the same order as declaredPackages, since
 * both derive from discover_packages's own "packages" array). Deliberately
 * does NOT gate on the aggregate step status the way a single (non
 * fan-out) step read would -- if the runner ever promotes one item's
 * failure/timeout to an aggregate status other than completed/restored
 * while still populating output.items with the observations that DID come
 * back, gating on the aggregate status here would silently discard every
 * successful peer along with the bad one. Array.isArray-guarded so a shape
 * mismatch degrades to an empty list instead of throwing, and one
 * malformed item's JSON never sinks the rest of the report -- every
 * package missing a usable row still gets an explicit line below ("no
 * result", or -- when the item was truncated by rote's capture cap rather
 * than simply missing -- its own named truncated row instead). */
function readFanOutRows(step: ReturnType<typeof ctx.step>): Array<{ index: number } & StdoutResult> {
  const items = step?.outcome?.output?.items;
  if (!Array.isArray(items)) return [];
  const results: Array<{ index: number } & StdoutResult> = [];
  items.forEach((item: any, index: number) => {
    const stdout = item?.body?.stdout;
    if (stdout?.truncated === true) {
      results.push({ index, kind: "truncated", bytes: typeof stdout?.bytes === "number" ? stdout.bytes : null });
      return;
    }
    const text = stdout?.text ?? "";
    if (typeof text !== "string" || !text.trim()) {
      results.push({ index, kind: "absent" });
      return;
    }
    try {
      const row = JSON.parse(text);
      results.push(row && typeof row === "object" ? { index, kind: "ok", data: row } : { index, kind: "unparseable" });
    } catch {
      results.push({ index, kind: "unparseable" });
    }
  });
  return results;
}

/** One STAGES ledger row, tolerant of every outcome status the runner can
 * hand back. A truncated payload gets its own labeled row -- never folded
 * into the "ok" note as though the step's output were complete. */
function stageLine(label: string, step: ReturnType<typeof ctx.step>, truncatedNote: string | null, okNote: () => string): string {
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(10)}  ${label}  step ${status}`;
  }
  if (truncatedNote) {
    return `  ${"truncated".padEnd(10)}  ${label}  ${truncatedNote}`;
  }
  return `  ok          ${label}  ${okNote()}`;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function asArray(value: any): any[] {
  return Array.isArray(value) ? value : [];
}

function fmtBytes(n: unknown): string {
  return typeof n === "number" ? `${n.toLocaleString("en-US")} bytes` : "an unknown number of bytes";
}

const discoverStep = ctx.step(stepName("discover_packages"));
const fetchStep = ctx.step(stepName("fetch_registry"));

const discoverResult = parsedStdout(discoverStep);
const discovery = discoverResult.kind === "ok" ? discoverResult.data : null;
const discoverTruncated = discoverResult.kind === "truncated";

const fetchResults = readFanOutRows(fetchStep);
const fetchRows = fetchResults.filter((r) => r.kind === "ok").map((r) => (r as any).data);
const fetchTruncatedItems = fetchResults.filter((r) => r.kind === "truncated") as Array<{ index: number; bytes: number | null }>;

const declaredPackages = asArray(discovery?.packages);
const unresolvable = asArray(discovery?.unresolvable);
const notRegistry = asArray(discovery?.not_registry);
const remote = asArray(discovery?.remote);
const sources = asArray(discovery?.sources);
const discoveryWarnings = asArray(discovery?.warnings).filter((w) => typeof w === "string");

/** Non-integer or out-of-declared-range parameter values fail the whole
 * play closed (thrown here, uncaught) rather than silently falling back to
 * a default -- an omitted parameter is not an error and uses the
 * documented default, but a SUPPLIED value outside its documented shape is
 * a contract violation the reader should see, not one this play should
 * quietly paper over. */
function parseIntParam(name: string, raw: unknown, fallback: number, min: number, max: number): number {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n)) {
    throw new Error(`${name} must be an integer, got: ${String(raw)}`);
  }
  if (n < min || n > max) {
    throw new Error(`${name} must be between ${min} and ${max}, got: ${n}`);
  }
  return n;
}

const staleDays = parseIntParam("stale_release_days", ctx.params?.stale_release_days, 365, 30, 3650);

const byKey = new Map<string, any>();
for (const row of fetchRows) {
  if (row && typeof row.key === "string") byKey.set(row.key, row);
}
const truncatedByIndex = new Map(fetchTruncatedItems.map((r) => [r.index, r]));

// Every declared package normally gets back exactly one fetch_registry row
// (fan-out runs over discover_packages's own "packages" array, one item
// each) -- one of: a usable registry row, a row truncated at rote's
// capture cap (named below, tier "unknown" like any other unreached row,
// but with its own reason so it is never mistaken for a network failure),
// or, as a defensive fallback that should not happen (the underlying
// process.exec item failed outright rather than fetch_registry.py
// degrading to JSON on its own, per its contract), no row at all --
// labeled honestly here rather than silently dropped.
const merged: any[] = [];
declaredPackages.forEach((pkg, index) => {
  const truncatedItem = truncatedByIndex.get(index);
  if (truncatedItem) {
    merged.push({ ...pkg, state: "unknown", reason: "truncated", truncated: true, truncated_bytes: truncatedItem.bytes });
    return;
  }
  const row = byKey.get(pkg.key);
  if (row) {
    merged.push({ ...pkg, ...row });
  } else {
    merged.push({ ...pkg, state: "unknown", reason: "no-result-returned" });
  }
});

type Tier = "flagged" | "pin-drift-stale" | "pin-drift" | "no-recent-release" | "healthy" | "not-found" | "unknown";
const TIER_ORDER: Tier[] = ["flagged", "pin-drift-stale", "pin-drift", "no-recent-release", "healthy", "not-found", "unknown"];

// "unknown" here always means state !== "ok" -- but state "unknown" itself
// covers two different situations: the registry genuinely was never
// reached (timeout, DNS/network failure, rate-limited, curl missing), or
// it WAS reached and answered but the body was unusable (invalid JSON, or
// missing the one field this play cannot derive anything without). Rows
// carrying one of these reasons were reached; every other "unknown" reason
// (including every malformed-item:* contract-violation reason, which never
// even got as far as a curl call) is reported as not reached.
const REACHED_BUT_UNUSABLE_REASONS = new Set([
  "invalid-json",
  "unparseable-response",
  "missing-dist-tags-latest",
  "missing-info-version",
  "response-unreadable",
]);

function tierOf(row: any): Tier {
  if (row.state === "not_found") return "not-found";
  if (row.state !== "ok") return "unknown";
  if (row.deprecated || row.yanked) return "flagged";
  if (row.pin_drift) {
    // ANY pin drift (age known or not) is never "healthy" -- a row whose
    // own detail line reports drift must never carry a [healthy] label.
    if (typeof row.pinned_days_old === "number" && row.pinned_days_old >= staleDays) return "pin-drift-stale";
    return "pin-drift";
  }
  if (typeof row.days_since_release !== "number") {
    // state is "ok" (the registry answered and we have an identity) but
    // no publish-date evidence could be established -- freshness is
    // genuinely unknowable here, never presented as "healthy".
    return "unknown";
  }
  return row.days_since_release >= staleDays ? "no-recent-release" : "healthy";
}

function detailFor(row: any): string {
  if (row.state === "unknown") {
    const reason = typeof row.reason === "string" ? row.reason : "network failure";
    if (reason === "truncated") {
      // A fact about rote's capture, never about the registry or the
      // package -- distinct from every other "unknown" reason above,
      // which are all facts about whether/how the registry was reached.
      return `unknown -- output was truncated at rote's capture cap (${fmtBytes(row.truncated_bytes)} captured); the registry was contacted but this run cannot report what it said, not a claim about the package itself`;
    }
    const qualifier = REACHED_BUT_UNUSABLE_REASONS.has(reason)
      ? "registry responded but the data could not be used; not a claim the package itself is unhealthy"
      : "registry not reached this run; not a claim the package itself is unhealthy";
    return `unknown -- ${reason} (${qualifier})`;
  }
  if (row.state === "not_found") {
    return "not found in the public registry (may be private, internal, renamed, or unpublished)";
  }
  const parts: string[] = [];
  if (row.deprecated) {
    parts.push(`DEPRECATED per npm: ${row.deprecated_message ?? "no message given"}`);
  }
  if (row.yanked) {
    parts.push(`YANKED per PyPI: ${row.yanked_reason ?? "no reason given"}`);
  }
  if (row.pin_drift) {
    const pinAge = typeof row.pinned_days_old === "number" ? `, pin is ${row.pinned_days_old}d old` : "";
    parts.push(`pinned ${row.pinned_version} but registry latest is ${row.latest_version ?? "?"}${pinAge}`);
  }
  if (typeof row.days_since_release === "number") {
    parts.push(
      row.days_since_release >= staleDays
        ? `no release in ${row.days_since_release}d (>= ${staleDays}d threshold) -- a fact, not a verdict; a finished package can go years without one`
        : `last release ${row.days_since_release}d ago`,
    );
  } else {
    parts.push("registry responded but published-date evidence was missing; freshness cannot be determined this run");
  }
  if (parts.length === 0) parts.push("current, no registry-flagged issue");
  return parts.join("; ");
}

const ranked = merged
  .map((row) => ({ row, tier: tierOf(row) }))
  .sort((a, b) => {
    const t = TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier);
    if (t !== 0) return t;
    return String(a.row.package ?? "").localeCompare(String(b.row.package ?? ""));
  });

const tierCounts: Record<Tier, number> = { flagged: 0, "pin-drift-stale": 0, "pin-drift": 0, "no-recent-release": 0, healthy: 0, "not-found": 0, unknown: 0 };
for (const { tier } of ranked) tierCounts[tier] += 1;

const npmQueried = declaredPackages.filter((p) => p.ecosystem === "npm").length;
const pypiQueried = declaredPackages.filter((p) => p.ecosystem === "pypi").length;

const truncatedPackages = merged.filter((r) => r.truncated === true);
const anyTruncated = discoverTruncated || truncatedPackages.length > 0;
const truncationUnverifiedNote =
  truncatedPackages.length > 0
    ? `result truncated at rote's capture cap for ${truncatedPackages.length} package(s) (${truncatedPackages.map((r) => r.package).join(", ")}) -- the registry was contacted but this run cannot report what it said, not a claim about the package itself`
    : null;

const lines: string[] = [];
lines.push("MCP PACKAGE HEALTH");
lines.push("");

if (discoverTruncated) {
  lines.push(
    `discover_packages step output was truncated at rote's capture cap (${fmtBytes(discoverResult.kind === "truncated" ? discoverResult.bytes : null)} captured) -- this report covers only part of what the step produced`,
  );
} else if (!discovery || discovery.ok !== true) {
  lines.push(`discovery unavailable -- discover_packages step ${discoverStep?.outcome?.status ?? "unknown"}`);
} else {
  const total = merged.length;
  const assessed = total - tierCounts.unknown;
  if (total === 0) {
    lines.push("no npm/PyPI-resolvable MCP server packages found on this machine");
  } else if (assessed === 0) {
    // Every resolved package came back unknown this run (outage, every
    // request rate-limited, etc.) -- "clean" would be a claim this run
    // has no basis for, since nothing was actually assessed.
    lines.push(`${total} package(s) resolved from your MCP configs: registry unreachable for all of them this run -- not a claim of cleanliness, see PER-PACKAGE`);
  } else if (tierCounts.flagged === 0 && anyTruncated) {
    // Some packages ARE assessed and clean of flagged issues so far, but
    // at least one result was truncated by rote's capture cap rather than
    // read -- "clean" would claim more than this run actually saw.
    lines.push(
      `${total} package(s) resolved from your MCP configs: 0 flagged so far, but ${truncatedPackages.length} result(s) truncated at rote's capture cap -- not a claim of cleanliness, see PER-PACKAGE`,
    );
  } else if (tierCounts.flagged === 0) {
    lines.push(`${total} package(s) resolved from your MCP configs: clean of registry-flagged issues`);
  } else {
    lines.push(`${total} package(s) resolved from your MCP configs: ${tierCounts.flagged} deprecated/yanked -- see TOP FLAGS`);
  }
  lines.push(
    `  ${tierCounts.flagged} flagged, ${tierCounts["pin-drift-stale"]} stale pin drift, ${tierCounts["pin-drift"]} pin drift (not yet stale), ` +
      `${tierCounts["no-recent-release"]} no recent release, ${tierCounts.healthy} healthy, ${tierCounts["not-found"]} not found, ${tierCounts.unknown} unknown`,
  );
  if (unresolvable.length > 0) lines.push(`  + ${unresolvable.length} server(s) unresolvable to any package -- see UNRESOLVABLE`);
  if (notRegistry.length > 0) lines.push(`  + ${notRegistry.length} server(s) not a registry package (local script / container / other) -- see NOT A REGISTRY PACKAGE`);
  if (remote.length > 0) lines.push(`  + ${remote.length} remote server(s), never contacted -- see REMOTE`);
  lines.push("");

  if (tierCounts.flagged > 0) {
    lines.push(`TOP FLAGS -- deprecated (npm) or yanked (PyPI), the registry's own words (${tierCounts.flagged})`);
    ranked
      .filter((r) => r.tier === "flagged")
      .forEach(({ row }) => {
        lines.push(`  ${String(row.package ?? "?").padEnd(40)} [${row.ecosystem}]  ${detailFor(row)}`);
      });
    lines.push("");
  }

  lines.push(`PER-PACKAGE (${merged.length})`);
  if (merged.length === 0) {
    lines.push("  none -- no server config on this machine resolved to an npm or PyPI package");
  } else {
    lines.push(`  ${"PACKAGE".padEnd(38)}${"ECO".padEnd(6)}${"DECLARED BY".padEnd(24)}${"LATEST".padEnd(12)}STATUS`);
    ranked.forEach(({ row, tier }) => {
      const pkg = truncate(String(row.package ?? "?"), 37).padEnd(38);
      const eco = String(row.ecosystem ?? "?").padEnd(6);
      const by = truncate(asArray(row.harnesses).join(","), 23).padEnd(24);
      const latest = truncate(String(row.latest_version ?? "-"), 11).padEnd(12);
      lines.push(`  ${pkg}${eco}${by}${latest}[${tier}] ${detailFor(row)}`);
    });
  }
  lines.push("");

  if (unresolvable.length > 0) {
    lines.push(`UNRESOLVABLE (${unresolvable.length}) -- a command was found but no package name could be inferred, never guessed`);
    unresolvable.forEach((r: any) => {
      lines.push(`  ${String(r.server_name ?? "?").padEnd(24)} ${String(r.harness ?? "?").padEnd(14)} ${r.command ?? "?"} -- ${r.reason ?? "?"}`);
    });
    lines.push("");
  }

  if (notRegistry.length > 0) {
    lines.push(`NOT A REGISTRY PACKAGE (${notRegistry.length}) -- local script, container, or other launcher, never queried`);
    notRegistry.forEach((r: any) => {
      lines.push(`  ${String(r.server_name ?? "?").padEnd(24)} ${String(r.harness ?? "?").padEnd(14)} ${r.command ?? "?"} -- ${r.reason ?? "?"}`);
    });
    lines.push("");
  }

  if (remote.length > 0) {
    lines.push(`REMOTE (${remote.length}) -- url-based servers, never contacted by this play`);
    remote.forEach((r: any) => {
      lines.push(`  ${String(r.server_name ?? "?").padEnd(24)} ${String(r.harness ?? "?").padEnd(14)}`);
    });
    lines.push("");
  }

  if (sources.length > 0) {
    lines.push("SOURCES");
    sources.forEach((s: any) => {
      lines.push(`  ${String(s.status).padEnd(30)} ${s.harness}  ${s.path}`);
    });
    lines.push("");
  }

  lines.push("LEGEND");
  lines.push("  deprecated/yanked are the registry's own words, ranked first.");
  lines.push("  pin drift means your config pins a version other than the registry's current latest;");
  lines.push("  pin-drift-stale means that drift AND the pin's own age both cross stale_release_days.");
  lines.push(`  "no recent release" (>= ${staleDays}d, set by stale_release_days) is a FACT, never a verdict --`);
  lines.push("  a mature, finished package can go years between releases; this play never says abandoned/dead/unmaintained.");
  lines.push("");

  lines.push("CHECKED -- what this run actually read or contacted");
  lines.push(`  - ${sources.length} harness-owned config source(s) read (see SOURCES)`);
  lines.push(`  - ${npmQueried} package name(s) queried against registry.npmjs.org`);
  lines.push(`  - ${pypiQueried} package name(s) queried against pypi.org`);
  lines.push(`  - ${discovery?.counts?.names_withheld_unsafe ?? 0} candidate name(s) withheld from any network request (name shape not safe to send)`);
  lines.push("");

  lines.push("UNVERIFIED -- what this play cannot tell you");
  lines.push("  - whether a package with no recent release is actually unmaintained; it may simply be finished");
  lines.push("  - whether the package resolved from an npx/uvx/uv/pipx invocation is the one that actually installs at runtime -- launcher version/dist-tag resolution can differ from what this play resolved");
  lines.push(`  - the ${unresolvable.length + notRegistry.length} server(s) in UNRESOLVABLE / NOT A REGISTRY PACKAGE above -- never queried`);
  lines.push("  - whether a private registry mirror (a corporate npm/PyPI proxy) would answer differently than the public registries this play queried");
  if (truncationUnverifiedNote) lines.push(`  - ${truncationUnverifiedNote}`);
  lines.push("");

  if (discoveryWarnings.length > 0) {
    lines.push("WARNINGS");
    discoveryWarnings.forEach((w) => lines.push(`  - ${w}`));
    lines.push("");
  }
}

lines.push("STAGES");
lines.push(
  stageLine(
    "discover packages ",
    discoverStep,
    discoverTruncated
      ? `output was truncated at rote's capture cap (${fmtBytes(discoverResult.kind === "truncated" ? discoverResult.bytes : null)} captured) -- this report covers only part of what the step produced`
      : null,
    () =>
      discovery
        ? `${sources.length} source(s) read, ${discovery.counts?.servers_discovered ?? 0} server(s), ${declaredPackages.length} package(s) resolved`
        : "output did not parse as JSON",
  ),
);
lines.push(
  stageLine(
    "fetch registry    ",
    fetchStep,
    truncatedPackages.length > 0
      ? `${truncatedPackages.length} of ${declaredPackages.length} result(s) truncated at rote's capture cap -- see PER-PACKAGE / UNVERIFIED, not counted toward a clean bill`
      : null,
    () => `${fetchRows.length} package(s) queried`,
  ),
);
lines.push("");
lines.push("Only two hosts are ever contacted: registry.npmjs.org and pypi.org. Only a package NAME is ever sent.");
lines.push("This play never spawns a server and never installs, upgrades, or modifies any package.");

out.human(lines.join("\n"));

out.summary(
  discoverTruncated
    ? "mcp-package-health unavailable (discover_packages output truncated at rote's capture cap)"
    : discovery && discovery.ok === true
      ? `mcp-package-health: ${merged.length} package(s), ${tierCounts.flagged} deprecated/yanked, ${tierCounts["pin-drift-stale"]} stale pin drift, ${tierCounts["no-recent-release"]} no recent release` +
        (truncatedPackages.length > 0 ? ` (${truncatedPackages.length} truncated -- partial)` : "")
      : "mcp-package-health unavailable (discovery degraded)",
);

out.result({
  ok: Boolean(discovery && discovery.ok === true && !anyTruncated),
  generated_at: new Date().toISOString(),
  counts: {
    packages: merged.length,
    flagged: tierCounts.flagged,
    pin_drift_stale: tierCounts["pin-drift-stale"],
    pin_drift: tierCounts["pin-drift"],
    no_recent_release: tierCounts["no-recent-release"],
    healthy: tierCounts.healthy,
    not_found: tierCounts["not-found"],
    unknown: tierCounts.unknown,
    unresolvable: unresolvable.length,
    not_registry: notRegistry.length,
    remote: remote.length,
    names_withheld_unsafe: discovery?.counts?.names_withheld_unsafe ?? 0,
    truncated_results: truncatedPackages.length,
    discover_truncated: discoverTruncated,
  },
  packages: ranked.map(({ row, tier }) => ({
    key: row.key,
    ecosystem: row.ecosystem,
    package: row.package,
    server_names: asArray(row.server_names),
    harnesses: asArray(row.harnesses),
    pinned_version: row.pinned_version ?? null,
    pin_conflict: Boolean(row.pin_conflict),
    state: row.state,
    tier,
    latest_version: row.latest_version ?? null,
    days_since_release: row.days_since_release ?? null,
    deprecated: Boolean(row.deprecated),
    deprecated_message: row.deprecated_message ?? null,
    yanked: Boolean(row.yanked),
    yanked_reason: row.yanked_reason ?? null,
    pin_drift: Boolean(row.pin_drift),
    pinned_days_old: row.pinned_days_old ?? null,
    truncated: Boolean(row.truncated),
    truncated_bytes: row.truncated_bytes ?? null,
    detail: detailFor(row),
  })),
  unresolvable,
  not_registry: notRegistry,
  remote,
  sources,
  warnings: discoveryWarnings,
  checked: [
    `${sources.length} harness-owned config source(s) read`,
    `${npmQueried} package name(s) queried against registry.npmjs.org`,
    `${pypiQueried} package name(s) queried against pypi.org`,
    `${discovery?.counts?.names_withheld_unsafe ?? 0} candidate name(s) withheld from any network request (name shape not safe to send)`,
  ],
  unverified: [
    "whether a package with no recent release is actually unmaintained; it may simply be finished",
    "whether the package resolved from an npx/uvx/uv/pipx invocation is the one that actually installs at runtime",
    `the ${unresolvable.length + notRegistry.length} server(s) in the unresolvable/not-a-registry-package buckets -- never queried`,
    "whether a private registry mirror would answer differently than the public registries this play queried",
    ...(truncationUnverifiedNote ? [truncationUnverifiedNote] : []),
  ],
  representations: {
    human: "complete -- headline, top flags, per-package table, unresolvable/not-a-registry-package/remote tables, sources, legend, CHECKED/UNVERIFIED footer, stage ledger",
    json: "canonical -- every resolved package this run produced, ranked, plus every unresolvable/not-registry/remote row and full source list",
    summary: "intentionally lossy -- counts only",
  },
});
