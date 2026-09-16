#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: mcp-context-tax
 * description: 'How many tokens of your context window do your configured MCP servers consume before you type a word? Discovers MCP server configs across installed harnesses (Claude Code, Claude Desktop, Cursor, Codex, Windsurf), sorts each into stdio (local, spawnable) or remote (never contacted -- zero network calls of its own), then briefly spawns each local server in an isolated process group with a minimal allowlisted environment to read its advertised schemas via the standard MCP handshake before terminating that process group. You get every server''s estimated token cost (schema size, chars divided by four, always labeled an ESTIMATE, never a real tokenizer count), ranked, with each landing in one honest bucket: healthy, needs-auth, slow, unresponsive, remote-not-probed, or config-error. A server needing credentials it was never given, or refusing to spawn, is a labeled degrade (a short reason code, never raw child output that could echo a credential) -- never a crash. Read-only against your configs: it collects only advertised schemas and byte sizes, never environment variable values (only a has_env flag and var name count) and never argument values (only a structural summary) -- real values exist only long enough to spawn a server for probing, in a private file this play never prints. No credentials transmitted beyond that allowlisted environment; needs only python3.'
 * version: 0.1.8
 * source_url: https://play.modiqo.ai/dotisacat/mcp-context-tax
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: mcp-context-tax
 * metadata:
 *   version: 0.1.8
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   discover_configs: resources/presentation-fixtures/discover_configs/fixture.yaml
 *   probe_server: resources/presentation-fixtures/probe_server/fixture.yaml
 * tags:
 * - domain-agent-operations
 * - job-context-measurement
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-context-measurement
 *   - audience-developers
 *   - effect-read-only
 *   - tool-shell
 * output:
 *   schema:
 *     type: object
 *     properties:
 *       ok:
 *         type: object
 *       generated_at:
 *         type: object
 *       totals:
 *         type: object
 *       states:
 *         type: object
 *       ranked:
 *         type: object
 *       capped_unprobed:
 *         type: object
 *       servers:
 *         type: object
 *       note:
 *         type: string
 *       representations:
 *         type: object
 * parameters:
 * - name: per_server_timeout_s
 *   param_type: integer
 *   required: false
 *   default: '10'
 *   description: Seconds to wait for each server's handshake (1-60)
 *   example: '10'
 * - name: max_servers
 *   param_type: integer
 *   required: false
 *   default: '20'
 *   description: Probe at most this many servers (1-50); the rest are listed unprobed
 *   example: '20'
 * steps:
 *   discover_configs:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{discover.py}'
 *   probe_server:
 *     type: process.exec
 *     timeout_ms: 70000
 *     depends_on:
 *     - discover_configs
 *     for_each: $.stdout.text | fromjson | .servers
 *     max_concurrency: 3
 *     argv:
 *     - python3
 *     - '@resource{probe.py}'
 *     - $item
 *     - $item_index
 *     - $per_server_timeout_s
 *     - $max_servers
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

/** Read a single (non fan-out) step's stdout as a discriminated result:
 * { kind: "ok", data } | { kind: "truncated", bytes } | { kind: "unparseable" } | { kind: "absent" }.
 * truncated is read off stdout.truncated with a strict === true check -- a
 * missing field is never treated as truncation -- and truncated wins over
 * unparseable when both apply: truncation is the cause, an unparseable
 * payload is only its symptom. */
function readStepJson(step) {
  const outcome = step?.outcome;
  if (outcome?.status !== "completed" && outcome?.status !== "restored") return { kind: "absent" };
  const stdout = outcome?.output?.body?.stdout;
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
 * discriminated result per item (same shape as readStepJson, plus its
 * index in the fan-out list -- the same order as allServers, since both
 * derive from the same discovery.servers array the for_each iterates
 * over). Deliberately does NOT gate on the aggregate step status the way a
 * single (non fan-out) step read would -- if the runner ever promotes one
 * item's failure/timeout to an aggregate status other than completed/restored
 * while still populating output.items with the observations that DID come
 * back, gating on the aggregate status here would silently discard every
 * successful peer along with the bad one. Array.isArray-guarded so a shape
 * mismatch (items absent, e.g. a genuine pre-fan-out failure) degrades to
 * an empty list instead of throwing, and one malformed item's JSON never
 * sinks the rest of the briefing; every server missing a usable row still
 * gets an explicit line below -- "no-probe-result" for a genuine gap, or,
 * when the item was truncated by rote's capture cap rather than simply
 * missing, its own named truncated row instead. */
function readFanOutRows(step) {
  const items = step?.outcome?.output?.items;
  if (!Array.isArray(items)) return [];
  const results = [];
  items.forEach((item, index) => {
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

const discoverStep = ctx.step(stepName("discover_configs"));
const probeStep = ctx.step(stepName("probe_server"));

const discoverResult = readStepJson(discoverStep);
const discovery = discoverResult.kind === "ok" ? discoverResult.data : null;
const discoverTruncated = discoverResult.kind === "truncated";

const probeResults = readFanOutRows(probeStep);
const probeRows = probeResults.filter((r) => r.kind === "ok").map((r) => r.data);
const probeTruncatedItems = probeResults.filter((r) => r.kind === "truncated");

// exec_store is a private, owner-only-readable path discover.py writes so
// probe.py can spawn servers with their REAL args (see discover.py's
// module docstring) -- an internal wiring detail, never meant for a
// report a human reads, so it is stripped here before anything below
// touches allServers (used both for the ranked/STATES tables and for
// out.result().servers).
const allServers = Array.isArray(discovery?.servers)
  ? discovery.servers.map(({ exec_store: _exec_store, ...rest }) => rest)
  : [];
const sources = Array.isArray(discovery?.sources) ? discovery.sources : [];

const probedById = new Map();
for (const row of probeRows) {
  if (row && row.id !== null && row.id !== undefined) probedById.set(row.id, row);
}
const truncatedByIndex = new Map(probeTruncatedItems.map((r) => [r.index, r]));

// The fan-out runs over every discovered server (capping happens inside
// probe.py itself, by item_index, never by narrowing the fan-out set -- see
// probe.py's module docstring for why), so every server normally gets back
// exactly one row -- one of: a usable probe row, a row truncated at rote's
// capture cap (named below, never folded into "missing"), or, as a
// defensive fallback that should not happen (the underlying process.exec
// item failed outright rather than probe.py degrading to JSON on its own,
// per its contract), no row at all -- labeled honestly rather than
// silently dropped.
const probed = [];
const missingRows = [];
const truncatedRows = [];
allServers.forEach((server, index) => {
  const truncatedItem = truncatedByIndex.get(index);
  if (truncatedItem) {
    truncatedRows.push({ ...server, truncated_bytes: truncatedItem.bytes });
    return;
  }
  const row = probedById.get(server.id);
  if (row) {
    probed.push({ ...server, ...row });
  } else {
    missingRows.push(server);
  }
});

const cappedRows = probed.filter((s) => s.state === "capped");
const localProbed = probed.filter((s) => s.transport !== "remote" && s.state !== "capped");
const remoteRows = probed.filter((s) => s.state === "remote-not-probed");

const toolsTotal = localProbed.reduce((sum, s) => sum + (s.tools?.count ?? 0), 0);
const tokensTotal = localProbed.reduce((sum, s) => sum + (s.total_est_tokens ?? 0), 0);

const byState = (state) => probed.filter((s) => s.state === state);
const needsAuth = byState("needs-auth");
const unresponsive = byState("unresponsive");
const configError = byState("config-error");

const ranked = [...localProbed].sort((a, b) => (b.total_est_tokens ?? 0) - (a.total_est_tokens ?? 0));

const anyTruncated = discoverTruncated || truncatedRows.length > 0;

function fmtInt(n) {
  return (n ?? 0).toLocaleString("en-US");
}

function fmtBytes(n) {
  return typeof n === "number" ? `${fmtInt(n)} bytes` : "an unknown number of bytes";
}

/** One STAGES ledger row, tolerant of every outcome status the runner can
 * hand back. A truncated payload gets its own labeled row -- never folded
 * into the "ok" note as though the step's output were complete. */
function stageLine(label, step, truncatedNote, okNote) {
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(10)}  ${label}  step ${status}`;
  }
  if (truncatedNote) {
    return `  ${"truncated".padEnd(10)}  ${label}  ${truncatedNote}`;
  }
  return `  ok          ${label}  ${okNote()}`;
}

const lines = [];
lines.push("MCP CONTEXT TAX");
lines.push("");

if (discoverTruncated) {
  lines.push(
    `discover_configs step output was truncated at rote's capture cap (${fmtBytes(discoverResult.bytes)} captured) -- this report covers only part of what the step produced`,
  );
} else if (!discovery || discovery.ok !== true) {
  lines.push(`discovery unavailable -- discover_configs step ${discoverStep?.outcome?.status ?? "unknown"}`);
} else {
  lines.push(
    `${localProbed.length} local server(s) advertise ${fmtInt(toolsTotal)} tool(s) ` +
      `≈ ${fmtInt(tokensTotal)} estimated tokens of every session's context`,
  );
  if (remoteRows.length > 0) {
    lines.push(`  + ${remoteRows.length} remote server(s) not probed (no network calls made) -- see STATES`);
  }
  if (cappedRows.length > 0) {
    lines.push(
      `  + ${cappedRows.length} server(s) beyond the max_servers cap, not probed -- raise max_servers to include them`,
    );
  }
  if (missingRows.length > 0) {
    lines.push(`  + ${missingRows.length} server(s) in scope but never returned a probe result -- see STATES`);
  }
  if (truncatedRows.length > 0) {
    lines.push(
      `  + ${truncatedRows.length} server(s) whose probe result was truncated at rote's capture cap -- not counted above, see STATES`,
    );
  }
  lines.push("");

  lines.push(`RANKED BY ESTIMATED TOKENS (${ranked.length})`);
  if (ranked.length === 0) {
    lines.push("  none -- no local stdio servers were probed");
  } else {
    ranked.forEach((s, i) => {
      const rank = `${i + 1}.`.padEnd(4);
      const name = String(s.name ?? "(unnamed)").padEnd(24);
      const harness = String(s.harness ?? "?").padEnd(14);
      const state = String(s.state ?? "?").padEnd(15);
      const tools = String(s.tools?.count ?? 0).padStart(5);
      const tokens = fmtInt(s.total_est_tokens).padStart(9);
      lines.push(`  ${rank}${name} ${harness} ${state} ${tools} tools  ${tokens} est_tokens`);
    });
  }
  lines.push("");

  lines.push("STATES");
  const stateLine = (label, rows, detail) => {
    if (rows.length === 0) {
      lines.push(`  ${label} (0): none`);
      return;
    }
    const names = rows.map((r) => detail ? `${r.name}${detail(r)}` : r.name).join(", ");
    lines.push(`  ${label} (${rows.length}): ${names}`);
  };
  stateLine("needs-auth        ", needsAuth);
  stateLine("unresponsive      ", unresponsive);
  stateLine("config-error      ", configError, (r) => r.error ? ` (${r.error})` : "");
  stateLine("remote-not-probed ", remoteRows);
  stateLine("truncated         ", truncatedRows, (r) =>
    ` (output truncated at rote's capture cap, ${fmtBytes(r.truncated_bytes)} captured -- this server's result covers only part of what probe_server produced, not a claim about the server itself)`,
  );
  if (cappedRows.length > 0) {
    lines.push(`  not-probed (max_servers cap) (${cappedRows.length}): ${cappedRows.map((s) => s.name).join(", ")}`);
  }
  if (missingRows.length > 0) {
    lines.push(`  no-probe-result   (${missingRows.length}): ${missingRows.map((s) => s.name).join(", ")}`);
  }
  lines.push("");

  if (sources.length > 0) {
    lines.push("SOURCES");
    sources.forEach((s) => {
      lines.push(`  ${String(s.status).padEnd(30)} ${s.harness}  ${s.path}`);
    });
    lines.push("");
  }
}

lines.push("STAGES");
lines.push(
  stageLine(
    "discover configs  ",
    discoverStep,
    discoverTruncated
      ? `output was truncated at rote's capture cap (${fmtBytes(discoverResult.bytes)} captured) -- this report covers only part of what the step produced`
      : null,
    () =>
      discovery
        ? `${sources.length} source(s) read, ${allServers.length} server(s) found (${discovery.duplicates_dropped ?? 0} duplicate(s) dropped)`
        : "output did not parse as JSON",
  ),
);
lines.push(
  stageLine(
    "probe servers     ",
    probeStep,
    truncatedRows.length > 0
      ? `${truncatedRows.length} of ${allServers.length} server(s)' probe result truncated at rote's capture cap -- see STATES, not counted in the totals above`
      : null,
    () => `${probeRows.length} probed, ${fmtInt(tokensTotal)} est tokens`,
  ),
);
lines.push("");
lines.push("Token figures are ESTIMATES only (advertised-schema chars / 4), not a real tokenizer count.");

out.human(lines.join("\n"));

out.summary(
  discoverTruncated
    ? "mcp-context-tax unavailable (discover_configs output truncated at rote's capture cap)"
    : discovery && discovery.ok === true
      ? `mcp-context-tax: ${localProbed.length} local servers, ${fmtInt(toolsTotal)} tools, ~${fmtInt(tokensTotal)} est tokens; ` +
        `${needsAuth.length} needs-auth, ${unresponsive.length} unresponsive, ${configError.length} config-error, ${remoteRows.length} remote not probed` +
        (truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated (partial)` : "")
      : "mcp-context-tax unavailable (discovery degraded)",
);

out.result({
  ok: Boolean(discovery && discovery.ok === true && !anyTruncated),
  generated_at: new Date().toISOString(),
  sources,
  totals: {
    servers_discovered: allServers.length,
    local_probed: localProbed.length,
    remote_not_probed: remoteRows.length,
    capped_unprobed: cappedRows.length,
    no_probe_result: missingRows.length,
    tools_total: toolsTotal,
    est_tokens_total: tokensTotal,
    truncated_probe_items: truncatedRows.length,
    discover_truncated: discoverTruncated,
  },
  states: {
    "needs-auth": needsAuth.map((s) => s.name),
    unresponsive: unresponsive.map((s) => s.name),
    "config-error": configError.map((s) => ({ name: s.name, error: s.error ?? null })),
    "remote-not-probed": remoteRows.map((s) => s.name),
    truncated: truncatedRows.map((s) => ({ id: s.id, name: s.name, bytes: s.truncated_bytes ?? null })),
  },
  ranked: ranked.map((s) => ({
    id: s.id,
    name: s.name,
    harness: s.harness,
    state: s.state,
    tools: s.tools?.count ?? 0,
    est_tokens: s.total_est_tokens ?? 0,
  })),
  capped_unprobed: cappedRows.map((s) => ({ id: s.id, name: s.name, harness: s.harness })),
  servers: allServers,
  note: "est_tokens figures are ESTIMATES from advertised-schema JSON size (chars / 4), never a real tokenizer count.",
  representations: {
    human: "complete -- headline, ranked table, states section, sources, stage ledger",
    json: "canonical -- full server inventory plus every probe outcome this run produced, covers servers beyond the max_servers cap even though they were not probed",
    summary: "intentionally lossy -- counts and totals only",
  },
});
