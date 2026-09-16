#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: mcp-doctor
 * description: 'Is each of your configured MCP servers healthy, and what should you do about the ones that are not? You get a health state for every server, a cold-start time that is a real measurement (never an estimate), a plain-text advisory for anything that needs attention, and any config drift where the same server name is declared differently across your harnesses. Configs are discovered read-only from Claude Code, Claude Desktop, Cursor, Codex, and Windsurf''s own well-known paths -- never a filesystem walk. Each local stdio server is briefly spawned in its own isolated process group with a minimal environment (PATH plus locale/timezone only) just for the standard MCP handshake, then that whole process group is always terminated -- nothing else on your machine is signaled. Remote servers are never contacted; this play makes zero network calls of its own, though a spawned server''s own launcher (uvx/npx) may reach the network on its own. No credential is transmitted beyond that minimal spawn environment, no argument value or env var value is ever shown, and only an env-var count survives per server. Advisories are text only and nothing here is ever executed. Needs only python3.'
 * version: 0.1.6
 * source_url: https://play.modiqo.ai/dotisacat/mcp-doctor
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: mcp-doctor
 * metadata:
 *   version: 0.1.6
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
 * - job-mcp-diagnosis
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-agent-operations
 *   - job-mcp-diagnosis
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
 *       servers:
 *         type: object
 *       no_probe_result:
 *         type: object
 *       hidden_duplicates:
 *         type: object
 *       drift:
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
 *   description: Seconds to wait for each server's handshake (1-60); servers answering after half this are flagged slow-coldstart
 *   example: '10'
 * - name: max_servers
 *   param_type: integer
 *   required: false
 *   default: '20'
 *   description: Diagnose at most this many servers (1-50); the rest are listed capped, not probed
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

/** Discriminated read of a single (non fan-out) step's captured stdout.
 * rote caps a step's captured stdout and sets stdout.truncated when that
 * cap was hit -- a truncated payload must never be conflated with a clean
 * parse failure (the capture cap is the CAUSE, an unparseable/partial
 * payload is only its symptom), so truncated === true is checked, and
 * wins, before any JSON.parse is even attempted -- a partial payload that
 * would happen to still parse is never read as "ok" either. */
function readStepResult(step) {
  const outcome = step?.outcome;
  if (outcome?.status !== "completed" && outcome?.status !== "restored") return { kind: "absent" };
  const s = outcome?.output?.body?.stdout;
  if (!s) return { kind: "absent" };
  if (s.truncated === true) return { kind: "truncated", bytes: s.bytes ?? null };
  const text = s.text ?? "";
  if (typeof text !== "string" || !text.trim()) return { kind: "absent" };
  try {
    const data = JSON.parse(text);
    return data && typeof data === "object" ? { kind: "ok", data } : { kind: "unparseable" };
  } catch {
    return { kind: "unparseable" };
  }
}

/** Read a single (non fan-out) step's stdout as JSON, or null when unusable. */
function readStepJson(step) {
  const r = readStepResult(step);
  return r.kind === "ok" ? r.data : null;
}

/** Read a for_each fan-out step: one process observation per item -> row list.
 * Deliberately does NOT gate on the aggregate step status the way a single
 * (non fan-out) step read would -- if the runner ever promotes one item's
 * failure/timeout to an aggregate status other than completed/restored
 * while still populating output.items with the observations that DID come
 * back, gating on the aggregate status here would silently discard every
 * successful peer along with the bad one. Array.isArray-guarded so a shape
 * mismatch (items absent, e.g. a genuine pre-fan-out failure) degrades to
 * an empty list instead of throwing, and one malformed item's JSON never
 * sinks the rest of the report; every server missing a row still gets an
 * explicit "no-probe-result" line below, whichever way this comes back
 * empty.
 *
 * Each item's captured stdout is read through the same truncated-first
 * discipline as readStepResult above: rote sets stdout.truncated when one
 * item's own output hit the capture cap, and that must never be silently
 * read as "no probe result" (this server never ran) or, worse, as a normal
 * result if the partial JSON happened to still parse -- checked before any
 * JSON.parse is attempted, so a truncated item always comes back as
 * `kind: "truncated"`, never `"ok"`. A truncated item's OWN captured stdout
 * can't be parsed for its server id, so the id is instead read off
 * item.body.invocation.args[2] -- the item_index this item was invoked
 * with (`$item_index` in the frontmatter), which is part of the DAG's own
 * invocation record, not the captured output, so it survives truncation
 * intact; per discover.py's identity(), a server's id is assigned as its
 * position in the discovered list, the same list for_each iterates, so
 * item_index reliably equals that server's id. */
function readFanOutRows(step) {
  const items = step?.outcome?.output?.items;
  if (!Array.isArray(items)) return { rows: [], truncated: [] };
  const rows = [];
  const truncated = [];
  for (const item of items) {
    const s = item?.body?.stdout;
    if (!s) continue;
    if (s.truncated === true) {
      const idArg = item?.body?.invocation?.args?.[2];
      const id = idArg !== undefined ? Number(idArg) : NaN;
      truncated.push({ id: Number.isFinite(id) ? id : null, bytes: s.bytes ?? null });
      continue;
    }
    try {
      const text = s.text ?? "";
      if (typeof text !== "string" || !text.trim()) continue;
      const row = JSON.parse(text);
      if (row && typeof row === "object") rows.push(row);
    } catch {
      // one malformed item never sinks the report
    }
  }
  return { rows, truncated };
}

const discoverStep = ctx.step(stepName("discover_configs"));
const probeStep = ctx.step(stepName("probe_server"));

const discoverResult = readStepResult(discoverStep);
const discovery = discoverResult.kind === "ok" ? discoverResult.data : null;
const { rows: probeRows, truncated: truncatedProbeItems } = readFanOutRows(probeStep);

// exec_store is a private, owner-only-readable path discover.py writes so
// probe.py can spawn servers with their REAL args (see discover.py's
// module docstring) -- an internal wiring detail, never meant for a
// report a human reads, so it is stripped here before anything below
// touches allServers.
const allServers = Array.isArray(discovery?.servers)
  ? discovery.servers.map(({ exec_store: _exec_store, ...rest }) => rest)
  : [];
const sources = Array.isArray(discovery?.sources) ? discovery.sources : [];
const duplicatesRaw = Array.isArray(discovery?.duplicates) ? discovery.duplicates : [];

const probedById = new Map();
for (const row of probeRows) {
  if (row && row.id !== null && row.id !== undefined) probedById.set(row.id, row);
}
const truncatedById = new Map();
for (const t of truncatedProbeItems) {
  if (t.id !== null) truncatedById.set(t.id, t);
}

// The fan-out runs over every discovered server (capping happens inside
// probe.py itself, by item_index, never by narrowing the fan-out set -- see
// probe.py's module docstring for why), so every server normally gets back
// exactly one row. A row missing entirely is a defensive fallback that
// should not happen (the underlying process.exec item failed outright
// rather than probe.py degrading to JSON on its own, per its contract) --
// labeled honestly rather than silently dropped. A server whose item WAS
// truncated is a distinct, named third case -- it ran, but rote's capture
// cap cut its output short, so it is neither a clean result nor silently
// indistinguishable from a server that never ran at all.
const probed = [];
const missingRows = [];
const truncatedRows = [];
for (const server of allServers) {
  const row = probedById.get(server.id);
  if (row) {
    probed.push({ ...server, ...row });
  } else if (truncatedById.has(server.id)) {
    truncatedRows.push({ ...server, _truncated: truncatedById.get(server.id) });
  } else {
    missingRows.push(server);
  }
}

const byState = (state) => probed.filter((s) => s.state === state);
const healthyRows = byState("healthy");
const needsAuth = byState("needs-auth");
const slowColdstart = byState("slow-coldstart");
const unresponsive = byState("unresponsive");
const configError = byState("config-error");
const remoteRows = byState("remote-not-probed");
const cappedRows = byState("capped");

const ATTENTION_STATES = new Set(["needs-auth", "slow-coldstart", "unresponsive", "config-error"]);
const attentionRows = probed.filter((s) => ATTENTION_STATES.has(s.state));

// BROKEN_STATES is ATTENTION_STATES minus slow-coldstart: a slow-coldstart
// server did hand back its tools list, just slowly, so it is not a server
// that "never handed you a tool" -- that headline claim is reserved for
// the states where tools/resources/prompts were never measured at all.
const BROKEN_STATES = new Set(["needs-auth", "unresponsive", "config-error"]);
const brokenRows = probed.filter((s) => BROKEN_STATES.has(s.state));

/** CONFIG DRIFT, part 1: scope shadowing. discover.py's own dedup already
 * merges any two entries whose (transport, command, real-args) identity is
 * byte-identical (first occurrence wins, see discover.py's identity()) --
 * so if the SAME name still appears more than once in allServers, those
 * copies are, by construction, NOT identical: a genuine shadowing case,
 * computed here purely as display logic over discover's already-emitted
 * rows, no extra step needed. */
function groupByName(rows) {
  const map = new Map();
  for (const row of rows) {
    const key = row?.name ?? "(unnamed)";
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return map;
}

const shadowGroups = [];
for (const [name, rows] of groupByName(allServers)) {
  if (rows.length > 1) {
    shadowGroups.push({
      name,
      entries: rows.map((r) => ({
        harness: r.harness ?? "?",
        source_path: r.source_path ?? null,
        command: r.command ?? null,
        args: Array.isArray(r.args) ? r.args : [],
      })),
    });
  }
}

// CONFIG DRIFT, part 2: identical-definition duplicates. These are the
// entries discover.py's dedup DID drop (see discover.py's "duplicates"
// list) -- kept here only when the dropped copy's own name matches the
// name of the copy that survived, which is the "same server name,
// redundant duplicate declaration" case this play reports; a coincidental
// identity match across two genuinely different names is not a naming
// drift finding and is left out of THIS list (see hiddenDuplicates below
// for where it still surfaces).
const duplicateFindings = duplicatesRaw.filter(
  (d) => d && typeof d === "object" && d.name === d.kept_name,
);

// discover.py's dedup identity deliberately does not include name (see its
// identity() docstring), so a server whose (transport, command, real-args)
// happens to byte-match another entry configured under a DIFFERENT name is
// dropped from "servers" there even though it is a genuinely distinct,
// user-configured entry -- not a naming-drift duplicate of the one kept.
// Filtering these out of duplicateFindings above (correctly -- they are not
// a "same name" drift finding) must never mean they vanish from the report
// with no trace at all, so every one is still accounted for here, the same
// way missingRows accounts for a server that never returned a probe row.
const hiddenDuplicates = duplicatesRaw.filter(
  (d) => d && typeof d === "object" && d.name !== d.kept_name,
);

/** A short, text-only, never-executed suggestion for one non-healthy
 * server. Never reproduces a command line: even discover.py's own
 * redacted structural args summary (flag names kept, every value and
 * positional argument replaced with an "<arg:Nchars>" placeholder) reads
 * as noise once a server has more than one or two argv values -- so
 * instead of a half-redacted pseudo-command, this points the reader at
 * where the real, runnable command already lives: their own config file.
 * Env vars stay a bare count everywhere, never a name or value. */
function configPointer(s) {
  const scope = s.harness ? `your ${s.harness} MCP config` : "your MCP config";
  return `this server is defined in ${scope} under "${s.name ?? "(unnamed)"}" -- the command is not reproduced here, run it by hand from that config to see why`;
}

function advisoryFor(s) {
  const state = s.state;
  if (state === "config-error") {
    const err = String(s.error || "");
    if (err.startsWith("spawn-failed")) {
      // probe.py's reason code is "spawn-failed:<ExceptionType>" -- the
      // exception type is the honest signal here (FileNotFoundError really
      // is "not on PATH", but PermissionError/NotADirectoryError/a bare
      // OSError are a different problem, e.g. not executable or a bad exec
      // format); collapsing all of these to "not found on PATH" would be a
      // wrong diagnosis for those other cases.
      const exceptionType = err.slice("spawn-failed:".length);
      if (exceptionType === "FileNotFoundError") {
        return `command not found on PATH: ${s.command ?? "(unknown)"} -- check the config's command or install it`;
      }
      if (exceptionType === "PermissionError") {
        return `command found but not executable (permission denied): ${s.command ?? "(unknown)"} -- check its file permissions`;
      }
      if (exceptionType === "NotADirectoryError") {
        return `configured command path is invalid (a path component isn't a directory): ${s.command ?? "(unknown)"} -- check the config's command`;
      }
      return `failed to start (${exceptionType || "unknown reason"}): ${s.command ?? "(unknown)"} -- check the config's command or install it`;
    }
    if (err.startsWith("process-exited-early")) {
      return `crashes on start -- ${configPointer(s)}`;
    }
    return `config error (${err || "unknown reason"}) -- ${configPointer(s)}`;
  }
  if (state === "needs-auth") {
    const envCount = s.env_count ?? 0;
    return envCount > 0
      ? `auth failed on handshake -- declares ${envCount} env var(s) in its config; sign in / set them via your harness`
      : "auth failed on handshake -- no env vars declared in its config; sign in via your harness (e.g. an OAuth/browser flow)";
  }
  if (state === "slow-coldstart") {
    return `took ${s.cold_start_ms ?? "?"}ms to first response -- uvx/npx cold starts download on first run; a short client timeout will silently drop this server`;
  }
  if (state === "unresponsive") {
    return `spoke no MCP within ${s.timeout_s ?? "?"}s -- likely not an MCP stdio server, or hung`;
  }
  if (state === "remote-not-probed") {
    return "remote server -- never contacted (no network calls made by this play)";
  }
  if (state === "capped") {
    return "beyond max_servers cap -- not probed; raise max_servers to include it";
  }
  return null;
}

const advisories = [];
for (const s of probed) {
  const text = advisoryFor(s);
  if (text) advisories.push({ name: s.name ?? "(unnamed)", harness: s.harness ?? "?", state: s.state, advisory: text });
}
// A truncated probe item never gets to fall out of ADVISORIES silently --
// its health was never actually verified this run, and the "none -- every
// server is healthy" line below must not read as true when this is why one
// server has no better answer.
for (const s of truncatedRows) {
  const bytesNote = s._truncated?.bytes != null ? `${s._truncated.bytes} bytes captured` : "capture cap reached";
  advisories.push({
    name: s.name ?? "(unnamed)",
    harness: s.harness ?? "?",
    state: "truncated",
    advisory: `probe output was truncated at rote's capture cap (${bytesNote}) -- this server's health could not be verified this run`,
  });
}

function fmtMs(ms) {
  return ms === null || ms === undefined ? "-" : `${ms}ms`;
}

function fmtSec(ms) {
  return (ms / 1000).toFixed(1);
}

/** A short (2-4 word) headline reason for a server in a BROKEN_STATE --
 * distinct from advisoryFor's longer, actionable advisory text below, and
 * derived from the same real state/error this run measured, never a
 * canned phrase unrelated to what actually happened. */
function shortBrokenReason(s) {
  if (s.state === "needs-auth") return "cannot authenticate";
  if (s.state === "unresponsive") return "unresponsive";
  const err = String(s.error || "");
  if (err.startsWith("process-exited-early")) return "crashes on start";
  if (err.startsWith("spawn-failed:FileNotFoundError")) return "not found on PATH";
  if (err.startsWith("spawn-failed:PermissionError")) return "not executable (permission denied)";
  if (err.startsWith("spawn-failed:NotADirectoryError")) return "invalid command path";
  if (err.startsWith("spawn-failed")) return "fails to start";
  return "config error";
}

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back.
 * `result` is a StdoutResult-shaped object for a single (non fan-out) step,
 * or null for a fan-out step (which has no one stdout to check truncated
 * on -- its per-item truncation is named in okNote() and in PER-SERVER /
 * ADVISORIES instead). */
function stageLine(label, step, result, okNote) {
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(10)}  ${label}  step ${status}`;
  }
  if (result?.kind === "truncated") {
    const bytesNote = result.bytes != null ? `${result.bytes} bytes captured` : "capture cap reached";
    return `  ${"truncated".padEnd(10)}  ${label}  output was truncated at rote's capture cap (${bytesNote}) -- this report covers only part of what the step produced`;
  }
  return `  ok          ${label}  ${okNote()}`;
}

const lines = [];
lines.push("MCP DOCTOR");
lines.push("");

// Set below, only when discovery succeeded and there were two or more
// healthy servers to compare -- reused verbatim at the very end as the
// most useful sentence on offer when there is otherwise no advisory to
// point the reader at.
let coldStartSpreadLine = null;

if (discoverResult.kind === "truncated") {
  const bytesNote = discoverResult.bytes != null ? `${discoverResult.bytes} bytes captured` : "capture cap reached";
  lines.push(`discovery unavailable -- discover_configs output was truncated at rote's capture cap (${bytesNote}) -- this report covers only part of what the step produced`);
} else if (!discovery || discovery.ok !== true) {
  lines.push(`discovery unavailable -- discover_configs step ${discoverStep?.outcome?.status ?? "unknown"}`);
} else {
  const total = probed.length + missingRows.length + truncatedRows.length;

  if (truncatedRows.length > 0) {
    lines.push(
      `${total} server(s): ${healthyRows.length} healthy, ${attentionRows.length} need attention, ${truncatedRows.length} truncated (not a verified clean result)`,
    );
  } else if (attentionRows.length === 0) {
    lines.push(`${total} server(s): clean bill of health -- ${healthyRows.length} healthy, 0 need attention`);
  } else if (brokenRows.length > 0) {
    // Name the consequence and the broken servers themselves, not just a
    // status count -- a server in a BROKEN_STATE never got as far as
    // handing back a tools list this run.
    const named = brokenRows.map((s) => `${s.name ?? "(unnamed)"} ${shortBrokenReason(s)}`).join(", ");
    lines.push(`${brokenRows.length} of your ${total} MCP servers have never handed you a tool: ${named}.`);
    if (slowColdstart.length > 0) {
      lines.push(`  + ${slowColdstart.length} more answer, just slowly to start -- see table`);
    }
  } else {
    // attentionRows.length > 0 here only via slow-coldstart servers --
    // they DID hand back tools, just slowly, so they get their own named
    // line rather than being folded into the "never handed you a tool" one.
    const named = slowColdstart.map((s) => `${s.name ?? "(unnamed)"} ${fmtMs(s.cold_start_ms)}`).join(", ");
    lines.push(`${total} server(s): ${healthyRows.length} healthy, ${slowColdstart.length} slow to start: ${named}`);
  }
  // cold_start_ms is a real measurement for every healthy server (never an
  // estimate) -- with two or more to compare, the spread itself is often
  // the more actionable fact than any single server's number alone.
  const timedHealthy = healthyRows.filter((s) => typeof s.cold_start_ms === "number" && s.cold_start_ms > 0);
  if (timedHealthy.length >= 2) {
    const sorted = [...timedHealthy].sort((a, b) => a.cold_start_ms - b.cold_start_ms);
    const fastest = sorted[0];
    const slowest = sorted[sorted.length - 1];
    if (slowest.cold_start_ms > fastest.cold_start_ms) {
      const ratio = slowest.cold_start_ms / fastest.cold_start_ms;
      coldStartSpreadLine = `Your healthy ones vary ${ratio.toFixed(1)}x on cold start -- ${slowest.name ?? "(unnamed)"} ${fmtSec(slowest.cold_start_ms)}s for ${slowest.tools?.count ?? 0} tools, ${fastest.name ?? "(unnamed)"} ${fmtSec(fastest.cold_start_ms)}s for ${fastest.tools?.count ?? 0}.`;
      lines.push(coldStartSpreadLine);
    }
  }
  if (remoteRows.length > 0) {
    lines.push(`  + ${remoteRows.length} remote server(s) not probed (no network calls made) -- see table`);
  }
  if (cappedRows.length > 0) {
    lines.push(
      `  + ${cappedRows.length} server(s) beyond the max_servers cap, not probed -- raise max_servers to include them`,
    );
  }
  if (missingRows.length > 0) {
    lines.push(`  + ${missingRows.length} server(s) in scope but never returned a probe result -- see table`);
  }
  if (truncatedRows.length > 0) {
    lines.push(
      `  + ${truncatedRows.length} server(s) had truncated probe output (rote's capture cap) -- not a verified state; see table`,
    );
  }
  if (hiddenDuplicates.length > 0) {
    lines.push(
      `  + ${hiddenDuplicates.length} server(s) not diagnosed -- identical command+args to another, differently-named entry -- see table`,
    );
  }
  lines.push("");

  lines.push(`PER-SERVER (${total + hiddenDuplicates.length})`);
  if (total === 0 && hiddenDuplicates.length === 0) {
    lines.push("  none -- no MCP servers configured on this machine");
  } else {
    probed.forEach((s) => {
      const name = String(s.name ?? "(unnamed)").padEnd(24);
      const harness = String(s.harness ?? "?").padEnd(14);
      const state = String(s.state ?? "?").padEnd(17);
      const cold = fmtMs(s.cold_start_ms).padStart(8);
      const tools = String(s.tools?.count ?? 0).padStart(5);
      lines.push(`  ${name} ${harness} ${state} ${cold} cold-start  ${tools} tools`);
    });
    missingRows.forEach((s) => {
      const name = String(s.name ?? "(unnamed)").padEnd(24);
      const harness = String(s.harness ?? "?").padEnd(14);
      lines.push(`  ${name} ${harness} no-probe-result`);
    });
    truncatedRows.forEach((s) => {
      const name = String(s.name ?? "(unnamed)").padEnd(24);
      const harness = String(s.harness ?? "?").padEnd(14);
      const bytesNote = s._truncated?.bytes != null ? `${s._truncated.bytes} bytes captured` : "capture cap reached";
      lines.push(`  ${name} ${harness} truncated (${bytesNote}) -- this report covers only part of what this server's probe produced`);
    });
    hiddenDuplicates.forEach((d) => {
      const name = String(d.name ?? "(unnamed)").padEnd(24);
      const harness = String(d.harness ?? "?").padEnd(14);
      lines.push(`  ${name} ${harness} not-diagnosed (identical command+args to "${d.kept_name}")`);
    });
  }
  lines.push("");

  lines.push('ADVISORIES -- text only, nothing here was executed');
  if (advisories.length === 0) {
    lines.push("  none -- every server is healthy");
  } else {
    advisories.forEach((a) => {
      lines.push(`  ${String(a.name).padEnd(24)} [${a.state}] ${a.advisory}`);
    });
  }
  lines.push("");

  lines.push("CONFIG DRIFT");
  if (shadowGroups.length === 0 && duplicateFindings.length === 0) {
    lines.push("  no drift -- every server name resolves to one definition");
  } else {
    if (shadowGroups.length > 0) {
      lines.push(`  shadowing (${shadowGroups.length}):`);
      shadowGroups.forEach((g) => {
        const where = g.entries.map((e) => `${e.harness} (${e.source_path ?? "?"})`).join(" vs ");
        lines.push(`    "${g.name}" defined differently in ${where} -- which one wins depends on the harness`);
      });
    }
    if (duplicateFindings.length > 0) {
      lines.push(`  duplicate identical definitions (${duplicateFindings.length}):`);
      duplicateFindings.forEach((d) => {
        lines.push(
          `    "${d.name}" declared identically in ${d.kept_harness ?? "?"} (${d.kept_source_path ?? "?"}) and ${d.harness ?? "?"} (${d.source_path ?? "?"})`,
        );
      });
    }
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
  stageLine("discover configs  ", discoverStep, discoverResult, () =>
    discovery
      ? `${sources.length} source(s) read, ${allServers.length} server(s) found (${discovery.duplicates_dropped ?? 0} duplicate(s) dropped)`
      : "output did not parse as JSON",
  ),
);
lines.push(
  stageLine("probe servers     ", probeStep, null, () =>
    truncatedProbeItems.length > 0
      ? `${probeRows.length} probed, ${truncatedProbeItems.length} truncated at rote's capture cap (see PER-SERVER)`
      : `${probeRows.length} probed`,
  ),
);
lines.push("");
lines.push("cold_start_ms is a real measurement (spawn to first initialize response), never an estimate.");
lines.push("");

// The report must not end on the STAGES ledger -- STAGES restates counts
// already shown above it; the reader's next action belongs in that last
// slot instead. discoveryUsable gates this the same way every clean-bill
// headline above is gated: a truncated or failed discover_configs step
// means nothing below it -- including "every server is healthy" -- was
// actually verified this run.
const discoveryUsable = discoverResult.kind !== "truncated" && Boolean(discovery) && discovery.ok === true;
let nextLine;
if (!discoveryUsable) {
  nextLine = "NEXT: fix discovery first -- see the message above; nothing below could be verified this run.";
} else if (advisories.length > 0) {
  const top = advisories[0];
  nextLine = `NEXT: ${top.name} [${top.state}] -- ${top.advisory}`;
} else if (shadowGroups.length > 0 || duplicateFindings.length > 0) {
  const driftCount = shadowGroups.length + duplicateFindings.length;
  nextLine = `NEXT: resolve the ${driftCount} config drift finding(s) above -- until then, which definition wins depends on your harness.`;
} else if (coldStartSpreadLine) {
  nextLine = `NEXT: ${coldStartSpreadLine}`;
} else if (missingRows.length === 0 && truncatedRows.length === 0 && probed.length + missingRows.length + truncatedRows.length > 0) {
  nextLine = "NEXT: nothing needs attention -- every discovered server is healthy.";
} else {
  nextLine = "NEXT: nothing to act on from this run.";
}
lines.push(nextLine);
lines.push("Advisories are text only -- nothing here was executed.");

out.human(lines.join("\n"));

out.summary(
  discovery && discovery.ok === true
    ? `mcp-doctor: ${probed.length + missingRows.length + truncatedRows.length} servers, ${healthyRows.length} healthy, ${attentionRows.length} need attention` +
      (truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated (not verified)` : "") +
      (shadowGroups.length + duplicateFindings.length > 0
        ? `, ${shadowGroups.length + duplicateFindings.length} config drift finding(s)`
        : "") +
      (hiddenDuplicates.length > 0
        ? `, ${hiddenDuplicates.length} not diagnosed (identical to a differently-named entry)`
        : "")
    : "mcp-doctor unavailable (discovery degraded)",
);

out.result({
  ok: Boolean(discovery && discovery.ok === true),
  generated_at: new Date().toISOString(),
  sources,
  totals: {
    servers_discovered: allServers.length,
    probed: probed.length,
    no_probe_result: missingRows.length,
    probe_truncated: truncatedRows.length,
    healthy: healthyRows.length,
    needs_attention: attentionRows.length,
    remote_not_probed: remoteRows.length,
    capped_unprobed: cappedRows.length,
    hidden_duplicates: hiddenDuplicates.length,
  },
  states: {
    healthy: healthyRows.map((s) => s.name),
    "needs-auth": needsAuth.map((s) => s.name),
    "slow-coldstart": slowColdstart.map((s) => s.name),
    unresponsive: unresponsive.map((s) => s.name),
    "config-error": configError.map((s) => ({ name: s.name, error: s.error ?? null })),
    "remote-not-probed": remoteRows.map((s) => s.name),
    capped: cappedRows.map((s) => s.name),
    truncated: truncatedRows.map((s) => ({ name: s.name, bytes: s._truncated?.bytes ?? null })),
  },
  servers: probed.map((s) => ({
    id: s.id,
    name: s.name,
    harness: s.harness,
    source_path: s.source_path ?? null,
    state: s.state,
    cold_start_ms: s.cold_start_ms ?? null,
    tools: s.tools?.count ?? 0,
    error: s.error ?? null,
  })),
  no_probe_result: missingRows.map((s) => ({ id: s.id, name: s.name, harness: s.harness })),
  hidden_duplicates: hiddenDuplicates.map((d) => ({
    name: d.name,
    harness: d.harness,
    identical_to: d.kept_name,
    identical_to_harness: d.kept_harness ?? null,
  })),
  advisories,
  drift: {
    shadowing: shadowGroups,
    duplicates: duplicateFindings,
  },
  note: "cold_start_ms is a REAL measured duration (monotonic milliseconds, spawn to first initialize response), never an estimate. Advisories are text only; this play never executes anything it advises.",
  representations: {
    human: "complete -- header, verdict, per-server table, advisories, config drift, sources, stage ledger",
    json: "canonical -- full server inventory, every probe outcome, all advisory text, and drift findings this run produced",
    summary: "intentionally lossy -- counts only",
  },
});
