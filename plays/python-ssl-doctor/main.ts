#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: python-ssl-doctor
 * description: 'One HTTPS request fails with CERTIFICATE_VERIFY_FAILED and silently breaks every tool built on that python -- the real-incident hook here: a single shadowed interpreter failing exactly that way once quietly broke four separate downstream tools before anyone thought to check which python each one was actually running. Finds every python3 (and bare python) on this machine''s PATH. Fingerprints each install''s source (python.org, homebrew, conda, pyenv, uv-managed, system CLT, or unknown), then runs one bounded TLS handshake per python against pypi.org:443 -- its only network activity. Every failure gets an exact, source-specific fix (Install Certificates.command, conda install ca-certificates, or an openssl/certifi note) plus a universal pip install certifi fallback. Also reports ssl module linkage and whether certifi/SSL_CERT_FILE/REQUESTS_CA_BUNDLE are set -- names and a flag only, never the value or file contents. A handshake timeout degrades only that python to an "unreachable, not necessarily a cert problem" verdict. TRUST BOUNDARY: executes every matching python on PATH with fixed -c scripts carrying no user input, gated by a fail-closed pre-exec check (regular file, owned by root or you, never world-writable, never in a world-writable dir lacking the sticky bit) -- a file failing this check is reported as discovered, never run. Read-only otherwise, no credentials transmitted; needs only python3.'
 * version: 0.1.4
 * source_url: https://play.modiqo.ai/dotisacat/python-ssl-doctor
 * provenance:
 *   author: sunzeyu06@gmail.com
 *   workspace: python-ssl-doctor
 * metadata:
 *   version: 0.1.4
 *   rote_version: 0.77.0
 *   status: released
 *   kind: atomic
 *   flow_type: parallel
 *   execution_model: steps_with_presentation
 *   requires_sessions: false
 * presentation_fixtures:
 *   find_pythons: resources/presentation-fixtures/find_pythons/fixture.yaml
 *   probe_ssl: resources/presentation-fixtures/probe_ssl/fixture.yaml
 * tags:
 * - domain-developer-workflow
 * - job-ssl-diagnosis
 * - audience-developers
 * - effect-read-only
 * - tool-shell
 * discoverability:
 *   tags:
 *   - domain-developer-workflow
 *   - job-ssl-diagnosis
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
 *       host:
 *         type: object
 *       totals:
 *         type: object
 *       pythons:
 *         type: object
 *       env_overrides:
 *         type: object
 *       all_failed_identically:
 *         type: object
 *       note:
 *         type: string
 *       representations:
 *         type: object
 * parameters:
 * - name: timeout_s
 *   param_type: integer
 *   required: false
 *   default: '5'
 *   description: TLS handshake timeout per python (1-30)
 *   example: '5'
 * steps:
 *   find_pythons:
 *     type: process.exec
 *     timeout_ms: 15000
 *     argv:
 *     - python3
 *     - '@resource{find_pythons.py}'
 *   probe_ssl:
 *     type: process.exec
 *     timeout_ms: 40000
 *     depends_on:
 *     - find_pythons
 *     for_each: $.stdout.text | fromjson | .pythons
 *     max_concurrency: 3
 *     argv:
 *     - python3
 *     - '@resource{probe_ssl.py}'
 *     - $item
 *     - $item_index
 *     - $timeout_s
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

const HOST = "pypi.org";

type StepJsonResult =
  | { kind: "ok"; data: any }
  | { kind: "truncated"; bytes: number | null }
  | { kind: "unparseable" }
  | { kind: "absent" };

/** Read a single (non fan-out) step's stdout as a discriminated result --
 * truncation is read as a first-class, named outcome (`stdout.truncated
 * === true`, strict) BEFORE any JSON.parse is attempted, never inferred
 * from a parse failure -- truncated wins even on the off chance the
 * partial text still happens to parse as valid JSON. */
function readStepJson(step: any): StepJsonResult {
  try {
    const outcome = step?.outcome;
    if (outcome?.status !== "completed" && outcome?.status !== "restored") return { kind: "absent" };
    const s = outcome?.output?.body?.stdout;
    if (!s) return { kind: "absent" };
    if (s.truncated === true) {
      return { kind: "truncated", bytes: typeof s.bytes === "number" ? s.bytes : null };
    }
    const text = s.text ?? "";
    if (typeof text !== "string" || !text.trim()) return { kind: "absent" };
    const data = JSON.parse(text);
    return data && typeof data === "object" ? { kind: "ok", data } : { kind: "unparseable" };
  } catch {
    return { kind: "unparseable" };
  }
}

/** Human-readable reason a step's data is unavailable, truncation-aware --
 * a truncated capture is a fact about rote's capture cap, never described
 * merely as "unavailable" or "did not parse". */
function truncationNote(bytes: number | null): string {
  const bytesNote = bytes != null ? `${bytes} byte(s) captured` : "rote's capture cap reached";
  return `output was truncated at rote's capture cap (${bytesNote}) -- this report covers only part of what the step produced`;
}
function unavailableReason(step: any, result: StepJsonResult): string {
  if (result.kind === "truncated") return truncationNote(result.bytes);
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") return `step ${status}`;
  return result.kind === "unparseable" ? "output did not parse as JSON" : `step ${status}`;
}

/** Read a for_each fan-out step: one process observation per item -> row
 * list, PLUS a parallel list of which item positions were truncated by
 * rote's own capture cap. Deliberately does NOT gate on the aggregate step
 * status the way a single (non fan-out) step read would -- if the runner
 * ever promotes one item's failure/timeout to an aggregate status other
 * than completed/restored while still populating output.items with the
 * observations that DID come back, gating on the aggregate status here
 * would silently discard every successful peer along with the bad one.
 * Array.isArray-guarded so a shape mismatch (items absent, e.g. a genuine
 * pre-fan-out failure) degrades to an empty list instead of throwing, and
 * one malformed item's JSON never sinks the rest of the report; every
 * python missing a row still gets an explicit "no-probe-result" line
 * below, whichever way this comes back empty.
 * Truncation is read directly off each item's OWN stdout.truncated flag
 * (strict === true), BEFORE any JSON.parse is attempted on that item's
 * text -- a truncated item's text is never even a row-list candidate,
 * since a truncated payload happening to still parse would silently
 * report a partial per-python observation as a complete one. The item's
 * own array POSITION (its for_each order) is what later identifies which
 * discovered python a truncated item belonged to, since a truncated
 * item's own embedded `id` is exactly what truncation may have cut off. */
function readFanOutRows(step: any): { rows: any[]; truncated: { index: number; bytes: number | null }[] } {
  const items = step?.outcome?.output?.items;
  if (!Array.isArray(items)) return { rows: [], truncated: [] };
  const rows: any[] = [];
  const truncated: { index: number; bytes: number | null }[] = [];
  items.forEach((item: any, index: number) => {
    const s = item?.body?.stdout;
    if (s?.truncated === true) {
      truncated.push({ index, bytes: typeof s.bytes === "number" ? s.bytes : null });
      return;
    }
    try {
      const text = s?.text ?? "";
      if (typeof text !== "string" || !text.trim()) return;
      const row = JSON.parse(text);
      if (row && typeof row === "object") rows.push(row);
    } catch {
      // one malformed item never sinks the report
    }
  });
  return { rows, truncated };
}

const findStep = ctx.step(stepName("find_pythons"));
const probeStep = ctx.step(stepName("probe_ssl"));

const findResult = readStepJson(findStep);
const discovery = findResult.kind === "ok" ? findResult.data : null;
const findTruncated = findResult.kind === "truncated";

const probeReadResult = readFanOutRows(probeStep);
const probeRows = probeReadResult.rows;
const probeTruncatedByIndex = new Map(probeReadResult.truncated.map((t) => [t.index, t.bytes]));

const allPythons: any[] = Array.isArray(discovery?.pythons) ? discovery.pythons : [];

const probedById = new Map<any, any>();
for (const row of probeRows) {
  if (row && row.id !== null && row.id !== undefined) probedById.set(row.id, row);
}

// Every discovered python normally gets back exactly one probe row (the
// fan-out runs over every discovered python, unconditionally). A row
// missing entirely is a defensive fallback that should not happen (the
// underlying process.exec item failed outright rather than probe_ssl.py
// degrading to JSON on its own, per its own contract) -- labeled honestly
// rather than silently dropped, the same pattern mcp-doctor's main.ts uses
// for its own probe step. A python whose fan-out item was truncated by
// rote's own capture cap is kept in a THIRD bucket, separate from
// missingRows -- it was not silently dropped, and it is not a generic
// "no probe result" either; the item's own for_each POSITION (never
// anything inside its own possibly-truncated stdout) identifies which
// python it belonged to.
const probed: any[] = [];
const missingRows: any[] = [];
const truncatedRows: any[] = [];
allPythons.forEach((py, index) => {
  if (probeTruncatedByIndex.has(index)) {
    truncatedRows.push({ ...py, truncated_bytes: probeTruncatedByIndex.get(index) ?? null });
    return;
  }
  const row = probedById.get(py.id);
  if (row) {
    probed.push({ ...py, ...row });
  } else {
    missingRows.push(py);
  }
});

const VERDICT_LABEL: Record<string, string> = {
  verified: "verified",
  cert_verify_failed: "BROKEN (cert verify failed)",
  ssl_other: "BROKEN (other TLS error)",
  network_unreachable: "unreachable",
  probe_error: "could not probe",
};

const byVerdict = (v: string) => probed.filter((p) => p.verdict === v);
const verifiedRows = byVerdict("verified");
const certBrokenRows = byVerdict("cert_verify_failed");
const sslOtherRows = byVerdict("ssl_other");
const brokenRows = [...certBrokenRows, ...sslOtherRows];
const unreachableRows = byVerdict("network_unreachable");
const probeErrorRows = byVerdict("probe_error");

/** Every broken python's exact fix, derived from its own fingerprinted
 * source and its own measured values -- never a generic guess. Every
 * command is anchored to THIS python specifically (its own path, or its
 * own sys.prefix for conda's -p) rather than a bare `python3`/`conda`,
 * which would follow the CALLER's active environment/PATH instead of the
 * affected interpreter and could repair an unrelated install entirely.
 * The universal fallback is always appended, regardless of source, as the
 * spec calls for -- also anchored the same way. Only called for
 * cert_verify_failed rows; ssl_other gets its own, separate, non-cert
 * presentation (see FIXES / OTHER TLS FAILURES below). */
function deriveFix(p: any): string[] {
  const lines: string[] = [];
  const source = p.source;
  const pyRef = p.path_redacted ?? p.path ?? "<this python>";
  if (source === "python.org framework build") {
    const v = typeof p.version === "string" ? p.version.split(".").slice(0, 2).join(".") : null;
    const dir = v ? `Python ${v}` : "Python 3.x";
    lines.push(`run "/Applications/${dir}/Install Certificates.command" -- the certificate installer python.org ships next to this interpreter`);
  } else if (source === "conda-anaconda") {
    const prefixRef = p.sys_prefix || "<this conda's prefix -- sys_prefix unavailable, see -p below>";
    lines.push(`conda install -p ${prefixRef} ca-certificates -- refresh conda's own CA bundle, anchored to THIS exact environment via -p so it can't silently patch whatever conda a bare \`conda\` on PATH would currently target`);
    lines.push("use this conda's python only inside its own envs -- don't let a bare python3 on PATH silently resolve to a conda base install elsewhere");
  } else if (source === "pyenv" || source === "homebrew") {
    lines.push(`openssl linkage: this build reports ${p.openssl_version || "an unknown OpenSSL/LibreSSL version"} -- a pyenv/homebrew python links against whatever openssl was present at build time, and a later brew upgrade can leave it pointing at a moved or removed cert store`);
    if (p.certifi && p.certifi.present) {
      lines.push(`certifi is installed for this interpreter (${p.certifi.path || "path unknown"}) -- confirm SSL_CERT_FILE isn't overriding it with a stale path (see ENV OVERRIDES below)`);
    } else {
      lines.push(`certifi is NOT installed for this interpreter -- ${pyRef} -m pip install certifi is the fastest fix`);
    }
  } else {
    lines.push("no source-specific fix is known for this install (system CLT / unknown build) -- use the universal fallback below");
  }
  lines.push("universal fallback, THIS python specifically (never a bare python3, which would follow the caller's own PATH instead):");
  lines.push(`  ${pyRef} -m pip install certifi`);
  lines.push(`  export SSL_CERT_FILE=$(${pyRef} -m certifi)`);
  return lines;
}

function fmtError(p: any): string {
  if (!p.error_class) return "";
  const msg = p.error_message ? `: ${p.error_message}` : "";
  return `${p.error_class}${msg}`;
}

// ENV OVERRIDES: SSL_CERT_FILE / REQUESTS_CA_BUNDLE are process-level
// environment variables -- every discovered python's own fingerprint probe
// inherits the identical environment this play itself was run with, so
// these values are expected to agree across every python. Computed once
// here (rather than shown per row in the per-python table, which the spec
// reserves for path/source/openssl/certifi/verdict) from whichever
// fingerprinted python reported first; if any python ever disagrees with
// that baseline (should not happen under normal PATH/env inheritance),
// that disagreement is surfaced explicitly rather than silently averaged
// away.
const ENV_NAMES = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"];
function envKey(overrides: any): string {
  return ENV_NAMES.map((n) => {
    const e = overrides?.[n];
    return `${n}:${e?.set ? "set" : "unset"}:${e?.path_exists === null || e?.path_exists === undefined ? "n/a" : e.path_exists}`;
  }).join("|");
}
const fingerprintedPythons = allPythons.filter((p) => p.fingerprint_ok && p.env_overrides);
const envKeys = new Set(fingerprintedPythons.map((p) => envKey(p.env_overrides)));
const envBaseline = fingerprintedPythons[0]?.env_overrides ?? null;
const envDisagreement = envKeys.size > 1;

// Cross-note: when every probed python fails with the SAME verdict AND the
// same underlying error signature, that pattern reads as strongly as a
// shared, upstream network cause (a network outage, a captive portal, a
// corporate proxy breaking every chain alike) as it does N independent
// per-python cert failures -- this play never makes an extra network call
// to settle that question (its one job is the per-python handshake
// itself), so it surfaces the ambiguity in the report instead of quietly
// implying "every python here is broken." Narrowed on three axes (see
// this play's own hardening review, finding #6):
//   (1) requires at least TWO probed pythons -- one failing interpreter is
//       not a pattern, it is one data point.
//   (2) compares normalized (verdict, error_class) SIGNATURES, not just
//       the coarse verdict -- a DNS failure and a connection refusal both
//       land in network_unreachable but are not "identical" in any way
//       that supports a shared-cause claim.
//   (3) the wording is literally about a NETWORK outage/block/portal, so
//       it only fires when the shared verdict is itself network_unreachable
//       -- cert_verify_failed or probe_error sharing across pythons is a
//       real, different pattern (a systemically broken trust store, or a
//       shared inability to even run these interpreters), not a network
//       claim, and dressing it up as one would be misleading.
const totalProbed = probed.length;
const nonVerifiedProbed = probed.filter((p) => p.verdict !== "verified");
const failureSignatures = new Set(nonVerifiedProbed.map((p) => `${p.verdict}|${p.error_class ?? "?"}`));
const allFailedIdentically =
  totalProbed >= 2 &&
  nonVerifiedProbed.length === totalProbed &&
  failureSignatures.size === 1 &&
  nonVerifiedProbed[0].verdict === "network_unreachable"
    ? nonVerifiedProbed[0].verdict
    : null;

/** One STAGES ledger row, tolerant of every outcome status the runner can hand back. */
function stageLine(label: string, step: any, okNote: () => string): string {
  const status = step?.outcome?.status ?? "unknown";
  if (status !== "completed" && status !== "restored") {
    return `  ${status.padEnd(10)}  ${label}  step ${status}`;
  }
  return `  ok          ${label}  ${okNote()}`;
}

const lines: string[] = [];
lines.push("PYTHON SSL DOCTOR");
lines.push("");

if (!discovery || discovery.ok !== true) {
  lines.push(`discovery unavailable -- ${findTruncated ? unavailableReason(findStep, findResult) : `find_pythons step ${findStep?.outcome?.status ?? "unknown"}`}`);
} else {
  const total = allPythons.length;
  const brokenCount = brokenRows.length;

  if (total === 0) {
    lines.push("no python3 or python executable found on this machine's PATH -- nothing to diagnose");
  } else if (brokenCount === 0 && unreachableRows.length === 0 && probeErrorRows.length === 0 && missingRows.length === 0 && truncatedRows.length === 0) {
    lines.push(`${total} python(s) found: clean bill of health -- every one verifies TLS against ${HOST} fine`);
  } else {
    lines.push(`${total} python(s) found: ${verifiedRows.length} verify TLS fine, ${brokenCount} broken`);
    if (unreachableRows.length > 0) {
      lines.push(`  + ${unreachableRows.length} unreachable -- network?, not necessarily a cert problem`);
    }
    if (probeErrorRows.length > 0) {
      lines.push(`  + ${probeErrorRows.length} could not be probed at all -- see table`);
    }
    if (missingRows.length > 0) {
      lines.push(`  + ${missingRows.length} python(s) in scope but never returned a probe result -- see table`);
    }
    if (truncatedRows.length > 0) {
      lines.push(`  + ${truncatedRows.length} probe(s) truncated at rote's capture cap -- this report covers only part of what ${truncatedRows.length === 1 ? "it" : "they"} produced, see table`);
    }
  }
  lines.push("");

  lines.push(`PER-PYTHON (${total})`);
  if (total === 0) {
    lines.push("  none");
  } else {
    probed.forEach((p) => {
      const path = String(p.path_redacted ?? p.path ?? "?").padEnd(46);
      const source = String(p.source ?? "unknown").padEnd(27);
      const openssl = String(p.openssl_version ?? "?").slice(0, 24).padEnd(25);
      const certifi = (p.certifi?.present ? "yes" : "no").padEnd(5);
      const verdict = VERDICT_LABEL[p.verdict] ?? p.verdict ?? "?";
      lines.push(`  ${path} ${source} ${openssl} certifi:${certifi} ${verdict}`);
    });
    missingRows.forEach((p) => {
      const path = String(p.path_redacted ?? p.path ?? "?").padEnd(46);
      const source = String(p.source ?? "unknown").padEnd(27);
      lines.push(`  ${path} ${source} no-probe-result`);
    });
    truncatedRows.forEach((p) => {
      const path = String(p.path_redacted ?? p.path ?? "?").padEnd(46);
      const source = String(p.source ?? "unknown").padEnd(27);
      const bytesNote = p.truncated_bytes != null ? `${p.truncated_bytes}B captured` : "capture cap";
      lines.push(`  ${path} ${source} truncated (${bytesNote}) -- this report covers only part of what this probe produced`);
    });
  }
  lines.push("");

  lines.push("FIXES -- certificate-store fixes, text only, nothing here was executed");
  if (certBrokenRows.length === 0) {
    lines.push("  none needed -- no certificate-verify failure to fix");
  } else {
    certBrokenRows.forEach((p) => {
      lines.push(`  ${p.path_redacted ?? p.path} [${p.verdict}] ${fmtError(p)}`);
      deriveFix(p).forEach((l) => lines.push(`    ${l}`));
      lines.push("");
    });
  }

  if (sslOtherRows.length > 0) {
    // Deliberately NOT run through deriveFix: a protocol/handshake
    // failure that was never identified as CERTIFICATE_VERIFY_FAILED is
    // not a certificate-store problem, and a certificate-repair command
    // would not address it -- presented separately, with its own TLS
    // error, and no cert-repair advice (see this play's own hardening
    // review, finding #4).
    lines.push("OTHER TLS FAILURES (not a certificate-store problem -- no cert fix given) -- text only");
    sslOtherRows.forEach((p) => {
      lines.push(`  ${p.path_redacted ?? p.path} [${p.verdict}] ${fmtError(p)} -- protocol/handshake failure, not CERTIFICATE_VERIFY_FAILED; investigate the TLS error itself, a certificate-store fix would not address this`);
    });
    lines.push("");
  }

  if (unreachableRows.length > 0 || probeErrorRows.length > 0) {
    lines.push("NOT A CERT PROBLEM (honest distinction) -- text only");
    unreachableRows.forEach((p) => {
      lines.push(`  ${p.path_redacted ?? p.path}  unreachable within ${p.timeout_s ?? "?"}s -- ${fmtError(p) || "no response"} -- could be network, DNS, or a firewall, not necessarily this python's cert store`);
    });
    probeErrorRows.forEach((p) => {
      lines.push(`  ${p.path_redacted ?? p.path}  could not be probed at all -- ${fmtError(p) || "unknown reason"}`);
    });
    lines.push("");
  }

  lines.push("ENV OVERRIDES");
  if (!envBaseline) {
    lines.push("  unknown -- no python could be fingerprinted");
  } else {
    ENV_NAMES.forEach((name) => {
      const e = envBaseline[name] ?? {};
      if (!e.set) {
        lines.push(`  ${name}: unset`);
      } else {
        const existsNote = e.path_exists === true ? "the file it points at exists" : e.path_exists === false ? "the file it points at does NOT exist -- likely cause of a broken verify" : "could not check whether the file it points at exists";
        lines.push(`  ${name}: set -- ${existsNote} (value itself never printed)`);
      }
    });
    if (envDisagreement) {
      lines.push("  note: pythons disagreed on these values (unexpected -- normally every process inherits the same environment); see the JSON result for the per-python detail");
    }
  }
  lines.push("");

  if (allFailedIdentically) {
    lines.push("CROSS-NOTE");
    lines.push(`  every probed python failed identically (${VERDICT_LABEL[allFailedIdentically] ?? allFailedIdentically}) -- that pattern is exactly what a network outage, DNS block, or captive portal would also look like from here. This play never makes an extra network call to settle that question; treat "every python is broken" as unconfirmed until you know ${HOST} itself was reachable just now.`);
    lines.push("");
  }
}

lines.push("STAGES");
lines.push(
  stageLine("find pythons      ", findStep, () =>
    findTruncated
      ? unavailableReason(findStep, findResult)
      : discovery ? `${allPythons.length} found, ${discovery.duplicates_deduped ?? 0} duplicate path(s) deduped by realpath` : "output did not parse as JSON",
  ),
);
lines.push(
  stageLine("probe ssl         ", probeStep, () =>
    `${probeRows.length} probed${truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated at rote's capture cap` : ""}`,
  ),
);
lines.push("");
if (findTruncated) {
  lines.push(`CHECKED: find_pythons ${unavailableReason(findStep, findResult)} -- which pythons exist on this machine's PATH could not be fully confirmed this run.`);
} else {
  lines.push(`CHECKED: every python3/python found on this machine's PATH was fingerprinted and probed with one real TLS handshake to ${HOST}:443 (${allPythons.length} found, ${probed.length} probed, ${missingRows.length} missing a probe result${truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated at rote's capture cap` : ""}).`);
}
lines.push(`UNVERIFIED: whether ${HOST} itself was reachable/healthy right now was never independently confirmed beyond these per-python handshakes -- see the cross-note above when every python fails the same way.`);
if (findTruncated) {
  lines.push(`UNVERIFIED: find_pythons -- ${unavailableReason(findStep, findResult)}; nothing about which pythons exist above is CHECKED.`);
}
if (truncatedRows.length > 0) {
  lines.push(`UNVERIFIED: ${truncatedRows.length} probe(s) truncated at rote's capture cap -- ${truncatedRows.map((p) => p.path_redacted ?? p.path).join(", ")}; ${truncatedRows.length === 1 ? "its" : "their"} verdict above is not confirmed.`);
}
lines.push("TRUST BOUNDARY: EVERY matching python/python3/python3.N found anywhere on PATH was executed (twice each: once to fingerprint, once for the TLS handshake), not only the one a bare python3 would resolve to -- that is this play's whole point (catching a shadowed interpreter). Each execution was gated by a fail-closed trust check first (owned by root or this user, not world-writable, not writable by a group this user does not belong to); a candidate that failed that check was reported as discovered but never run.");
lines.push("Fixes are text only -- nothing here was executed.");

out.human(lines.join("\n"));

out.summary(
  discovery && discovery.ok === true
    ? `python-ssl-doctor: ${allPythons.length} pythons, ${verifiedRows.length} verify TLS fine, ${brokenRows.length} broken` +
      (unreachableRows.length > 0 ? `, ${unreachableRows.length} unreachable` : "") +
      (truncatedRows.length > 0 ? `, ${truncatedRows.length} truncated at rote's capture cap` : "") +
      (allFailedIdentically ? ", ALL failed identically -- see cross-note" : "")
    : findTruncated
      ? `python-ssl-doctor unavailable -- ${unavailableReason(findStep, findResult)}`
      : "python-ssl-doctor unavailable (discovery degraded)",
);

out.result({
  ok: Boolean(discovery && discovery.ok === true) && truncatedRows.length === 0,
  generated_at: new Date().toISOString(),
  host: HOST,
  discovery_truncated: findTruncated,
  totals: {
    discovered: allPythons.length,
    probed: probed.length,
    no_probe_result: missingRows.length,
    probe_truncated: truncatedRows.length,
    verified: verifiedRows.length,
    broken: brokenRows.length,
    unreachable: unreachableRows.length,
    probe_error: probeErrorRows.length,
  },
  pythons: probed.map((p) => ({
    id: p.id,
    path: p.path_redacted ?? p.path,
    source: p.source,
    version: p.version,
    openssl_version: p.openssl_version,
    certifi: p.certifi,
    verdict: p.verdict,
    error_class: p.error_class ?? null,
    error_message: p.error_message ?? null,
    elapsed_ms: p.elapsed_ms ?? null,
    // Certificate fixes are derived ONLY for the classic cert-verify
    // signature -- never for ssl_other (a protocol/handshake failure that
    // was never identified as a cert problem; a cert fix would not
    // address it) and never for network_unreachable/probe_error (this
    // python could not even be meaningfully tested). See deriveFix() and
    // this play's own hardening review, finding #4.
    fix: p.verdict === "cert_verify_failed" ? deriveFix(p) : null,
  })),
  no_probe_result: missingRows.map((p) => ({ id: p.id, path: p.path_redacted ?? p.path, source: p.source })),
  probe_truncated: truncatedRows.map((p) => ({ id: p.id, path: p.path_redacted ?? p.path, source: p.source, bytes_captured: p.truncated_bytes ?? null })),
  env_overrides: envBaseline,
  all_failed_identically: allFailedIdentically,
  note: "Fixes and every error_message are text only; this play never executes anything it advises. The one and only network activity performed is the per-python TLS handshake to pypi.org:443 that is this play's own diagnosis. Trust boundary: every python/python3/python3.N found anywhere on PATH is executed (fingerprint + handshake), not only the one a bare python3 would resolve to -- each execution is gated by a fail-closed trust check first (owned by root or this user, not world-writable, not writable by a group this user does not belong to); a candidate that fails that check is reported as discovered but never run.",
  representations: {
    human: "complete -- headline, per-python table, fixes, unreachable/probe-error distinction, env overrides, cross-note, stage ledger, CHECKED/UNVERIFIED footer",
    json: "canonical -- every discovered python, every probe outcome, and every derived fix this run produced",
    summary: "intentionally lossy -- counts only",
  },
});
