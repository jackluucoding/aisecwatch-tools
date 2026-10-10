#!/usr/bin/env node
/**
 * AI Sec Watch Stack Check from the command line.
 *
 * Finds dependency manifests, lockfiles and SBOMs (or takes them as arguments), sends them to
 * the Stack Check API, prints a Markdown report, optionally writes JSON, SARIF and a CycloneDX
 * AI-BOM, and exits non-zero when a vulnerability at or above --fail-on is found. Needs Node.js
 * 18 or later and no dependencies.
 *
 * Usage:
 *   stack-check [files...] [--fail-on critical|high|medium|low|none] [--json out.json]
 *               [--sarif out.sarif] [--cyclonedx ai-bom.cdx.json] [--markdown out.md]
 *               [--no-osv] [--api https://aisecwatch.com]
 */

import { readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { basename, relative } from "node:path";

const KNOWN = [
  "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
  "poetry.lock", "uv.lock", "Pipfile.lock", "requirements.txt", "go.sum", "Cargo.lock",
  "package.json", "pyproject.toml", "go.mod", "Cargo.toml",
  "bom.json", "sbom.json", "bom.cdx.json", "sbom.cdx.json", "sbom.spdx.json",
];
const LOCK_FOR = {
  "package.json": ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"],
  "pyproject.toml": ["poetry.lock", "uv.lock"],
  "go.mod": ["go.sum"],
  "Cargo.toml": ["Cargo.lock"],
};
const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 99 };
const MAX_FILES = 5;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_SBOM_BYTES = 5 * 1024 * 1024;
const isSbom = (f) => /(^|[\\/])s?bom(\.cdx|\.spdx)?\.json$|\.(cdx|spdx)\.json$/i.test(f);

function parseArgs(argv) {
  const opts = { files: [], failOn: "high", osv: true, api: "https://aisecwatch.com", json: null, sarif: null, markdown: null, cyclonedx: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--fail-on") opts.failOn = (argv[++i] ?? "high").toLowerCase();
    else if (a === "--json") opts.json = argv[++i];
    else if (a === "--sarif") opts.sarif = argv[++i];
    else if (a === "--markdown") opts.markdown = argv[++i];
    else if (a === "--cyclonedx") opts.cyclonedx = argv[++i];
    else if (a === "--api") opts.api = (argv[++i] ?? opts.api).replace(/\/$/, "");
    else if (a === "--no-osv") opts.osv = false;
    else if (a === "-h" || a === "--help") opts.help = true;
    else if (a.trim()) opts.files.push(...a.split(/\s+/).filter(Boolean));
  }
  if (!(opts.failOn in RANK)) throw new Error(`--fail-on must be one of ${Object.keys(RANK).join(", ")}`);
  return opts;
}

/** Lockfiles in the working directory; a manifest only when its lockfile is absent. */
function discover() {
  const present = KNOWN.filter((f) => existsSync(f) && statSync(f).isFile());
  return present.filter((f) => !(LOCK_FOR[f] ?? []).some((lock) => present.includes(lock))).slice(0, MAX_FILES);
}

function severityOf(v) {
  return v.severity ?? "medium";
}

function toMarkdown(report, api) {
  const s = report.summary;
  const out = [
    "## Stack Check",
    "",
    `${s.dependencies} dependencies (${s.direct} direct, ${s.pinned} pinned), ${s.llmComponents} LLM components, ${s.vulnerabilities} advisories on ${s.vulnerablePackages} pinned packages.`,
  ];
  if (s.authority.length) out.push(`Authority reachable from dependencies: ${s.authority.join(", ")}.`);
  if (report.vulnerabilities.length) {
    out.push("", "| Package | Advisory | Severity | Fixed in |", "|---|---|---|---|");
    for (const v of report.vulnerabilities.slice(0, 100)) {
      const url = v.record?.url ?? `https://osv.dev/vulnerability/${v.id}`;
      out.push(`| \`${v.package.name}@${v.package.version}\`${v.package.direct ? "" : " (indirect)"} | [${v.id}](${url}) | ${v.severity ?? "see advisory"} | ${v.fixedVersions.join(", ") || "no fix listed"} |`);
    }
  }
  if (report.llmComponents.length) {
    out.push("", "### LLM components", "");
    for (const c of report.llmComponents) out.push(`- \`${c.name}\` ${c.version ?? c.versionSpec ?? ""}${c.direct ? "" : " (indirect)"}`);
  }
  if (report.controls.length) {
    out.push("", "### Controls", "");
    for (const c of report.controls) out.push(`- **${c.title}.** ${c.why}`);
  }
  for (const n of report.notes) out.push("", `> ${n}`);
  out.push("", `Report by [AI Sec Watch Stack Check](${api}/check). Advisory data from OSV.`);
  return out.join("\n");
}

function toSarif(report, files, api) {
  const level = (sev) => (sev === "critical" || sev === "high" ? "error" : sev === "medium" ? "warning" : "note");
  const rules = new Map();
  const results = [];
  const uri = files[0] ?? "package.json";
  for (const v of report.vulnerabilities) {
    if (!rules.has(v.id)) {
      rules.set(v.id, {
        id: v.id,
        name: v.id,
        shortDescription: { text: v.summary ?? v.id },
        helpUri: v.record?.url ?? `https://osv.dev/vulnerability/${v.id}`,
        properties: { tags: ["security", "dependency", ...v.cwes] },
      });
    }
    const fix = v.fixedVersions.length ? ` Fixed in ${v.fixedVersions.join(", ")}.` : " No fixed version listed.";
    results.push({
      ruleId: v.id,
      level: level(severityOf(v)),
      message: { text: `${v.package.name}@${v.package.version} is affected by ${v.id}${v.aliases.length ? ` (${v.aliases.join(", ")})` : ""}.${fix}` },
      locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
    });
  }
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{ tool: { driver: { name: "AI Sec Watch Stack Check", informationUri: `${api}/check`, rules: [...rules.values()] } }, results }],
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(2, 15).join("\n").replace(/^ \* ?/gm, ""));
    return 0;
  }
  const files = (opts.files.length ? opts.files : discover()).slice(0, MAX_FILES);
  if (files.length === 0) {
    console.error("No manifest or lockfile found. Pass file paths, e.g. stack-check package-lock.json");
    return 2;
  }
  const payload = files.map((f) => {
    const content = readFileSync(f, "utf8");
    const limit = isSbom(f) ? MAX_SBOM_BYTES : MAX_BYTES;
    if (Buffer.byteLength(content) > limit) throw new Error(`${f} is larger than ${limit / 1024 / 1024} MB`);
    return { filename: basename(f), content };
  });

  const res = await fetch(`${opts.api}/api/v1/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "aisecwatch-stack-check/1.1" },
    body: JSON.stringify({ files: payload, osv: opts.osv }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.data) {
    console.error(`Stack Check failed: ${body?.error?.message ?? res.status}`);
    return 2;
  }
  const report = body.data;
  const markdown = toMarkdown(report, opts.api);
  console.log(markdown);
  const relFiles = files.map((f) => relative(process.cwd(), f).replace(/\\/g, "/"));
  if (opts.markdown) writeFileSync(opts.markdown, markdown + "\n", { flag: "a" });
  if (opts.json) writeFileSync(opts.json, JSON.stringify(report, null, 2));
  if (opts.sarif) writeFileSync(opts.sarif, JSON.stringify(toSarif(report, relFiles, opts.api), null, 2));
  if (opts.cyclonedx) {
    // A second request: the API builds the AI-BOM so the format lives in one place.
    const bom = await fetch(`${opts.api}/api/v1/check?format=cyclonedx`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "aisecwatch-stack-check/1.1" },
      body: JSON.stringify({ files: payload, osv: opts.osv }),
    });
    if (bom.ok) writeFileSync(opts.cyclonedx, await bom.text());
    else console.error(`AI-BOM export failed: ${bom.status}`);
  }

  const threshold = RANK[opts.failOn];
  const failing = report.vulnerabilities.filter((v) => RANK[severityOf(v)] >= threshold);
  if (failing.length > 0) {
    console.error(`\n${failing.length} advisories at or above "${opts.failOn}".`);
    return 1;
  }
  return 0;
}

// Set the exit code and let Node exit on its own: calling process.exit() while fetch's
// sockets are still closing can abort the process on Windows.
main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(`Stack Check failed: ${err instanceof Error ? err.message : err}`);
    process.exitCode = 2;
  }
);
