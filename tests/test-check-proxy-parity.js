#!/usr/bin/env node
'use strict';
// Self-test for .github/actions/check-proxy-parity.
//
// PORTED, NOT REWRITTEN. Everything down to the `── the ACTION's own run body`
// banner is security-orchestration's `remediation/gates/test-check-proxy-parity.js`
// at its origin/main, with ONE logic edit: the path the gate is resolved from
// (see ACTION_DIR below). Canonical is the parent of the script this action
// ships and of this suite; a case rewritten here rather than there is drift in
// the same way a re-worded comment in the gate is. The section below the banner
// is additive and belongs only here, because it tests action.yml — a file
// canonical does not have.
//
// ── canonical's own header follows ─────────────────────────────────────────
//
// This gate had none, and it has been wrong twice: once reporting "no outbound
// HTTP call sites found" for a task that demonstrably makes them, and once
// attributing a LOCALLY DEFINED function to a package because the two share a
// name. Both failures are the same shape -- the inventory silently changes size
// and the verdict follows it -- which is precisely what a gate over "did we miss
// a call site" must never do.
//
// Every case builds a fixture repository, runs the real script over it as a
// SUBPROCESS, and asserts on the --json verdict. The script is copied INTO the
// fixture rather than run from here on purpose. It is not that the gate cannot
// run out-of-tree -- every walk boundary is ROOT (argv) now, which is the whole
// reason one canonical copy can serve every repository. It is that a fixture
// which copies the gate in is the arrangement each consumer repository actually
// ships, so a case that passes here passes there, and Phase B/C can move these
// bytes without rewriting the suite.
//
// What the suite can and cannot prove is worth being explicit about: every case
// below tests the MECHANISM -- floors, aliases, local definitions, vacuity. Only
// the `exchangeOidcForUpst` case tests the INVENTORY, and the inventory is what
// went wrong: two copies of this gate were blind to a real outbound WIF hop for
// as long as they existed, and passed their own suites throughout, because no
// case named a sink. The replay's `enumerated` set is the other half of that
// guard.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// THE ONE LOGIC EDIT THIS PORT MAKES. Canonical resolves the gate beside
// itself in `remediation/gates/`; here it lives inside the composite action, so
// the suite drives the REAL shipped script at
// .github/actions/check-proxy-parity/check-proxy-parity.js — the same file
// every consumer's pinned SHA resolves to. Same three-line shape
// tests/test-check-enforced-disciplines.js already uses. Nothing else in the
// ported half of this file changed; the action-body section at the bottom is
// additive.
const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'check-proxy-parity');
const ACTION = path.join(ACTION_DIR, 'action.yml');
const SCRIPT = path.join(ACTION_DIR, 'check-proxy-parity.js');
const PKG = '@4cloudguru/pipeline-task-ado';
const CORE = '@4cloudguru/pipeline-task-core';
const DATA_REL = path.join('scripts', 'lib', 'proxy-parity.data.json');

// The versions a healthy fixture declares and installs. They must sit at or
// above every floor the gate enforces -- and those floors track the fleet
// (sethbacon/azure-pipelines-terraform#1108, finding 2), so raising ESTATE_FLOORS
// means raising these two in the same change. Named once so that is a single
// edit rather than a hunt through the cases below, each of which is about
// something else entirely.
const CURRENT_PKG = '^0.11.0';
const CURRENT_CORE = '^0.9.3';
const CURRENT_CORE_INSTALLED = '0.9.3';

let failures = 0;
const report = (ok, msg) => {
    if (ok) console.log(`  OK   ${msg}`);
    else { console.error(`  FAIL ${msg}`); failures += 1; }
};

// One of the three floor sources is a file the ANALYSED repository owns. A
// fixture carries one exactly as a real repository will, written from the same
// CURRENT_* constants as its manifests so "raise a floor" stays a single edit.
const DATA = (floors) => JSON.stringify({
    schemaVersion: 1,
    repo: 'fixture',
    floors: floors ?? {
        [PKG]: CURRENT_PKG.replace('^', ''),
        [CORE]: CURRENT_CORE.replace('^', ''),
    },
}, null, 2);

function fixture(name, { deps = {}, coreVersion = CURRENT_CORE_INSTALLED, sources = {}, floors, writeData = true } = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `proxy-parity-${name}-`));
    fs.mkdirSync(path.join(root, 'scripts', 'lib'), { recursive: true });
    fs.copyFileSync(SCRIPT, path.join(root, 'scripts', 'check-proxy-parity.js'));
    fs.cpSync(path.join(ACTION_DIR, 'lib'), path.join(root, 'scripts', 'lib'), { recursive: true });
    if (writeData) fs.writeFileSync(path.join(root, DATA_REL), DATA(floors));

    const taskDir = path.join(root, 'Tasks', 'Fixture', 'FixtureV1');
    fs.mkdirSync(path.join(taskDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(taskDir, 'package.json'),
        JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: deps }, null, 2));
    fs.writeFileSync(path.join(taskDir, 'package-lock.json'), JSON.stringify({
        name: 'fixture', lockfileVersion: 3,
        packages: { '': { name: 'fixture' }, [`node_modules/${CORE}`]: { version: coreVersion } },
    }, null, 2));
    for (const [file, body] of Object.entries(sources)) {
        fs.writeFileSync(path.join(taskDir, 'src', file), body);
    }
    return root;
}

function spawn(root, env = {}) {
    return spawnSync(process.execPath, [path.join(root, 'scripts', 'check-proxy-parity.js'), '--json', root],
        { encoding: 'utf8', cwd: root, env: { ...process.env, ...env } });
}

// A crashed gate must never read as a clean one. `out` is left with NO
// staleFloors key when the JSON does not parse, so every assertion on that key
// goes through Array.isArray -- `(out.staleFloors || []).length === 0` is true
// of a gate that printed a stack trace, and this suite has already watched that
// expression report OK against a gate that never ran.
function run(root, env) {
    const r = spawn(root, env);
    try { return JSON.parse(r.stdout); } catch { return { sites: [], failures: -1, raw: r.stdout + r.stderr }; }
}

const CALLER = (importLine, callName) => `${importLine}
export async function handle(): Promise<void> {
    await ${callName}('svc');
}
`;

// ── 1. imported from the package: floor applies, verdict is PROXIED-BY-PACKAGE
{
    const root = fixture('imported', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const out = run(root);
    const sites = out.sites.filter((s) => s.sink === 'generateIdToken');
    report(sites.length === 1 && sites[0].verdict === 'PROXIED-BY-PACKAGE',
        `imported from the package -> PROXIED-BY-PACKAGE (got ${JSON.stringify(sites.map((s) => s.verdict))})`);
}

// ── 2. defined locally: NOT a package delegation at all
{
    const root = fixture('local', {
        deps: { [CORE]: '^0.6.0' },
        sources: {
            // Mirrors the real shape: the local generateIdToken WRAPS a proxied
            // fetch. That inner call is the actual sink and must be the one
            // counted -- counting the wrapper too is the double-count this fix
            // removes. It also keeps the fixture non-vacuous, which the script
            // rightly refuses to analyse.
            'id-token-generator.ts': `import { buildProxyFetchOptions } from './proxy-config';
export async function generateIdToken(id: string): Promise<string> {
    const res = await fetch('https://example.invalid/token', { ...buildProxyFetchOptions(), method: 'POST' });
    return String(res.status) + id;
}
`,
            'proxy-config.ts': `export function buildProxyFetchOptions(): Record<string, unknown> { return {}; }\n`,
            'handler.ts': CALLER(`import { generateIdToken } from './id-token-generator';`, 'generateIdToken'),
        },
    });
    const out = run(root);
    const sites = out.sites.filter((s) => s.sink === 'generateIdToken');
    report(sites.length === 0,
        `defined locally -> not attributed to ${PKG} (got ${sites.length} site(s): ${JSON.stringify(sites.map((s) => s.verdict))})`);
    report(out.failures === 0, `defined locally -> no failure (got ${out.failures})`);
    const inner = out.sites.filter((s) => s.sink === 'fetch');
    report(inner.length === 1 && inner[0].verdict === 'PROXIED',
        `the wrapped fetch is counted once, as the real sink (got ${JSON.stringify(inner.map((s) => s.verdict))})`);
}

// ── 3. aliased import: the call names the alias, and it must still be seen
{
    const root = fixture('aliased', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken as mintToken } from '${PKG}';`, 'mintToken') },
    });
    const out = run(root);
    const sites = out.sites.filter((s) => s.sink === 'mintToken');
    report(sites.length === 1 && sites[0].verdict === 'PROXIED-BY-PACKAGE',
        `aliased import -> still enumerated (got ${sites.length} site(s): ${JSON.stringify(sites.map((s) => s.verdict))})`);
}

// ── 4. THE INVENTORY. exchangeOidcForUpst is the OCI WIF flow's second network
//      hop, and it is imported from the package and called for real in two of
//      the three extensions. Two copies of this gate did not carry it and were
//      therefore blind to it, while passing a suite in which no case named any
//      sink at all -- a missing axis and a clean axis look identical from the
//      outside (signature-blind-vs-clean). This case is the only thing in the
//      suite that fails when a row leaves the table.
{
    const root = fixture('wif-second-hop', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { exchangeOidcForUpst } from '${PKG}';`, 'exchangeOidcForUpst') },
    });
    const out = run(root);
    const sites = out.sites.filter((s) => s.sink === 'exchangeOidcForUpst');
    report(sites.length === 1 && sites[0].verdict === 'PROXIED-BY-PACKAGE',
        `the OCI WIF second hop is in the table and enumerated (got ${sites.length} site(s): ${JSON.stringify(sites.map((s) => s.verdict))})`);
}

// ── 5. imported from the package but below the floor: the floor still bites
{
    const root = fixture('stale', {
        deps: { [PKG]: '^0.4.0', [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const out = run(root);
    const sites = out.sites.filter((s) => s.sink === 'generateIdToken');
    report(sites.length === 1 && sites[0].verdict === 'UNPROXIED',
        `below the version floor -> UNPROXIED (got ${JSON.stringify(sites.map((s) => s.verdict))})`);
}

// ── 6. a tree with no outbound call at all must NOT pass: an empty inventory is
//      how this gate failed before, and the guard against it is worth pinning.
//      There are TWO such guards, at opposite ends of the run, and they fail for
//      different reasons -- no SOURCE to read, and source read but no SINK
//      found. Both are pinned: a mutation run found the first one covered by
//      nothing, which is the same "guard nobody can break" shape as the rest of
//      this file.
{
    const root = fixture('vacuous', {
        deps: { [CORE]: '^0.6.0' },
        sources: { 'noop.ts': `export function noop(): void {}\n` },
    });
    const r = spawn(root);
    report(r.status !== 0 && /no outbound HTTP call sites found/.test(r.stderr),
        `source but no call site -> refuses to pass vacuously (exit ${r.status})`);

    // Nothing to read at all: a repository whose src/ layout moved, or a ROOT
    // pointed one directory too deep. Reporting a clean inventory there is how
    // this gate went green over a task that demonstrably makes HTTP calls.
    const empty = fixture('no-sources', { deps: { [CORE]: '^0.6.0' } });
    const e = spawn(empty);
    report(e.status !== 0 && /no \*\*\/src\/\*\*\/\*\.ts files found/.test(e.stderr),
        `no source to read at all -> refuses to pass vacuously (exit ${e.status})`);
}

// ── 7. sethbacon/azure-pipelines-terraform#1108, finding 2: a version floor
//      that has fallen behind the fleet is inert -- it cannot fire, so the gate
//      is green about nothing. The check
//      must report it, must name WHICH of the three sources to raise, and must
//      NOT report a floor the fleet has not yet passed.
{
    const root = fixture('stale-floor', {
        // Far ahead of every floor, so all of them are inert.
        deps: { [PKG]: '^9.9.9', [CORE]: '^9.9.9' },
        // The data file deliberately stays at the current floors: it is the
        // thing that has fallen behind, and staleFloors() must say so.
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const r = spawn(root);
    let out = {};
    try { out = JSON.parse(r.stdout); } catch { /* left empty on purpose; Array.isArray below catches it */ }
    const stale = Array.isArray(out.staleFloors) ? out.staleFloors : null;
    report(r.status === 1 && stale !== null && stale.length > 0 && stale.every((f) => f.fleet === '9.9.9'),
        `a floor the whole fleet has passed -> reported stale and fails (exit ${r.status}, ${stale ? stale.length : 'no JSON'} stale)`);
    report(stale !== null && stale.some((f) => f.where === 'DELEGATED_NODE_HTTP_SINKS.httpsRequest'),
        'the raw-https floor is covered too, not just the package-delegated table');
    report(stale !== null && stale.length > 0 && stale.every((f) => f.source === DATA_REL),
        `the blame lands on the repo's own data file, which is the one of the three sources it can raise alone (got ${JSON.stringify([...new Set((stale || []).map((f) => f.source))])})`);
}

// ── 8. the same check must stay quiet while the floors still track the fleet.
//      Array.isArray, not `|| []`: a gate that CRASHED has no staleFloors key,
//      and `(undefined || []).length === 0` reports that as clean. This exact
//      case was observed printing OK against a gate whose output would not
//      parse, which is a self-test being green about nothing.
{
    const root = fixture('current-floor', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const out = run(root);
    report(Array.isArray(out.staleFloors) && out.staleFloors.length === 0,
        `floors level with the fleet -> nothing reported (got ${JSON.stringify(out.staleFloors)})`);
}

// ── 9. a task that depends on neither package must not make every floor "stale"
{
    const root = fixture('no-dependency', {
        deps: {},
        sources: { 'handler.ts': 'export const noop = 1;\nconst r = await fetch(url, { ...buildFetchOptions() });\n' },
    });
    const out = run(root);
    report(Array.isArray(out.staleFloors) && out.staleFloors.length === 0,
        `no task declares the packages -> no floor is judged stale (got ${JSON.stringify(out.staleFloors)})`);
}

// ── 10. PHASE A. No repository carries a data file yet, and this canonical copy
//       is what the replay runs against all of them, so "no data file" has to be
//       the ordinary case and has to enforce the estate ratchet on its own.
//       max(since, ESTATE_FLOORS) is exactly the strongest floor any copy of
//       this gate enforces today, so the same manifests get the same verdicts
//       with the file absent as with it present.
{
    const src = { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') };
    const healthy = run(fixture('nodata-ok', { deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE }, sources: src, writeData: false }));
    const sites = healthy.sites.filter((s) => s.sink === 'generateIdToken');
    report(sites.length === 1 && sites[0].verdict === 'PROXIED-BY-PACKAGE' && Array.isArray(healthy.staleFloors) && healthy.staleFloors.length === 0,
        `no data file -> the gate still runs and the fleet-level repo is clean (got ${JSON.stringify(sites.map((s) => s.verdict))})`);

    // The ratchet, with no data file to help it: 0.6.0 is above the sink's
    // `since` (ado 0.5.0), so ONLY ESTATE_FLOORS can refuse it. A case whose
    // verdict survives deleting the term it names is a case that tests nothing.
    const regressed = run(fixture('nodata-ratchet', { deps: { [PKG]: '^0.6.0', [CORE]: CURRENT_CORE }, sources: src, writeData: false }));
    const bad = regressed.sites.filter((s) => s.sink === 'generateIdToken');
    report(bad.length === 1 && bad[0].verdict === 'UNPROXIED',
        `no data file -> the estate ratchet alone still refuses a stale package (got ${JSON.stringify(bad.map((s) => s.verdict))})`);
}

// ── 11. PHASE C, executed now. Once every repository carries a data file the
//       default flips and an absent one is could-not-run -- exit 2, no JSON,
//       never an enumerated zero, which would look exactly like a repository
//       with no outbound calls. Exercised here through the override so the
//       refusal is a path that has actually run before it becomes the default.
{
    const root = fixture('nodata-required', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
        writeData: false,
    });
    const r = spawn(root, { PROXY_PARITY_DATA_OPTIONAL: '0' });
    report(r.status === 2 && !r.stdout.includes('"sites"') && /proxy-parity\.data\.json is missing/.test(r.stderr),
        `data required but absent -> exit 2 and no envelope, so the replay reads could-not-run (exit ${r.status})`);
}

// ── 12. a data file the gate cannot read is could-not-run in every phase: a
//       schema it does not know, or a range where an exact version belongs.
{
    const src = { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') };
    const deps = { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE };
    const bumped = fixture('bad-schema', { deps, sources: src });
    fs.writeFileSync(path.join(bumped, DATA_REL), JSON.stringify({ schemaVersion: 2, repo: 'fixture', floors: {} }, null, 2));
    const schema = spawn(bumped);
    report(schema.status === 2 && /schemaVersion/.test(schema.stderr),
        `a schemaVersion this gate cannot read -> exit 2, not a pass (exit ${schema.status})`);

    const ranged = fixture('range-floor', { deps, sources: src, floors: { [PKG]: '^0.11.0' } });
    const r = spawn(ranged);
    report(r.status === 2 && /only form this gate can compare/.test(r.stderr),
        `a range where an exact x.y.z belongs -> exit 2, not a floor guessed at (exit ${r.status})`);
}

// ── the ACTION's own run body, not just the script it calls ─────────────────
//
// Everything above drives the gate directly, which is the half a consumer never
// executes: what a consumer runs is action.yml's `run:` block, and what two
// task L0 suites will spawn is whatever path that block exported. The estate
// has been bitten twice by suites that PARSE a shell body while every mutation
// of it ran inert, so this follows the osv-scan / footer-guard idiom — extract
// the real block by its `run: |` marker and by indentation, execute it under
// bash with exactly the env the action binds, assert on what it did.

let actionAssertions = 0;
const actionReport = (ok, msg) => { actionAssertions += 1; report(ok, msg); };

function extractRunBlock(yaml) {
    const lines = yaml.split('\n');
    // The block indicator may carry a trailing comment: the shipped step ends
    // `run: | # zizmor: ignore[github-env]`, an inline suppression that has to be
    // on that exact line. Tolerated here rather than matched loosely, so a body
    // that stopped being a literal block scalar is still a miss.
    const start = lines.findIndex((l) => /^\s+run: \|\s*(#.*)?$/.test(l));
    if (start === -1) return null;
    const indent = lines[start].match(/^(\s*)/)[1].length + 2;
    const body = [];
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') { body.push(''); continue; }
        const lead = line.match(/^(\s*)/)[1].length;
        if (lead < indent) break;
        body.push(line.slice(indent));
    }
    return body.join('\n');
}

const RUN_BODY = extractRunBlock(fs.readFileSync(ACTION, 'utf8'));
actionReport(RUN_BODY !== null && RUN_BODY.includes('check-proxy-parity.js'),
    'extracted the gate step from action.yml');

// The action must not splice inputs into the script through ${{ }}: that is a
// template substitution performed before bash parses the line, so a value
// carrying a quote becomes shell. zizmor's template-injection audit is a
// required check here, and a gate step is the last place to model the class it
// exists to refuse.
actionReport(!/\$\{\{/.test(RUN_BODY),
    'the gate body interpolates no ${{ }} expression; inputs arrive through env');

/**
 * Run the extracted step with the env the action binds.
 *
 * `GITHUB_ENV` points at a real file, because the whole point of this action
 * beyond running the gate is the line it writes there: that value is what the
 * consumers' L0 suites will resolve the gate from. It is read back and returned
 * verbatim rather than matched loosely — a trailing separator or a `dirname`
 * would still match a regex and would still be wrong.
 */
function runStep(root, { json = 'false', minSites = '1', actionPath } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-parity-step-'));
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, RUN_BODY);
    const envFile = path.join(dir, 'github_env');
    fs.writeFileSync(envFile, '');
    const r = spawnSync('bash', [script], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            ROOT: root,
            JSON: json,
            MIN_SITES: minSites,
            ACTION_PATH: actionPath !== undefined ? actionPath : ACTION_DIR,
            GITHUB_ENV: envFile,
            RUNNER_TEMP: dir,
        },
    });
    const written = fs.readFileSync(envFile, 'utf8');
    fs.rmSync(dir, { recursive: true, force: true });
    return { status: r.status, stdout: `${r.stdout}${r.stderr}`, env: written };
}

const exported = (written) => {
    const m = /^SHARED_GATE_CHECK_PROXY_PARITY=(.*)$/m.exec(written);
    return m === null ? null : m[1];
};

{
    // A tree the gate passes, with a floor measured from the same tree rather
    // than guessed at.
    const green = fixture('action-green', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const measured = run(green).sites.length;
    actionReport(measured >= 1, `the action fixture enumerates something to floor (${measured} site(s))`);

    const atFloor = runStep(green, { minSites: String(measured) });
    actionReport(atFloor.status === 0, `a floor AT the measured count passes (exit ${atFloor.status})`);
    actionReport(exported(atFloor.env) === ACTION_DIR,
        `the step exports SHARED_GATE_CHECK_PROXY_PARITY=<action path>, verbatim (got ${JSON.stringify(exported(atFloor.env))})`);
    actionReport(atFloor.env === `SHARED_GATE_CHECK_PROXY_PARITY=${ACTION_DIR}\n`,
        'and writes exactly that one line to GITHUB_ENV, with no second line to be parsed wrong');

    // A floor ABOVE the count is the anti-vacuity case this input exists for.
    // It must name BOTH numbers: a message giving only the floor leaves the
    // reader unable to tell a broken walk from a stale number.
    const above = runStep(green, { minSites: String(measured + 1) });
    actionReport(above.status === 1, `a floor above the measured count fails (exit ${above.status})`);
    actionReport(above.stdout.includes(`enumerated ${measured} site(s), below the declared floor of ${measured + 1}`),
        'and the failure names the measured count and the floor, not just one of them');

    // Zero is refused for THIS gate specifically: its --json envelope carries
    // no `scanned` denominator, so a floor of zero cannot separate "looked and
    // found none" from "looked nowhere".
    const zero = runStep(green, { minSites: '0' });
    actionReport(zero.status === 1 && /no 'scanned' denominator/.test(zero.stdout),
        `min-sites: 0 is refused, naming the missing denominator as the reason (exit ${zero.status})`);
    actionReport(zero.env === '' && !/generateIdToken/.test(zero.stdout),
        'and refused BEFORE the gate runs — nothing in GITHUB_ENV, no report emitted');

    const junk = runStep(green, { minSites: '1x' });
    actionReport(junk.status === 1 && /min-sites must be a non-negative integer/.test(junk.stdout),
        `a non-numeric floor is refused rather than compared (exit ${junk.status})`);
    actionReport(junk.env === '', 'and it too is refused before anything is exported');
}

{
    // THE ORDER OF THE TWO RUNS IS LOAD-BEARING. The floor may only ever turn a
    // green into a red; it runs after the verdict, so a real finding aborts
    // before the floor line executes. Proven by giving a FAILING tree an
    // absurd floor and watching the floor's own message never appear.
    const red = fixture('action-verdict-first', {
        deps: { [PKG]: '^0.4.0', [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });
    const r = runStep(red, { minSites: '9999' });
    actionReport(r.status === 1, `a tree with a real finding fails the step (exit ${r.status})`);
    actionReport(!/below the declared floor/.test(r.stdout),
        'and fails on the VERDICT, before the floor line runs — the floor cannot turn a red into anything else');
    actionReport(/UNPROXIED/.test(r.stdout),
        "and the gate's own finding reaches the log rather than being swallowed");
}

{
    // github.action_path is the whole mechanism pinning the implementation to
    // the caller's `uses:` SHA. An action directory that does not carry the
    // gate must say so by name, and must export NOTHING — an exported path to a
    // directory the gate could not start from is worse than no variable at all,
    // because the L0 resolver would find it, believe it, and spawn nothing.
    const green = fixture('action-preflight', {
        deps: { [PKG]: CURRENT_PKG, [CORE]: CURRENT_CORE },
        sources: { 'handler.ts': CALLER(`import { generateIdToken } from '${PKG}';`, 'generateIdToken') },
    });

    const nowhere = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-parity-empty-action-'));
    const absent = runStep(green, { actionPath: nowhere });
    actionReport(absent.status === 1 && /check-proxy-parity\.js is missing from the action/.test(absent.stdout),
        `an action path with no gate fails naming the gate (exit ${absent.status})`);
    actionReport(absent.env === '', 'and exports nothing to GITHUB_ENV');

    // The asset case. `require('./lib/package-delegation.js')` resolves against
    // the SCRIPT, so an action shipped without lib/ dies in module resolution —
    // which node reports as exit 1, the very code this gate uses for a finding.
    // That is why it gets its own preflight and its own message.
    const noLib = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy-parity-action-without-lib-'));
    fs.copyFileSync(SCRIPT, path.join(noLib, 'check-proxy-parity.js'));
    const libless = runStep(green, { actionPath: noLib });
    actionReport(libless.status === 1 && /lib\/package-delegation\.js is missing from the action/.test(libless.stdout),
        `an action shipped without lib/ fails naming the lib, not with a module-resolution trace (exit ${libless.status})`);
    actionReport(libless.env === '', 'and exports nothing to GITHUB_ENV');

    // VERBATIM, against a path that is not this repository's. A real directory,
    // so the preflight passes and the export actually happens, and its absolute
    // path is compared byte for byte: a trailing separator, a `dirname`, a
    // `realpath` or a `cd && pwd` would all still look like a path.
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'proxy parity fake action-'));
    fs.copyFileSync(SCRIPT, path.join(fake, 'check-proxy-parity.js'));
    fs.cpSync(path.join(ACTION_DIR, 'lib'), path.join(fake, 'lib'), { recursive: true });
    const relocated = runStep(green, { actionPath: fake, minSites: '1' });
    actionReport(relocated.status === 0, `the gate runs from a relocated action directory (exit ${relocated.status})`);
    actionReport(exported(relocated.env) === fake,
        `the exported value is the ACTION_PATH it was handed, byte for byte (got ${JSON.stringify(exported(relocated.env))}, wanted ${JSON.stringify(fake)})`);

    for (const dir of [nowhere, noLib, fake]) fs.rmSync(dir, { recursive: true, force: true });
}

{
    // WHY THE EXPORT DOES NO ARITHMETIC, AS A MEASUREMENT RATHER THAN A CLAIM.
    //
    // On windows-2025 github.action_path is a Windows path, and bash still runs
    // the body (Git Bash). This case cannot run the gate from such a path — no
    // such directory exists on this machine, and the preflight would refuse it,
    // which is exactly why the verbatim case above uses a real directory
    // instead. What it CAN do is measure what the two path operations a
    // reviewer might reach for return when handed that string. `dirname` gives
    // `.`, a directory that exists, on one OS only, inside a required check;
    // `${AP%/*}` gives the input back unchanged. Both are silently wrong, and
    // that is the whole reason each composite exports its own directory rather
    // than a parent computed in bash.
    const WINDOWS_ACTION_PATH = 'D:\\a\\_actions\\4cloudguru\\shared-workflows\\abc\\.github\\actions\\check-proxy-parity';
    const probe = spawnSync('bash', ['-c', 'printf "%s\\n%s\\n" "$(dirname "$AP")" "${AP%/*}"'],
        { encoding: 'utf8', env: { ...process.env, AP: WINDOWS_ACTION_PATH } });
    const [dirnameSays, trimSays] = String(probe.stdout).split('\n');
    actionReport(dirnameSays === '.',
        `dirname on a windows-2025 action path returns '.', a directory that exists (got ${JSON.stringify(dirnameSays)})`);
    actionReport(trimSays === WINDOWS_ACTION_PATH,
        '${AP%/*} returns the input unchanged on the same string — neither operation is safe, so the body performs neither');
    actionReport(!/dirname|%\/\*|realpath|basename/.test(RUN_BODY),
        'and the shipped body contains no dirname, no ${…%/*}, no realpath and no basename');
}

// A floor on the action section itself, because a harness that asserted nothing
// would print no failures and exit 0 — the same vacuous green the gate exists
// to make impossible.
const ACTION_ASSERTION_FLOOR = 20;
if (actionAssertions < ACTION_ASSERTION_FLOOR) {
    console.error(`  FAIL harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ncheck-proxy-parity.js self-test: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('\ncheck-proxy-parity.js self-test: all cases passed.');
