#!/usr/bin/env node
'use strict';

// Self-test for check-egress-authorization.js -- the first this gate has ever
// had, anywhere. It was hand-copied into three extensions for a year with no
// suite behind any copy, which is how the three drifted into disagreeing about
// the same code without anybody watching a case go red.
//
// WHAT IS DRIVEN HERE. Each case builds a throwaway repository in the layout
// every ADO extension ships (Tasks/<Family>/<Version>/src/*.ts), plants ONE
// shape, and asserts the verdict the gate gives it -- so a case that passes is
// a case somebody has watched decide. The verdicts are the gate's own:
//
//   AUTHORIZED            the enclosing function calls assertEgressHostAllowed,
//                         or hands the decision to a wrapper that does.
//   UNAUTHORIZED          nothing authorizes, and nothing textual either.
//   TEXTUAL-ONLY          a raw classifier (isPrivateOrLinkLocalHost and its
//                         siblings) stands in for the authorizer -- the
//                         half-applied shape, which is a finding, not a pass.
//   EXEMPT-CONSTANT-HOST  the URL is fixed at build time AND the sink takes no
//                         per-hop callback.
//
// THE NARROWING HAS ITS OWN CASE, and it is the reason this suite exists at all.
// A constant host with a redirect-hop authorization callback is NOT exempt: the
// redirect can leave the constant host, so the callback is what decides. Two of
// the three copies of this gate exempted it anyway and would pass exactly the
// shape the gate exists to catch (sethbacon/azure-pipelines-packer#334, the #191
// defect). Delete the `callbackArgs.length === 0` term from the gate and the
// case below goes red.
//
// The vacuity guards are cases too: this gate exits non-zero over a tree with no
// source files and over a tree with no sink, because a green earned by walking
// nothing is the failure mode the whole apparatus refuses.
//
// WHERE A SITE BELONGS is cases 5 to 7: the unit a sink is attributed to is the
// one whose authorization decides it, so a class method, a wrapped signature and
// a parameter list behind a callback type are each read the way the code is
// written, and a unit that takes its authorizer from its callers is held to them.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// Canonical is security-orchestration's remediation/gates/check-egress-authorization.js;
// this file drives the copy the action SHIPS, which is that file byte for byte.
const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'check-egress-authorization');
const GATE = path.join(ACTION_DIR, 'check-egress-authorization.js');

let failures = 0;
let assertions = 0;

function report(ok, message, extra) {
    assertions += 1;
    if (ok) {
        console.log(`  OK   ${message}`);
        return;
    }
    failures += 1;
    console.error(`  FAIL ${message}`);
    if (extra !== undefined) console.error(String(extra).split('\n').map((l) => `       ${l}`).join('\n'));
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-selftest-'));

// THE URL IS BUILT INSIDE EACH FUNCTION, deliberately. A sink handed the
// enclosing function's OWN parameter makes that function a WRAPPER -- the gate
// records the parameter position and moves the decision to its callers, so the
// function itself yields no site and a case asserting one would fail for a
// reason that has nothing to do with what it is testing.
/** A throwaway repository carrying `sources` under one task's src/. */
function fixture(name, sources) {
    const root = path.join(scratch, name);
    const src = path.join(root, 'Tasks', 'Fixture', 'FixtureV1', 'src');
    fs.mkdirSync(src, { recursive: true });
    for (const [file, body] of Object.entries(sources)) {
        fs.writeFileSync(path.join(src, file), body);
    }
    return root;
}

function run(root, { json = true } = {}) {
    const args = json ? [GATE, root, '--json'] : [GATE, root];
    const r = spawnSync(process.execPath, args, { encoding: 'utf8' });
    let body = null;
    const start = r.stdout.indexOf('{');
    if (start >= 0) {
        try { body = JSON.parse(r.stdout.slice(start)); } catch { body = null; }
    }
    return { status: r.status, body, stderr: r.stderr, out: `${r.stdout}${r.stderr}` };
}

const verdictOf = (body, fn) => (body && body.sites || []).filter((s) => s.fn === fn).map((s) => s.verdict);

// ── 1. the authorizer, present and absent ───────────────────────────────────
{
    const authorized = run(fixture('authorized', {
        'dl.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const url = new URL('/packer.zip', mirror).toString();",
            '    await assertEgressHostAllowed(new URL(url).hostname);',
            '    await downloadToFile(url);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(authorized.body, 'pull').join() === 'AUTHORIZED',
        `a sink whose function authorizes the host is AUTHORIZED (got ${JSON.stringify(verdictOf(authorized.body, 'pull'))})`);
    report(authorized.status === 0 && authorized.body.failures === 0,
        `and the gate exits 0 over it (exit ${authorized.status}, failures ${authorized.body && authorized.body.failures})`);

    const bare = run(fixture('unauthorized', {
        'dl.ts': [
            'export async function pull(mirror: string): Promise<void> {',
            "    const url = new URL('/packer.zip', mirror).toString();",
            '    await downloadToFile(url);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(bare.body, 'pull').join() === 'UNAUTHORIZED',
        `the same sink with nothing authorizing is UNAUTHORIZED (got ${JSON.stringify(verdictOf(bare.body, 'pull'))})`);
    report(bare.status === 1 && bare.body.failures === 1,
        `and the gate FAILS on it (exit ${bare.status}, failures ${bare.body && bare.body.failures})`);
}

// ── 2. the half-applied shape: a classifier standing in for the authorizer ──
{
    const textual = run(fixture('textual-only', {
        'dl.ts': [
            "import { isPrivateOrLinkLocalHost } from './registry-allowlist';",
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const url = new URL('/packer.zip', mirror).toString();",
            "    if (isPrivateOrLinkLocalHost(new URL(url).hostname)) throw new Error('no');",
            '    await downloadToFile(url);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(textual.body, 'pull').join() === 'TEXTUAL-ONLY',
        `a raw classifier instead of the authorizer is TEXTUAL-ONLY, not AUTHORIZED (got ${JSON.stringify(verdictOf(textual.body, 'pull'))})`);
    report(textual.status === 1,
        `and it FAILS the gate, because a textual check is not an authorization (exit ${textual.status})`);
}

// ── 3. the constant-host exemption, and the narrowing that bounds it ────────
{
    const constant = run(fixture('constant-host', {
        'dl.ts': [
            'export async function pull(version: string): Promise<void> {',
            '    await downloadToFile(`https://releases.hashicorp.com/packer/${version}/packer.zip`);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(constant.body, 'pull').join() === 'EXEMPT-CONSTANT-HOST',
        `a URL fixed at build time, with no per-hop callback, is exempt (got ${JSON.stringify(verdictOf(constant.body, 'pull'))})`);
    report(constant.status === 0, `and the gate exits 0 over it (exit ${constant.status})`);

    // THE CASE THIS SUITE EXISTS FOR. Same constant host, but the sink takes a
    // redirect-hop callback that does NOT authorize. A redirect can leave the
    // constant host, so the initial URL proves nothing and the callback decides.
    const redirecting = run(fixture('constant-host-with-callback', {
        'dl.ts': [
            'export async function pull(version: string): Promise<void> {',
            '    await downloadToFile(',
            '        `https://releases.hashicorp.com/packer/${version}/packer.zip`,',
            "        (hop: string) => { if (hop.startsWith('http://')) throw new Error('no'); },",
            '    );',
            '}',
            '',
        ].join('\n'),
    }));
    const v = verdictOf(redirecting.body, 'pull');
    report(!v.includes('EXEMPT-CONSTANT-HOST'),
        `a constant host whose redirect callback does not authorize is NOT exempted (got ${JSON.stringify(v)})`);
    report(redirecting.status === 1 && redirecting.body.failures >= 1,
        `and it FAILS the gate (exit ${redirecting.status}, failures ${redirecting.body && redirecting.body.failures})`);

    // ...and the callback that DOES authorize passes, so the case above is
    // about the authorization and not merely about having a callback.
    const guarded = run(fixture('constant-host-callback-authorizes', {
        'dl.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export async function pull(version: string): Promise<void> {',
            '    await downloadToFile(',
            '        `https://releases.hashicorp.com/packer/${version}/packer.zip`,',
            '        async (hop: string) => { await assertEgressHostAllowed(hop); },',
            '    );',
            '}',
            '',
        ].join('\n'),
    }));
    report(guarded.status === 0 && !verdictOf(guarded.body, 'pull').includes('UNAUTHORIZED'),
        `the same shape whose callback DOES authorize passes (exit ${guarded.status}, ${JSON.stringify(verdictOf(guarded.body, 'pull'))})`);
}

// ── 4. vacuity: a green earned by walking nothing is refused ────────────────
{
    const noSources = fixture('no-sources', {});
    fs.rmSync(path.join(noSources, 'Tasks'), { recursive: true, force: true });
    fs.mkdirSync(path.join(noSources, 'Tasks'), { recursive: true });
    const empty = run(noSources, { json: false });
    report(empty.status !== 0 && /pass vacuously/.test(empty.out),
        `a tree with no src TypeScript refuses to pass (exit ${empty.status})`);

    const noSinks = run(fixture('no-sinks', { 'util.ts': 'export const add = (a: number, b: number) => a + b;\n' }), { json: false });
    report(noSinks.status !== 0 && /pass vacuously/.test(noSinks.out),
        `a tree with source but no outbound sink refuses to pass (exit ${noSinks.status})`);
}

// ── 5. a site's `fn` is the unit that CONTAINS it ───────────────────────────
//
// A block was named after the nearest `function` or `const` declared within
// 2000 characters above its `{`, and `class` was not a declaration. So a class
// body either had no name and was skipped, sinks and all, or borrowed one: the
// `const url` inside the function above it, or a module constant. Each check
// here was watched failing against that gate, except the three marked sites
// it already named -- `authorized`, `wrapped`, `generic` -- which are guards.
{
    // The class comes FIRST: nothing above it to borrow, so the whole class was
    // skipped and one authorized function made the tree pass.
    const first = run(fixture('class-first', {
        'dl.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export class Mirror {',
            '    async fetch(mirror: string): Promise<void> {',
            "        const url = new URL('/tool.zip', mirror).toString();",
            '        await downloadToFile(url);',
            '    }',
            '}',
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const url = new URL('/pkg.zip', mirror).toString();",
            '    await assertEgressHostAllowed(new URL(url).hostname);',
            '    await downloadToFile(url);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(first.body, 'fetch').join() === 'UNAUTHORIZED' && first.status === 1,
        `an unauthorized download in a class method is a site, named after the method, and fails the gate (got ${JSON.stringify(verdictOf(first.body, 'fetch'))}, exit ${first.status})`);

    const constant = run(fixture('class-under-a-const', {
        'dl.ts': [
            'const TIMEOUT_MS = 30000;',
            'export class Puller {',
            '    async pull(mirror: string): Promise<void> {',
            "        const url = new URL('/pkg.zip', mirror).toString();",
            '        await downloadToFile(url);',
            '    }',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(constant.body, 'pull').join() === 'UNAUTHORIZED' && verdictOf(constant.body, 'TIMEOUT_MS').length === 0,
        `a class under a module constant does not borrow the constant's name (pull: ${JSON.stringify(verdictOf(constant.body, 'pull'))}, TIMEOUT_MS: ${JSON.stringify(verdictOf(constant.body, 'TIMEOUT_MS'))})`);

    // Each sink carries the unit it must be reported under. `authorized` comes
    // first, so the class after it used to borrow `url` from inside it; the
    // interface's signature, named like a sink, used to be one.
    const sources = {
        'shapes.ts': `import { assertEgressHostAllowed } from './guards';

export async function authorized(mirror: string): Promise<void> {
    const url = new URL('/a.zip', mirror).toString();
    await assertEgressHostAllowed(new URL(url).hostname);
    await downloadToFile(url); // expect authorized AUTHORIZED
}

export class After {
    private readonly retries = 3;

    constructor(private readonly mirror: string) {}

    async pull(): Promise<void> {
        const url = new URL('/b.zip', this.mirror).toString();
        await downloadToFile(url); // expect pull UNAUTHORIZED
    }

    get manifest(): Promise<unknown> {
        return fetchJson(new URL('/index.json', this.mirror).toString()); // expect manifest UNAUTHORIZED
    }
}

export interface Transport {
    fetchJson(url: string): Promise<unknown>;
}

export async function wrapped(
    mirror: string,
    name: string,
): Promise<void> {
    const url = new URL(name, mirror).toString();
    await downloadToFile(url); // expect wrapped UNAUTHORIZED
}

export const generic = <K, V>(mirror: K, name: V): Promise<void> => {
    return downloadToFile(new URL(String(name), String(mirror)).toString()); // expect generic UNAUTHORIZED
};
`,
    };
    const out = run(fixture('enclosing-unit', sources));
    const expected = Object.entries(sources).flatMap(([file, body]) => body.split('\n')
        .map((text, i) => ({ file, line: i + 1, want: /\/\/ expect (\S+) (\S+)/.exec(text) }))
        .filter((e) => e.want !== null));
    const sites = (out.body && out.body.sites) || [];
    for (const e of expected) {
        const site = sites.find((s) => s.rel.endsWith(`/src/${e.file}`) && s.line === e.line);
        report(site !== undefined && site.fn === e.want[1] && site.verdict === e.want[2],
            `${e.file}:${e.line} is ${e.want[1]} ${e.want[2]} (got ${site === undefined ? 'no site at that line' : `${site.fn} ${site.verdict}`})`);
    }
    report(expected.length === 5 && sites.length === expected.length,
        `and the tree enumerates exactly its ${expected.length} marked sites -- the interface signature is none of them (got ${sites.length})`);
}

// ── 6. a parameter list is read by a balanced scan ──────────────────────────
//
// Read as `[^)]*` and split at every comma, a list stopped at a callback type's
// first `)` and split inside `Map<K, V>`. A wrapper's URL then sat at the wrong
// POSITION, and the position is what its callers are verdicted by.
{
    // `url` read as the third parameter: the caller's constant fallback was
    // judged in place of its attacker-reachable URL, and the tree passed.
    const shifted = run(fixture('generic-before-url', {
        'dl.ts': [
            'export async function fetchWith(headers: Map<string, string>, url: string, fallback: string): Promise<void> {',
            '    await downloadToFile(url);',
            '}',
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const target = new URL('/pkg.zip', mirror).toString();",
            "    await fetchWith(new Map(), target, 'https://releases.example.com/pkg.zip');",
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(shifted.body, 'pull').join() === 'UNAUTHORIZED' && shifted.status === 1,
        `a URL behind a Map<K, V> parameter is judged, not the constant after it (got ${JSON.stringify(verdictOf(shifted.body, 'pull'))}, exit ${shifted.status})`);

    // `url` lost after a callback-typed parameter: fetchVia was not seen to be a
    // wrapper and failed on its own, while the caller that authorizes the host
    // was never looked at. (The callback is passed by name: an arrow written
    // into a sink's arguments is read as its per-hop callback, case 3.)
    const callback = run(fixture('callback-before-url', {
        'dl.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'function quiet(received: number): void {',
            '    void received;',
            '}',
            '',
            'export async function fetchVia(onProgress: (received: number) => void, url: string): Promise<void> {',
            '    await downloadToFile(url);',
            '}',
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const target = new URL('/pkg.zip', mirror).toString();",
            '    await assertEgressHostAllowed(new URL(target).hostname);',
            '    await fetchVia(quiet, target);',
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(callback.body, 'pull').join() === 'AUTHORIZED' && verdictOf(callback.body, 'fetchVia').length === 0
        && callback.status === 0,
        `a wrapper whose URL follows a callback-typed parameter delegates to its caller (pull: ${JSON.stringify(verdictOf(callback.body, 'pull'))}, fetchVia: ${JSON.stringify(verdictOf(callback.body, 'fetchVia'))}, exit ${callback.status})`);

    // The helper a URL is built by is looked up the same way.
    const helper = run(fixture('helper-with-callback', {
        'dl.ts': [
            'function newest(versions: string[]): string {',
            '    return versions[0];',
            '}',
            '',
            'function releaseUrl(pick: (versions: string[]) => string, opts: { channel?: string }): string {',
            '    return `https://releases.example.com/${pick([])}/${opts.channel}/tool.zip`;',
            '}',
            '',
            'export async function install(): Promise<void> {',
            "    await downloadToFile(releaseUrl(newest, { channel: 'stable' }));",
            '}',
            '',
        ].join('\n'),
    }));
    report(verdictOf(helper.body, 'install').join() === 'EXEMPT-CONSTANT-HOST' && helper.status === 0,
        `a constant host built by a helper with a callback-typed parameter is resolved (got ${JSON.stringify(verdictOf(helper.body, 'install'))}, exit ${helper.status})`);
}

// ── 7. an injected authorizer binds every unit that declares one ────────────
//
// A unit that authorizes by awaiting an authorizer its caller passes is only
// authorized if every caller passes the real one. The callers were found by
// reading the name off `function x(` alone: a `const` arrow or a class method
// could declare the parameter, be handed a no-op, and still read as AUTHORIZED.
{
    const out = run(fixture('injected-authorizer', {
        'registry.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export class Registry {',
            '    async resolve(mirror: string, authorize: (hostname: string) => Promise<void>): Promise<void> {',
            "        const url = new URL('/index.json', mirror).toString();",
            '        await authorize(new URL(url).hostname);',
            '        await downloadToFile(url);',
            '    }',
            '',
            '    async latest(mirror: string): Promise<void> {',
            '        await this.resolve(mirror, async () => undefined);',
            '    }',
            '',
            '    async checked(mirror: string): Promise<void> {',
            '        await this.resolve(mirror, (host) => assertEgressHostAllowed(host));',
            '    }',
            '}',
            '',
            'export interface Resolver {',
            '    resolve(mirror: string, authorize: (hostname: string) => Promise<void>): Promise<void>;',
            '}',
            '',
        ].join('\n'),
        'resolve-from.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export const resolveFrom = async (mirror: string, authorize: (hostname: string) => Promise<void>): Promise<void> => {',
            "    const url = new URL('/index.json', mirror).toString();",
            '    await authorize(new URL(url).hostname);',
            '    await downloadToFile(url);',
            '};',
            '',
            'export async function useConst(mirror: string): Promise<void> {',
            '    await resolveFrom(mirror, async () => undefined);',
            '}',
            '',
            'export async function useConstChecked(mirror: string): Promise<void> {',
            '    await resolveFrom(mirror, (host) => assertEgressHostAllowed(host));',
            '}',
            '',
        ].join('\n'),
    }));
    const refused = ((out.body && out.body.suspects) || []).map((s) => s.replace(/^.*\/src\//, '').replace(/ requires.*$/, '')).sort();
    report(verdictOf(out.body, 'resolve').join() === 'AUTHORIZED' && verdictOf(out.body, 'resolveFrom').join() === 'AUTHORIZED',
        `a method and a const that await an injected authorizer are AUTHORIZED at their own sinks (resolve: ${JSON.stringify(verdictOf(out.body, 'resolve'))}, resolveFrom: ${JSON.stringify(verdictOf(out.body, 'resolveFrom'))})`);
    report(refused.join() === 'registry.ts:11: resolve(),resolve-from.ts:10: resolveFrom()' && out.status === 1,
        `so the two callers that hand them a no-op are refused -- and neither the callers that pass the real one, nor the method's own declaration, nor the interface signature is (got ${JSON.stringify(refused)}, exit ${out.status})`);
}

fs.rmSync(scratch, { recursive: true, force: true });

// ── the ACTION's own run: body, not only the script it calls ────────────────
//
// What a consumer runs is action.yml's `run:` block; a wrapper that swallowed
// the gate's exit code, or wrote the wrong thing to $GITHUB_ENV, would leave
// every case above green while the consumer's check never went red. The block
// is extracted from the manifest and executed, the way every sibling suite
// here does it.
{
    const ACTION = path.join(ACTION_DIR, 'action.yml');
    const yaml = fs.readFileSync(ACTION, 'utf8');

    const lines = yaml.split('\n');
    const start = lines.findIndex((l) => /^\s+run: \|/.test(l));
    report(start >= 0, 'the gate step is extractable from action.yml');
    const indent = lines[start + 1].match(/^\s*/)[0].length;
    const body = [];
    for (let i = start + 1; i < lines.length; i += 1) {
        if (lines[i].trim() !== '' && lines[i].match(/^\s*/)[0].length < indent) break;
        body.push(lines[i].slice(indent));
    }
    const RUN_BODY = body.join('\n');
    report(/check-egress-authorization\.js/.test(RUN_BODY), 'and the extracted block runs the gate');

    // Inputs must reach the body through env only: an expression spliced into a
    // run: body is substituted before bash sees it, which is the template
    // injection class this estate refuses.
    report(!/\$\{\{/.test(RUN_BODY), 'the body interpolates no ${{ }} expression; inputs arrive through env');

    const clean = fixture('action-clean', {
        'dl.ts': [
            "import { assertEgressHostAllowed } from './guards';",
            '',
            'export async function pull(mirror: string): Promise<void> {',
            "    const url = new URL('/packer.zip', mirror).toString();",
            '    await assertEgressHostAllowed(new URL(url).hostname);',
            '    await downloadToFile(url);',
            '}',
            '',
        ].join('\n'),
    });

    function runStep({ root = clean, floor = '1', actionPath = ACTION_DIR } = {}) {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-step-'));
        const script = path.join(dir, 'step.sh');
        fs.writeFileSync(script, RUN_BODY);
        const ghEnv = path.join(dir, 'github_env');
        fs.writeFileSync(ghEnv, 'PRE_EXISTING_FROM_AN_EARLIER_STEP=kept\n');
        const r = spawnSync('bash', [script], {
            cwd: dir,
            encoding: 'utf8',
            env: {
                ...process.env,
                ROOT: root,
                JSON: 'false',
                MIN_SITES: floor,
                ACTION_PATH: actionPath,
                GITHUB_ENV: ghEnv,
                RUNNER_TEMP: dir,
            },
        });
        const written = fs.readFileSync(ghEnv, 'utf8');
        fs.rmSync(dir, { recursive: true, force: true });
        return { status: r.status, out: `${r.stdout}${r.stderr}`, written };
    }

    const ok = runStep({ floor: '1' });
    report(ok.status === 0 && /floor met/.test(ok.out), `the step passes over a clean tree (exit ${ok.status})`);

    const exported = /^SHARED_GATE_CHECK_EGRESS_AUTHORIZATION=(.*)$/m.exec(ok.written);
    report(exported !== null && exported[1] === ACTION_DIR,
        `and exports its own action path VERBATIM (${exported && exported[1]})`);
    report(/PRE_EXISTING_FROM_AN_EARLIER_STEP=kept/.test(ok.written),
        'appending rather than truncating, so an earlier step\'s exports survive');

    const high = runStep({ floor: '99' });
    report(high.status === 1 && /below the declared floor/.test(high.out),
        `a floor above the count fails, naming both numbers (exit ${high.status})`);

    const absent = runStep({ floor: '' });
    report(absent.status === 1 && /must be a non-negative integer/.test(absent.out),
        'an omitted floor is refused: GitHub does not enforce required: true on an action input');
    report(!/SHARED_GATE_CHECK_EGRESS_AUTHORIZATION/.test(absent.written),
        'and a refused run exports nothing');

    const missing = runStep({ actionPath: path.join(clean, 'nowhere') });
    report(missing.status === 1 && /is missing from the action/.test(missing.out),
        'a gate missing from the action path fails with an error naming it');
}

const ASSERTION_FLOOR = 36;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL only ${assertions} assertion(s) ran (floor ${ASSERTION_FLOOR}); a case was skipped`);
    failures += 1;
}
if (failures > 0) {
    console.error(`\ncheck-egress-authorization.js self-test: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('\ncheck-egress-authorization.js self-test: all cases passed.');
