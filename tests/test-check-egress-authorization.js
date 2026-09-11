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

const ASSERTION_FLOOR = 21;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL only ${assertions} assertion(s) ran (floor ${ASSERTION_FLOOR}); a case was skipped`);
    failures += 1;
}
if (failures > 0) {
    console.error(`\ncheck-egress-authorization.js self-test: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('\ncheck-egress-authorization.js self-test: all cases passed.');
