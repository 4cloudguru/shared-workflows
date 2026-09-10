#!/usr/bin/env node
'use strict';

// Self-test for tests/gate-identity.py, the byte-identity check between this
// repository's gate composites and security-orchestration's canonical copies.
//
// The script reads its pairs from gatelib in the --signatures directory, so the
// fixture plants a minimal gatelib.py declaring SHARED_ACTIONS,
// SHARED_ACTION_ASSETS and gate_files() with the real module's shape. That
// tests the script's own contract -- identical passes, one byte of drift fails,
// an action shipped without its lib fails, a gate registered ahead of its action
// is skipped, comparing nothing fails, and --advisory turns every failure into a
// warning at exit 0 -- against a map the test controls. Whether the REAL map is
// satisfied is what self-check.yml's blocking step answers on every pull
// request, using the real gatelib and a clone of canonical main.
//
// Every red case is a mutation of the green fixture, so a script that failed
// on everything could not pass here either.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, 'gate-identity.py');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-identity-selftest-'));

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

const GATELIB = [
    'SHARED_ACTIONS = {',
    '    "check-one.js": "check-one",',
    '    "check-two.cjs": "check-two",',
    '}',
    'SHARED_ACTION_ASSETS = {',
    '    "check-one.js": ("lib/helper.js",),',
    '}',
    'def gate_files(gate_filename):',
    '    return (gate_filename,) + tuple(SHARED_ACTION_ASSETS.get(gate_filename, ()))',
    '',
].join('\n');

/** Build a fixture: canonical gates + signatures, and actions carrying the named gates. */
function fixture(name, { actions = ['check-one', 'check-two'], mutate } = {}) {
    const root = path.join(scratch, name);
    const gates = path.join(root, 'gates');
    const signatures = path.join(root, 'signatures');
    const actionsDir = path.join(root, 'actions');
    fs.mkdirSync(path.join(gates, 'lib'), { recursive: true });
    fs.mkdirSync(signatures, { recursive: true });
    fs.mkdirSync(actionsDir, { recursive: true });
    fs.writeFileSync(path.join(signatures, 'gatelib.py'), GATELIB);
    const files = {
        'check-one.js': "console.log('one');\n",
        'lib/helper.js': "module.exports = { helper: () => 1 };\n",
        'check-two.cjs': "console.log('two');\n",
    };
    for (const [rel, body] of Object.entries(files)) fs.writeFileSync(path.join(gates, rel), body);
    if (actions.includes('check-one')) {
        fs.mkdirSync(path.join(actionsDir, 'check-one', 'lib'), { recursive: true });
        fs.writeFileSync(path.join(actionsDir, 'check-one', 'check-one.js'), files['check-one.js']);
        fs.writeFileSync(path.join(actionsDir, 'check-one', 'lib', 'helper.js'), files['lib/helper.js']);
    }
    if (actions.includes('check-two')) {
        fs.mkdirSync(path.join(actionsDir, 'check-two'), { recursive: true });
        fs.writeFileSync(path.join(actionsDir, 'check-two', 'check-two.cjs'), files['check-two.cjs']);
    }
    if (mutate) mutate({ root, gates, signatures, actionsDir });
    return { root, gates, signatures, actionsDir };
}

function run(fx, extra = []) {
    const r = spawnSync('python3', [SCRIPT, '--actions', fx.actionsDir, '--gates', fx.gates, '--signatures', fx.signatures, ...extra], { encoding: 'utf8' });
    return { status: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

// ── green: identical everywhere ─────────────────────────────────────────────
{
    const r = run(fixture('identical'));
    report(r.status === 0, 'identical composites and canonical: exit 0', r.out);
    report(/compared 3 file\(s\) across 2 registered gate\(s\)/.test(r.out), 'the summary counts every file of every registered gate (3 across 2)', r.out);
    report(!/::error::|::warning::/.test(r.out), 'no annotation on a clean comparison', r.out);
}

// ── one byte of drift in a composite ─────────────────────────────────────────
{
    const fx = fixture('drift', { mutate: ({ actionsDir }) => fs.appendFileSync(path.join(actionsDir, 'check-two', 'check-two.cjs'), '// re-worded\n') });
    const r = run(fx);
    report(r.status === 1, 'a composite that differs from canonical by one comment line: exit 1', r.out);
    report(/::error::.*check-two\.cjs differs from/.test(r.out), 'the error names the drifted file', r.out);
    report(/Fix it in security-orchestration's remediation\/gates\/ first/.test(r.out), 'the error says where the fix goes (canonical first)', r.out);
    const adv = run(fx, ['--advisory']);
    report(adv.status === 0, '--advisory: the same drift is exit 0', adv.out);
    report(/::warning::.*check-two\.cjs differs from/.test(adv.out) && !/::error::/.test(adv.out), '--advisory: reported as ::warning::, never ::error::', adv.out);
    report(/advisory mode: findings above are warnings/.test(adv.out), '--advisory says which check is the blocking one', adv.out);
}

// ── drift in the lib that travels with the gate ───────────────────────────────
{
    const fx = fixture('lib-drift', { mutate: ({ actionsDir }) => fs.appendFileSync(path.join(actionsDir, 'check-one', 'lib', 'helper.js'), '\n') });
    const r = run(fx);
    report(r.status === 1 && /lib\/helper\.js differs from/.test(r.out), 'a drifted lib beside an identical entry point is exit 1 and named', r.out);
}

// ── an action shipped without its lib ────────────────────────────────────────
{
    const fx = fixture('incomplete', { mutate: ({ actionsDir }) => fs.rmSync(path.join(actionsDir, 'check-one', 'lib'), { recursive: true }) });
    const r = run(fx);
    report(r.status === 1, 'an action directory missing a file the gate requires: exit 1', r.out);
    report(/::error::a delegated gate is incomplete: .*check-one.*lib\/helper\.js/.test(r.out), 'the error names the action and the missing asset', r.out);
    report(/compared 2 file\(s\)/.test(r.out), 'the other files were still compared (the count is honest)', r.out);
}

// ── a gate registered ahead of its action ────────────────────────────────────
{
    const r = run(fixture('ahead', { actions: ['check-one'] }));
    report(r.status === 0, 'a registered gate whose action does not exist yet is skipped, not failed', r.out);
    report(/skipped: check-two\.cjs is registered for the 'check-two' action, which does not exist here yet/.test(r.out), 'the skip is said out loud and names the gate and action', r.out);
    report(/compared 2 file\(s\)/.test(r.out), 'the present action was still compared', r.out);
}

// ── nothing to compare at all ────────────────────────────────────────────────
{
    const r = run(fixture('nothing', { actions: [] }));
    report(r.status === 1, 'every registered action absent: exit 1, not a pass', r.out);
    report(/::error::no delegated gate file was compared/.test(r.out), 'the error says the check would be enforcing nothing', r.out);
    const adv = run(fixture('nothing-advisory', { actions: [] }), ['--advisory']);
    report(adv.status === 0 && /::warning::no delegated gate file was compared/.test(adv.out), '--advisory: nothing-compared is a warning at exit 0', adv.out);
}

// ── canonical missing a file the action carries ──────────────────────────────
{
    const fx = fixture('canonical-missing', { mutate: ({ gates }) => fs.rmSync(path.join(gates, 'check-two.cjs')) });
    const r = run(fx);
    report(r.status === 1 && /the canonical copy of check-two\.cjs/.test(r.out), 'a composite with no canonical parent is exit 1 and named', r.out);
}

// ── unusable arguments are exit 2, not a pass ────────────────────────────────
{
    const fx = fixture('bad-args');
    const r = spawnSync('python3', [SCRIPT, '--actions', path.join(fx.root, 'no-such-dir'), '--gates', fx.gates, '--signatures', fx.signatures], { encoding: 'utf8' });
    report(r.status === 2, 'a missing --actions directory is exit 2 (could-not-run), not 0', r.stdout + r.stderr);
    const r2 = spawnSync('python3', [SCRIPT, '--actions', fx.actionsDir, '--gates', fx.gates, '--signatures', path.join(fx.root, 'no-gatelib-here')], { encoding: 'utf8' });
    report(r2.status === 2, 'a --signatures directory without gatelib is exit 2', r2.stdout + r2.stderr);
}

// ── the two workflows call the script the way this suite ran it ──────────────
{
    const selfCheck = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'self-check.yml'), 'utf8');
    const replay = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'signature-replay.yml'), 'utf8');
    const blocking = /python3 tests\/gate-identity\.py --actions \.github\/actions --gates "\$RUNNER_TEMP\/security-orchestration\/remediation\/gates" --signatures "\$RUNNER_TEMP\/security-orchestration\/remediation\/signatures"\s*$/m;
    report(blocking.test(selfCheck), 'self-check.yml runs the check BLOCKING (no --advisory) against a clone of canonical main', selfCheck.match(/gate-identity[^\n]*/g));
    const advisory = /python3 suite\/shared-workflows\/tests\/gate-identity\.py --actions suite\/shared-workflows\/\.github\/actions --gates security-orchestration\/remediation\/gates --signatures security-orchestration\/remediation\/signatures --advisory/;
    report(advisory.test(replay), 'signature-replay.yml runs the check ADVISORY in every host', replay.match(/gate-identity[^\n]*/g));
    report(!/gate-identity\.py[^\n]*--advisory/.test(selfCheck), 'self-check.yml never passes --advisory', null);
}

fs.rmSync(scratch, { recursive: true, force: true });

const ASSERTION_FLOOR = 24;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL only ${assertions} assertions ran (floor ${ASSERTION_FLOOR}); a case was skipped`);
    failures += 1;
}
console.log(failures ? `\n${failures} FAILED of ${assertions}` : `\nall ${assertions} passed`);
process.exit(failures ? 1 : 0);
