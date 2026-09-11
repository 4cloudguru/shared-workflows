#!/usr/bin/env node
'use strict';

// Self-test for .github/actions/check-shared-module-pins.
//
// Ported from `scripts/test-check-shared-module-pins.js` in the three ADO
// extensions (azure-pipelines-terraform, azure-pipelines-packer,
// azure-pipelines-release-docs), which carried byte-identical copies of it
// beside byte-identical copies of the gate. Every case below is one of theirs;
// what changed is the file it drives — the REAL script at
// .github/actions/check-shared-module-pins/check-shared-module-pins.js, which
// is the same file every consumer's pinned SHA resolves to, so a regression
// here is a regression in all three at once.
//
// It runs the gate as a SUBPROCESS rather than requiring it, because the exit
// code is half of what is under test: this gate answers 0 / 1, and a caller
// reads the code, not the text. A suite that imported the module would assert
// on findings while the thing the workflow actually consumes went unchecked.
//
// A gate whose thresholds silently stop matching reality is the failure mode
// sethbacon/azure-pipelines-terraform#1108 finding 2 describes for
// check-proxy-parity.js — green over three resolved versions of one shared
// package — so the fixtures below break each invariant in turn and watch it go
// red, rather than only watching a clean tree pass.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const GATE = path.join(
    __dirname,
    '..',
    '.github',
    'actions',
    'check-shared-module-pins',
    'check-shared-module-pins.js',
);
const CORE = '@4cloudguru/pipeline-task-core';

let failures = 0;
let assertions = 0;
const report = (ok, message) => {
    assertions += 1;
    if (ok) {
        console.log(`  OK   ${message}`);
    } else {
        console.error(`  FAIL ${message}`);
        failures += 1;
    }
};

/**
 * One Tasks/<Family>/<Task> declaring `range` and locking `locked`.
 *
 * `nested` writes a SECOND copy of the package under another shared package's
 * node_modules, which is the shape a range mismatch between two shared packages
 * takes on disk — and the shape that decides which copy the delegated code
 * actually runs.
 */
function writeTask(root, family, task, range, locked, nested) {
    const dir = path.join(root, 'Tasks', family, task);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: task.toLowerCase(), dependencies: { [CORE]: range } }),
    );
    const packages = {
        '': { dependencies: { [CORE]: range } },
        [`node_modules/${CORE}`]: { version: locked },
    };
    if (nested) {
        packages[`node_modules/@4cloudguru/pipeline-task-ado/node_modules/${CORE}`] = { version: nested };
    }
    fs.writeFileSync(
        path.join(dir, 'package-lock.json'),
        JSON.stringify({ lockfileVersion: 3, packages }),
    );
}

function run(root) {
    try {
        const stdout = execFileSync(process.execPath, [GATE, root, '--json'], { encoding: 'utf8' });
        return { code: 0, body: JSON.parse(stdout) };
    } catch (err) {
        return { code: err.status, body: JSON.parse(err.stdout) };
    }
}

function fixture(build) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-selftest-'));
    try {
        build(root);
        return run(root);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

// The script has to actually be at the path the action invokes. Asserted first,
// because every case below would otherwise fail with a node module-resolution
// error that reads like a gate defect.
report(fs.existsSync(GATE), 'the gate is where the action invokes it from');

// ── lockstep holds ──────────────────────────────────────────────────────────
{
    const { code, body } = fixture((root) => {
        writeTask(root, 'A', 'AV1', '^0.9.0', '0.9.0');
        writeTask(root, 'B', 'BV1', '^0.9.0', '0.9.0');
    });
    report(code === 0, 'two tasks on one version pass');
    report(body.findings.length === 0, 'a clean tree reports no findings');
    report(body.enumerated.length === 2 && body.scanned === 2,
        'a clean tree still says what it enumerated — exit 0 over nothing is not a pass');
}

// ── each invariant, broken in turn, reported against the drifting task ONLY ──
//
// The "only" half is the part worth having. A gate that failed the whole tree
// would be red for a real defect and useless for locating it, and the ledger
// records a SITE, so a site that names the wrong task is a site nobody can
// adjudicate.
for (const [label, args] of [
    ['range', ['^0.8.0', '0.9.0']],
    ['locked version', ['^0.9.0', '0.8.1']],
    ['nested copy', ['^0.9.0', '0.9.0', '0.7.2']],
]) {
    const { code, body } = fixture((root) => {
        writeTask(root, 'A', 'AV1', '^0.9.0', '0.9.0');
        writeTask(root, 'B', 'BV1', ...args);
    });
    const sites = [...new Set(body.findings.map((f) => f.site))];
    report(code === 1, `${label} drift fails the gate`);
    report(sites.length === 1 && sites[0] === `Tasks/B/BV1:pin:${CORE}`,
        `${label} drift names the drifting task, and only it`);
}

// ── a task with no shared dependency is not a site ──────────────────────────
//
// And a repository with none enumerates nothing while still reporting how many
// manifests it read. A denominator is what separates "looked and found nothing"
// from "looked nowhere", which are the same exit code.
{
    const { code, body } = fixture((root) => {
        const dir = path.join(root, 'Tasks', 'A', 'AV1');
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(
            path.join(dir, 'package.json'),
            JSON.stringify({ name: 'a', dependencies: { 'left-pad': '^1.0.0' } }),
        );
    });
    report(code === 0, 'a task depending on nothing shared is not a site');
    report(body.enumerated.length === 0 && body.scanned === 1,
        'an empty universe carries a denominator (0 pins over 1 manifest)');
}

// ── a repository with no Tasks/ tree at all ─────────────────────────────────
//
// Which is what this gate meets in azure-pipelines-release-docs today, and what
// it meets if a caller points it at a repository that is not an extension. It
// must pass and say the universe was empty, never fail.
{
    const { code, body } = fixture(() => {});
    report(code === 0 && body.scanned === 0 && body.enumerated.length === 0,
        'a repository with no Tasks/ tree passes with a zero denominator');
}

// ── the action passes a root, and the root is what gets read ────────────────
//
// The gate falls back to its OWN parent directory when handed nothing, which
// inside a composite action is `.github/actions` — it would walk this
// repository instead of the caller's and report a clean tree every time. That
// is why the action's `root` input defaults to `.` rather than to nothing, and
// this is the case that would notice if the argument stopped arriving.
{
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-selftest-root-'));
    try {
        writeTask(root, 'A', 'AV1', '^0.9.0', '0.9.0');
        writeTask(root, 'B', 'BV1', '^0.9.0', '0.8.1');
        const here = run('.');
        report(here.code === 0 && here.body.scanned === 0,
            'pointed at this repository the gate finds no tasks — so a root that fails to arrive cannot look like a pass over a drifting tree');
        const there = run(root);
        report(there.code === 1 && there.body.scanned === 2,
            'pointed at the fixture it reads the fixture: the positional root is load-bearing');
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

// ── the ACTION's own run body, not just the script it calls ─────────────────
//
// Everything above drives the gate directly, which is the half a consumer never
// executes: what a consumer runs is action.yml's `run:` block. The estate has
// been bitten twice by suites that PARSE a shell body while every mutation of
// it ran inert, so this follows the osv-scan idiom — extract the real block by
// its `run: |` marker and by indentation, execute it, assert on what it did.
// A test carrying its own copy of the script passes while the real one rots.

const ACTION = path.join(
    __dirname,
    '..',
    '.github',
    'actions',
    'check-shared-module-pins',
    'action.yml',
);

function extractRunBlock(yaml) {
    const lines = yaml.split('\n');
    const start = lines.findIndex((l) => /^\s+run: \|\s*$/.test(l));
    if (start === -1) return null;
    const indent = lines[start].match(/^(\s*)/)[1].length + 2;
    const body = [];
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') {
            body.push('');
            continue;
        }
        const lead = line.match(/^(\s*)/)[1].length;
        if (lead < indent) break;
        body.push(line.slice(indent));
    }
    return body.join('\n');
}

const RUN_BODY = extractRunBlock(fs.readFileSync(ACTION, 'utf8'));
report(RUN_BODY !== null && RUN_BODY.includes('check-shared-module-pins.js'),
    'extracted the gate step from action.yml');

// The action must not splice inputs into the script through ${{ }}. That is a
// template substitution performed before bash parses the line, so a value
// carrying a quote becomes shell — zizmor's template-injection audit, and a
// required check on this repository. Asserted on the body, because it is the
// one property a reviewer cannot see by reading the run block alone: the
// interpolation would look like an ordinary variable.
report(!/\$\{\{/.test(RUN_BODY),
    'the gate body interpolates no ${{ }} expression; inputs arrive through env');

/** Run the extracted step with the env the action binds, and report its status. */
function runStep(root, { json = 'false', actionPath, floor = '1' } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-step-'));
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, RUN_BODY);
    const r = require('child_process').spawnSync('bash', [script], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            ROOT: root,
            JSON: json,
            MIN_SCANNED: floor,
            // The floor writes its machine report here. A runner always sets it;
            // the harness must too, or `set -u` fails the body before the gate runs.
            RUNNER_TEMP: dir,
            ACTION_PATH: actionPath !== undefined ? actionPath : path.dirname(GATE),
        },
    });
    fs.rmSync(dir, { recursive: true, force: true });
    return { status: r.status, stdout: `${r.stdout}${r.stderr}` };
}

{
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-step-fixture-'));
    try {
        writeTask(root, 'A', 'AV1', '^0.9.0', '0.9.0');
        writeTask(root, 'B', 'BV1', '^0.9.0', '0.9.0');
        report(runStep(root).status === 0, 'the action step succeeds on a tree in lockstep');

        // The exit code has to PROPAGATE. A `|| true`, a pipe or a `set +e`
        // anywhere in that body turns a red gate green, and a filter on the end
        // of a command replaces its exit code outright.
        writeTask(root, 'B', 'BV1', '^0.9.0', '0.8.1');
        const drifted = runStep(root);
        report(drifted.status === 1, "the gate's exit 1 propagates out of the action step");
        report(/BV1:pin/.test(drifted.stdout), 'the step surfaces the finding rather than swallowing it');

        const asJson = runStep(root, { json: 'true' });
        report(asJson.status === 1 && /"findings"/.test(asJson.stdout),
            'json=true appends --json and does not change the verdict');
        report(runStep(root, { json: 'false' }).stdout.includes('shared-module pin(s) out of lockstep'),
            'json=false leaves the human report in place');

        // A root with a space must stay ONE argument.
        const spaced = path.join(root, 'a dir');
        fs.mkdirSync(spaced, { recursive: true });
        writeTask(spaced, 'A', 'AV1', '^0.9.0', '0.9.0');
        report(runStep(spaced).status === 0, 'a root containing a space survives as one argument');

        // A missing script must say so rather than surfacing as a node stack
        // trace, because github.action_path is the whole mechanism pinning the
        // implementation to the caller's `uses:` SHA.
        const absent = runStep(root, { actionPath: path.join(root, 'nowhere') });
        report(absent.status !== 0 && /is missing from the action/.test(absent.stdout),
            'a script missing from the action path fails with an error naming it');
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
}

// A floor, because a harness that asserted nothing would print no failures and
// exit 0 — the same vacuous green this gate exists to make impossible.
const ASSERTION_FLOOR = 20;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
}

// ── the required anti-vacuity floor (4cloudguru/shared-workflows#75) ────────
//
// This gate exits 0 over a repository it enumerated nothing in, so the caller
// declares what it measured and the step refuses a count below it. The floor
// runs AFTER the gate's own verdict, so it can only ever turn a green into a
// red. Driven from every direction that would leave it useless: absent, zero,
// non-numeric, one above the count, and exactly at it.
{
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-floor-'));
    writeTask(root, 'A', 'AV1', '^0.9.0', '0.9.0');
    writeTask(root, 'B', 'BV1', '^0.9.0', '0.9.0');
    const measured = JSON.parse(require('child_process')
        .spawnSync(process.execPath, [GATE, root, '--json'], { encoding: 'utf8' }).stdout).scanned;
    const atFloor = runStep(root, { floor: String(measured) });
    report(atFloor.status === 0 && /floor met/.test(atFloor.stdout),
        `a floor at the measured count passes and says so (exit ${atFloor.status})`);

    const above = runStep(root, { floor: String(measured + 1) });
    report(above.status === 1 && /below the declared floor/.test(above.stdout),
        `a floor one above the count fails, naming both numbers (exit ${above.status})`);

    const absent = runStep(root, { floor: '' });
    report(absent.status === 1 && /must be a non-negative integer/.test(absent.stdout),
        'an omitted floor is refused -- GitHub does not enforce `required: true` on an action input');

    const zero = runStep(root, { floor: '0' });
    report(zero.status === 1 && /cannot tell/.test(zero.stdout),
        'a floor of zero is refused: it cannot tell "checked everything" from "checked nothing"');

    const junk = runStep(root, { floor: 'lots' });
    report(junk.status === 1 && /must be a non-negative integer/.test(junk.stdout),
        'a non-numeric floor is refused rather than compared');
    fs.rmSync(root, { recursive: true, force: true });
}

if (failures > 0) {
    console.error(`\ntest-check-shared-module-pins: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-check-shared-module-pins: all cases pass.');
