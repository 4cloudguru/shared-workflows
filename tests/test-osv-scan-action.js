// Self-test for .github/actions/osv-scan.
//
// EXECUTES the action's own run body, extracted from action.yml, against a
// stubbed `docker` that exits with whatever code the case wants. The estate has
// been bitten twice by suites that PARSE a shell body while every mutation of it
// runs inert, so this follows the release-pr-guard idiom: extract the real
// block, put a stub first on PATH, run it, and assert on outputs.
//
// The property under test is the one terraform-registry-backend#894 is about:
// exit 0, exit 1 and exit 127 must reach the caller as three different answers.
// `continue-on-error` collapses the last two into one `outcome`, and the numeric
// code appears nowhere in the REST or GraphQL jobs API, so a scanner that
// stopped working produced the same run record as a clean one.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ACTION = path.join(__dirname, '..', '.github', 'actions', 'osv-scan', 'action.yml');

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
 * Pull the `run:` body out of the action's single step.
 *
 * Deliberately not a YAML parse into a library this repository does not
 * otherwise depend on: the block is found by its `run: |` marker and read by
 * indentation, the same way tests/test-release-pr-closing-keywords.js extracts
 * the composite action's four bodies. A test carrying its own copy of the
 * script passes while the real one rots, which is the failure this avoids.
 */
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

const yaml = fs.readFileSync(ACTION, 'utf8');
const RUN_BODY = extractRunBlock(yaml);
report(RUN_BODY !== null && RUN_BODY.includes('docker run'), 'extracted the scan step from action.yml');

// The action must not splice inputs into the script through ${{ }}. That is a
// template substitution performed before bash parses the line, so a value
// carrying a quote becomes shell. Asserted on the body, because this is the one
// property a reviewer cannot see by reading the run block alone — the
// interpolation would look like an ordinary variable.
report(
    !/\$\{\{/.test(RUN_BODY),
    'the scan body interpolates no ${{ }} expression; inputs arrive through env',
);

const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'osv-scan-selftest-'));

/**
 * Run the extracted body with a stubbed `docker` that exits with `code`.
 *
 * Returns the step's own exit status plus the outputs and annotations it wrote,
 * which is exactly what a calling workflow sees.
 */
function runScan(code, { failOnError = 'true', scanArgs = '--recursive\n./' } = {}) {
    const dir = fs.mkdtempSync(path.join(workRoot, 'case-'));
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const argLog = path.join(dir, 'docker-args.txt');
    // A NUL-separated log, because the whole point of the last argument is that
    // it CONTAINS newlines: a newline-separated log cannot tell one argument
    // holding "--recursive\n./" from two arguments, which is exactly the
    // property these cases exist to check.
    fs.writeFileSync(
        path.join(bin, 'docker'),
        `#!/bin/sh\nprintf '%s\\0' "$@" > "${argLog}"\nexit ${code}\n`,
        { mode: 0o755 },
    );
    const outputs = path.join(dir, 'outputs.txt');
    const summary = path.join(dir, 'summary.md');
    fs.writeFileSync(outputs, '');
    fs.writeFileSync(summary, '');
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, RUN_BODY);

    const r = spawnSync('bash', [script], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            PATH: `${bin}:${process.env.PATH}`,
            GITHUB_WORKSPACE: dir,
            GITHUB_OUTPUT: outputs,
            GITHUB_STEP_SUMMARY: summary,
            OSV_IMAGE: 'ghcr.io/google/osv-scanner-action:test',
            OSV_SCAN_ARGS: scanArgs,
            OSV_GOTOOLCHAIN: 'auto',
            OSV_FAIL_ON_ERROR: failOnError,
        },
    });

    const out = {};
    for (const line of fs.readFileSync(outputs, 'utf8').split('\n')) {
        const i = line.indexOf('=');
        if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
    }
    return {
        status: r.status,
        outputs: out,
        stdout: `${r.stdout}\n${r.stderr}`,
        summary: fs.readFileSync(summary, 'utf8'),
        dockerArgs: fs.existsSync(argLog)
            ? fs.readFileSync(argLog, 'utf8').split('\0').slice(0, -1)
            : [],
    };
}

// ── the three answers that must stay three answers ──────────────────────────
//
// The exit codes are not invented here: they were measured on 2026-09-02
// against ghcr.io/google/osv-scanner-action:v2.5.1 over real trees. 0 on a
// module with no advisories, 1 on a lockfile pinning lodash 4.17.15 (six
// advisories), and 127 on a Go module whose `go` directive names a release
// newer than the image's bundled toolchain with call analysis left on — which
// wrote an EMPTY report, the shape that reads as clean.

const clean = runScan(0);
report(clean.status === 0, 'a clean scan (exit 0) succeeds');
report(clean.outputs['exit-code'] === '0', 'a clean scan reports exit-code=0');
report(clean.outputs.findings === 'false' && clean.outputs.errored === 'false',
    'a clean scan is neither findings nor errored');

const found = runScan(1);
report(found.status === 0, 'findings (exit 1) do NOT fail the step — triage is the caller\'s judgement');
report(found.outputs['exit-code'] === '1', 'findings report exit-code=1');
report(found.outputs.findings === 'true' && found.outputs.errored === 'false',
    'findings are reported as findings, not as an error');

const broken = runScan(127);
report(broken.status !== 0, 'a scanner error (exit 127) FAILS the step by default');
report(broken.outputs['exit-code'] === '127', 'a scanner error reports its real exit code');
report(broken.outputs.errored === 'true' && broken.outputs.findings === 'false',
    'a scanner error is reported as an error, not as a clean scan');
report(/did not complete/i.test(broken.stdout),
    'a scanner error says so in an annotation rather than exiting quietly');

// 128 is "no packages found". The image entrypoint rewrites it to 0 unless the
// caller passes --allow-no-lockfiles=false; when it does arrive it means nothing
// was scanned, which is an error by this action's reckoning and not a clean run.
const nothingScanned = runScan(128);
report(nothingScanned.outputs.errored === 'true' && nothingScanned.status !== 0,
    'exit 128 (nothing scanned) is an error, not a clean scan');

// ── the opt-out, and that it is an opt-out ──────────────────────────────────
const brokenTolerated = runScan(127, { failOnError: 'false' });
report(brokenTolerated.status === 0, 'fail-on-scanner-error=false lets the caller decide');
report(brokenTolerated.outputs.errored === 'true',
    'the opt-out silences the failure, never the finding: errored is still reported');

// ── the invocation itself ───────────────────────────────────────────────────
//
// The whole design rests on this being the same invocation the official action
// performs, so the outputs describe the same scan a consumer had before.
report(clean.dockerArgs.includes('--rm'), 'the container is removed after the run');
report(
    clean.dockerArgs.some((a) => /:\/github\/workspace$/.test(a)),
    'the workspace is mounted at /github/workspace, as GitHub mounts it for a docker action',
);
report(
    clean.dockerArgs.includes('/github/workspace'),
    'the working directory is /github/workspace, so relative scan-args keep their meaning',
);
report(
    clean.dockerArgs.some((a) => a === 'GOTOOLCHAIN=auto'),
    'GOTOOLCHAIN reaches the container (the official action sets auto at v2.5.1; the image itself carries local)',
);
report(
    clean.dockerArgs[clean.dockerArgs.length - 1] === '--recursive\n./',
    'scan-args are passed as ONE final argument, which is what the image entrypoint splits on newlines',
);

// A multi-line scan-args value with a space in it must survive as one argument.
// Passing it unquoted is the classic break, and it turns "./my dir" into two.
const spaced = runScan(0, { scanArgs: '--recursive\n./some dir\n--format=json' });
report(
    spaced.dockerArgs[spaced.dockerArgs.length - 1] === '--recursive\n./some dir\n--format=json',
    'scan-args survive word-splitting intact',
);

// ── the summary a human reads ───────────────────────────────────────────────
report(/exit code/i.test(broken.summary) && broken.summary.includes('127'),
    'the job summary carries the real exit code, which the API record cannot');

fs.rmSync(workRoot, { recursive: true, force: true });

// A floor, because a harness that asserted nothing would print no failures and
// exit 0 — the same vacuous green this action exists to make impossible.
const ASSERTION_FLOOR = 20;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ntest-osv-scan-action: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-osv-scan-action: all cases pass.');
