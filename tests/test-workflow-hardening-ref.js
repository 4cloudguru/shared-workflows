'use strict';

// The "Resolve the checker commit" step of workflow-hardening.yml, run for real.
//
// That step decides which commit of this repository the hardening checker is
// checked out from: the caller's own `uses:` pin of workflow-hardening.yml,
// read from its checkout, or `script-ref` for this repository's `./` self-call.
// Its predecessor (v1.22.0, reverted in #68) passed every test it had and still
// failed its first genuine remote call, so each branch the script can take is
// driven here against a caller tree built for it, with the script read out of
// the workflow file rather than copied, so a test cannot pass while the
// shipped step rots.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const WORKFLOW = path.join(__dirname, '..', '.github', 'workflows', 'workflow-hardening.yml');
const STEP = 'Resolve the checker commit';

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

/** The `run: |` body of the named step, read by indentation. */
function extractStepRun(yaml, stepName) {
    const lines = yaml.split('\n');
    const named = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
    if (named === -1) return null;
    const start = lines.findIndex((l, i) => i > named && /^\s+run: \|\s*$/.test(l));
    if (start === -1) return null;
    const indent = lines[start].match(/^(\s*)/)[1].length + 2;
    const body = [];
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') {
            body.push('');
            continue;
        }
        if (line.match(/^(\s*)/)[1].length < indent) break;
        body.push(line.slice(indent));
    }
    return body.join('\n');
}

const script = extractStepRun(fs.readFileSync(WORKFLOW, 'utf8'), STEP);
if (!script) {
    console.error(`could not find the "${STEP}" step's run block in ${WORKFLOW}`);
    process.exit(2);
}

const A = '9276df8e0bdb3152e2529ab98c8b99cfb9e22d4b';
const B = '8b7215beac6420881d20d52f9b096edff4238ec9';
const call = (sha) => `---
name: Hardening
"on":
  push:
    branches: [main]
jobs:
  workflow-hardening:
    uses: 4cloudguru/shared-workflows/.github/workflows/workflow-hardening.yml@${sha} # v1.0.0
`;

/** Build a caller tree from {file: content}, run the step in it, return the outcome. */
function run(files, scriptRef = '') {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hardening-ref-'));
    try {
        fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true });
        for (const [name, content] of Object.entries(files)) {
            fs.writeFileSync(path.join(dir, '.github', 'workflows', name), content);
        }
        const out = path.join(dir, 'github-output');
        fs.writeFileSync(out, '');
        const r = spawnSync('bash', ['-c', script], {
            cwd: dir,
            env: { PATH: process.env.PATH, SCRIPT_REF: scriptRef, GITHUB_OUTPUT: out },
            encoding: 'utf8',
        });
        const ref = (/^ref=(.*)$/m.exec(fs.readFileSync(out, 'utf8')) || [])[1] || null;
        return { status: r.status, ref, log: `${r.stdout}${r.stderr}` };
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

console.log('remote callers — the commit comes from the uses: pin:');
let r = run({ 'hardening.yml': call(A) });
report(r.status === 0 && r.ref === A, 'one pin and no script-ref resolves to the pin');
r = run({ 'hardening.yml': call(A) }, A);
report(r.status === 0 && r.ref === A && /script-ref .* is ignored/.test(r.log) === false, 'a script-ref equal to the pin resolves to the pin, with no warning');
r = run({ 'hardening.yml': call(A) }, B);
report(r.status === 0 && r.ref === A, 'a stale script-ref (what a Dependabot bump leaves) is ignored: the pin wins');
report(/::warning.*script-ref \(8b7215be\) is ignored.*uses: pin \(9276df8e\)/.test(r.log), 'and the stale value is named in a warning');
r = run({ 'one.yml': call(A), 'two.yml': call(A) });
report(r.status === 0 && r.ref === A, 'the same pin in two workflow files resolves to it');
r = run({ 'hardening.yml': call(A), 'notes.yml': `# was: uses: 4cloudguru/shared-workflows/.github/workflows/workflow-hardening.yml@${B}\n` });
report(r.status === 0 && r.ref === A, 'a commented-out pin is not counted');
r = run({ 'hardening.yaml': call(A) });
report(r.status === 0 && r.ref === A, 'a .yaml workflow file is read too');

console.log('\nfail closed:');
r = run({ 'one.yml': call(A), 'two.yml': call(B) });
report(r.status !== 0 && r.ref === null && /2 different commits/.test(r.log), 'pins at two commits fail, and no commit is chosen');
r = run({ 'one.yml': call(A), 'two.yml': call(B) }, A);
report(r.status !== 0 && r.ref === null, 'a script-ref does not break the tie between two pins');
r = run({ 'other.yml': '---\nname: Other\n"on": push\njobs: {}\n' });
report(r.status !== 0 && r.ref === null && /no script-ref was passed/.test(r.log), 'no pin and no script-ref fails');

console.log('\nthis repository\'s ./ self-call — no pin, so script-ref:');
r = run({ 'self-check.yml': '---\njobs:\n  h:\n    uses: ./.github/workflows/workflow-hardening.yml\n' }, A);
report(r.status === 0 && r.ref === A, 'a ./ call with a script-ref resolves to the script-ref');
r = run({ 'self-check.yml': '---\njobs:\n  h:\n    uses: ./.github/workflows/workflow-hardening.yml\n' }, 'main');
report(r.status !== 0 && r.ref === null && /full 40-hex SHA/.test(r.log), 'a script-ref that is not a full SHA (a branch name) fails');

if (failures) {
    console.error(`\ntest-workflow-hardening-ref: ${failures} of ${assertions} assertion(s) failed.`);
    process.exit(1);
}
console.log(`\ntest-workflow-hardening-ref: all ${assertions} assertions passed against the step as shipped.`);
