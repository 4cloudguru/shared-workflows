// The resolve step in `.github/workflows/workflow-hardening.yml`, executed.
//
// This is the step that replaced a required `script-ref` input with a value
// derived from `github.job_workflow_sha`. It is the only thing standing between
// a pinned gate and a mutable one: an empty `ref:` does NOT fail a checkout, it
// silently resolves the default branch, so the failure this guards against
// looks like a green run against the wrong tree.
//
// The script is EXTRACTED from the workflow and run, rather than copied here.
// A test carrying its own copy of the shell passes while the real block rots --
// the lesson already recorded on the closing-keyword guard's own suite.
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const WORKFLOW = path.join(__dirname, '..', '.github', 'workflows', 'workflow-hardening.yml');
const STEP_ID = 'checker';

let failures = 0;
const report = (ok, message) => {
    if (!ok) failures++;
    console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${message}`);
};

/**
 * The `run: |` body of the step with `id: <STEP_ID>`, keyed by id so a
 * reordered or renamed step cannot silently re-point these cases at a
 * different script.
 */
function extractRun(yaml, wantId) {
    const lines = yaml.split(/\r?\n/);
    let id = null;
    for (let i = 0; i < lines.length; i++) {
        const idAt = /^\s+id:\s*(\S+)\s*$/.exec(lines[i]);
        if (idAt) {
            id = idAt[1];
            continue;
        }
        if (!/^\s+run:\s*\|\s*$/.test(lines[i])) continue;
        if (id !== wantId) {
            id = null;
            continue;
        }
        let first = i + 1;
        while (first < lines.length && lines[first].trim() === '') first += 1;
        const indent = /^(\s+)/.exec(lines[first] || '');
        if (!indent) return null;
        const script = [];
        for (let j = i + 1; j < lines.length; j++) {
            if (lines[j].trim() === '') { script.push(''); continue; }
            if (!lines[j].startsWith(indent[1])) break;
            script.push(lines[j].slice(indent[1].length));
        }
        return script.join('\n');
    }
    return null;
}

const script = extractRun(fs.readFileSync(WORKFLOW, 'utf8'), STEP_ID);
if (!script) {
    console.error(`FAIL: no \`run: |\` block for step id "${STEP_ID}" in ${WORKFLOW}.`);
    console.error('Refusing to report a pass: the cases below would all be vacuous.');
    process.exit(1);
}

const SHA_A = '9276df8e0bdb3152e2529ab98c8b99cfb9e22d4b';
const SHA_B = '8b7215beac6420881d20d52f9b096edff4238ec9';

function run({ requested = '', resolved = '', caller = '' }) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'script-ref-'));
    const out = path.join(dir, 'output');
    fs.writeFileSync(out, '');
    const proc = spawnSync('bash', ['-c', script], {
        encoding: 'utf8',
        env: {
            ...process.env,
            REQUESTED: requested,
            RESOLVED: resolved,
            CALLER_SHA: caller,
            GITHUB_OUTPUT: out,
        },
    });
    return {
        code: proc.status,
        text: `${proc.stdout || ''}${proc.stderr || ''}`,
        output: fs.readFileSync(out, 'utf8'),
    };
}

console.log('workflow-hardening: resolving the checker commit\n');

// The ordinary case after a caller drops the input.
{
    const r = run({ resolved: SHA_A, caller: SHA_B });
    report(r.code === 0, `derives the commit when no script-ref is passed (exit ${r.code})`);
    report(!r.output.includes(`ref=${SHA_B}`), 'prefers the workflow commit over the caller commit');
    report(r.output.includes(`ref=${SHA_A}`), 'publishes the resolved commit as the step output');
}

// A LOCAL `./` CALL LEAVES job_workflow_sha EMPTY. GitHub populates it only for
// a workflow referenced from another repository; a `./` reference has no
// separate commit to name, because it IS the caller's commit. This repository
// calls its own hardening workflow that way, and found it the first time the
// derivation ran -- the step failed closed, which is the right failure, but the
// derivation still has to work.
{
    const r = run({ resolved: '', caller: SHA_A });
    report(r.code === 0, `falls back to the caller's commit for a local ./ call (exit ${r.code})`);
    report(r.output.includes(`ref=${SHA_A}`), 'uses the caller commit as the checker commit');
}

// THE ONE THAT MATTERS. An empty ref checks out the default branch instead of
// failing, so with NOTHING usable this must be a hard error and not a fallback.
{
    const r = run({ resolved: '', caller: '' });
    report(r.code !== 0, 'REFUSES when neither commit is available, rather than checking out a default branch');
    report(/job_workflow_sha/.test(r.text), 'names the context that was unusable');
    report(!r.output.includes('ref='), 'publishes no ref when it refuses');
}

// The fallback must be held to the same shape rule as the derived value, or it
// re-opens mutability by the door the shape check was closing.
{
    const r = run({ resolved: '', caller: 'main' });
    report(r.code !== 0, 'refuses a caller commit that is not a 40-character commit');
}

// A branch name is not a commit. Accepting one would re-open mutability by a
// different door than the empty string.
{
    const r = run({ resolved: 'main' });
    report(r.code !== 0, 'refuses a job_workflow_sha that is not a 40-character commit');
}

// A caller that still passes the old input is held to it, not ignored.
{
    const r = run({ requested: SHA_B, resolved: SHA_A });
    report(r.code !== 0, 'refuses a script-ref that disagrees with the resolved commit');
    report(/8b7215be/.test(r.text) && /9276df8e/.test(r.text), 'names both commits, so the diff can be read against the run');
    report(/[Dd]rop the script-ref/.test(r.text), 'says what to do about it');
}

// The transition state: every consumer passes the input today, and must keep
// working until it is removed.
{
    const r = run({ requested: SHA_A, resolved: SHA_A });
    report(r.code === 0, 'accepts a script-ref that agrees, so existing callers keep working');
    report(r.output.includes(`ref=${SHA_A}`), 'still publishes the commit for the checkout');
}

console.log('');
if (failures > 0) {
    console.error(`test-hardening-script-ref: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('test-hardening-script-ref: the derived commit cannot be empty, cannot be a branch, and cannot disagree with an explicit input.');
