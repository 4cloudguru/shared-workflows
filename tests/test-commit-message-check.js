// Self-test for `.github/actions/commit-message-check`.
//
// The action's own node:test suite drives the REAL verify.mjs as a subprocess,
// so there is no second copy of the logic here to drift from it. This entry
// point runs that suite and holds it to a floor, then makes the few contract
// assertions the suite itself cannot make -- that action.yml still calls the
// file the suite tests, and that the parser dependency is pinned exactly.
//
// WHY A FLOOR. `node --test` over a directory containing no test files exits 0
// and prints "tests 0 ... pass 0 ... fail 0" -- indistinguishable from a passing
// suite. A renamed file, a wrong working directory or a missing checkout would
// report exactly like success. That is the vacuous green this guard exists to
// prevent elsewhere, so it must not be the shape of the guard itself. The floor
// moves only UP; 9 is what the suite enumerates today.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'commit-message-check');
const CASE_FLOOR = 9;

let failures = 0;
const report = (ok, message) => {
    if (!ok) failures++;
    console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${message}`);
};

console.log('commit-message-check action self-test\n');

/* ------------------------------------------------------------------ *
 * The action's node:test suite, run where the action lives.
 * ------------------------------------------------------------------ */

const suite = spawnSync('node', ['--test', '--test-reporter=tap'], {
    cwd: ACTION_DIR,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
});
const tap = `${suite.stdout || ''}${suite.stderr || ''}`;
const readCount = (label) => {
    const m = [...tap.matchAll(new RegExp(`^# ${label} (\\d+)$`, 'gm'))];
    return m.length ? Number(m[m.length - 1][1]) : null;
};
const passed = readCount('pass');
const failed = readCount('fail');

if (passed === null || failed === null) {
    console.error(tap);
    report(false, 'suite: could not read a case count out of the TAP summary; refusing to report a pass');
} else {
    if (failed !== 0 || suite.status !== 0) console.error(tap);
    report(failed === 0 && suite.status === 0, `suite: ${passed} passing, ${failed} failing`);
    report(passed >= CASE_FLOOR, `suite: enumerated ${passed} case(s), floor is ${CASE_FLOOR}`);
}

/* ------------------------------------------------------------------ *
 * Contract: the action still calls the file the suite tests.
 * ------------------------------------------------------------------ */

const actionYml = fs.readFileSync(path.join(ACTION_DIR, 'action.yml'), 'utf8');

report(
    /verify\.mjs/.test(actionYml),
    'action.yml invokes verify.mjs -- the file the suite drives',
);
report(
    /npm ci --ignore-scripts/.test(actionYml),
    'action.yml installs with --ignore-scripts, so no dependency install hook runs',
);
report(
    /working-directory: \$\{\{ github\.action_path \}\}/.test(actionYml),
    'the install runs in the ACTION path, not the caller checkout -- a consumer ships no package.json',
);

/* ------------------------------------------------------------------ *
 * Contract: the parser is the one release-please resolves, pinned exactly.
 *
 * An approximation of the Conventional Commits grammar that disagrees with
 * release-please is worse than no check: it reports green about exactly the
 * commits release-please drops. A caret or tilde range would let that agreement
 * drift on any consumer's next install.
 * ------------------------------------------------------------------ */

const pkg = JSON.parse(fs.readFileSync(path.join(ACTION_DIR, 'package.json'), 'utf8'));
const parserPin = (pkg.dependencies || {})['@conventional-commits/parser'];

report(
    typeof parserPin === 'string' && /^\d+\.\d+\.\d+$/.test(parserPin),
    `@conventional-commits/parser is pinned exactly (${parserPin})`,
);

const lock = JSON.parse(fs.readFileSync(path.join(ACTION_DIR, 'package-lock.json'), 'utf8'));
report(
    lock.name === pkg.name,
    `package-lock name matches package.json (${lock.name}) -- npm ci refuses to install when they disagree`,
);

console.log('');
if (failures) {
    console.error(`FAILED: ${failures} check(s)`);
    process.exit(1);
}
console.log('All checks passed.');
