#!/usr/bin/env node
'use strict';
// Mutation self-test for scripts/check-tooling-pins.cjs.
//
// The canary this replaces died silently: it grepped azure-pipelines-terraform's
// own unit-test.yml, and when that repo moved onto the shared workflow the pins
// it read went with them. Its next scheduled run would have failed with "Could
// not resolve the actionlint version pinned in unit-test.yml" -- which is the
// good outcome, and only because it checked. A version that had returned "no
// drift" on finding nothing would have reported clean forever.
//
// So the first case here is the one that matters: resolving NOTHING is a
// finding, not a pass. The rest break each pin in turn and assert it is named.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { problems, zizmorPins, actionlintPin } = require('../scripts/check-tooling-pins.cjs');
const REAL = path.resolve(__dirname, '..');
const CURRENT = { actionlint: '1.7.12', zizmor: '1.29.0' };

let failures = 0;
const report = (ok, msg) => {
    if (ok) console.log(`  OK   ${msg}`);
    else { console.error(`  FAIL ${msg}`); failures += 1; }
};

/** A copy of the two real workflow files, optionally rewritten. */
function tree(edit = (s) => s) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tooling-pins-'));
    fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
    for (const f of ['workflow-security.yml', 'workflow-security-record.yml']) {
        const src = path.join(REAL, '.github', 'workflows', f);
        fs.writeFileSync(path.join(root, '.github', 'workflows', f), edit(fs.readFileSync(src, 'utf8'), f));
    }
    return root;
}

// ── the pins are read at all
{
    report(zizmorPins(REAL).length === 2, `both zizmor pins are found (got ${zizmorPins(REAL).length})`);
    const al = actionlintPin(REAL);
    report(al.urlVersion && al.sha256, `the actionlint version and checksum are found (v${al.urlVersion})`);
    report(problems(REAL, CURRENT).length === 0, `the real tree is clean against its own pinned versions`);
}

// ── resolving nothing must not read as clean
{
    const root = tree((s) => s.replace(/version:\s*["'][0-9.]+["']/g, 'version: ""'));
    const found = problems(root, CURRENT);
    report(found.some((f) => /no zizmor version pin found/.test(f)),
        `a tree where the zizmor pin cannot be resolved is a finding, not a pass`);
}

// ── upstream moved
{
    const found = problems(REAL, { actionlint: '1.7.12', zizmor: '1.30.0' });
    report(found.some((f) => /zizmor is pinned to 1\.29\.0 but the latest release is 1\.30\.0/.test(f)),
        `a newer zizmor upstream is reported`);
    const found2 = problems(REAL, { actionlint: '1.8.0', zizmor: '1.29.0' });
    report(found2.some((f) => /actionlint is pinned to 1\.7\.12 but the latest release is 1\.8\.0/.test(f)),
        `a newer actionlint upstream is reported`);
}

// ── the two zizmor pins drifting apart from each other
{
    const root = tree((s, f) => (f === 'workflow-security-record.yml' ? s.replace('"1.29.0"', '"1.28.0"') : s));
    const found = problems(root, CURRENT);
    report(found.some((f) => /pinned at 2 different versions/.test(f)),
        `the gate and the recorder pinning different scanners is a finding`);
}

// ── a half-landed actionlint bump: URL moved, checksum did not
{
    // Globally, and only the tarball URL: the file carries the same URL twice --
    // once in a comment pointing at checksums.txt, which the reader deliberately
    // skips. A non-global replace edits the comment and leaves the real pin
    // untouched, which is how the first version of this case passed for the
    // wrong reason.
    const root = tree((s) => s.replace(/download\/v1\.7\.12\/actionlint_1\.7\.12_([a-z0-9_]+)\.tar\.gz/g,
        'download/v1.8.0/actionlint_1.8.0_$1.tar.gz'));
    const found = problems(root, { actionlint: '1.8.0', zizmor: '1.29.0' });
    report(found.some((f) => /internally inconsistent/.test(f)),
        `a URL bumped without its checksum is a finding`);
}

if (failures > 0) {
    console.error(`\ntest-tooling-pins: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('\ntest-tooling-pins: all cases passed.');
