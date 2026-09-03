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

// DERIVED FROM THE TREE, never written down here.
//
// These were hardcoded, and every one of the three cases that referenced them
// broke on the routine zizmor 1.29.0 -> 1.30.0 bump: "the real tree is clean"
// compared the new pin against the old constant, "a newer upstream is reported"
// asserted a message naming a version the tree no longer carried, and the
// drift case rewrote a string that was no longer in the file. Three red cases
// for a bump that was correct, which is how a suite teaches people that a green
// tooling bump means editing the tests until they stop complaining.
//
// The tree is the source of truth for what it pins, and the reader under test
// is the thing that knows how to find it — so the suite asks it.
const CURRENT = {
    actionlint: actionlintPin(REAL).urlVersion,
    zizmor: (zizmorPins(REAL)[0] || {}).version,
};
if (!CURRENT.actionlint || !CURRENT.zizmor) {
    // The readers under test are how this file learns what the tree pins, so a
    // reader that stopped resolving would otherwise hand every case below the
    // string "undefined" and let them pass against nothing.
    console.error(`  FAIL harness: could not read the tree's own pins (actionlint=${CURRENT.actionlint}, zizmor=${CURRENT.zizmor})`);
    process.exit(1);
}

/** The next minor of a pinned version, as a stand-in for "upstream moved". */
const bumped = (v) => {
    const [major, minor] = v.split('.');
    return `${major}.${Number(minor) + 1}.0`;
};

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
    const newerZizmor = bumped(CURRENT.zizmor);
    const found = problems(REAL, { actionlint: CURRENT.actionlint, zizmor: newerZizmor });
    report(
        found.some((f) => f.includes(`zizmor is pinned to ${CURRENT.zizmor} but the latest release is ${newerZizmor}`)),
        `a newer zizmor upstream is reported (${CURRENT.zizmor} -> ${newerZizmor})`,
    );
    const newerActionlint = bumped(CURRENT.actionlint);
    const found2 = problems(REAL, { actionlint: newerActionlint, zizmor: CURRENT.zizmor });
    report(
        found2.some((f) => f.includes(`actionlint is pinned to ${CURRENT.actionlint} but the latest release is ${newerActionlint}`)),
        `a newer actionlint upstream is reported (${CURRENT.actionlint} -> ${newerActionlint})`,
    );
}

// ── the two zizmor pins drifting apart from each other
{
    const root = tree((s, f) =>
        f === 'workflow-security-record.yml' ? s.replace(`"${CURRENT.zizmor}"`, '"0.0.1"') : s);
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
    const nextActionlint = bumped(CURRENT.actionlint);
    const urlRe = new RegExp(
        `download/v${CURRENT.actionlint.replace(/\./g, '\\.')}/actionlint_${CURRENT.actionlint.replace(/\./g, '\\.')}_([a-z0-9_]+)\\.tar\\.gz`,
        'g',
    );
    const root = tree((s) =>
        s.replace(urlRe, `download/v${nextActionlint}/actionlint_${nextActionlint}_$1.tar.gz`));
    const found = problems(root, { actionlint: nextActionlint, zizmor: CURRENT.zizmor });
    report(found.some((f) => /internally inconsistent/.test(f)),
        `a URL bumped without its checksum is a finding`);
}

if (failures > 0) {
    console.error(`\ntest-tooling-pins: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('\ntest-tooling-pins: all cases passed.');
