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

const { problems, zizmorPins, zizmorActionPins, actionlintPin } = require('../scripts/check-tooling-pins.cjs');
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

// ── the OWNER is part of the actionlint pin
//
// The reader used to start matching at `actionlint/releases/download/`, so it
// resolved rhysd and any fork identically while `fetchLatest` asked a hardcoded
// rhysd for the latest version. Point the workflow at a fork and the checker
// would compare that fork's version against rhysd's releases — an answer about a
// different project than the one the gate runs. It fails closed at runtime
// (`curl -sSf` 404s on a bad owner) so it was never a security hole, but it was
// a reporting one, and reporting is this script's entire job.
{
    const al = actionlintPin(REAL);
    report(!!al.owner, `the actionlint pin names an owner (${al.owner})`);
    // Deliberately asserts the CURRENT owner. Unlike a version, which moves on
    // routine work, the owner moving means the estate changed which project
    // supplies a required gate's linter — see #45. This case exists to make
    // that a reviewed edit rather than a silent one; if you are changing it on
    // purpose, change it, and say why in the commit.
    report(al.owner === 'rhysd', `the actionlint linter still comes from rhysd/actionlint (got ${al.owner})`);

    // An unreadable owner must be a finding, not a pass. Same rule as the
    // zizmor pin above: resolving nothing and finding nothing must not look
    // alike.
    const noOwner = tree((s) => s.replace(/https:\/\/github\.com\/[A-Za-z0-9._-]+\/actionlint\/releases/g,
        'https://example.invalid/actionlint/releases'));
    report(
        problems(noOwner, CURRENT).some((f) => /could not resolve the actionlint download URL/.test(f) && /owner=none/.test(f)),
        `a download URL whose owner cannot be read is a finding, not a pass`,
    );
}

// ── the action pin, and whether it can install the scanner pin
//
// THE REGRESSION THESE EXIST FOR. #47 bumped `version:` to 1.30.0, this checker
// reported every pin current, and both zizmor jobs died on the first real run
// with `Unknown version: 1.30.0`. The action ships a FROZEN TABLE of the zizmor
// releases it can install and v0.6.2's stops at 1.29.0, so the two pins have to
// move together. Every case above compares one pin to upstream; none of them
// could see two pins that disagree with each other, which is why the checker was
// green about a configuration that could not run at all.
{
    const actionPins = zizmorActionPins(REAL);
    report(actionPins.length === 2, `both zizmor-action pins are found (got ${actionPins.length})`);
    report(
        actionPins.every((a) => a.sha === actionPins[0].sha) && !!actionPins[0].tag,
        `the two action pins agree and carry a tag comment (${actionPins[0] && actionPins[0].tag})`,
    );

    // The tree as it stands, against a table that DOES offer its pinned version.
    const supporting = {
        ...CURRENT,
        zizmorActionSupports: ['1.28.0', '1.29.0', CURRENT.zizmor],
        zizmorActionTag: actionPins[0].tag,
    };
    report(problems(REAL, supporting).length === 0,
        `the real tree is clean when the pinned action offers its pinned scanner`);

    // The #47 tree: same pins, a table that stops short.
    const short = { ...supporting, zizmorActionSupports: ['1.28.0', '1.29.0'] };
    report(
        problems(REAL, short).some((f) => /cannot install zizmor/.test(f) && f.includes(CURRENT.zizmor)),
        `an action whose table lacks the pinned scanner is a finding (the #47 regression)`,
    );

    // A failed read resolves to nothing, and nothing must not read as agreement.
    // This is the shape that makes a checker green while it knows less than it
    // did before: an empty universe answers "is X in this set" with a confident
    // no, or with silence, depending on which way the condition was written.
    const empty = { ...supporting, zizmorActionSupports: [] };
    report(
        problems(REAL, empty).some((f) => /EMPTY list/.test(f)),
        `an empty version table is a failed read, not a pass`,
    );

    // The gate and the recorder running different actions.
    const split = tree((s, f) => (f === 'workflow-security-record.yml'
        ? s.replace(actionPins[0].sha, 'a'.repeat(40))
        : s));
    report(
        problems(split, supporting).some((f) => /pinned at 2 different commits/.test(f)),
        `the gate and the recorder pinning different actions is a finding`,
    );

    // Upstream moved the action itself, which is how the pin rots into the
    // failure above rather than being noticed on the day it matters.
    const newerAction = { ...supporting, zizmorActionTag: 'v99.0.0' };
    report(
        problems(REAL, newerAction).some((f) => /zizmor-action is pinned to .* but the latest release is v99\.0\.0/.test(f)),
        `a newer zizmor-action upstream is reported`,
    );
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
