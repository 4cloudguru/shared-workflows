#!/usr/bin/env node
'use strict';
// Self-test for .github/actions/check-zizmor-anchors.
//
// Every case builds a fixture repository — a zizmor config plus a findings
// file — and runs the real shipped script over it as a SUBPROCESS.
//
// NO ZIZMOR, NO DOCKER, NO NETWORK. That is deliberate and it is the reason
// the gate takes findings as a file rather than running zizmor itself: the
// suite can state "these are the findings" and assert purely on the matching
// rule, which is the part that can be wrong. The cost is that the shape of
// zizmor's JSON is an assumption here rather than an observation, so the
// fixture below is not invented — it is the literal shape emitted by
// `zizmor 1.30.1 --format=json`, including the 0-based `row`/`column` and the
// Primary/Related/Hidden location split, both of which this gate depends on
// and neither of which is guessable.
//
// What this suite CANNOT prove is that zizmor still emits that shape. A
// version bump is the one change that can break this gate silently, which is
// why the action pins the version to the lint's and refuses `latest`.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'check-zizmor-anchors');
const ACTION = path.join(ACTION_DIR, 'action.yml');
const SCRIPT = path.join(ACTION_DIR, 'check-zizmor-anchors.js');

let failures = 0;
const report = (ok, msg) => {
    if (ok) console.log(`  OK   ${msg}`);
    else { console.error(`  FAIL ${msg}`); failures += 1; }
};

// One finding, in zizmor json-v1's real shape. `row`/`column` are 0-BASED
// here and 1-based in the ignore syntax; the gate converts, and a case below
// pins that conversion because an off-by-one would make every anchor look
// dead.
const finding = (ident, file, row, column) => ({
    ident,
    desc: `${ident} finding`,
    url: `https://docs.zizmor.sh/audits/#${ident}`,
    determinations: { confidence: 'High', severity: 'Medium', persona: 'Regular' },
    locations: [
        // A Related location at different coordinates. An ignore anchored here
        // suppresses nothing, so the gate must not count it as a match.
        {
            symbolic: { key: { Local: { verbatim_path: file } }, kind: 'Related', annotation: 'context' },
            concrete: { location: { start_point: { row: 3, column: 0 }, end_point: { row: 3, column: 9 } }, feature: 'on:', comments: [] },
        },
        {
            symbolic: { key: { Local: { verbatim_path: file } }, kind: 'Primary', annotation: 'here' },
            concrete: { location: { start_point: { row, column }, end_point: { row, column: column + 10 } }, feature: 'uses: x', comments: [] },
        },
        {
            symbolic: { key: { Local: { verbatim_path: file } }, kind: 'Hidden', annotation: 'hidden' },
            concrete: { location: { start_point: { row, column }, end_point: { row, column: column + 10 } }, feature: 'uses: x', comments: [] },
        },
    ],
    ignored: false,
    fixes: [],
});

function fixture(name, config, findings) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `zizmor-anchors-${name}-`));
    fs.mkdirSync(path.join(root, '.github'), { recursive: true });
    if (config !== null) fs.writeFileSync(path.join(root, '.github', 'zizmor.yml'), config);
    const findingsPath = path.join(root, 'findings.json');
    fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2));
    return { root, findingsPath };
}

function run(name, config, findings) {
    const { root, findingsPath } = fixture(name, config, findings);
    const r = spawnSync(process.execPath, [SCRIPT, root, '--findings', findingsPath], { encoding: 'utf8' });
    return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

const CACHE = [finding('cache-poisoning', '.github/workflows/release.yml', 216, 8)];

// ── 1. the baseline: a live file-scoped ignore is not rot
{
    const r = run('live-file', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml\n', CACHE);
    report(r.code === 0, `a file-scoped ignore over a real finding passes (exit ${r.code})`);
}

// ── 2. THE FAILURE THIS GATE EXISTS FOR: the finding was fixed, the ignore stayed
{
    const r = run('dead-file', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml\n', []);
    report(r.code === 1 && /fixed at source/.test(r.out),
        `an ignore whose finding no longer exists fails (exit ${r.code})`);
}

// ── 3. a live line:col anchor passes, and proves the 0-based -> 1-based conversion
{
    const r = run('live-anchor', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml:217:9\n', CACHE);
    report(r.code === 0, `row 216/col 8 in JSON is 217:9 in an ignore (exit ${r.code})`);
}

// ── 4. an anchor one line off fails, and says where the finding actually is.
// This is terraform's recorded failure mode: five ignores went stale at once
// when a `permissions:` block shifted every line below it.
{
    const r = run('stale-anchor', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml:218:9\n', CACHE);
    report(r.code === 1 && /it is at 217:9/.test(r.out),
        `a stale anchor fails AND names the real coordinates (exit ${r.code})`);
}

// ── 5. right line, wrong column
{
    const r = run('wrong-col', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml:217:8\n', CACHE);
    report(r.code === 1, `right line and wrong column is still dead (exit ${r.code})`);
}

// ── 6. a line-only anchor (no column) is legal and matches on the line alone
{
    const r = run('line-only', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml:217\n', CACHE);
    report(r.code === 0, `a line-only anchor matches without a column (exit ${r.code})`);
}

// ── 7. AN ANCHOR ON A NON-PRIMARY LOCATION IS DEAD. The fixture's finding also
// carries Related and Hidden locations at 4:1; zizmor does not match those, so
// neither may this gate. Matching any location instead of Primary would pass
// this case and silently accept anchors that suppress nothing.
{
    const r = run('related-loc', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml:4:1\n', CACHE);
    report(r.code === 1, `an anchor on a Related/Hidden location is dead (exit ${r.code})`);
}

// ── 8. the rule name is part of the match: a live finding does not license an
// ignore for a DIFFERENT rule in the same file
{
    const r = run('wrong-rule', 'rules:\n  dangerous-triggers:\n    ignore:\n      - release.yml\n', CACHE);
    report(r.code === 1, `an ignore for a rule that never fires there is dead (exit ${r.code})`);
}

// ── 9. a path suppresses nothing, however correct it looks. Measured against
// zizmor 1.30.1: `release.yml` suppressed 4 of 7 findings on a real config
// while `workflows/release.yml` and `.github/workflows/release.yml` suppressed
// 0 each.
{
    const r = run('path-form', 'rules:\n  cache-poisoning:\n    ignore:\n      - workflows/release.yml\n', CACHE);
    report(r.code === 1 && /basename/.test(r.out),
        `a path-form entry fails and says why (exit ${r.code})`);
}

// ── 10. `config:` blocks are not ignore lists and must not be read as one.
// unpinned-uses carries a policy map whose keys would otherwise parse as entries.
{
    const config = 'rules:\n'
        + '  unpinned-uses:\n'
        + '    config:\n'
        + '      policies:\n'
        + '        "*": hash-pin\n'
        + '  cache-poisoning:\n'
        + '    ignore:\n'
        + '      - release.yml\n';
    const r = run('config-block', config, CACHE);
    report(r.code === 0, `a rule with config: but no ignore: is not treated as rot (exit ${r.code})`);
}

// ── 11. comments and trailing comments are not entries
{
    const config = 'rules:\n'
        + '  cache-poisoning:\n'
        + '    ignore:\n'
        + '      # this explains the entry below\n'
        + '      - release.yml # and this trails it\n';
    const r = run('comments', config, CACHE);
    report(r.code === 0, `comments and trailing comments are stripped (exit ${r.code})`);
}

// ── 12. no config is not a failure; there are no ignores to rot
{
    const r = run('no-config', null, CACHE);
    report(r.code === 0, `a repository with no zizmor config passes (exit ${r.code})`);
}

// ── 13. A COULD-NOT-RUN IS NOT A PASS. The estate's own lesson: a gate that
// cannot run must exit 2, never 0. Exit 0 here would make a missing findings
// file indistinguishable from a clean config.
{
    const { root } = fixture('no-findings', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml\n', []);
    const r = spawnSync(process.execPath, [SCRIPT, root], { encoding: 'utf8' });
    report(r.status === 2, `a run with no --findings exits 2, not 0 (exit ${r.status})`);
}
{
    const { root } = fixture('bad-findings', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml\n', []);
    const r = spawnSync(process.execPath, [SCRIPT, root, '--findings', path.join(root, 'nope.json')], { encoding: 'utf8' });
    report(r.status === 2, `a missing findings file exits 2, not 0 (exit ${r.status})`);
}
{
    const { root, findingsPath } = fixture('sarif', 'rules:\n  cache-poisoning:\n    ignore:\n      - release.yml\n', []);
    fs.writeFileSync(findingsPath, JSON.stringify({ runs: [], version: '2.1.0' }));
    const r = spawnSync(process.execPath, [SCRIPT, root, '--findings', findingsPath], { encoding: 'utf8' });
    report(r.status === 2 && /sarif/i.test(r.stdout + r.stderr),
        `SARIF handed over instead of json-v1 exits 2 and says so (exit ${r.status})`);
}

// ── 14. a config that is all dead reports every entry, not just the first
{
    const config = 'rules:\n'
        + '  cache-poisoning:\n'
        + '    ignore:\n'
        + '      - gone-a.yml\n'
        + '      - gone-b.yml\n'
        + '      - release.yml\n';
    const r = run('multi-dead', config, CACHE);
    report(r.code === 1 && /2 of 3/.test(r.out),
        `all dead entries are reported together, with a count (exit ${r.code})`);
}

// ── the ACTION's own run body ──────────────────────────────────────────────
// The script above is only reachable through action.yml, and the two have
// already been able to disagree elsewhere in this repository. These cases read
// the shipped action.yml as text.
{
    const body = fs.readFileSync(ACTION, 'utf8').replace(/\r\n/g, '\n');

    report(/--no-ignores/.test(body),
        'the action passes --no-ignores, without which the gate can never see a dead entry');
    report(/--no-exit-codes/.test(body),
        'the action passes --no-exit-codes, so a found finding is not read as a crash');
    report(!/--no-online-audits/.test(body),
        'the action does NOT force offline, which would make the four online-only audits look dead');
    report(/ghcr\.io\/zizmorcore\/zizmor:\$\{VERSION\}/.test(body),
        'the version is interpolated from the input, so it can be pinned to the lint\'s');

    // Inputs must reach bash through env, never through ${{ }} spliced into the
    // run body — the template-injection class zizmor itself exists to refuse.
    const runBody = body.slice(body.indexOf('run: |'));
    report(!/\$\{\{/.test(runBody),
        'no ${{ }} expression is spliced into the run body');
    for (const v of ['VERSION', 'ROOT', 'TOKEN', 'ACTION_PATH']) {
        report(new RegExp(`^\\s+${v}: \\$\\{\\{ [a-z.]+`, 'm').test(body),
            `${v} is bound through env:`);
    }

    // The gate's exit code must be the step's verdict: no `|| true`, no pipe.
    const invocation = (runBody.match(/node "\$ACTION_PATH\/check-zizmor-anchors\.js".*/) || [''])[0];
    report(invocation !== '' && !/\|\||\|/.test(invocation),
        `the gate's exit code is the step's verdict, uncaptured (got: ${invocation.trim()})`);

    report(/case "\$VERSION" in/.test(body) && /\[0-9\]\*\.\[0-9\]\*\.\[0-9\]\*/.test(body),
        'an unusable version is refused before anything is pulled');

    // THE SKEW GUARD. The gate audits a config against the findings ONE zizmor
    // version produces, and the lint that honours that config runs in a
    // different file. If the two versions drift, the gate starts reporting
    // dead anchors that are alive under the version the lint actually used —
    // a false failure that looks exactly like a true one. Neither literal is
    // reachable from the other at runtime, so it is asserted here instead.
    const LINT = path.join(__dirname, '..', '.github', 'workflows', 'workflow-security.yml');
    const lintBody = fs.readFileSync(LINT, 'utf8').replace(/\r\n/g, '\n');
    const lintVersion = (lintBody.match(/^\s*ZIZMOR_VERSION:\s*"([^"]+)"/m) || [])[1];
    const actionDefault = (body.match(/default:\s*"(\d+\.\d+\.\d+)"/) || [])[1];
    report(lintVersion !== undefined, `workflow-security.yml declares ZIZMOR_VERSION (got ${lintVersion})`);
    report(actionDefault !== undefined, `the action declares a pinned default version (got ${actionDefault})`);
    report(lintVersion === actionDefault,
        `the gate audits at the version the lint runs (lint ${lintVersion}, gate ${actionDefault})`);

    // And the lint must actually USE the named value rather than re-stating it.
    report(/version: \$\{\{ env\.ZIZMOR_VERSION \}\}/.test(lintBody),
        'the lint consumes ZIZMOR_VERSION rather than repeating the literal');
}

console.log(failures === 0
    ? '\ncheck-zizmor-anchors.js self-test: all cases passed.'
    : `\ncheck-zizmor-anchors.js self-test: ${failures} case(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
