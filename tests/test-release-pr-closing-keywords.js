#!/usr/bin/env node
// Mutation self-test for the release-PR closing-keyword guard in
// .github/actions/release-pr-closing-keywords/, shared across the estate.
//
// Same contract as tests/test-breaking-change-footers.js, and the same reason:
// the parts of that guard which live in YAML are a shell script embedded in a
// composite action. actionlint checks its syntax, zizmor checks the workflow
// around it, and nothing runs it.
//
// WHAT THIS FILE COVERS, AND WHAT IT DELIBERATELY DOES NOT.
//
// The guard is two kinds of artifact and they need two kinds of proof:
//
//   * FIVE .mjs MODULES and their five node:test suites. Those suites import the
//     modules directly, so there is no copy to drift from -- the module IS the
//     artifact under test. They port BESIDE the action unchanged (two fixture
//     edits aside) and are RUN from here, with a case-count floor, because
//     `node --test` over a directory containing no test files exits 0. A renamed
//     file, a wrong working directory or a bad glob would otherwise report
//     exactly like a passing suite.
//
//   * The action's own SHELL BODIES, which have no such property. A test with
//     its own copy of a shell script passes while the real one rots, so these
//     are EXTRACTED from action.yml, exactly as the footer guard's test extracts
//     its one `run:` block. This half is NEW: in the source repository the
//     pull-request job's shell body was covered only by TEXT assertions against
//     the workflow file, so its ordering -- publish the status, THEN fail --
//     was asserted about and never executed.
//
// `gh` is stubbed with the guard's own stub-gh.cjs, which serves a fixture
// dataset and records every call, so no network and no repository are involved.
//
// Cases, and the property each one pins:
//   contract-unknown-mode      a mode the action does not implement FAILS.
//                              It would otherwise satisfy no `if:`, run no step,
//                              and report success -- the vacuous green this
//                              whole guard exists to remove, arriving through
//                              the one door none of the modules can watch
//   contract-missing-input     mode=pull-request with no pr-number fails
//   contract-missing-module    a `github.action_path` without the modules fails
//                              loudly instead of as a node stack trace
//   grade-fails-open-issue     THE case -- a `Refs #N` rendered as `closes` on an
//                              OPEN issue with no closing intent is rejected
//   status-posted-before-fail  and the FAILURE status reaches the head SHA
//                              anyway. Branch protection grades a context on the
//                              head SHA and nothing else, so a verdict that
//                              never reaches one blocks nothing
//   grade-passes-deliberate    a commit that really does close it passes
//   non-release-pr-still-posts a pull request release-please did not create gets
//                              a PASSING status. A required context that reports
//                              on some pull requests and not others blocks the
//                              ones it skips forever
//   status-goes-to-api-sha     the status is posted to the head SHA read from
//                              the API alongside the body that was graded, not
//                              to a stale one
//   gh-unavailable             it FAILS CLOSED when it cannot read the pull
//                              request -- an unreadable body counted as zero
//                              closing references is a green context asserting
//                              nothing, and it is what a lost `set -euo
//                              pipefail` degrades to
//   step-present               the vacuity contract: if a step or its script
//                              cannot be found, this test fails rather than
//                              passing over nothing
//   module-suites              the five ported suites run, and a floor makes an
//                              empty run a failure rather than a pass

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'release-pr-closing-keywords');
const ACTION = path.join(ACTION_DIR, 'action.yml');
const STUB = path.join(ACTION_DIR, 'stub-gh.cjs');

// The floor moves only UP. 125 is what the ported suites enumerate today.
//
// It was 115 against 121 actual cases, and that slack was itself a finding
// (#39): six deletions fitted underneath it, so removing merge-backstop-cli's
// whole suite left the harness green with "116 passing". A floor with room in
// it measures nothing but the room.
const CASE_FLOOR = 125;

// The shell/contract half was counted by NOTHING. `report()` tallies failures,
// not assertions, so deleting the flagship grade-fails-open-issue block simply
// removed its lines from the output and the run stayed green — the same vacuous
// pass the module floor exists to prevent, on the half that executes the real
// action bodies. Raise it when assertions are added, the same rule as above.
const SHELL_ASSERTION_FLOOR = 33;

const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'release-pr-guard-selftest-'));

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

/* ------------------------------------------------------------------ *
 * Extract the shell bodies from the composite action.
 * ------------------------------------------------------------------ */

/**
 * Every `run: |` block in the action, keyed by its step's `id:`.
 *
 * Keyed by id and not by position: a step reordered or renamed must not
 * silently re-point a case at a different script. A step with no id is a
 * failure here rather than a block this file quietly skips.
 */
function extractRunBlocks(yaml) {
    const lines = yaml.split(/\r?\n/);
    const stepsAt = lines.findIndex((l) => /^ {2}steps:\s*$/.test(l));
    if (stepsAt === -1) return { error: 'no `steps:` list in the action' };

    const blocks = new Map();
    let id = null;
    for (let i = stepsAt + 1; i < lines.length; i++) {
        const line = lines[i];
        const idAt = /^ {6}id: (\S+)\s*$/.exec(line);
        if (idAt) {
            id = idAt[1];
            continue;
        }
        if (!/^\s+run:\s*\|\s*$/.test(line)) continue;
        if (!id) return { error: `a \`run: |\` block at line ${i + 1} belongs to a step with no id:` };

        // Indent comes from the first NON-BLANK line of the block. Taking it
        // from `i + 1` unconditionally would turn a block that merely opens
        // with a blank line -- which is what deleting the `set -euo pipefail`
        // line leaves behind -- into "block is empty", and this file would then
        // report that instead of running the cases against the guard it still
        // has.
        let first = i + 1;
        while (first < lines.length && lines[first].trim() === '') first += 1;
        const indent = /^(\s+)/.exec(lines[first] || '');
        if (!indent) return { error: `step \`${id}\`'s \`run: |\` block is empty` };

        const script = [];
        for (let j = i + 1; j < lines.length; j++) {
            if (lines[j].trim() === '') {
                script.push('');
                continue;
            }
            if (!lines[j].startsWith(indent[1])) break;
            script.push(lines[j].slice(indent[1].length));
        }
        blocks.set(id, script.join('\n'));
        id = null;
    }
    return { blocks };
}

const extracted = extractRunBlocks(fs.readFileSync(ACTION, 'utf8'));
if (extracted.error) {
    console.error(`  FAIL vacuity: ${extracted.error}`);
    console.error('\ntest-release-pr-closing-keywords: the guard this file exists to prove could not be found, which is a failure and not a pass.');
    process.exit(1);
}

const WANTED = ['contract', 'pull-request', 'link-regrade', 'merge-backstop'];
for (const id of WANTED) {
    report(extracted.blocks.has(id), `extracted the \`${id}\` step's script from action.yml`);
}
if (WANTED.some((id) => !extracted.blocks.has(id))) {
    console.error('\ntest-release-pr-closing-keywords: a mode of the guard is missing, which is a failure and not a pass.');
    process.exit(1);
}

// The extraction has to be of the REAL scripts, not of empty matches that then
// "pass" every case below.
report(
    extracted.blocks.get('pull-request').includes('node "$ACTION_PATH/verify.mjs"'),
    'the extracted pull-request script runs the verifier',
);
report(
    extracted.blocks.get('pull-request').includes('-X POST "repos/$REPO/statuses/$head_sha"'),
    'the extracted pull-request script posts a commit status on the head SHA',
);
report(
    extracted.blocks.get('contract').includes('Unknown mode'),
    'the extracted contract script rejects a mode the action does not implement',
);
report(
    extracted.blocks.get('link-regrade').includes('link-regrade.sh'),
    'the extracted link-regrade script runs the extracted re-grade script',
);
// THE INVOCATION LINES MUST NOT SWALLOW A FAILURE (#39).
//
// action.yml claims, six lines above the merge-backstop invocation, that the
// mode "FAILS rather than skipping, because there is no `|| true` in the repair
// path". Nothing executed those two lines, so the claim and the code could
// diverge in silence: appending `|| true` to either passed the whole suite.
//
// Asserted on the extracted body rather than on a grep of action.yml, so a
// second invocation added elsewhere in the same step is covered too.
for (const mode of ['merge-backstop', 'link-regrade']) {
    const body = extracted.blocks.get(mode);
    const swallowing = body
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => !l.startsWith('#'))
        .filter((l) => /(merge-backstop\.mjs|link-regrade\.sh)/.test(l))
        .filter((l) => /\|\|\s*true|\|\|\s*:|;\s*true\b/.test(l));
    report(
        swallowing.length === 0,
        `the extracted ${mode} script's invocation does not swallow a non-zero exit` +
            (swallowing.length ? ` — found: ${swallowing.join(' / ')}` : ''),
    );
}

report(
    extracted.blocks.get('merge-backstop').includes('merge-backstop.mjs'),
    'the extracted merge-backstop script runs the backstop',
);

const scriptPath = (id) => {
    const p = path.join(workRoot, `${id}.sh`);
    fs.writeFileSync(p, extracted.blocks.get(id));
    return p;
};
const PULL_REQUEST_SH = scriptPath('pull-request');
const CONTRACT_SH = scriptPath('contract');

/* ------------------------------------------------------------------ *
 * A `gh` that serves a fixture instead of calling GitHub.
 * ------------------------------------------------------------------ */

const binDir = path.join(workRoot, 'bin');
fs.mkdirSync(binDir);
fs.writeFileSync(path.join(binDir, 'gh'), `#!/bin/sh\nexec node "${STUB}" "$@"\n`, { mode: 0o755 });

// The other `gh`: one that fails the way the real one does on an API error, a
// revoked token or a rate limit. The guard must not read that as "this release
// closes nothing".
const failingBinDir = path.join(workRoot, 'bin-failing');
fs.mkdirSync(failingBinDir);
fs.writeFileSync(
    path.join(failingBinDir, 'gh'),
    '#!/bin/sh\necho "gh: HTTP 403: Resource not accessible by integration" >&2\nexit 1\n',
    { mode: 0o755 },
);

const O = 'sethbacon';
const R = 'terraform-state-manager-backend';
const SHA = (p, f = '0') => (p + f.repeat(40)).slice(0, 40);
const COMMIT = SHA('ca2e5b3');
const HEAD_SHA = SHA('head', 'a');
const CONTEXT = 'release-guard/link-regrade';

// The #480 incident, reduced to the shape that matters: a `Refs #459` trailer
// that release-please rendered as a closing keyword, against an OPEN issue.
const releaseBody = () =>
    ':robot: I have created a release *beep* *boop*\n---\n\n' +
    `## [3.13.0](https://github.com/${O}/${R}/compare/v3.12.0...v3.13.0) (2026-08-25)\n\n### Bug Fixes\n\n` +
    `* segment the storage keys, closes [#459](https://github.com/${O}/${R}/issues/459) ` +
    `([ca2e5b3](https://github.com/${O}/${R}/commit/${COMMIT}))\n`;

const incident = (over = {}) => ({
    pulls: [
        {
            number: 481,
            state: 'open',
            base: 'main',
            headSha: HEAD_SHA,
            headRef: 'release-please--branches--main',
            body: releaseBody(),
            closingIssuesReferences: {
                pageInfo: { hasNextPage: false },
                nodes: [{ number: 459, state: 'OPEN', repository: { name: R, owner: { login: O } } }],
            },
            ...over,
        },
    ],
    commits: { [COMMIT]: 'fix: segment the storage keys\n\nRefs #459' },
    issues: { [`${O}/${R}#459`]: { state: 'open', closed_at: null } },
    statuses: {},
});

let seq = 0;
function runPullRequest(data, { stubDir = binDir, prNumber = '481', prefix = 'release-please--branches--' } = {}) {
    const dir = path.join(workRoot, `case-${(seq += 1)}`);
    fs.mkdirSync(dir);
    const dataFile = path.join(dir, 'data.json');
    const logFile = path.join(dir, 'log.jsonl');
    const summary = path.join(dir, 'summary.md');
    fs.writeFileSync(dataFile, JSON.stringify(data));
    fs.writeFileSync(summary, '');

    const r = spawnSync('bash', [PULL_REQUEST_SH], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            PATH: `${stubDir}${path.delimiter}${process.env.PATH}`,
            STUB_DATA: dataFile,
            STUB_LOG: logFile,
            GH_TOKEN: 'stub',
            REPO: `${O}/${R}`,
            PR_NUMBER: prNumber,
            STATUS_CONTEXT: CONTEXT,
            RELEASE_BRANCH_PREFIX: prefix,
            ACTION_PATH: ACTION_DIR,
            RUN_URL: 'http://example.invalid/run/1',
            GITHUB_STEP_SUMMARY: summary,
        },
    });
    const log = fs.existsSync(logFile)
        ? fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
        : [];
    return { status: r.status, out: `${r.stdout || ''}${r.stderr || ''}`, log };
}

const postedStatuses = (log) =>
    log.filter((e) => e.method === 'POST' && /\/statuses\//.test(e.path));

function runContract(env) {
    const dir = path.join(workRoot, `contract-${(seq += 1)}`);
    fs.mkdirSync(dir);
    const r = spawnSync('bash', [CONTRACT_SH], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            REPO: `${O}/${R}`,
            PR_NUMBER: '481',
            MERGE_SHA: '',
            STATUS_CONTEXT: CONTEXT,
            BASE_BRANCH: 'main',
            RELEASE_BRANCH_PREFIX: 'release-please--branches--',
            ACTION_PATH: ACTION_DIR,
            ...env,
        },
    });
    return { status: r.status, out: `${r.stdout || ''}${r.stderr || ''}` };
}

try {
    console.log('\nthe contract step — a mode that runs no step must not report success:');

    {
        const r = runContract({ MODE: 'pull_request' });
        report(
            r.status !== 0 && /Unknown mode/.test(r.out),
            `contract-unknown-mode: exits ${r.status} naming the unknown mode`,
        );
    }
    {
        const r = runContract({ MODE: 'pull-request', PR_NUMBER: '' });
        report(
            r.status !== 0 && /requires pr-number/.test(r.out),
            `contract-missing-input: mode=pull-request with no pr-number exits ${r.status}`,
        );
    }
    {
        const r = runContract({ MODE: 'merge-backstop', MERGE_SHA: '' });
        report(
            r.status !== 0 && /requires merge-sha/.test(r.out),
            `contract-missing-merge-sha: exits ${r.status}`,
        );
    }
    {
        const r = runContract({ MODE: 'pull-request', ACTION_PATH: workRoot });
        report(
            r.status !== 0 && /is missing from the action/.test(r.out),
            `contract-missing-module: an action_path without the modules exits ${r.status} saying which file`,
        );
    }
    {
        const r = runContract({ MODE: 'link-regrade', RELEASE_BRANCH_PREFIX: '' });
        report(
            r.status !== 0 && /matches every branch/.test(r.out),
            `contract-empty-prefix: an empty prefix exits ${r.status} rather than matching everything`,
        );
    }
    for (const mode of ['pull-request', 'link-regrade', 'merge-backstop']) {
        const r = runContract({ MODE: mode, MERGE_SHA: SHA('deadbeef', 'd') });
        report(r.status === 0, `contract-accepts-${mode}: a correctly-called mode is not obstructed`);
    }

    console.log('\nthe pull-request step — the grade, and the verdict reaching the head SHA:');

    {
        const r = runPullRequest(incident());
        const posts = postedStatuses(r.log);
        report(r.status !== 0, `grade-fails-open-issue: exits ${r.status} on a release that would close an open #459`);
        report(
            /FAIL sethbacon\/terraform-state-manager-backend#459/.test(r.out),
            'grade-fails-open-issue: says WHICH issue, by name',
        );
        report(
            posts.length === 1 && posts[0].fields.state === 'failure' && posts[0].path.endsWith(`/statuses/${HEAD_SHA}`),
            'status-posted-before-fail: a FAILURE status reached the head SHA even though the step then failed',
        );
        report(
            posts.length === 1 && posts[0].fields.context === CONTEXT,
            'status-posted-before-fail: under the shared context, which is what the cron overwrites',
        );
    }
    {
        // The same release, with a commit that deliberately closes #459. The
        // whole point of the guard: `Refs` and `Closes` stop being the same
        // thing the moment they reach it.
        const data = incident();
        data.commits[COMMIT] = 'fix: segment the storage keys\n\nCloses #459';
        const r = runPullRequest(data);
        const posts = postedStatuses(r.log);
        report(r.status === 0, `grade-passes-deliberate: exits ${r.status} when a commit closes it on purpose`);
        report(
            posts.length === 1 && posts[0].fields.state === 'success',
            'grade-passes-deliberate: posts a SUCCESS status',
        );
    }
    {
        // A pull request release-please did not create. It must still receive a
        // passing status: a required context that only some pull requests ever
        // get blocks the rest forever.
        const data = incident({ headRef: 'feat/some-ordinary-branch' });
        const r = runPullRequest(data);
        const posts = postedStatuses(r.log);
        report(r.status === 0, `non-release-pr-still-posts: exits ${r.status}`);
        report(
            posts.length === 1 && posts[0].fields.state === 'success' && /Not a release pull request/.test(posts[0].fields.description),
            'non-release-pr-still-posts: posts a passing status anyway, so the context is never missing',
        );
        report(
            !/verify/.test(r.out) || /nothing to check/.test(r.out),
            'non-release-pr-still-posts: short-circuits rather than grading a body release-please never wrote',
        );
    }
    {
        // The status must land on the SHA the body was read beside. The source
        // took the ref and body from the API but the SHA from the event
        // payload; taking all three from one response is what closes that skew.
        const data = incident({ headSha: SHA('newer', 'b') });
        const r = runPullRequest(data);
        const posts = postedStatuses(r.log);
        report(
            posts.length === 1 && posts[0].path.endsWith(`/statuses/${SHA('newer', 'b')}`),
            'status-goes-to-api-sha: posted to the head SHA read from the API alongside the body',
        );
    }
    {
        const r = runPullRequest(incident(), { stubDir: failingBinDir });
        report(
            r.status !== 0,
            `gh-unavailable: exits ${r.status} rather than treating an unreadable pull request as clean`,
        );
        report(
            postedStatuses(r.log).length === 0,
            'gh-unavailable: posts no status at all, rather than a success it cannot justify',
        );
    }

    /* -------------------------------------------------------------- *
     * The five ported module suites.
     * -------------------------------------------------------------- */

    console.log('\nthe ported module suites:');

    // THE COUNT IS NOT DECORATION. `node --test` over a directory containing no
    // test files exits 0 -- it prints "tests 0 ... pass 0 ... fail 0" and
    // returns success. A renamed file, a wrong working directory or a bad glob
    // would therefore report exactly like a passing suite, which is the same
    // vacuous green the guard beside it exists to catch. The floor is what makes
    // this mean anything, and it moves only up.
    const suites = spawnSync('node', ['--test', '--test-reporter=tap'], {
        cwd: ACTION_DIR,
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
    });
    const tap = `${suites.stdout || ''}${suites.stderr || ''}`;
    const readCount = (label) => {
        const m = [...tap.matchAll(new RegExp(`^# ${label} (\\d+)$`, 'gm'))];
        return m.length ? Number(m[m.length - 1][1]) : null;
    };
    const passed = readCount('pass');
    const failed = readCount('fail');

    if (passed === null || failed === null) {
        console.error(tap);
        report(false, 'module-suites: could not read a case count out of the TAP summary; refusing to report a pass');
    } else {
        if (failed !== 0 || suites.status !== 0) console.error(tap);
        report(failed === 0 && suites.status === 0, `module-suites: ${passed} passing, ${failed} failing`);
        report(
            passed >= CASE_FLOOR,
            `module-suites: enumerated ${passed} case(s), floor is ${CASE_FLOOR}`,
        );
    }
} finally {
    fs.rmSync(workRoot, { recursive: true, force: true });
}

// The shell/contract floor, checked AFTER everything has reported. It counts
// the assertions this file made, including the two module-suite reports, so it
// is a statement about this harness rather than about node:test.
if (assertions < SHELL_ASSERTION_FLOOR) {
    console.error(
        `  FAIL harness: made ${assertions} assertion(s), floor is ${SHELL_ASSERTION_FLOOR}. ` +
            'Assertions were deleted, or a block stopped running and took its reports with it — ' +
            'which is indistinguishable from a clean run in the output above.',
    );
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${SHELL_ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ntest-release-pr-closing-keywords: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-release-pr-closing-keywords: all cases pass.');
