#!/usr/bin/env node
'use strict';

// Self-test for .github/actions/check-enforced-disciplines.
//
// Ported from `scripts/test-check-enforced-disciplines.js` in
// azure-pipelines-terraform, which sat beside a byte-identical copy of it in
// azure-pipelines-packer and azure-pipelines-release-docs. Every case below is
// one of theirs; what changed is the file it drives. The extensions' copy wrote
// the gate INTO each fixture and ran the fixture's copy, which is the right
// shape when the gate lives in the tree under test and the wrong one here: this
// suite drives the REAL script at
// .github/actions/check-enforced-disciplines/check-enforced-disciplines.js —
// the same file every consumer's pinned SHA resolves to — so a regression here
// is a regression in all three consumers at once, and a mutation of the shipped
// script cannot pass because the test kept a copy of the old one.
//
// Running the real script against a fixture root is exactly what replay does:
// security-orchestration's enforced-disciplines.py resolves ONE canonical gate
// and invokes it as `node <gate> <root>`. The gate takes every path it reads
// from that root argument; its only script-relative resolution is
// `require('./lib/task-dirs.js')`, which is why `lib/` ships inside the action.
//
// WHAT THE CASES ARE FOR. The whole point of this gate is to make a rule fail
// loudly instead of depending on someone remembering it, so a gate that cannot
// itself be SEEN failing is the same defect one level up. Each row builds a
// throwaway repo, violates exactly ONE discipline, and asserts the gate exits
// non-zero NAMING that site — and the baseline row asserts a fully compliant
// repo exits 0, so the rows are not passing because the gate fails on
// everything.
//
// The fixture is a miniature of the real extension layout
// (Tasks/<Family>/<Version>/task.json + src + Tests,
// .github/workflows/{unit-test,pr-checks,release}.yml,
// scripts/check-minor-bumps.js), which is why one `mutate` function per row is
// enough to express a violation.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'check-enforced-disciplines');
const GATE = path.join(ACTION_DIR, 'check-enforced-disciplines.js');
const LIB = path.join(ACTION_DIR, 'lib', 'task-dirs.js');
const ACTION = path.join(ACTION_DIR, 'action.yml');

const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-enforced-disciplines-selftest-'));
const TASK = 'Tasks/DemoTask/DemoTaskV1';

let failures = 0;
let assertions = 0;

function report(ok, message, extra) {
    assertions += 1;
    if (ok) {
        console.log(`  OK   ${message}`);
        return;
    }
    console.error(`  FAIL ${message}`);
    if (extra !== undefined) console.error(extra);
    failures += 1;
}

function write(root, rel, content) {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
}

/**
 * A fixture repo in which every enumerated discipline is enforced.
 *
 * `where` lets a caller place it somewhere other than the scratch root — used
 * by the space-in-the-path case, which is about argument quoting in the
 * action's shell body rather than about any discipline.
 */
function makeCompliantRepo(name, where) {
    const root = path.join(where || scratchDir, name);
    // No copy of the gate is written here: this suite runs the shipped one.
    // The two stubs below exist because the gate asserts their PRESENCE
    // (check-minor-bumps.js) or matches their path out of a workflow body.
    write(root, 'scripts/check-minor-bumps.js', '// stub: presence is what the gate checks\n');
    write(root, 'scripts/bump-minor-versions.js', '// stub\n');
    write(root, 'scripts/publish-marketplace.js', '// stub\n');

    write(root, `${TASK}/task.json`, JSON.stringify({
        id: 'demo',
        version: { Major: 1, Minor: 2, Patch: 0 },
        execution: { Node24: { target: 'src/index.js' }, Node20_1: { target: 'src/index.js' } },
    }, null, 2));
    write(root, `${TASK}/src/index.ts`, 'export const demo = 1;\n');
    // Makes DemoTaskV1 a "verifying" task for discipline 6 below (matched by
    // filename, same as the real gpg-verifier.ts/cosign-verifier.ts/
    // tool-integrity.ts modules) -- the compliant fixture must exercise that
    // discipline too, not just be exempt from it.
    write(root, `${TASK}/src/tool-integrity.ts`, 'export async function verifySha256(): Promise<void> {}\n');
    write(root, `${TASK}/.nycrc.json`, JSON.stringify({ exclude: ['src/**/*.d.ts'] }, null, 2));
    write(root, `${TASK}/Tests/EntryPointL0.ts`, "import '../src/index';\n");

    write(root, '.github/workflows/unit-test.yml', `---
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  build-and-test-demo:
    name: Build and Test Demo
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: ${TASK}
    steps:
      - uses: actions/setup-node@v0
        with:
          node-version: "24"
      - run: npm test
      - uses: actions/setup-node@v0
        with:
          node-version: "20"
      - run: node src/index.js
      - run: npm test
`);
    write(root, '.github/workflows/pr-checks.yml', `---
name: PR Checks
on:
  pull_request:
    branches: [main]
jobs:
  release-pr-minor-bumps:
    name: Release PR Minor Bumps
    runs-on: ubuntu-latest
    steps:
      - run: node scripts/check-minor-bumps.js
`);
    write(root, '.github/workflows/release-pr-minor-bumps.yml', `---
name: Auto-bump
on:
  pull_request:
    branches: [main]
jobs:
  auto-bump:
    name: Auto-bump
    runs-on: ubuntu-latest
    steps:
      - run: node scripts/bump-minor-versions.js
`);
    write(root, '.github/workflows/release.yml', `---
name: Release
on:
  push:
    tags:
      - 'v*'
jobs:
  guard:
    name: Guard
    runs-on: ubuntu-latest
    steps:
      - run: node scripts/check-minor-bumps.js
  publish-marketplace:
    name: Publish to VS Marketplace
    runs-on: ubuntu-latest
    environment: marketplace
    steps:
      - run: node scripts/publish-marketplace.js --vsix "$VSIX_FILE"
`);
    return root;
}

/**
 * The gate, as replay invokes it: `node <gate> <root>`.
 *
 * Both streams are folded into one string because the report is interleaved --
 * `[check]` headers and OK rows go to stdout, FAIL rows to stderr -- and a case
 * asserting on a FAIL row would otherwise have to guess which pipe it landed
 * in.
 */
function runGate(root, extraArgs) {
    const res = spawnSync(process.execPath, [GATE, root, ...(extraArgs || [])], { encoding: 'utf8' });
    return { status: res.status, out: `${res.stdout}${res.stderr}` };
}

// The script and its one import have to actually be where the action invokes
// them from. Asserted first, because every case below would otherwise fail with
// a node module-resolution error that reads like a gate defect.
report(fs.existsSync(GATE), 'the gate is where the action invokes it from');
report(fs.existsSync(LIB), "the gate's lib/task-dirs.js ships inside the action, beside it");

// Each row inverts ONE discipline. `expect` is a substring the failure output
// must contain, so a row cannot pass on an unrelated failure.
const CASES = [
    {
        name: 'entry-point-exercised',
        why: 'a task whose declared execution target no test ever loads',
        mutate: (root) => fs.rmSync(path.join(root, TASK, 'Tests', 'EntryPointL0.ts')),
        expect: 'the execution entry point is never loaded by any test',
    },
    {
        name: 'entry-point-in-coverage',
        why: 'a task that carves its entry point out of the coverage metric',
        mutate: (root) => write(root, `${TASK}/.nycrc.json`, JSON.stringify({ exclude: ['src/**/*.d.ts', 'src/index.js'] }, null, 2)),
        expect: 'excludes src/index.js from the coverage metric',
    },
    {
        name: 'execution-handler-exercised',
        why: 'a declared Node20_1 fallback handler that no CI job ever runs',
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/unit-test.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('          node-version: "20"\n      - run: node src/index.js\n', ''));
        },
        // "test-workflow" rather than "unit-test.yml": the gate reads whichever
        // of unit-test.yml / ci.yml a repo keeps its task tests in.
        expect: 'declares the Node20_1 handler but no test-workflow job',
    },
    {
        name: 'verification-real-tests-under-node20',
        why: 'a verifying task (ships tool-integrity.ts) whose Node 20 leg is load-only smoke, never the real suite',
        // Removes ONLY the trailing real-test step, leaving the Node 20 setup
        // and the load-only smoke check (discipline 3's own concern) intact --
        // this must fire on discipline 6 specifically, not be indistinguishable
        // from the execution-handler-exercised mutation above.
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/unit-test.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('      - run: node src/index.js\n      - run: npm test\n', '      - run: node src/index.js\n'));
        },
        expect: 'only the load-only smoke check (if any) exercises it',
    },
    {
        name: 'minor-bump-enforced/script',
        why: 'the Minor-bump rule with no script implementing it',
        mutate: (root) => fs.rmSync(path.join(root, 'scripts', 'check-minor-bumps.js')),
        expect: 'scripts/check-minor-bumps.js must exist',
    },
    {
        name: 'minor-bump-enforced/auto-bump-workflow',
        why: 'the Minor bumps left to a human to apply on the Release PR',
        mutate: (root) => fs.rmSync(path.join(root, '.github/workflows/release-pr-minor-bumps.yml')),
        expect: 'must run scripts/bump-minor-versions.js on the Release PR',
    },
    {
        name: 'minor-bump-enforced/pr-merge-gate',
        why: 'a Release PR that can merge without the bumps',
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/pr-checks.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('node scripts/check-minor-bumps.js', 'echo skip'));
        },
        expect: 'pr-checks.yml must run scripts/check-minor-bumps.js as a merge gate',
    },
    {
        name: 'minor-bump-enforced/tag-time-guard',
        why: 'a tag that can build and publish without the bumps',
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/release.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('      - run: node scripts/check-minor-bumps.js\n', '      - run: echo skip\n'));
        },
        expect: 'release.yml must run scripts/check-minor-bumps.js before it builds',
    },
    {
        name: 'marketplace-publish-retry',
        why: 'a publish with no bounded retry (the v1.2.7 503 that burned a release)',
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/release.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(
                '      - run: node scripts/publish-marketplace.js --vsix "$VSIX_FILE"',
                '      - run: ./node_modules/.bin/tfx extension publish --vsix "$VSIX_FILE" --auth-type pat',
            ));
        },
        expect: 'no bounded retry',
    },
    {
        name: 'marketplace-token-off-argv',
        why: 'the minted Entra token passed to tfx as a CLI argument',
        mutate: (root) => {
            const p = path.join(root, '.github/workflows/release.yml');
            fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(
                '      - run: node scripts/publish-marketplace.js --vsix "$VSIX_FILE"',
                '      - run: ./node_modules/.bin/tfx extension publish --vsix "$VSIX_FILE" --auth-type pat --token "$ENTRA_TOKEN"',
            ));
        },
        expect: 'passed as a CLI argument',
    },
];

try {
    // Baseline: a compliant fixture must PASS, or every row below is vacuous.
    {
        const root = makeCompliantRepo('compliant');
        const { status, out } = runGate(root);
        report(status === 0, 'a fully compliant repo passes the gate', status === 0 ? undefined : out);
        report(/all \d+ enumerated disciplines are enforced/.test(out),
            'a passing run still says how much it enumerated — exit 0 over nothing is not a pass');
    }

    // The gate must recognise the CURRENT publish shape too: publishing through
    // the shared 4cloudguru/shared-workflows composite action, adopted after
    // v1.15.2's release died to the exact defect this discipline exists to
    // catch. A gate that stopped recognising the discipline the moment every
    // consumer actually migrated to it would be green for the wrong reason --
    // the same vacuous pass the local-wrapper shape used to leave for a repo
    // that never wired the check in at all.
    {
        const root = makeCompliantRepo('shared-action-compliant');
        const p = path.join(root, '.github/workflows/release.yml');
        fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(
            '      - run: node scripts/publish-marketplace.js --vsix "$VSIX_FILE"',
            '      - uses: 4cloudguru/shared-workflows/.github/actions/publish-marketplace@9c0851095cc6deeafcd1038fab0b57be0c74cd78 # v1.19.0\n'
            + '        with:\n'
            + '          vsix-path: ${{ steps.mint-token.outputs.vsix-file }}\n'
            + '          marketplace-token: ${{ steps.mint-token.outputs.token }}',
        ));
        const { status, out } = runGate(root);
        report(
            status === 0 && out.includes('shared publish-marketplace composite action'),
            'a repo publishing through the shared composite action passes, naming it as the reason',
            status === 0 ? undefined : out,
        );
    }

    // ...and must not be fooled by a job that merely NAMES the shared action in
    // prose (a comment, a doc reference) without actually calling it -- proving
    // the match is on the real `uses:` line, not a coincidental substring.
    {
        const root = makeCompliantRepo('shared-action-mention-only');
        const p = path.join(root, '.github/workflows/release.yml');
        fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(
            '      - run: node scripts/publish-marketplace.js --vsix "$VSIX_FILE"',
            '      # See 4cloudguru/shared-workflows/.github/actions/publish-marketplace for the general idea.\n'
            + '      - run: ./node_modules/.bin/tfx extension publish --vsix "$VSIX_FILE" --auth-type pat',
        ));
        const { status, out } = runGate(root);
        report(
            status !== 0 && out.includes('no bounded retry'),
            'a comment merely mentioning the shared action does not satisfy the discipline',
            status !== 0 ? undefined : out,
        );
    }

    for (const c of CASES) {
        const root = makeCompliantRepo(c.name.replace(/\//g, '-'));
        c.mutate(root);
        const { status, out } = runGate(root);
        report(
            status !== 0 && out.includes(c.expect),
            `${c.name}: the gate fires on ${c.why}`,
            status !== 0 && out.includes(c.expect) ? undefined : out,
        );
    }

    // An empty universe must not pass silently: a gate that enumerates nothing
    // is indistinguishable from one that found no problems. This is also the
    // case that notices a root failing to ARRIVE -- the gate falls back to the
    // process cwd, and under a composite action that cwd is a checkout with no
    // Tasks/ as often as not.
    {
        const root = path.join(scratchDir, 'no-tasks');
        write(root, 'scripts/check-minor-bumps.js', '// stub\n');
        const { status, out } = runGate(root);
        report(
            status !== 0 && out.includes('empty universe'),
            'a repo with no task directories fails rather than trivially passing',
            status !== 0 ? undefined : out,
        );
    }

    // The positional root is load-bearing in both directions: pointed at THIS
    // repository (which has no Tasks/) the gate must refuse rather than report
    // a clean tree, and pointed at the fixture it must read the fixture.
    {
        const here = runGate(path.join(__dirname, '..'));
        report(here.status !== 0 && here.out.includes('empty universe'),
            'pointed at this repository the gate refuses: a root that fails to arrive cannot look like a pass');
        const there = runGate(makeCompliantRepo('root-is-load-bearing'));
        report(there.status === 0, 'pointed at a compliant fixture it reads the fixture');
    }

    // `--json` is not a mode this gate has. It is ignored rather than rejected
    // by the script -- `process.argv[2]` is the root and nothing else is read --
    // which is exactly why the ACTION refuses the input instead of forwarding
    // it. Asserted here so that the day canonical grows a `--json` reporter,
    // this case goes red and the action's refusal gets revisited with it.
    {
        const root = makeCompliantRepo('json-is-ignored');
        const plain = runGate(root);
        const flagged = runGate(root, ['--json']);
        report(flagged.status === plain.status && flagged.out === plain.out,
            'the script ignores --json entirely — same exit, same bytes — so the action must refuse the input rather than forward it');
    }

    // ── the ACTION's own run body, not just the script it calls ─────────────
    //
    // Everything above drives the gate directly, which is the half a consumer
    // never executes: what a consumer runs is action.yml's `run:` block. The
    // estate has been bitten twice by suites that PARSE a shell body while
    // every mutation of it ran inert, so this follows the osv-scan idiom --
    // extract the real block by its `run: |` marker and by indentation,
    // execute it, assert on what it did.

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
    report(RUN_BODY !== null && RUN_BODY.includes('check-enforced-disciplines.js'),
        'extracted the gate step from action.yml');

    // The action must not splice inputs into the script through ${{ }}. That is
    // a template substitution performed before bash parses the line, so a value
    // carrying a quote becomes shell -- zizmor's template-injection audit, and a
    // required check on this repository. Asserted on the body, because it is the
    // one property a reviewer cannot see by reading the run block alone: the
    // interpolation would look like an ordinary variable.
    report(!/\$\{\{/.test(RUN_BODY),
        'the gate body interpolates no ${{ }} expression; inputs arrive through env');

    /** Run the extracted step with the env the action binds, and report its status. */
    function runStep(root, { json = 'false', actionPath } = {}) {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'disciplines-step-'));
        const script = path.join(dir, 'step.sh');
        fs.writeFileSync(script, RUN_BODY);
        const r = spawnSync('bash', [script], {
            cwd: dir,
            encoding: 'utf8',
            env: {
                ...process.env,
                ROOT: root,
                JSON: json,
                ACTION_PATH: actionPath !== undefined ? actionPath : ACTION_DIR,
            },
        });
        fs.rmSync(dir, { recursive: true, force: true });
        return { status: r.status, stdout: `${r.stdout}${r.stderr}` };
    }

    {
        const root = makeCompliantRepo('step-fixture');
        report(runStep(root).status === 0, 'the action step succeeds on a compliant tree');

        // The exit code has to PROPAGATE. A `|| true`, a pipe or a `set +e`
        // anywhere in that body turns a red gate green, and a filter on the end
        // of a command replaces its exit code outright.
        const p = path.join(root, '.github/workflows/unit-test.yml');
        fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('          node-version: "20"\n      - run: node src/index.js\n', ''));
        const broken = runStep(root);
        report(broken.status === 1, "the gate's exit 1 propagates out of the action step");
        report(/declares the Node20_1 handler but no test-workflow job/.test(broken.stdout),
            'the step surfaces the finding rather than swallowing it');

        // json=true is refused, and refused BEFORE the gate runs -- otherwise a
        // caller who asked for machine output would get the human report and
        // believe it was JSON. The compliant half of the assertion is that the
        // gate's own report is absent from the output.
        const asJson = runStep(root, { json: 'true' });
        report(asJson.status !== 0 && /has no --json mode/.test(asJson.stdout),
            'json=true is refused with an error naming the gate, not silently ignored');
        report(!/\[execution-handler-exercised\]/.test(asJson.stdout),
            'the json=true refusal happens before the gate runs, so no report is emitted to be mistaken for JSON');
        report(runStep(root, { json: 'false' }).stdout.includes('[execution-handler-exercised]'),
            'json=false runs the gate and leaves its human report in place');
    }

    {
        // A root with a space must stay ONE argument.
        const spacedParent = path.join(scratchDir, 'a dir');
        fs.mkdirSync(spacedParent, { recursive: true });
        const spaced = makeCompliantRepo('spaced', spacedParent);
        report(runStep(spaced).status === 0, 'a root containing a space survives as one argument');
    }

    {
        const root = makeCompliantRepo('preflight-fixture');

        // A missing script must say so rather than surfacing as a node stack
        // trace, because github.action_path is the whole mechanism pinning the
        // implementation to the caller's `uses:` SHA.
        const absent = runStep(root, { actionPath: path.join(scratchDir, 'nowhere') });
        report(absent.status !== 0 && /check-enforced-disciplines\.js is missing from the action/.test(absent.stdout),
            'a script missing from the action path fails with an error naming it');

        // ...and a checkout that carried the gate but not its lib/ must fail on
        // the lib, not on `Cannot find module`. This is the failure an
        // incomplete port of THIS action produces, so it gets its own message
        // and its own case.
        const noLib = path.join(scratchDir, 'action-without-lib');
        fs.mkdirSync(noLib, { recursive: true });
        fs.copyFileSync(GATE, path.join(noLib, 'check-enforced-disciplines.js'));
        const libless = runStep(root, { actionPath: noLib });
        report(libless.status !== 0 && /lib\/task-dirs\.js is missing from the action/.test(libless.stdout),
            'an action shipped without lib/task-dirs.js fails naming the lib, not with a module-resolution trace');
    }

    {
        // THE CALLER'S OWN COPY OF lib/task-dirs.js IS COMPARED TOO.
        //
        // `scripts/check-enforced-disciplines.js` leaves the three consumers in
        // this release; `scripts/lib/task-dirs.js` cannot, because four to six
        // non-gate scripts per repository import it and one of them,
        // copy-build.js, decides what ships inside the signed .vsix. Replay's
        // gatelib compares a consumer's ENTRY POINT against canonical and
        // nothing else, so the moment the entry point leaves, that lib is
        // compared by nobody. The action's step closes the hole, and this pair
        // of cases is the proof: a caller carrying the identical file passes,
        // and one byte of drift is a red step naming the file.
        //
        // Derived from the file's presence, with no input: the ABSENT case is
        // every fixture above, all of which still pass, which is what says the
        // check is silent on a tree that does not carry the file at all.
        const identical = makeCompliantRepo('task-dirs-identical');
        write(identical, 'scripts/lib/task-dirs.js', fs.readFileSync(LIB, 'utf8'));
        report(runStep(identical).status === 0,
            "a caller whose scripts/lib/task-dirs.js is identical to the action's copy passes");

        const drifted = makeCompliantRepo('task-dirs-drifted');
        // ONE byte, and a semantically inert one: the point is that the
        // comparison is over bytes, not over behaviour. A drift that changed
        // discoverTaskDirs would be caught by other things; a drift that only
        // looks harmless is the one nothing else in the estate can see.
        write(drifted, 'scripts/lib/task-dirs.js', `${fs.readFileSync(LIB, 'utf8')} `);
        const bad = runStep(drifted);
        report(bad.status === 1, 'one byte of drift in the caller\'s copy fails the step');
        report(/scripts\/lib\/task-dirs\.js differs from this action's copy/.test(bad.stdout),
            'and the error names the file and says where to re-sync it from');
        report(!/\[execution-handler-exercised\]/.test(bad.stdout),
            'and it is refused before the gate runs, so the drift is not buried under a clean report');

        // COULD-NOT-READ IS NOT DRIFT, AND THE MESSAGE HAS TO SAY WHICH.
        //
        // `cmp -s` returns 1 for "the files differ" and 2 for "one of them could
        // not be read". Folded into one `||` arm, both produced the drift
        // message, which sends the reader to re-sync a file that is byte-
        // identical. Both are still refusals -- the step must never run the gate
        // over a repository whose shared lib it could not read -- so what is
        // asserted here is the exit code AND which of the two messages appears.
        report(/cmp_status/.test(RUN_BODY) && /could not be compared/.test(RUN_BODY),
            "the shipped body branches on cmp's status rather than folding 1 and 2 into one message");

        const unreadable = makeCompliantRepo('task-dirs-unreadable');
        const hidden = path.join(unreadable, 'scripts/lib/task-dirs.js');
        write(unreadable, 'scripts/lib/task-dirs.js', fs.readFileSync(LIB, 'utf8'));
        fs.chmodSync(hidden, 0o000);
        let readable = true;
        try { fs.readFileSync(hidden); } catch { readable = false; }
        if (readable) {
            // Running as root, where mode 000 is still readable. The static
            // assertion above is what covers the branch in that environment;
            // this one records why the dynamic case did not run rather than
            // silently passing.
            report(process.getuid !== undefined && process.getuid() === 0,
                'the unreadable case is only skippable as root, and this run is root');
        } else {
            const blocked = runStep(unreadable);
            report(blocked.status === 1, 'a caller copy that cannot be READ fails the step too, closed rather than open');
            report(/could not be compared with this action's copy/.test(blocked.stdout),
                'and says it could not be compared, not that it differs -- the file is byte-identical');
            report(!/differs from this action's copy/.test(blocked.stdout),
                'so the reader is not sent to re-sync a file that is already in step');
        }
        fs.chmodSync(hidden, 0o644);
    }
} finally {
    fs.rmSync(scratchDir, { recursive: true, force: true });
}

// A floor, because a harness that asserted nothing would print no failures and
// exit 0 -- the same vacuous green this gate exists to make impossible.
const ASSERTION_FLOOR = 35;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ntest-check-enforced-disciplines: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-check-enforced-disciplines: all cases pass.');
