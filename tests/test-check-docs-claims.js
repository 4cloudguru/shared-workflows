#!/usr/bin/env node
'use strict';

// Self-test for .github/actions/check-docs-claims.
//
// Ported from `scripts/test-check-docs-claims.js` in the three ADO extensions
// (azure-pipelines-terraform, azure-pipelines-packer,
// azure-pipelines-release-docs), which carried byte-identical copies of it
// beside copies of the gate that had ALREADY drifted. What changed in the port
// is the file it drives — the REAL script at
// .github/actions/check-docs-claims/check-docs-claims.js, which is the same
// file every consumer's pinned SHA resolves to, so a regression here is a
// regression in all three at once.
//
// Every case builds a minimal fixture repository, runs the gate as a SUBPROCESS
// with `--json`, and asserts on its `findings` — filtered to the surface under
// test, so drift in a surface a case is not about can never make it flaky. The
// gate checks six surfaces and this file covers three of them; the other three
// (the control ledger, the CONTRIBUTING ci-jobs region, THIRD_PARTY_NOTICES)
// need fixtures shaped like a whole extension and are covered by running the
// gate against the real extension trees, which is what signature replay does.
//
// TWO OF THESE CASES ARE MUTATIONS, in the sense the estate means it: they
// break the thing the gate protects and watch it go red. Case 2 is the one the
// gate's own header nominates ("rename the documented workflow -> the gate goes
// red"); deleting the workflow from the fixture is the same defect a real
// `git mv` of release-pr-guard.yml would produce. Case 5 is a docs table naming
// a source file that is not there. A guard nobody has watched fail is not a
// guard.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync, execFileSync } = require('child_process');

const SCRIPT = path.join(
    __dirname,
    '..',
    '.github',
    'actions',
    'check-docs-claims',
    'check-docs-claims.js',
);
const CONTEXT = 'release-guard/link-regrade';
const WORKFLOW_REL = '.github/workflows/release-pr-guard.yml';

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
 * A minimal repo root: a git tree (the path-ref check shells out to
 * `git check-ignore`, and a check that cannot answer must not pass), SECURITY.md
 * and README.md (both are required, or the gate fails for vacuity instead of
 * for the thing under test), and a README carrying the required-checks table.
 * `workflowBody` is written at WORKFLOW_REL unless omitted — that omission IS
 * the rename/delete mutation.
 */
function fixture(name, { workflowBody, extraReadme = [], build } = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `docs-claims-${name}-`));
    execFileSync('git', ['init', '-q'], { cwd: root });
    fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(root, 'SECURITY.md'), '# Security\n');
    fs.writeFileSync(
        path.join(root, 'README.md'),
        [
            '# Fixture',
            '',
            '<!-- required-checks:begin -->',
            '| Context | Workflow |',
            '| --- | --- |',
            `| \`${CONTEXT}\` | \`${WORKFLOW_REL}\` |`,
            '<!-- required-checks:end -->',
            '',
            ...extraReadme,
            '',
        ].join('\n'),
    );
    if (workflowBody !== undefined) {
        fs.writeFileSync(path.join(root, WORKFLOW_REL), workflowBody);
    }
    if (build) build(root);
    return root;
}

function run(root) {
    const r = spawnSync(process.execPath, [SCRIPT, root, '--json'], { encoding: 'utf8' });
    let body;
    try {
        body = JSON.parse(r.stdout);
    } catch {
        throw new Error(`unparseable output for ${root}:\n${r.stdout}\n${r.stderr}`);
    }
    return { code: r.status, body };
}

const contextFindings = (j) => j.findings.filter((f) => f.kind === 'path-ref' && f.message.includes(CONTEXT));

// The script has to actually be at the path the action invokes. Asserted first,
// because every case below would otherwise fail with a node error that reads
// like a gate defect rather than a missing file.
report(fs.existsSync(SCRIPT), 'the gate is where the action invokes it from');

// ── 1. clean: the documented workflow declares statuses: write ──────────────
{
    const root = fixture('clean', {
        workflowBody: [
            'name: Release PR Guard',
            'jobs:',
            '  closing-keywords:',
            '    name: Release PR closes only what it completes',
            '    permissions:',
            '      statuses: write',
            '    runs-on: ubuntu-latest',
            '    steps: []',
            '',
        ].join('\n'),
    });
    const hits = contextFindings(run(root).body);
    report(hits.length === 0, 'a workflow that declares statuses: write satisfies the documented context');
    fs.rmSync(root, { recursive: true, force: true });
}

// ── 2. MUTATION: the documented workflow has been renamed or deleted ────────
{
    const root = fixture('renamed', {});
    const { code, body } = run(root);
    const hits = contextFindings(body);
    report(code === 1, 'a renamed/deleted workflow turns the gate red');
    report(hits.length === 1 && /does not exist/.test(hits[0].message),
        'it is reported, by name, against this exact context');
    fs.rmSync(root, { recursive: true, force: true });
}

// ── 3. the workflow exists but can post neither a status nor a check run ────
//
// The half that makes this a provenance check rather than a path check: a
// documented workflow that cannot produce the context is a claim about who
// produces a required check that nobody produces.
{
    const root = fixture('cannot-post', {
        workflowBody: [
            'name: Release PR Guard',
            'jobs:',
            '  closing-keywords:',
            '    name: Some Unrelated Job',
            '    permissions:',
            '      contents: read',
            '    runs-on: ubuntu-latest',
            '    steps: []',
            '',
        ].join('\n'),
    });
    const hits = contextFindings(run(root).body);
    report(hits.length === 1 && /cannot post this context/.test(hits[0].message),
        'a workflow with neither statuses: write nor a matching job name is reported');
    fs.rmSync(root, { recursive: true, force: true });
}

// ── 4. a job named exactly for the context satisfies it too ─────────────────
//
// The check-run shape, as opposed to the commit-status shape case 1 covers.
{
    const root = fixture('job-name-match', {
        workflowBody: [
            'name: Release PR Guard',
            'jobs:',
            '  regrade:',
            `    name: ${CONTEXT}`,
            '    permissions:',
            '      contents: read',
            '    runs-on: ubuntu-latest',
            '    steps: []',
            '',
        ].join('\n'),
    });
    const hits = contextFindings(run(root).body);
    report(hits.length === 0, 'a job named exactly for the context satisfies the claim without statuses: write');
    fs.rmSync(root, { recursive: true, force: true });
}

const OK_WORKFLOW = [
    'name: Release PR Guard',
    'jobs:',
    '  closing-keywords:',
    '    name: Release PR closes only what it completes',
    '    permissions:',
    '      statuses: write',
    '    runs-on: ubuntu-latest',
    '    steps: []',
    '',
].join('\n');

// ── 5. MUTATION: a file table naming a file that is not there ───────────────
//
// A `| File | Role |` table anchored to a Tasks/<Family>/<Task>/src/ directory
// is a COMPLETENESS claim, and it is bidirectional: naming a file that does not
// exist and omitting one that does are both drift. Both directions are asserted
// here, because a gate that only caught the phantom would be green over a
// module nobody documented — which is the direction that hides new code.
{
    const table = [
        '## Sources',
        '',
        'Files in `Tasks/Fam/TaskV1/src/`:',
        '',
        '| File | Role |',
        '| --- | --- |',
        '| `index.ts` | entry point |',
        '| `ghost.ts` | a file that does not exist |',
        '',
    ];
    const root = fixture('file-table-phantom', {
        workflowBody: OK_WORKFLOW,
        extraReadme: table,
        build: (r) => {
            const src = path.join(r, 'Tasks', 'Fam', 'TaskV1', 'src');
            fs.mkdirSync(src, { recursive: true });
            fs.writeFileSync(path.join(src, 'index.ts'), '// entry\n');
            fs.writeFileSync(path.join(src, 'undocumented.ts'), '// nobody wrote this down\n');
        },
    });
    const { code, body } = run(root);
    const hits = body.findings.filter((f) => f.kind === 'file-table');
    report(code === 1, 'a docs table naming a file that does not exist turns the gate red');
    report(hits.some((f) => /names files that do not exist: ghost\.ts/.test(f.message)),
        'the phantom file is named in the finding');
    report(hits.some((f) => /omits: undocumented\.ts/.test(f.message)),
        'the file the table forgot is named too — the claim is checked in both directions');
    report(body.enumerated.fileTables === 1,
        'the table was actually enumerated, so this is a finding and not a coincidence');
    fs.rmSync(root, { recursive: true, force: true });

    // Restored: the same fixture with the table telling the truth passes.
    const clean = fixture('file-table-clean', {
        workflowBody: OK_WORKFLOW,
        extraReadme: [
            '## Sources',
            '',
            'Files in `Tasks/Fam/TaskV1/src/`:',
            '',
            '| File | Role |',
            '| --- | --- |',
            '| `index.ts` | entry point |',
            '| `undocumented.ts` | now documented |',
            '',
        ],
        build: (r) => {
            const src = path.join(r, 'Tasks', 'Fam', 'TaskV1', 'src');
            fs.mkdirSync(src, { recursive: true });
            fs.writeFileSync(path.join(src, 'index.ts'), '// entry\n');
            fs.writeFileSync(path.join(src, 'undocumented.ts'), '// nobody wrote this down\n');
        },
    });
    const after = run(clean);
    report(after.code === 0 && after.body.findings.length === 0,
        'a table that names exactly what is there passes — the gate is not simply always red');
    fs.rmSync(clean, { recursive: true, force: true });
}

// ── 6. a backticked repo-relative path that does not resolve ────────────────
//
// The cheapest overclaim there is: a doc pointing at a script somebody deleted.
// The gate exempts git-ignored paths, so the second half of this case proves the
// exemption is an exemption and not a hole big enough to swallow the check.
{
    const root = fixture('path-ref', {
        workflowBody: OK_WORKFLOW,
        extraReadme: ['Run `scripts/that-was-deleted.js` before releasing.', ''],
    });
    const { code, body } = run(root);
    report(code === 1 && body.findings.some(
        (f) => f.kind === 'path-ref' && /does not exist: scripts\/that-was-deleted\.js/.test(f.message),
    ), 'a backticked path the repository does not carry is reported');
    fs.rmSync(root, { recursive: true, force: true });

    const ignored = fixture('path-ref-ignored', {
        workflowBody: OK_WORKFLOW,
        extraReadme: ['Create `configs/self.json` locally to override the publisher.', ''],
        build: (r) => fs.writeFileSync(path.join(r, '.gitignore'), 'configs/self.json\n'),
    });
    const after = run(ignored);
    report(after.code === 0 && after.body.findings.length === 0,
        'a git-ignored path the repo deliberately does not carry is exempt, as it must be');
    fs.rmSync(ignored, { recursive: true, force: true });
}

// ── the ACTION's own run body, not just the script it calls ─────────────────
//
// Everything above drives the gate directly, which is the half a consumer never
// executes: what a consumer runs is action.yml's `run:` block. The estate has
// been bitten twice by suites that PARSE a shell body while every mutation of
// it ran inert, so this follows the osv-scan idiom — extract the real block by
// its `run: |` marker and by indentation, execute it, assert on what it did.
// A test carrying its own copy of the script passes while the real one rots.

const ACTION = path.join(
    __dirname,
    '..',
    '.github',
    'actions',
    'check-docs-claims',
    'action.yml',
);

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
report(RUN_BODY !== null && RUN_BODY.includes('check-docs-claims.js'),
    'extracted the gate step from action.yml');

// The action must not splice inputs into the script through ${{ }}. That is a
// template substitution performed before bash parses the line, so a value
// carrying a quote becomes shell — zizmor's template-injection audit, and a
// required check on this repository. Asserted on the body, because it is the
// one property a reviewer cannot see by reading the run block alone: the
// interpolation would look like an ordinary variable.
report(!/\$\{\{/.test(RUN_BODY),
    'the gate body interpolates no ${{ }} expression; inputs arrive through env');

/** Run the extracted step with the env the action binds, and report its status. */
function runStep(root, { json = 'false', actionPath } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-claims-step-'));
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, RUN_BODY);
    const r = spawnSync('bash', [script], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            ROOT: root,
            JSON: json,
            ACTION_PATH: actionPath !== undefined ? actionPath : path.dirname(SCRIPT),
        },
    });
    fs.rmSync(dir, { recursive: true, force: true });
    return { status: r.status, stdout: `${r.stdout}${r.stderr}` };
}

{
    const clean = fixture('step-clean', { workflowBody: OK_WORKFLOW });
    report(runStep(clean).status === 0, 'the action step succeeds on a tree whose claims hold');
    report(runStep(clean, { json: 'true' }).stdout.trimStart().startsWith('{'),
        'json=true appends --json, and the report parses as JSON');
    fs.rmSync(clean, { recursive: true, force: true });

    // The exit code has to PROPAGATE. A `|| true`, a pipe or a `set +e`
    // anywhere in that body turns a red gate green, and a filter on the end of
    // a command replaces its exit code outright. This is the same mutation as
    // case 2, driven through the action rather than the script.
    const broken = fixture('step-renamed', {});
    const red = runStep(broken);
    report(red.status === 1, "the gate's exit 1 propagates out of the action step");
    report(red.stdout.includes(CONTEXT), 'the step surfaces the finding rather than swallowing it');

    // A missing script must say so rather than surfacing as a node stack trace,
    // because github.action_path is the whole mechanism pinning the
    // implementation to the caller's `uses:` SHA.
    const absent = runStep(broken, { actionPath: path.join(broken, 'nowhere') });
    report(absent.status !== 0 && /is missing from the action/.test(absent.stdout),
        'a script missing from the action path fails with an error naming it');
    fs.rmSync(broken, { recursive: true, force: true });

    // A root with a space must stay ONE argument.
    const spacedParent = fs.mkdtempSync(path.join(os.tmpdir(), 'docs-claims-spaced-'));
    const spaced = path.join(spacedParent, 'a dir');
    fs.mkdirSync(spaced);
    execFileSync('git', ['init', '-q'], { cwd: spaced });
    fs.mkdirSync(path.join(spaced, '.github', 'workflows'), { recursive: true });
    fs.writeFileSync(path.join(spaced, 'SECURITY.md'), '# Security\n');
    fs.writeFileSync(path.join(spaced, 'README.md'), '# Fixture\n');
    fs.writeFileSync(path.join(spaced, '.github', 'workflows', 'ci.yml'), OK_WORKFLOW);
    report(runStep(spaced).status === 0, 'a root containing a space survives as one argument');
    fs.rmSync(spacedParent, { recursive: true, force: true });
}

// A floor, because a harness that asserted nothing would print no failures and
// exit 0 — the same vacuous green this gate exists to make impossible.
const ASSERTION_FLOOR = 20;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ntest-check-docs-claims: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-check-docs-claims: all cases pass.');
