#!/usr/bin/env node
'use strict';
// Self-test for .github/actions/auth-parity-matrix.
//
// PORTED, NOT REWRITTEN. Everything down to the `── the ACTION's own run body`
// banner is security-orchestration's `remediation/gates/test-auth-parity-matrix.js`
// at its origin/main, with ONE logic edit: the path the gate is resolved from
// (see ACTION_DIR below). Canonical is the parent of the script this action
// ships and of this suite; a case rewritten here rather than there is drift in
// the same way a re-worded comment in the gate is. The section below the banner
// is additive and belongs only here, because it tests action.yml — a file
// canonical does not have.
//
// ── canonical's own header follows ─────────────────────────────────────────
//
// THIS GATE HAS NEVER HAD ONE, in this repository or in any of the three
// extensions that carry a copy of it. It is the instrument
// provider-auth-failclosed delegates to, it is spawned under `npm test` by two
// task L0 suites in each of the two extensions that authenticate to a provider,
// and every one of those callers asserts on its verdicts. Nothing has ever
// watched it be wrong. It is written canonically here first so the composite
// action that ships it upstream has a parent to be `cp`'d from, rather than a
// suite invented beside the copy.
//
// Every case builds a fixture repository, runs the real script over it as a
// SUBPROCESS, and asserts on the --json verdict. Cells are keyed by SITE --
// `<handler>.<branch>.<cell>`, all three of the axes the gate's own header
// declares -- never by the bare cell name, because the branch is what the four
// consumer L0 tables deepStrictEqual against and a cell-keyed suite is
// self-consistent for any branch label the gate cares to invent. The reported
// TOTALS are asserted over fixtures whose true totals are not zero, in both
// output modes, because `report.unguarded` is the one field those same suites
// make their structural assertion on and a gate hard-wiring it to 0 agrees with
// every measurement taken over an all-guarded fixture. The fixture is derived from
// what the gate actually RECOGNISES -- the WIF conditional `scopeMap` keys a
// branch off, the accessor table, the guard helpers, the OIDC entry points, the
// PKR_VAR_ delivery detector and the credential-bearing env-var set -- because
// a fixture the gate cannot see is a test of nothing: it would enumerate zero
// cells, exit 0, and every assertion below would be green about an empty table.
// The vacuity cases at the end exist to keep that failure visible: "no handler
// files here" and "this walk started in the wrong directory" are the same zero,
// and only the `scanned` denominator separates them.
//
// The clean fixture is a SINGLE arrangement that every mutation case perturbs by
// exactly one guard. That is deliberate: a suite whose red cases each build
// their own fixture proves the gate can produce an UNGUARDED verdict, which is
// not the question. The question is whether removing one guard from code the
// gate calls clean is enough to turn that one cell red -- so every red case
// below is the green fixture minus one named thing, and the assertion names the
// cell that has to move.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// THE ONE LOGIC EDIT THIS PORT MAKES. Canonical resolves the gate beside itself
// in `remediation/gates/`; here it lives inside the composite action, so the
// suite drives the REAL shipped script at
// .github/actions/auth-parity-matrix/auth-parity-matrix.cjs — the same file
// every consumer's pinned SHA resolves to. Same three-line shape
// tests/test-check-enforced-disciplines.js already uses.
const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'auth-parity-matrix');
const ACTION = path.join(ACTION_DIR, 'action.yml');
const GATE = path.join(ACTION_DIR, 'auth-parity-matrix.cjs');
const EXEMPT_REASON = 'the fixture template declares every variable it is handed';

let failures = 0;
const report = (ok, msg) => {
    if (ok) console.log(`  OK   ${msg}`);
    else { console.error(`  FAIL ${msg}`); failures += 1; }
};

// --------------------------------------------------------------- the fixture

// One credential-bearing PKR_VAR_ secret and one identity selector, delivered
// from a WIF branch. Six of the gate's cell kinds are reachable in this one
// handler, and each is held up by exactly one line, so `drop` names a guard and
// removes precisely it. `exempt` puts a machine-readable marker where that
// guard was, which is the only thing that turns an UNGUARDED cell into an
// EXEMPT one.
//
// The names in here are not decoration. `-command-handler.ts` under a `src/`
// directory is what `discoverHandlers` keys off; `if (authScheme === 'Workload
// IdentityFederation')` is what `WIF_IF_RE` keys the branch off;
// `requireIdentityField` is in `GUARD_HELPERS`; `generateIdToken` is in the
// OIDC set; `PKR_VAR_arm_client_jwt` is both a SECRET_VAR_RE match and a member
// of `FAILCLOSED_CREDENTIAL_ENV`. Change one of them and the cell it produces
// stops existing, which is why the first case asserts the whole cell set by
// name before anything is mutated.
function handler({ drop = [], exempt = null, exemptAbove = false, credentials = true } = {}) {
    const dropped = new Set(drop);
    const line = (name, text) => {
        if (!dropped.has(name)) return text;
        return exempt === name
            ? '            // @credential-exempt: ' + EXEMPT_REASON
            : null;
    };
    if (!credentials) {
        return [
            'export class FixturePackerCommandHandler {',
            '    public async handleProvider(command: ProviderCommand): Promise<void> {',
            '        tasks.debug(`running ${command.name}`);',
            '    }',
            '}',
            '',
        ].join('\n');
    }
    const schemeGuard = dropped.has('scheme-throw')
        ? [
            "            tasks.warning('no authorization scheme declared; assuming MSI');",
            "            return 'ManagedServiceIdentity' as AuthorizationScheme;",
        ]
        : ["            throw new Error('the service connection declares no authorization scheme');"];
    const required = dropped.has('required-flag') ? '' : ', true';
    return [
        "import * as tasks from 'azure-pipelines-task-lib/task';",
        '',
        'export class FixturePackerCommandHandler {',
        '    private mapAuthorizationScheme(scheme: string | undefined): AuthorizationScheme {',
        '        if (!scheme) {',
        ...schemeGuard,
        '        }',
        '        return scheme as AuthorizationScheme;',
        '    }',
        '',
        '    public async handleProvider(command: ProviderCommand): Promise<void> {',
        '        const authScheme = this.mapAuthorizationScheme(',
        '            tasks.getEndpointAuthorizationScheme(command.serviceProviderName, false)',
        '        );',
        ...(exemptAbove ? ['        // @credential-exempt: ' + EXEMPT_REASON] : []),
        "        if (authScheme === 'WorkloadIdentityFederation') {",
        line('neutralize', "            neutralizeEnvironmentVariables(['PKR_VAR_arm_client_secret', 'PKR_VAR_arm_tenant_id']);"),
        line('connection-throw', [
            '            if (!command.serviceProviderName) {',
            "                throw new Error('an empty service connection cannot request a federated token');",
            '            }',
        ].join('\n')),
        "            const clientId = tasks.getEndpointAuthorizationParameter(command.serviceProviderName, 'serviceprincipalid', false);",
        line('identity-field', "            requireIdentityField(clientId, 'serviceprincipalid');"),
        '            const idToken = await generateIdToken(command.serviceProviderName);',
        line('template-declaration', "            assertTemplateDeclaresVariable('arm_client_jwt');"),
        `            setEnvironmentVariable('PKR_VAR_arm_client_id', clientId, false${required});`,
        "            setEnvironmentVariable('PKR_VAR_arm_client_jwt', idToken, true, true);",
        '        }',
        '    }',
        '}',
        '',
    ].filter((l) => l !== null).join('\n');
}

// `discoverHandlers` walks `<root>/Tasks`, descends at most six levels, and
// counts a `.ts` file only when the directory holding it is named `src`. The
// layout below is the one every ADO extension ships, so a case that passes here
// passes over a real repository.
const roots = [];
function tempRoot(name) {
    // realpath, because ROOT is path.resolve()d from argv and every cell's
    // `file` is path.relative(root, ...): on a platform whose temp directory is
    // a symlink an unresolved fixture path leaves every relative path outside
    // its own root.
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `auth-parity-${name}-`)));
    roots.push(root);
    return root;
}

function fixture(name, files, outsideSrc = {}) {
    const root = tempRoot(name);
    const task = path.join(root, 'Tasks', 'Fixture', 'FixtureV1');
    const src = path.join(task, 'src');
    fs.mkdirSync(src, { recursive: true });
    for (const [file, body] of Object.entries(files)) fs.writeFileSync(path.join(src, file), body);
    // Written under the task directory but NOT under `src/`, which is the one
    // boundary `discoverHandlers` draws.
    for (const [file, body] of Object.entries(outsideSrc)) {
        const full = path.join(task, file);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, body);
    }
    return root;
}

const HANDLER_FILE = 'fixture-packer-command-handler.ts';
const clean = (overrides) => ({ [HANDLER_FILE]: handler(overrides) });

// A crash prints no JSON, and a body silently defaulted to `{}` would let every
// assertion below read `undefined` and pass -- the "looked nowhere reads as
// clean" shape this gate exists to refuse. So an unparseable body is surfaced
// as null and every case asserts on a real array.
function run(root, args = ['--json']) {
    const proc = spawnSync(process.execPath, [GATE, root, ...args], { encoding: 'utf8' });
    let body = null;
    if (args.includes('--json')) {
        try { body = JSON.parse(proc.stdout); } catch { /* left null on purpose */ }
    }
    return { code: proc.status, body, stdout: proc.stdout, stderr: proc.stderr };
}

const cellsOf = (body) => (body && Array.isArray(body.cells) ? body.cells : null);
const sitesOf = (body) => [...new Set((cellsOf(body) ?? []).map((c) => c.site))].sort();
const withVerdict = (body, v) => (cellsOf(body) ?? []).filter((c) => c.verdict === v);
// Keyed on the SITE -- `<handler>.<branch>.<cell>` -- and never on the bare
// cell name. `branch` is one of the three axes this gate's header declares as
// its unit of enumeration, it is the axis the class is named for, and it is
// what the four consumer L0 tables deepStrictEqual against. A suite that keyed
// on `cell` alone is self-consistent for ANY branch value: renaming the WIF
// label in the gate would leave it entirely green while every consumer suite in
// the fleet went red. Watched, on a scratch copy: with `WorkloadIdentity-
// Federation` renamed the cell-keyed version of this file was 0 failures.
const verdictOf = (body, site) => {
    const rows = (cellsOf(body) ?? []).filter((c) => c.site === site);
    if (rows.length === 0) return `<no ${site} cell at all>`;
    return rows.some((c) => c.verdict === 'UNGUARDED') ? 'UNGUARDED'
        : rows.some((c) => c.verdict === 'EXEMPT') ? 'EXEMPT' : 'GUARDED';
};

console.log('auth-parity-matrix self-test — the matrix, one guard at a time\n');

// ----------------------------------------------------------------- the green

console.log('a fully guarded handler');

// handler x auth-branch x required-field, spelled out. Two handler-level cells
// and six inside the WIF branch, and the branch label is part of every one of
// them: `schemeResolution` is the synthetic branch the mapper's own verdict is
// filed under, `handleProvider` is the method, and the six that matter carry
// the auth branch itself.
const CLEAN_SITES = [
    'fixture.WorkloadIdentityFederation.competing-credential-env',
    'fixture.WorkloadIdentityFederation.credential-delivery-channel',
    'fixture.WorkloadIdentityFederation.failclosed:PKR_VAR_arm_client_id',
    'fixture.WorkloadIdentityFederation.failclosed:PKR_VAR_arm_client_jwt',
    'fixture.WorkloadIdentityFederation.serviceConnection',
    'fixture.WorkloadIdentityFederation.serviceprincipalid',
    'fixture.handleProvider.scheme',
    'fixture.schemeResolution.authorizationScheme',
];

{
    const root = fixture('clean', clean());
    const { code, body } = run(root);
    const cells = cellsOf(body);
    report(cells !== null && cells.length > 0,
        `the gate enumerates cells over the fixture (${cells === null ? 'no JSON at all' : cells.length})`);
    report(body && body.unguarded === 0, `and none of them is UNGUARDED (${body && body.unguarded})`);
    report(code === 0, `and it exits 0 (exit ${code})`);
    // The inventory, by name. Every red case below is this fixture minus one
    // guard, so a fixture that quietly stopped producing one of these cells
    // would make the matching red case vacuous -- it would assert that a cell
    // which no longer exists is not UNGUARDED, which is true of every string.
    const seen = sitesOf(body);
    report(JSON.stringify(seen) === JSON.stringify(CLEAN_SITES),
        `and the SITES are exactly the ones the red cases perturb, branch label included (${JSON.stringify(seen)})`);
    report((cells ?? []).every((c) => c.verdict === 'GUARDED'),
        'every cell reads GUARDED, so no red case below is measuring a pre-existing failure');
}

// ------------------------------------------------------------- the mutations

console.log('\nremove one guard, and exactly one cell goes red');

const MUTATIONS = [
    ['neutralize', 'fixture.WorkloadIdentityFederation.competing-credential-env',
        'a WIF branch that injects credentials without clearing the competing schemes'],
    ['template-declaration', 'fixture.WorkloadIdentityFederation.credential-delivery-channel',
        'a PKR_VAR_ secret delivered with nothing failing closed when the template omits it'],
    ['required-flag', 'fixture.WorkloadIdentityFederation.failclosed:PKR_VAR_arm_client_id',
        'a credential-bearing setEnvironmentVariable() without required:true'],
    ['connection-throw', 'fixture.WorkloadIdentityFederation.serviceConnection',
        'an empty service connection reaching the OIDC request unchecked'],
    ['identity-field', 'fixture.WorkloadIdentityFederation.serviceprincipalid',
        'an identity selector injected without charset/format validation'],
    ['scheme-throw', 'fixture.schemeResolution.authorizationScheme',
        'an auth-scheme mapper that defaults instead of throwing'],
];

for (const [guard, site, what] of MUTATIONS) {
    const root = fixture(guard, clean({ drop: [guard] }));
    const { code, body } = run(root);
    report(verdictOf(body, site) === 'UNGUARDED', `${what} -> ${site} is UNGUARDED (${verdictOf(body, site)})`);
    report(code === 1, `  and the gate exits 1 (exit ${code})`);
    // THE REPORTED TOTAL, ON A FIXTURE WHOSE TRUE TOTAL IS NOT ZERO. `unguarded`
    // is the single field both consumers' CredentialFailClosedMatrixL0 suites
    // make their structural assertion on (`assert.strictEqual(report.unguarded,
    // 0)`), and every OTHER assertion in this file reads the cells array or the
    // exit code instead. Asserted only over the clean fixture it would agree
    // with a hard-wired `unguarded: 0` -- which is exactly the value a gate
    // reporting nothing would print over a repository with real findings, and
    // the fleet's own suites would then be green about a matrix full of them.
    // Watched: `unguarded: unguarded.length` -> `unguarded: 0` in the gate is 0
    // failures without this block and 6 with it.
    const trueUnguarded = withVerdict(body, 'UNGUARDED').length;
    report(body !== null && trueUnguarded > 0 && body.unguarded === trueUnguarded,
        `  and the reported unguarded TOTAL is the real one (${body && body.unguarded} vs ${trueUnguarded})`);
    const others = withVerdict(body, 'UNGUARDED').filter((c) => c.site !== site);
    // `scheme-throw` is the one guard two cells depend on: the mapper's own cell
    // and the optional read handed to it. Every other removal must move exactly
    // one, or the suite cannot tell which line the verdict is about.
    const expected = guard === 'scheme-throw' ? ['fixture.handleProvider.scheme'] : [];
    const moved = [...new Set(others.map((c) => c.site))].sort();
    report(JSON.stringify(moved) === JSON.stringify(expected),
        `  and nothing else moves (${JSON.stringify(moved)})`);
}

// ------------------------------------------------------------- the exemption

console.log('\nan exemption marker is the only thing that clears a red cell');

for (const [guard, site] of [
    ['neutralize', 'fixture.WorkloadIdentityFederation.competing-credential-env'],
    ['template-declaration', 'fixture.WorkloadIdentityFederation.credential-delivery-channel'],
]) {
    const root = fixture(`${guard}-exempt`, clean({ drop: [guard], exempt: guard }));
    const { code, body } = run(root);
    report(verdictOf(body, site) === 'EXEMPT',
        `${site} with an @credential-exempt marker in its branch is EXEMPT, not UNGUARDED (${verdictOf(body, site)})`);
    const row = (cellsOf(body) ?? []).find((c) => c.site === site);
    report(/^exempt: /.test(row?.detail ?? ''), `  and the claimed reason is carried into the report (${row && row.detail})`);
    report(code === 0, `  and the gate exits 0 (exit ${code})`);
    report(JSON.stringify(sitesOf(body)) === JSON.stringify(CLEAN_SITES),
        '  and the whole inventory is still ENUMERATED -- an exemption is a recorded decision, not a deletion');
}

// `credential-delivery-channel` and the `failclosed:` cells pass strictExempt,
// which is the narrower lookup: the marker must sit INSIDE the branch region,
// where the 14-line lookback every other cell uses would let a marker in a
// PRECEDING branch exempt a genuinely unguarded sibling. That leak is not
// hypothetical -- the gate's own header records it being caught by mutation
// testing on packer, where a ManagedServiceIdentity marker exempted a mutated
// WorkloadIdentityFederation cell.
//
// So the fixture puts the marker where the two lookups DISAGREE: one line above
// the WIF `if`, inside the lenient window and outside the region. A marker at
// the top of the file would fall outside both, and the case would pass with
// strictExempt neutered -- watched: relaxing `strictExemptionFor` back to the
// 14-line lookback left a top-of-file version of this case green.
{
    const root = fixture('marker-out-of-scope', clean({
        drop: ['template-declaration', 'neutralize'],
        exemptAbove: true,
    }));
    const { code, body } = run(root);
    const strict = 'fixture.WorkloadIdentityFederation.credential-delivery-channel';
    const lenient = 'fixture.WorkloadIdentityFederation.competing-credential-env';
    report(verdictOf(body, strict) === 'UNGUARDED',
        `a marker ABOVE the branch does not exempt a strict cell (${verdictOf(body, strict)})`);
    report(verdictOf(body, lenient) === 'EXEMPT',
        `while the same marker DOES reach a lenient cell in that branch, which is what makes the pair discriminating (${verdictOf(body, lenient)})`);
    report(code === 1, `  and the gate still exits 1 (exit ${code})`);
}

// ------------------------------------------------- the no-credentials cell

console.log('\na handler that injects nothing has to say so');

const NO_CREDENTIALS = 'fixture.handleProvider.no-credentials';

{
    const root = fixture('no-credentials', clean({ credentials: false }));
    const { code, body } = run(root);
    report(verdictOf(body, NO_CREDENTIALS) === 'UNGUARDED',
        `a handler with no credential cells and no marker is one UNGUARDED no-credentials cell (${verdictOf(body, NO_CREDENTIALS)})`);
    report(JSON.stringify(sitesOf(body)) === JSON.stringify([NO_CREDENTIALS]),
        `  and it is the WHOLE inventory -- the handler is read, and nothing else in it is a cell (${JSON.stringify(sitesOf(body))})`);
    report(code === 1, `  and the gate exits 1 (exit ${code})`);

    const marked = fixture('no-credentials-marked', {
        [HANDLER_FILE]: handler({ credentials: false }).replace(
            'export class',
            '/** @credential-exempt: this provider authenticates from the agent image only */\nexport class'),
    });
    const second = run(marked);
    report(verdictOf(second.body, NO_CREDENTIALS) === 'EXEMPT',
        `and with the marker it is EXEMPT (${verdictOf(second.body, NO_CREDENTIALS)})`);
    report(second.code === 0, `  and the gate exits 0 (exit ${second.code})`);
}

// ------------------------------------------------------------- the vacuity

console.log('\nzero cells: "looked and found none" is not "looked nowhere"');

{
    // A task tree that is real, walked and read, and simply has no auth handler
    // in it. This is release-docs, measured on origin/main: 0 cells, 0 handler
    // files, 34 source files read. The denominator is the whole answer -- with
    // it the report says the walk worked, without it a gate pointed at the wrong
    // directory looks exactly the same and exits 0 either way.
    const root = fixture('no-handlers', {
        'render.ts': 'export const render = (s: string) => s.toUpperCase();\n',
        'markdown.ts': 'export const toHtml = (s: string) => s;\n',
    });
    const { code, body } = run(root);
    report((cellsOf(body) ?? null)?.length === 0, `a repository with no auth handler reports 0 cells (${cellsOf(body)?.length})`);
    report(body && body.handlerFiles === 0, `and 0 handler files (${body && body.handlerFiles})`);
    report(body && body.scanned === 2, `and a NON-ZERO scanned denominator -- it looked, and there was nothing (${body && body.scanned})`);
    report(code === 0, `and exits 0, which is only safe BECAUSE the denominator is on the record (exit ${code})`);

    // The same zero from the other cause. Nothing distinguishes these two
    // reports except `scanned`, which is the entire reason this pair is here.
    const nowhere = run(tempRoot('nowhere'));
    report((cellsOf(nowhere.body) ?? null)?.length === 0 && nowhere.body?.scanned === 0,
        `a root with no Tasks/ at all reports the same 0 cells with scanned=0 (${nowhere.body && nowhere.body.scanned})`);
    report(body && nowhere.body && body.scanned !== nowhere.body.scanned,
        'so the two zeros are distinguishable in the report, which is what a caller has to key its floor off');
}

// ---------------------------------------------------------- the inventory

console.log('\nthe inventory: what counts as a handler, and what counts as read');

{
    // `discoverHandlers` counts a `.ts` file only when the directory holding it
    // is named `src`, and calls it a handler only when the name ends
    // `-command-handler.ts`. Both halves are load-bearing and neither is
    // observable from a verdict, so they are asserted on the denominator.
    //
    // This is the axis that has actually gone wrong in this family: the sibling
    // gate check-proxy-parity spent two copies' lifetimes blind to a real
    // outbound WIF hop while passing its own suite, because no case named the
    // inventory. A gate whose walk quietly changes size reports a different
    // number and no failure.
    const root = fixture('inventory', clean(), {
        'Tests/L0.ts': 'export const suite = 1;\n',
        'Tests/other-packer-command-handler.ts': 'export class Decoy {}\n',
        'copy-build.ts': 'export const copy = () => 0;\n',
        'src/types.d.ts': 'declare const x: number;\n',
    });
    const { body, code } = run(root);
    report(body && body.handlerFiles === 1,
        `a *-command-handler.ts outside src/ is not a handler (${body && body.handlerFiles} handler file(s))`);
    report(body && body.scanned === 1,
        `and nothing outside src/ reaches the denominator either (${body && body.scanned} scanned)`);
    report(code === 0, `and the decoys change no verdict (exit ${code})`);
}

// ---------------------------------------------------------------- the shape

console.log('\nthe --json contract the replay adapter and four L0 suites read');

{
    const root = fixture('shape', clean());
    const { body, code } = run(root);
    report(body !== null && Object.keys(body).sort().join(',') === 'cells,handlerFiles,root,scanned,unguarded',
        `the envelope carries exactly root/handlerFiles/scanned/cells/unguarded (${body && Object.keys(body).sort().join(',')})`);
    report(body && body.root === root, `and names the root it was pointed at (${body && body.root})`);
    report(body && body.unguarded === (cellsOf(body) ?? []).filter((c) => c.verdict === 'UNGUARDED').length,
        'and the unguarded count agrees with the cells it printed');
    const row = (cellsOf(body) ?? [])[0];
    report(row !== undefined && ['file', 'handler', 'branch', 'cell', 'site', 'verdict', 'detail', 'line'].every((k) => k in row),
        `and every cell carries file/handler/branch/cell/site/verdict/detail/line (${row && Object.keys(row).join(',')})`);
    report(row !== undefined && row.site === `${row.handler}.${row.branch}.${row.cell}`,
        `and site is the handler.branch.cell key the L0 tables deepStrictEqual on (${row && row.site})`);
    report(row !== undefined && !path.isAbsolute(row.file),
        `and file is ROOT-relative, so a report is comparable across checkouts (${row && row.file})`);

    // The human report is a parsed contract too: the extensions run this gate as
    // a bare CI step, where the table and its totals line are the whole output.
    const human = run(root, []);
    const total = /cells:\s*(\d+)\s+GUARDED:\s*(\d+)/.exec(human.stdout);
    report(total !== null && Number(total[1]) === (cellsOf(body) ?? []).length,
        `the human report's totals line agrees with --json (${total && total[1]} vs ${cellsOf(body)?.length})`);
    report(human.code === code, `and both modes reach the same verdict (${human.code} vs ${code})`);

    // ...and over a fixture where all four of those numbers are NON-ZERO. Read
    // only against the all-GUARDED fixture, the totals line agrees with a gate
    // that prints `GUARDED: <every cell>  EXEMPT: 0  UNGUARDED: 0` no matter
    // what it found -- watched: that edit is 0 failures without this block and
    // 6 with it. The extensions run this gate as a bare CI step, where this line
    // and the table above it are the entire output a human ever sees.
    // The marker sits one line ABOVE the WIF branch, which the lenient lookup
    // reaches and the strict one does not, so the three dropped guards land as
    // one UNGUARDED cell and two EXEMPT ones beside the untouched GUARDED rest.
    const mixed = fixture('mixed-totals', clean({
        drop: ['neutralize', 'template-declaration', 'identity-field'],
        exemptAbove: true,
    }));
    const mixedJson = run(mixed);
    const mixedHuman = run(mixed, []);
    const count = (v) => withVerdict(mixedJson.body, v).length;
    report(count('GUARDED') > 0 && count('EXEMPT') > 0 && count('UNGUARDED') > 0,
        `a fixture with all three verdicts present (GUARDED ${count('GUARDED')}, EXEMPT ${count('EXEMPT')}, UNGUARDED ${count('UNGUARDED')})`);
    report(mixedJson.body !== null && mixedJson.body.unguarded === count('UNGUARDED'),
        `  --json's unguarded total is the real one there too (${mixedJson.body && mixedJson.body.unguarded} vs ${count('UNGUARDED')})`);
    const four = /cells:\s*(\d+)\s+GUARDED:\s*(\d+)\s+EXEMPT:\s*(\d+)\s+UNGUARDED:\s*(\d+)/.exec(mixedHuman.stdout);
    report(four !== null
        && Number(four[1]) === (cellsOf(mixedJson.body) ?? []).length
        && Number(four[2]) === count('GUARDED')
        && Number(four[3]) === count('EXEMPT')
        && Number(four[4]) === count('UNGUARDED'),
        `  and the human totals line reports all four truthfully (${four && four.slice(1).join('/')} vs ${(cellsOf(mixedJson.body) ?? []).length}/${count('GUARDED')}/${count('EXEMPT')}/${count('UNGUARDED')})`);
    report(mixedHuman.code === 1 && mixedJson.code === 1,
        `  and both modes exit 1 over it (${mixedHuman.code} / ${mixedJson.code})`);
}

// ── the ACTION's own run body, not just the script it calls ─────────────────
//
// Everything above drives the gate directly, which is the half a consumer never
// executes: what a consumer runs is action.yml's `run:` block, and what two
// task L0 suites will spawn is whatever path that block exported. The estate
// has been bitten twice by suites that PARSE a shell body while every mutation
// of it ran inert, so this follows the osv-scan / footer-guard idiom — extract
// the real block by its `run: |` marker and by indentation, execute it under
// bash with exactly the env the action binds, assert on what it did.

let actionAssertions = 0;
const actionReport = (ok, msg) => { actionAssertions += 1; report(ok, msg); };

function extractRunBlock(yaml) {
    const lines = yaml.split('\n');
    // The block indicator may carry a trailing comment: the shipped step ends
    // `run: | # zizmor: ignore[github-env]`, an inline suppression that has to be
    // on that exact line. Tolerated here rather than matched loosely, so a body
    // that stopped being a literal block scalar is still a miss.
    const start = lines.findIndex((l) => /^\s+run: \|\s*(#.*)?$/.test(l));
    if (start === -1) return null;
    const indent = lines[start].match(/^(\s*)/)[1].length + 2;
    const body = [];
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') { body.push(''); continue; }
        const lead = line.match(/^(\s*)/)[1].length;
        if (lead < indent) break;
        body.push(line.slice(indent));
    }
    return body.join('\n');
}

const RUN_BODY = extractRunBlock(fs.readFileSync(ACTION, 'utf8'));
actionReport(RUN_BODY !== null && RUN_BODY.includes('auth-parity-matrix.cjs'),
    'extracted the gate step from action.yml');
actionReport(!/\$\{\{/.test(RUN_BODY),
    'the gate body interpolates no ${{ }} expression; inputs arrive through env');
// ── the `env:` BLOCK THAT FEEDS THE BODY, AND THE INPUTS THAT FEED THAT ──────
//
// The idiom above extracts the `run:` body and drives it with an env of this
// harness's own making, which leaves the WIRING between the two asserted by
// nothing: delete one `inputs.<x> -> <ENV>` line from action.yml and every case
// below still passes, actionlint is silent and zizmor is silent, while every
// real caller dies at runtime under `set -u`. The same goes for the
// required-ness the whole floor design rests on — "REQUIRED with no default: a
// caller must have measured" is a declaration, and GitHub does not enforce
// `required:` on an action input at all. So both are parsed out of the shipped
// file and pinned here.

function extractEnvBlock(yaml) {
    const lines = yaml.split('\n');
    const runAt = lines.findIndex((l) => /^\s+run: \|\s*(#.*)?$/.test(l));
    if (runAt === -1) return null;
    let envAt = -1;
    for (let i = runAt; i >= 0; i--) { if (/^\s+env:\s*$/.test(lines[i])) { envAt = i; break; } }
    if (envAt === -1) return null;
    const indent = lines[envAt].match(/^(\s*)/)[1].length;
    const bindings = {};
    for (let i = envAt + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') continue;
        if (line.match(/^(\s*)/)[1].length <= indent) break;
        if (/^\s*#/.test(line)) continue;
        const m = /^\s*([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$/.exec(line);
        if (m !== null) bindings[m[1]] = m[2];
    }
    return bindings;
}

function parseInputs(yaml) {
    const lines = yaml.split('\n');
    const start = lines.findIndex((l) => /^inputs:\s*$/.test(l));
    if (start === -1) return null;
    const inputs = {};
    let current = null;
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '' || /^\s*#/.test(line)) continue;
        if (/^\S/.test(line)) break;
        const named = /^ {2}([A-Za-z][\w-]*):\s*$/.exec(line);
        if (named !== null) { current = named[1]; inputs[current] = { keys: [], required: null }; continue; }
        if (current === null) continue;
        const key = /^ {4}([A-Za-z][\w-]*):\s*(.*?)\s*$/.exec(line);
        if (key === null) continue;
        inputs[current].keys.push(key[1]);
        if (key[1] === 'required') inputs[current].required = key[2];
    }
    return inputs;
}

const ACTION_YAML = fs.readFileSync(ACTION, 'utf8');
const ENV_BINDINGS = extractEnvBlock(ACTION_YAML);
const EXPECTED_BINDINGS = {
    ROOT: '${{ inputs.root }}',
    JSON: '${{ inputs.json }}',
    MIN_SCANNED: '${{ inputs.min-scanned }}',
    MIN_CELLS: '${{ inputs.min-cells }}',
    ACTION_PATH: '${{ github.action_path }}',
};

const boundKeys = ENV_BINDINGS === null ? [] : Object.keys(ENV_BINDINGS).sort();
const wantedKeys = Object.keys(EXPECTED_BINDINGS).sort();
actionReport(boundKeys.join(',') === wantedKeys.join(','),
    `the step binds exactly ${wantedKeys.join(', ')} through env: and nothing else (found ${boundKeys.join(', ') || 'nothing'})`);
actionReport(wantedKeys.every((k) => ENV_BINDINGS !== null && ENV_BINDINGS[k] === EXPECTED_BINDINGS[k]),
    'and each is bound to the expression the body needs — a deleted or re-pointed inputs.<x> line is a failure here rather than a runtime one in every caller');

// Derived rather than listed, so a variable ADDED to the body later without a
// binding is caught too. GITHUB_ENV and RUNNER_TEMP are the runner's, not the
// action's, and are the only two exempt.
const RUNNER_PROVIDED = new Set(['GITHUB_ENV', 'RUNNER_TEMP']);
const referenced = new Set();
for (const m of RUN_BODY.matchAll(/\$\{?([A-Z][A-Z0-9_]*)\}?/g)) referenced.add(m[1]);
const unbound = [...referenced].filter((v) => !RUNNER_PROVIDED.has(v) && !(ENV_BINDINGS !== null && v in ENV_BINDINGS));
actionReport(unbound.length === 0,
    `every $VAR the shipped body reads has a binding in the step's env: block (unbound: ${JSON.stringify(unbound)})`);
actionReport(referenced.has('MIN_SCANNED') && referenced.has('MIN_CELLS') && referenced.has('ACTION_PATH') && referenced.has('ROOT') && referenced.has('JSON'),
    `and that scan is not vacuous — it found ${referenced.size} variable(s) in the body, including the floor and the action path`);

const INPUTS = parseInputs(ACTION_YAML);
for (const name of ['min-scanned', 'min-cells']) {
    const spec = INPUTS === null ? undefined : INPUTS[name];
    actionReport(spec !== undefined && spec.required === 'true',
        `\`${name}\` is declared required: true`);
    actionReport(spec !== undefined && !spec.keys.includes('default'),
        `and declares NO default — GitHub does not enforce required:, so a default would turn an omitted \`${name}\` into a silently permissive number instead of the refusal the body makes`);
}
actionReport(INPUTS !== null && INPUTS.root !== undefined && INPUTS.root.keys.includes('default')
    && INPUTS.json !== undefined && INPUTS.json.keys.includes('default'),
    'and the reader can see a default where one exists: root and json both declare one, so the assertions above are not passing on a parser that reads nothing');


/**
 * Run the extracted step with the env the action binds.
 *
 * `GITHUB_ENV` points at a real file, because the whole point of this action
 * beyond running the gate is the line it writes there: that value is what the
 * consumers' CredentialFailClosedMatrixL0 suites will resolve the gate from. It
 * is read back and compared verbatim rather than matched loosely — a trailing
 * separator or a `dirname` would still match a regex and would still be wrong.
 */
// A LINE THAT IS ALREADY IN $GITHUB_ENV WHEN THE STEP STARTS.
//
// The env file a runner hands a step is not empty: it accumulates every earlier
// step's exports for the whole job, and design section 0 puts two of these
// composites in the SAME Build-and-Test job (azure-pipelines-packer's
// PackerTaskV1 job spawns both ProxyParityL0 and CredentialFailClosedMatrixL0).
// Seeding the file proves the step APPENDS — against an empty file
// `>> "$GITHUB_ENV"` and `> "$GITHUB_ENV"` are indistinguishable, and the
// truncating form would erase the sibling composite's export and every other
// variable the job had set.
const ENV_SEED = 'PRE_EXISTING_FROM_AN_EARLIER_STEP=kept\n';

/** The gate's machine envelope, dug out of a step's stdout, or null.
 *
 *  The step prints the gate's chosen report and THEN its own floor line, so the
 *  JSON is a prefix rather than the whole stream. A human matrix parses as
 *  nothing, which is the point: this is what tells a live `json:` input from an
 *  inert one. */
const envelopeOf = (stdout) => {
    const open = stdout.indexOf('{');
    const close = stdout.lastIndexOf('}');
    if (open === -1 || close < open) return null;
    try {
        const parsed = JSON.parse(stdout.slice(open, close + 1));
        return parsed !== null && typeof parsed === 'object' ? parsed : null;
    } catch { return null; }
};

function runStep(root, { json = 'false', minScanned = '1', minCells = '0', actionPath } = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-parity-step-'));
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, RUN_BODY);
    const envFile = path.join(dir, 'github_env');
    fs.writeFileSync(envFile, ENV_SEED);
    const r = spawnSync('bash', [script], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            ...process.env,
            ROOT: root,
            JSON: json,
            MIN_SCANNED: minScanned,
            MIN_CELLS: minCells,
            ACTION_PATH: actionPath !== undefined ? actionPath : ACTION_DIR,
            GITHUB_ENV: envFile,
            RUNNER_TEMP: dir,
        },
    });
    const written = fs.readFileSync(envFile, 'utf8');
    fs.rmSync(dir, { recursive: true, force: true });
    return { status: r.status, stdout: `${r.stdout}${r.stderr}`, out: r.stdout, env: written };
}

const exportedGate = (written) => {
    const m = /^SHARED_GATE_AUTH_PARITY_MATRIX=(.*)$/m.exec(written);
    return m === null ? null : m[1];
};

{
    const green = fixture('action-green', clean());
    const measured = run(green);
    const scanned = measured.body && Number(measured.body.scanned);
    const cells = (cellsOf(measured.body) ?? []).length;
    actionReport(measured.code === 0 && scanned >= 1 && cells > 0,
        `the action fixture is green with a real denominator and a real table (scanned ${scanned}, cells ${cells})`);

    const atFloor = runStep(green, { minScanned: String(scanned), minCells: String(cells) });
    actionReport(atFloor.status === 0, `floors AT the measured counts pass (exit ${atFloor.status})`);
    actionReport(exportedGate(atFloor.env) === ACTION_DIR,
        `the step exports SHARED_GATE_AUTH_PARITY_MATRIX=<action path>, verbatim (got ${JSON.stringify(exportedGate(atFloor.env))})`);
    actionReport(atFloor.env === `${ENV_SEED}SHARED_GATE_AUTH_PARITY_MATRIX=${ACTION_DIR}\n`,
        'and APPENDS exactly that one line — the line an earlier step wrote is still there, so a truncating `>` is not what shipped');

    const overScanned = runStep(green, { minScanned: String(scanned + 1), minCells: String(cells) });
    actionReport(overScanned.status === 1 && overScanned.stdout.includes(`read ${scanned} source file(s), below the declared floor of ${scanned + 1}`),
        'a min-scanned above the measured denominator fails, naming both numbers');

    const overCells = runStep(green, { minScanned: String(scanned), minCells: String(cells + 1) });
    actionReport(overCells.status === 1 && overCells.stdout.includes(`enumerated ${cells} credential cell(s), below the declared floor of ${cells + 1}`),
        'a min-cells above the measured enumeration fails, naming both numbers');

    // min-cells: 0 is the honest zero azure-pipelines-release-docs will declare —
    // legitimate here precisely because min-scanned carries the weight.
    const honestZero = runStep(green, { minScanned: String(scanned), minCells: '0' });
    actionReport(honestZero.status === 0,
        'min-cells: 0 is accepted — the denominator is what separates "found none" from "looked nowhere"');

    const zeroScanned = runStep(green, { minScanned: '0', minCells: '0' });
    actionReport(zeroScanned.status === 1 && /min-scanned is '0'/.test(zeroScanned.stdout),
        `min-scanned: 0 is refused (exit ${zeroScanned.status})`);
    actionReport(zeroScanned.env === ENV_SEED && !/GUARDED/.test(zeroScanned.stdout),
        'and refused BEFORE the gate runs — nothing added to GITHUB_ENV, no matrix emitted');

    const junk = runStep(green, { minScanned: '1', minCells: '-1' });
    actionReport(junk.status === 1 && /min-cells must be a non-negative integer/.test(junk.stdout),
        'a non-numeric floor is refused rather than compared');
    actionReport(junk.env === ENV_SEED, 'and it too is refused before anything is exported');

    // The denominator's own junk arm, which nothing exercised: min-scanned and
    // min-cells are two separate `case` statements, and a mutation to either is
    // invisible to a suite that only ever feeds junk to the other.
    const junkScanned = runStep(green, { minScanned: 'lots', minCells: '0' });
    actionReport(junkScanned.status === 1 && /min-scanned must be a non-negative integer; got 'lots'/.test(junkScanned.stdout),
        'a non-numeric min-scanned is refused too, quoting what it got');
    actionReport(junkScanned.env === ENV_SEED, 'and it too is refused before anything is exported');

    // THE EMPTY STRING IS THE FLOOR VALUE A REAL CALLER PRODUCES.
    //
    // GitHub does NOT enforce `required: true` on an action input: a caller that
    // simply omits `min-scanned:` or `min-cells:` reaches this body with the
    // variable set to the empty string. The `"" |` arm of each case is therefore
    // the only thing standing between an omitted input and a comparison against
    // `Number('')`, which is 0 — a vacuously green required check.
    const omittedScanned = runStep(green, { minScanned: '', minCells: '0' });
    actionReport(omittedScanned.status === 1 && /min-scanned must be a non-negative integer; got ''/.test(omittedScanned.stdout),
        "an OMITTED min-scanned arrives as '' and is refused, quoting what it got");
    actionReport(omittedScanned.env === ENV_SEED, 'and it too is refused before anything is exported');

    const omittedCells = runStep(green, { minScanned: '1', minCells: '' });
    actionReport(omittedCells.status === 1 && /min-cells must be a non-negative integer; got ''/.test(omittedCells.stdout),
        "an OMITTED min-cells arrives as '' and is refused, quoting what it got");
    actionReport(omittedCells.env === ENV_SEED, 'and it too is refused before anything is exported');

    // THE `json:` INPUT, EXERCISED RATHER THAN DECLARED. Making the `--json` arm
    // a no-op leaves a caller that asked for machine output holding the human
    // matrix, and nothing else here would notice.
    const machine = runStep(green, { json: 'true', minScanned: String(scanned), minCells: String(cells) });
    const envelope = envelopeOf(machine.out);
    actionReport(machine.status === 0 && envelope !== null,
        `json: true makes the step emit the gate's machine envelope (exit ${machine.status})`);
    actionReport(envelope !== null
        && typeof envelope.root === 'string'
        && typeof envelope.handlerFiles === 'number'
        && typeof envelope.scanned === 'number'
        && Array.isArray(envelope.cells)
        && typeof envelope.unguarded === 'number',
        "and it is this gate's own envelope — root, handlerFiles, scanned, cells, unguarded");
    actionReport(envelope !== null && envelope.cells.length === cells && envelope.scanned === scanned,
        `and it reports the same counts the gate does when driven directly (cells ${cells}, scanned ${scanned})`);
    actionReport(envelopeOf(atFloor.out) === null,
        'while the default json: false yields the human matrix, which parses as no envelope at all');
}

{
    // THE ORDER OF THE TWO RUNS IS LOAD-BEARING. The floors may only ever turn
    // a green into a red; they run after the verdict, so one UNGUARDED cell
    // aborts before either floor line executes. This is also the mutation the
    // brief calls for: one credential guard removed from the fixture, watched
    // through the ACTION rather than through the gate alone.
    const red = fixture('action-verdict-first', clean({ drop: ['neutralize'] }));
    const r = runStep(red, { minScanned: '9999', minCells: '9999' });
    actionReport(r.status === 1, `an un-guarded credential cell fails the step (exit ${r.status})`);
    actionReport(!/below the declared floor/.test(r.stdout),
        'and fails on the VERDICT, before either floor line runs — a floor cannot turn a red into anything else');
    actionReport(/UNGUARDED:\s*[1-9]/.test(r.stdout),
        "and the gate's own totals line reaches the log rather than being swallowed");
}

{
    const green = fixture('action-preflight', clean());

    const nowhere = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-parity-empty-action-'));
    const absent = runStep(green, { actionPath: nowhere });
    actionReport(absent.status === 1 && /auth-parity-matrix\.cjs is missing from the action/.test(absent.stdout),
        `an action path with no gate fails naming the gate (exit ${absent.status})`);
    actionReport(absent.env === ENV_SEED, 'and exports nothing to GITHUB_ENV');

    // VERBATIM, against a path that is not this repository's. A real directory,
    // so the preflight passes and the export actually happens, and its absolute
    // path is compared byte for byte: a trailing separator, a `dirname`, a
    // `realpath` or a `cd && pwd` would all still look like a path. There is no
    // lib/ to copy — this gate requires `node:fs` and `node:path` and nothing
    // else, which is why it has no SHARED_ACTION_ASSETS entry and no second
    // preflight.
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'auth parity fake action-'));
    fs.copyFileSync(GATE, path.join(fake, 'auth-parity-matrix.cjs'));
    const relocated = runStep(green, { actionPath: fake });
    actionReport(relocated.status === 0, `the gate runs from a relocated action directory carrying the .cjs alone (exit ${relocated.status})`);
    actionReport(exportedGate(relocated.env) === fake,
        `the exported value is the ACTION_PATH it was handed, byte for byte (got ${JSON.stringify(exportedGate(relocated.env))}, wanted ${JSON.stringify(fake)})`);

    for (const d of [nowhere, fake]) fs.rmSync(d, { recursive: true, force: true });
}

{
    // WHY THE EXPORT DOES NO ARITHMETIC, AS A MEASUREMENT RATHER THAN A CLAIM.
    // On windows-2025 github.action_path is a Windows path and Git Bash still
    // runs this body. No such directory exists here and the preflight would
    // refuse it, which is why the verbatim case above uses a real directory
    // instead; what this case measures is what the two path operations a
    // reviewer might reach for return when handed that string.
    const WINDOWS_ACTION_PATH = 'D:\\a\\_actions\\4cloudguru\\shared-workflows\\abc\\.github\\actions\\auth-parity-matrix';
    const probe = spawnSync('bash', ['-c', 'printf "%s\\n%s\\n" "$(dirname "$AP")" "${AP%/*}"'],
        { encoding: 'utf8', env: { ...process.env, AP: WINDOWS_ACTION_PATH } });
    const [dirnameSays, trimSays] = String(probe.stdout).split('\n');
    actionReport(dirnameSays === '.',
        `dirname on a windows-2025 action path returns '.', a directory that exists (got ${JSON.stringify(dirnameSays)})`);
    actionReport(trimSays === WINDOWS_ACTION_PATH,
        '${AP%/*} returns the input unchanged on the same string — neither operation is safe, so the body performs neither');
    actionReport(!/dirname|%\/\*|realpath|basename/.test(RUN_BODY),
        'and the shipped body contains no dirname, no ${…%/*}, no realpath and no basename');
}

// A floor on the action section itself, because a harness that asserted nothing
// would print no failures and exit 0 — the same vacuous green the gate exists
// to make impossible.
const ACTION_ASSERTION_FLOOR = 41;
if (actionAssertions < ACTION_ASSERTION_FLOOR) {
    console.error(`  FAIL harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`);
}

for (const root of roots) fs.rmSync(root, { recursive: true, force: true });

console.log('');
if (failures > 0) {
    console.error(`auth-parity-matrix.cjs self-test: ${failures} case(s) failed.`);
    process.exit(1);
}
console.log('auth-parity-matrix.cjs self-test: all cases passed.');
