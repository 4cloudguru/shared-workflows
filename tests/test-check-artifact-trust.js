#!/usr/bin/env node
'use strict'

// Self-test for .github/actions/check-artifact-trust.
//
// PORTED, NOT REWRITTEN. Everything down to the `cross-file CACHE-ADMIT` banner
// is security-orchestration's `remediation/gates/test-check-artifact-trust.js`
// at its origin/main, with ONE logic edit: the path the gate is resolved from
// (see ACTION_DIR below). Canonical is the parent of the script this action
// ships and of this suite; a case rewritten here rather than there is drift in
// the same way a re-worded comment in the gate is. The two sections below that
// banner are additive and belong only here: one is a suite that used to live in
// a consumer's task tests and has no home in the consumer once the gate leaves,
// the other tests action.yml — a file canonical does not have.
//
// ── canonical's own header follows ─────────────────────────────────────────
//
// Self-test for check-artifact-trust.js's DELEGATED-VERIFY detector and the
// version-floor currency check that holds its floor honest, on fixtures it
// builds itself.
//
// The two are tested together because they are one mechanism seen from both
// sides. The detector's whole claim is that a declared floor decides WHICH
// implementation of verifyDetached actually runs; the currency check is what
// stops that floor from quietly sinking below every task in the repository,
// where it would still be a floor, still be printed, and never fire again. That
// is the failure this gate's sibling check-proxy-parity.js was caught by
// (azure-pipelines-terraform#1108 finding 2) and where the check is ported from.
//
// The other eight kinds are not re-tested here. They are driven against real
// task source by each extension's ArtifactTrustL0 suite, which asserts the whole
// enumerated set. What that suite cannot see is a floor going stale, because a
// stale floor changes no row -- it is invisible in exactly the place the L0
// tables look.

const { execFileSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

// THE ONE LOGIC EDIT THIS PORT MAKES. Canonical resolves the gate beside itself
// in `remediation/gates/`; here it lives inside the composite action, so the
// suite drives the REAL shipped script at
// .github/actions/check-artifact-trust/check-artifact-trust.js — the same file
// every consumer's pinned SHA resolves to. Same three-line shape
// tests/test-check-enforced-disciplines.js already uses.
const ACTION_DIR = path.join(__dirname, '..', '.github', 'actions', 'check-artifact-trust')
const ACTION = path.join(ACTION_DIR, 'action.yml')
const GATE = path.join(ACTION_DIR, 'check-artifact-trust.js')
const CORE = '@4cloudguru/pipeline-task-core'

// The floor DELEGATED_VERIFIERS.verifyDetached is written at. Restated here
// rather than read out of the gate on purpose: a fixture that derived the bar
// from the thing under test would move with it, and every case below would keep
// passing through a floor edited to any value at all.
// The floor under test is read from the gate, never restated here: a literal
// copy of it is how this file went red the day the floor was raised, and a
// literal that agreed by luck would be green about a bar it never measured.
const FLOOR = (/DELEGATED_VERIFIERS[\s\S]*?min:\s*'(\d+\.\d+\.\d+)'/.exec(fs.readFileSync(GATE, 'utf8')) || [])[1]
if (!FLOOR) throw new Error('could not read DELEGATED_VERIFIERS.verifyDetached.min out of the gate')
// One minor above the floor: the fleet that has moved past it.
const ABOVE = FLOOR.replace(/^(\d+)\.(\d+)\.\d+$/, (_, a, b) => `${a}.${Number(b) + 1}.0`)

let failures = 0
// Every assertion below reads the report through `?.`, never through a bare
// index. A mutation that empties the array it is looking at must be REPORTED,
// not thrown: a TypeError here aborts the run and silently skips every case
// after it, which is the same "looked nowhere" failure the gate itself exists
// to refuse. Watched: neutering staleFloors() crashed this file at the first
// currency case before the reads were guarded.
function check (ok, message, detail) {
  if (ok) { console.log(`  ok   ${message}`); return }
  failures += 1
  console.error(`  FAIL ${message}${detail === undefined ? '' : `: ${detail}`}`)
}

function run (root) {
  try {
    return { code: 0, body: JSON.parse(execFileSync(process.execPath, [GATE, root, '--json'], { encoding: 'utf8' })) }
  } catch (err) {
    // A crash prints no JSON. Returning `{}` here would let every assertion
    // below read `undefined` and pass, which is the shape this file exists to
    // refuse -- so a body that will not parse is surfaced as `body: null`, and
    // every case asserts on a real array rather than on `(x || []).length`.
    let body = null
    try { body = JSON.parse(err.stdout) } catch { /* left null on purpose */ }
    return { code: err.status, body }
  }
}

/**
 * A tree of tasks under Tasks/<name>/<name>V1. Each gets a package.json (with
 * `range` declared for core, unless `range` is null) and one file under src/,
 * which by default imports verifyDetached from the package.
 *
 * realpath, because declaredDependency() walks upward until it leaves ROOT and
 * ROOT is path.resolve()d from argv: on a platform where the temp directory is
 * a symlink, an unresolved fixture path leaves the walk outside its own root and
 * every task reads as declaring nothing.
 */
function fixture (tasks, assert) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-selftest-')))
  try {
    for (const [name, spec] of Object.entries(tasks)) {
      const dir = path.join(root, 'Tasks', name, `${name}V1`)
      fs.mkdirSync(path.join(dir, 'src'), { recursive: true })
      const dependencies = spec.range === null ? {} : { [CORE]: spec.range }
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: name.toLowerCase(), dependencies }))
      fs.writeFileSync(
        path.join(dir, 'src', spec.file ?? 'gpg-verifier.ts'),
        spec.source ?? `import { verifyDetached } from '${CORE}/gpg';\n\nexport async function verify(p: string): Promise<void> {\n    await verifyDetached(p, p + '.sig');\n}\n`
      )
    }
    return assert(root)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

const delegatedRows = (body) => (body && Array.isArray(body.sites) ? body.sites.filter((s) => s.kind === 'DELEGATED-VERIFY') : null)
const staleRows = (body) => (body && Array.isArray(body.staleFloors) ? body.staleFloors : null)
const verdictsByTask = (rows) => Object.fromEntries((rows ?? []).map((r) => [r.rel.split('/')[1], r.verdict]))

console.log('check-artifact-trust self-test — DELEGATED-VERIFY and floor currency\n')

// --------------------------------------------------- the detector
console.log('DELEGATED-VERIFY: which implementation of the verifier resolves')

fixture({ Installer: { range: `^${FLOOR}` } }, (root) => {
  const { code, body } = run(root)
  const rows = delegatedRows(body)
  check(rows !== null && rows.length === 1, 'a task importing verifyDetached from core is one DELEGATED-VERIFY row', JSON.stringify(rows))
  check(rows?.[0]?.verdict === 'PINNED-DELEGATE', 'a task AT the floor is PINNED-DELEGATE', rows?.[0]?.verdict)
  check(rows?.[0]?.fn === 'verifyDetached', 'named by the delegated binding, not by the enclosing function', rows?.[0]?.fn)
  check(body && body.failures === 0, 'a pinned delegate is not a failure', body && body.failures)
  check(code === 0, 'and with the fleet level with the floor the gate exits 0', code)
})

fixture({ Installer: { range: '^0.6.0' } }, (root) => {
  const { code, body } = run(root)
  const rows = delegatedRows(body)
  check(rows?.[0]?.verdict === 'DELEGATED-VERIFIER-UNPINNED', 'a task BELOW the floor is DELEGATED-VERIFIER-UNPINNED', rows?.[0]?.verdict)
  check(body && body.failures === 1, 'and is counted as a defective row', body && body.failures)
  check(code === 1, 'and the gate exits 1', code)
})

fixture({ Installer: { range: '^0.6.0' }, Other: { range: `^${FLOOR}` } }, (root) => {
  const { body } = run(root)
  const verdicts = verdictsByTask(delegatedRows(body))
  check(verdicts.Installer === 'DELEGATED-VERIFIER-UNPINNED' && verdicts.Other === 'PINNED-DELEGATE',
    'the verdict is per TASK -- one task regressing does not condemn its sibling', JSON.stringify(verdicts))
  check(body && body.failures === 1, 'and only the regressing task is counted', body && body.failures)
})

fixture({ Installer: { range: null } }, (root) => {
  const { code, body } = run(root)
  const rows = delegatedRows(body)
  check(rows?.[0]?.verdict === 'DELEGATED-VERIFIER-UNPINNED',
    'a task that imports the verifier while declaring NO dependency on it is unpinned', rows?.[0]?.verdict)
  check(/no dependency on it/.test(rows?.[0]?.why ?? ''), 'and says so rather than naming a version', rows?.[0]?.why)
  check(code === 1, 'and the gate exits 1', code)
})

fixture({
  Installer: {
    range: '^0.6.0',
    // verifyDetached named in a comment and called, but never IMPORTED from the
    // package. There is no delegation to verdict, so there must be no row -- a
    // gate that manufactured one here would report a site no version bump could
    // ever clear.
    source: `// verifyDetached is discussed here\nimport { other } from '${CORE}/gpg';\nexport const x = () => other();\n`,
  },
}, (root) => {
  const { body } = run(root)
  check((delegatedRows(body) ?? null)?.length === 0, 'a name in a comment, with no import of it, is not a site', JSON.stringify(delegatedRows(body)))
})

fixture({
  Installer: {
    range: '^0.6.0',
    // The same binding, from somewhere else. The floor belongs to a package, so
    // an identically named export of another package is a different decision
    // and this table says nothing about it.
    source: "import { verifyDetached } from 'some-other-gpg-lib';\nexport const x = (p: string) => verifyDetached(p, p);\n",
  },
}, (root) => {
  const { body } = run(root)
  check((delegatedRows(body) ?? null)?.length === 0, 'the same binding imported from another package is not a site', JSON.stringify(delegatedRows(body)))
})

fixture({
  Installer: { range: '^0.6.0', source: `import { verifyDetached, other } from '${CORE}';\nexport const x = (p: string) => verifyDetached(p, other);\n` },
}, (root) => {
  const { body } = run(root)
  check((delegatedRows(body) ?? []).length === 1, 'the package ROOT specifier and a multi-name import are both matched', JSON.stringify(delegatedRows(body)))
})

// --------------------------------------------------- floor currency
console.log('\nfloor currency: a bar below the whole fleet cannot fire')

fixture({ Installer: { range: `^${ABOVE}` }, Other: { range: `^${ABOVE}` } }, (root) => {
  const { code, body } = run(root)
  const stale = staleRows(body)
  check(stale !== null && stale.length === 1, 'a fleet that has moved past the floor reports it stale', JSON.stringify(stale))
  check(stale?.[0]?.where === 'DELEGATED_VERIFIERS.verifyDetached', 'and names where the floor is written', stale?.[0]?.where)
  check(stale?.[0]?.min === FLOOR && stale?.[0]?.fleet === ABOVE, 'and names both the stale value and the value to raise it to', JSON.stringify(stale?.[0]))
  check(body && body.failures === 0, 'with NO defective row -- a stale floor condemns no call site', body && body.failures)
  check((delegatedRows(body) ?? []).every((r) => r.verdict === 'PINNED-DELEGATE'), 'and every site still passes the bar it has outgrown')
  check(code === 1, 'and the gate exits 1 on a stale floor alone', code)
})

fixture({ Installer: { range: `^${ABOVE}` }, Other: { range: `^${FLOOR}` } }, (root) => {
  const { code, body } = run(root)
  check((staleRows(body) ?? null)?.length === 0,
    'ONE task still at the floor keeps the bar live -- the fleet floor is the LOWEST declaration, not the highest',
    JSON.stringify(staleRows(body)))
  check(code === 0, 'and the gate exits 0', code)
})

fixture({ Installer: { range: '^0.6.0' }, Other: { range: '^0.6.0' } }, (root) => {
  const { body } = run(root)
  check((staleRows(body) ?? null)?.length === 0, 'a fleet BELOW the floor is not a stale floor -- that is what the row verdict is for', JSON.stringify(staleRows(body)))
  check(body && body.failures === 2, 'and both tasks are reported as rows instead', body && body.failures)
})

// A repository whose tasks do not depend on the package at all: the floor has no
// fleet to be measured against, and "no fleet" must not read as "a fleet at
// 0.0.0", which would report every floor as stale in every repository that
// happens not to use the package.
fixture({
  Installer: { range: null, file: 'render.ts', source: 'export const render = (s: string) => s.toUpperCase();\n' },
}, (root) => {
  const { code, body } = run(root)
  check((staleRows(body) ?? null)?.length === 0, 'a repository declaring the package nowhere reports no stale floor', JSON.stringify(staleRows(body)))
  check((delegatedRows(body) ?? []).length === 0, 'and enumerates no delegated verifier')
  check(code === 0, 'and exits 0', code)
})

// ── cross-file CACHE-ADMIT resolution is not over-widened (#998) ────────────
//
// Ported from azure-pipelines-terraform's
// `Tasks/TerraformInstaller/TerraformInstallerV1/Tests/ArtifactTrustL0.ts`
// describe D, which builds these same four files in a `mkdtemp` fixture and
// points the gate at them. The fixtures assert nothing about that repository —
// they are the GATE's own ladder — so their home is beside the gate, which is
// here. Describe D stays in the consumer as well, and deliberately: over there
// it is the only live proof that what the composite exports is a BINARY the
// suite can point anywhere, and not a report of the consumer's own tree.
//
// The claim under test: teaching the gate to resolve reader/writer names
// imported from a sibling module (so writeCacheIntegrityMarker/verifyCachedTool
// could move into tool-integrity.ts without blinding it) must not also make it
// stop catching a genuinely blind cache admission. One CACHE-ADMIT function
// calls an imported reader and gates an imported writer on its result; one
// calls nothing at all. A third sibling carries the 64-hex validator the reader
// imports rather than declares, proving hexConsts resolves across the same
// import.
{
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-crossfile-')))
  fs.mkdirSync(path.join(dir, 'src'))
  fs.writeFileSync(path.join(dir, 'src', 'hex-pattern.ts'),
    `export const MARKER_HEX_PATTERN = /^[a-fA-F0-9]{64}$/;\n`)
  fs.writeFileSync(path.join(dir, 'src', 'reader.ts'), [
    `import * as fs from 'fs';`,
    `import { MARKER_HEX_PATTERN } from './hex-pattern';`,
    ``,
    `export function verifyMarker(markerPath: string, expected: string): boolean {`,
    `    const stored = fs.readFileSync(markerPath, 'utf8');`,
    `    if (!MARKER_HEX_PATTERN.test(stored)) return false;`,
    `    return stored === expected;`,
    `}`,
    ``,
    `export function writeMarker(markerPath: string, digestValue: string): void {`,
    `    const tmp = markerPath + '.tmp';`,
    `    fs.writeFileSync(tmp, digestValue);`,
    `    fs.renameSync(tmp, markerPath);`,
    `}`,
    ``,
  ].join('\n'))
  fs.writeFileSync(path.join(dir, 'src', 'admit-crossfile.ts'), [
    `import { verifyMarker, writeMarker } from './reader';`,
    ``,
    `export async function downloadWithCrossFileReverify(markerPath: string, expected: string): Promise<void> {`,
    `    const cached = findLocalTool('thing', '1.0.0');`,
    `    if (cached) {`,
    `        const verified = verifyMarker(markerPath, expected);`,
    `        if (verified) {`,
    `            writeMarker(markerPath, expected);`,
    `        }`,
    `    }`,
    `}`,
    ``,
  ].join('\n'))
  fs.writeFileSync(path.join(dir, 'src', 'admit-blind.ts'), [
    `export async function downloadBlindly(): Promise<void> {`,
    `    const cached = findLocalTool('other-thing', '2.0.0');`,
    `    if (cached) {`,
    `        // no re-verification of any kind`,
    `    }`,
    `}`,
    ``,
  ].join('\n'))

  const { code, body } = run(dir)
  const admit = (fn) => (body && Array.isArray(body.sites) ? body.sites : []).find((s) => s.fn === fn && s.kind === 'CACHE-ADMIT')
  check(admit('downloadBlindly')?.verdict === 'TRUSTS-CACHE-BLINDLY',
    'cross-file resolution does not exonerate a cache admission that calls no reader, local or imported',
    admit('downloadBlindly')?.verdict)
  check(admit('downloadWithCrossFileReverify')?.verdict === 'REVERIFIES-AND-GATES',
    'a cache admission calling an imported reader and gating an imported writer on it is not blind merely because the pair live in another file',
    admit('downloadWithCrossFileReverify')?.verdict)
  check(code === 1, 'and the blind sibling still fails the gate over that tree', code)
  fs.rmSync(dir, { recursive: true, force: true })
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

// Canonical's half needs only execFileSync; the extracted shell body is run
// with spawnSync so a non-zero exit is a value to assert on rather than a
// throw. Required here rather than at the top so the ported half above stays
// byte-comparable with canonical.
const { spawnSync } = require('node:child_process')

let actionAssertions = 0
const actionCheck = (ok, message, detail) => { actionAssertions += 1; check(ok, message, detail) }

function extractRunBlock (yaml) {
  const lines = yaml.split('\n')
  // The block indicator may carry a trailing comment: the shipped step ends
  // `run: | # zizmor: ignore[github-env]`, an inline suppression that has to be
  // on that exact line. Tolerated here rather than matched loosely, so a body
  // that stopped being a literal block scalar is still a miss.
  const start = lines.findIndex((l) => /^\s+run: \|\s*(#.*)?$/.test(l))
  if (start === -1) return null
  const indent = lines[start].match(/^(\s*)/)[1].length + 2
  const body = []
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]
    if (line.trim() === '') { body.push(''); continue }
    const lead = line.match(/^(\s*)/)[1].length
    if (lead < indent) break
    body.push(line.slice(indent))
  }
  return body.join('\n')
}

const RUN_BODY = extractRunBlock(fs.readFileSync(ACTION, 'utf8'))
actionCheck(RUN_BODY !== null && RUN_BODY.includes('check-artifact-trust.js'),
  'extracted the gate step from action.yml')
actionCheck(!/\$\{\{/.test(RUN_BODY),
  'the gate body interpolates no ${{ }} expression; inputs arrive through env')
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
  MIN_SITES: '${{ inputs.min-sites }}',
  ACTION_PATH: '${{ github.action_path }}',
};

const boundKeys = ENV_BINDINGS === null ? [] : Object.keys(ENV_BINDINGS).sort();
const wantedKeys = Object.keys(EXPECTED_BINDINGS).sort();
actionCheck(boundKeys.join(',') === wantedKeys.join(','),
    `the step binds exactly ${wantedKeys.join(', ')} through env: and nothing else (found ${boundKeys.join(', ') || 'nothing'})`);
actionCheck(wantedKeys.every((k) => ENV_BINDINGS !== null && ENV_BINDINGS[k] === EXPECTED_BINDINGS[k]),
    'and each is bound to the expression the body needs — a deleted or re-pointed inputs.<x> line is a failure here rather than a runtime one in every caller');

// Derived rather than listed, so a variable ADDED to the body later without a
// binding is caught too. GITHUB_ENV and RUNNER_TEMP are the runner's, not the
// action's, and are the only two exempt.
const RUNNER_PROVIDED = new Set(['GITHUB_ENV', 'RUNNER_TEMP']);
const referenced = new Set();
for (const m of RUN_BODY.matchAll(/\$\{?([A-Z][A-Z0-9_]*)\}?/g)) referenced.add(m[1]);
const unbound = [...referenced].filter((v) => !RUNNER_PROVIDED.has(v) && !(ENV_BINDINGS !== null && v in ENV_BINDINGS));
actionCheck(unbound.length === 0,
    `every $VAR the shipped body reads has a binding in the step's env: block (unbound: ${JSON.stringify(unbound)})`);
actionCheck(referenced.has('MIN_SCANNED') && referenced.has('MIN_SITES') && referenced.has('ACTION_PATH') && referenced.has('ROOT') && referenced.has('JSON'),
    `and that scan is not vacuous — it found ${referenced.size} variable(s) in the body, including the floor and the action path`);

const INPUTS = parseInputs(ACTION_YAML);
for (const name of ['min-scanned', 'min-sites']) {
    const spec = INPUTS === null ? undefined : INPUTS[name];
    actionCheck(spec !== undefined && spec.required === 'true',
        `\`${name}\` is declared required: true`);
    actionCheck(spec !== undefined && !spec.keys.includes('default'),
        `and declares NO default — GitHub does not enforce required:, so a default would turn an omitted \`${name}\` into a silently permissive number instead of the refusal the body makes`);
}
actionCheck(INPUTS !== null && INPUTS.root !== undefined && INPUTS.root.keys.includes('default')
    && INPUTS.json !== undefined && INPUTS.json.keys.includes('default'),
    'and the reader can see a default where one exists: root and json both declare one, so the assertions above are not passing on a parser that reads nothing');


/**
 * Run the extracted step with the env the action binds.
 *
 * `GITHUB_ENV` points at a real file, because the whole point of this action
 * beyond running the gate is the line it writes there: that value is what the
 * consumers' L0 suites resolve the gate from — including the describe-D case
 * above, which points this same binary at a directory that did not exist when
 * any report could have been written. It is read back and compared verbatim
 * rather than matched loosely: a trailing separator or a `dirname` would still
 * match a regex and would still be wrong.
 */
// A LINE THAT IS ALREADY IN $GITHUB_ENV WHEN THE STEP STARTS.
//
// The env file a runner hands a step is not empty: it accumulates every earlier
// step's exports for the whole job, and design section 0 puts two or three of
// these composites in the SAME Build-and-Test job. Seeding the file proves the
// step APPENDS — against an empty file `>> "$GITHUB_ENV"` and `> "$GITHUB_ENV"`
// are indistinguishable, and the truncating form would erase the sibling
// composite's export and every other variable the job had set.
const ENV_SEED = 'PRE_EXISTING_FROM_AN_EARLIER_STEP=kept\n'

/** The gate's machine envelope, dug out of a step's stdout, or null.
 *
 *  The step prints the gate's chosen report and THEN its own floor line, so the
 *  JSON is a prefix rather than the whole stream. A human report parses as
 *  nothing, which is the point: this is what tells a live `json:` input from an
 *  inert one. */
const envelopeOf = (stdout) => {
  const open = stdout.indexOf('{')
  const close = stdout.lastIndexOf('}')
  if (open === -1 || close < open) return null
  try {
    const parsed = JSON.parse(stdout.slice(open, close + 1))
    return parsed !== null && typeof parsed === 'object' ? parsed : null
  } catch { return null }
}

function runStep (root, { json = 'false', minScanned = '1', minSites = '0', actionPath } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-step-'))
  const script = path.join(dir, 'step.sh')
  fs.writeFileSync(script, RUN_BODY)
  const envFile = path.join(dir, 'github_env')
  fs.writeFileSync(envFile, ENV_SEED)
  const r = spawnSync('bash', [script], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...process.env,
      ROOT: root,
      JSON: json,
      MIN_SCANNED: minScanned,
      MIN_SITES: minSites,
      ACTION_PATH: actionPath !== undefined ? actionPath : ACTION_DIR,
      GITHUB_ENV: envFile,
      RUNNER_TEMP: dir,
    },
  })
  const written = fs.readFileSync(envFile, 'utf8')
  fs.rmSync(dir, { recursive: true, force: true })
  return { status: r.status, stdout: `${r.stdout}${r.stderr}`, out: r.stdout, env: written }
}

const exported = (written) => {
  const m = /^SHARED_GATE_CHECK_ARTIFACT_TRUST=(.*)$/m.exec(written)
  return m === null ? null : m[1]
}

/** A tree the gate passes: one task pinned at the floor. Left on disk for the
 *  action cases, which need a root rather than a callback. */
function greenRoot (name) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `artifact-trust-${name}-`)))
  const dir = path.join(root, 'Tasks', 'Installer', 'InstallerV1')
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'installer', dependencies: { [CORE]: `^${FLOOR}` } }))
  fs.writeFileSync(path.join(dir, 'src', 'gpg-verifier.ts'),
    `import { verifyDetached } from '${CORE}/gpg';\n\nexport async function verify(p: string): Promise<void> {\n    await verifyDetached(p, p + '.sig');\n}\n`)
  return root
}

const scratch = []
{
  const green = greenRoot('action-green')
  scratch.push(green)
  const measured = run(green)
  const scanned = measured.body && Number(measured.body.scanned)
  const sites = (measured.body && Array.isArray(measured.body.sites) ? measured.body.sites : []).length
  actionCheck(measured.code === 0 && scanned >= 1, `the action fixture is green and has a denominator (scanned ${scanned})`, measured.code)

  const atFloor = runStep(green, { minScanned: String(scanned), minSites: String(sites) })
  actionCheck(atFloor.status === 0, `floors AT the measured counts pass (exit ${atFloor.status})`, atFloor.stdout)
  actionCheck(exported(atFloor.env) === ACTION_DIR,
    'the step exports SHARED_GATE_CHECK_ARTIFACT_TRUST=<action path>, verbatim', JSON.stringify(exported(atFloor.env)))
  actionCheck(atFloor.env === `${ENV_SEED}SHARED_GATE_CHECK_ARTIFACT_TRUST=${ACTION_DIR}\n`,
    'and APPENDS exactly that one line — the line an earlier step wrote is still there, so a truncating `>` is not what shipped', JSON.stringify(atFloor.env))

  const overScanned = runStep(green, { minScanned: String(scanned + 1), minSites: String(sites) })
  actionCheck(overScanned.status === 1 && overScanned.stdout.includes(`read ${scanned} source file(s), below the declared floor of ${scanned + 1}`),
    'a min-scanned above the measured denominator fails, naming both numbers', overScanned.stdout)

  const overSites = runStep(green, { minScanned: String(scanned), minSites: String(sites + 1) })
  actionCheck(overSites.status === 1 && overSites.stdout.includes(`enumerated ${sites} trust site(s), below the declared floor of ${sites + 1}`),
    'a min-sites above the measured enumeration fails, naming both numbers', overSites.stdout)

  // min-sites: 0 is the honest zero azure-pipelines-release-docs will declare —
  // legitimate here precisely because min-scanned carries the weight.
  const honestZero = runStep(green, { minScanned: String(scanned), minSites: '0' })
  actionCheck(honestZero.status === 0, 'min-sites: 0 is accepted — the denominator is what separates "found none" from "looked nowhere"', honestZero.stdout)

  const zeroScanned = runStep(green, { minScanned: '0', minSites: '0' })
  actionCheck(zeroScanned.status === 1 && /min-scanned is '0'/.test(zeroScanned.stdout),
    'min-scanned: 0 is refused', zeroScanned.stdout)
  actionCheck(zeroScanned.env === ENV_SEED && !/PINNED-DELEGATE/.test(zeroScanned.stdout),
    'and refused BEFORE the gate runs — nothing added to GITHUB_ENV, no report emitted', JSON.stringify(zeroScanned.stdout))

  const junk = runStep(green, { minScanned: '1', minSites: 'many' })
  actionCheck(junk.status === 1 && /min-sites must be a non-negative integer/.test(junk.stdout),
    'a non-numeric floor is refused rather than compared', junk.stdout)
  actionCheck(junk.env === ENV_SEED, 'and it too is refused before anything is exported')

  // The denominator's own junk arm, which nothing exercised: min-scanned and
  // min-sites are two separate `case` statements and a mutation to either is
  // invisible to a suite that only ever feeds junk to the other.
  const junkScanned = runStep(green, { minScanned: 'lots', minSites: '0' })
  actionCheck(junkScanned.status === 1 && /min-scanned must be a non-negative integer; got 'lots'/.test(junkScanned.stdout),
    'a non-numeric min-scanned is refused too, quoting what it got', junkScanned.stdout)
  actionCheck(junkScanned.env === ENV_SEED, 'and it too is refused before anything is exported')

  // THE EMPTY STRING IS THE FLOOR VALUE A REAL CALLER PRODUCES.
  //
  // GitHub does NOT enforce `required: true` on an action input: a caller that
  // simply omits `min-scanned:` or `min-sites:` reaches this body with the
  // variable set to the empty string. The `"" |` arm of each case is therefore
  // the only thing standing between an omitted input and a comparison against
  // `Number('')`, which is 0 — a vacuously green required check.
  const omittedScanned = runStep(green, { minScanned: '', minSites: '0' })
  actionCheck(omittedScanned.status === 1 && /min-scanned must be a non-negative integer; got ''/.test(omittedScanned.stdout),
    "an OMITTED min-scanned arrives as '' and is refused, quoting what it got", omittedScanned.stdout)
  actionCheck(omittedScanned.env === ENV_SEED, 'and it too is refused before anything is exported')

  const omittedSites = runStep(green, { minScanned: '1', minSites: '' })
  actionCheck(omittedSites.status === 1 && /min-sites must be a non-negative integer; got ''/.test(omittedSites.stdout),
    "an OMITTED min-sites arrives as '' and is refused, quoting what it got", omittedSites.stdout)
  actionCheck(omittedSites.env === ENV_SEED, 'and it too is refused before anything is exported')

  // THE `json:` INPUT, EXERCISED RATHER THAN DECLARED. Making the `--json` arm
  // a no-op leaves a caller that asked for machine output holding the human
  // report, and nothing else here would notice.
  const machine = runStep(green, { json: 'true', minScanned: String(scanned), minSites: String(sites) })
  const envelope = envelopeOf(machine.out)
  actionCheck(machine.status === 0 && envelope !== null,
    "json: true makes the step emit the gate's machine envelope", machine.stdout)
  actionCheck(envelope !== null
    && typeof envelope.root === 'string'
    && Array.isArray(envelope.sites)
    && typeof envelope.failures === 'number'
    && typeof envelope.scanned === 'number'
    && Array.isArray(envelope.staleFloors),
  "and it is this gate's own envelope — root, sites, failures, scanned, staleFloors", JSON.stringify(envelope && Object.keys(envelope)))
  actionCheck(envelopeOf(atFloor.out) === null,
    'while the default json: false yields the human report, which parses as no envelope at all')
}

{
  // THE DENOMINATOR, PINNED TO A COUNT THIS FILE CHOSE.
  //
  // `scanned` is the number design section 4b makes load-bearing:
  // azure-pipelines-release-docs is wired to this gate precisely because it
  // reports 0 sites over 34 scanned, and "looked and found none" is only
  // distinguishable from "looked nowhere" if that number is true. Every other
  // `scanned` assertion in this file is self-referential — it reads the gate's
  // own answer and floors against it — so a gate that fabricated its
  // denominator would satisfy all of them. This one counts the files itself.
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-denominator-')))
  scratch.push(root)
  const dir = path.join(root, 'Tasks', 'Installer', 'InstallerV1')
  fs.mkdirSync(path.join(dir, 'src', 'nested'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'installer', dependencies: { [CORE]: `^${FLOOR}` } }))
  const PLANTED = ['src/a.ts', 'src/b.ts', 'src/nested/c.ts', 'src/nested/d.ts']
  for (const rel of PLANTED) fs.writeFileSync(path.join(dir, rel), 'export const x = 1;\n')
  // Neither of these is a `**/src/**/*.ts`, so neither may move the count.
  fs.writeFileSync(path.join(dir, 'src', 'notes.md'), 'not source\n')
  fs.writeFileSync(path.join(dir, 'outside.ts'), 'export const y = 2;\n')

  const measured = run(root)
  actionCheck(measured.body !== null && Number(measured.body.scanned) === PLANTED.length,
    `scanned is the count of **/src/**/*.ts files this test planted (${PLANTED.length}), not a number the gate invented`,
    measured.body && measured.body.scanned)
  actionCheck(measured.body !== null && Number(measured.body.scanned) !== PLANTED.length + 2,
    'and the markdown file and the .ts outside src/ are excluded from it')

  // A tree with NO source at all is the "looked nowhere" case, and this gate
  // refuses it itself rather than reporting a clean zero — which is why the
  // empty-root assertion here is exit 1 and a named refusal, not scanned === 0.
  const bare = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-empty-')))
  scratch.push(bare)
  const nothing = spawnSync(process.execPath, [GATE, bare, '--json'], { encoding: 'utf8' })
  actionCheck(nothing.status === 1 && /files found/.test(`${nothing.stderr}`) && !/"scanned"/.test(`${nothing.stdout}`),
    'a root with no source files is refused by the gate itself as a vacuous pass, rather than reported as a clean zero',
    `exit ${nothing.status}: ${nothing.stderr}`)
}

{
  // THE ORDER OF THE TWO RUNS IS LOAD-BEARING. The floors may only ever turn a
  // green into a red; they run after the verdict, so a real finding aborts
  // before either floor line executes.
  const red = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-action-verdict-first-')))
  scratch.push(red)
  const dir = path.join(red, 'Tasks', 'Installer', 'InstallerV1')
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'installer', dependencies: { [CORE]: '^0.6.0' } }))
  fs.writeFileSync(path.join(dir, 'src', 'gpg-verifier.ts'),
    `import { verifyDetached } from '${CORE}/gpg';\n\nexport async function verify(p: string): Promise<void> {\n    await verifyDetached(p, p + '.sig');\n}\n`)
  const r = runStep(red, { minScanned: '9999', minSites: '9999' })
  actionCheck(r.status === 1, 'a tree with a real finding fails the step', r.status)
  actionCheck(!/below the declared floor/.test(r.stdout),
    'and fails on the VERDICT, before either floor line runs — a floor cannot turn a red into anything else', r.stdout)
  actionCheck(/DELEGATED-VERIFIER-UNPINNED/.test(r.stdout),
    "and the gate's own finding reaches the log rather than being swallowed", r.stdout)
}

{
  const green = greenRoot('action-preflight')
  scratch.push(green)

  const nowhere = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-empty-action-'))
  const absent = runStep(green, { actionPath: nowhere })
  actionCheck(absent.status === 1 && /check-artifact-trust\.js is missing from the action/.test(absent.stdout),
    'an action path with no gate fails naming the gate', absent.stdout)
  actionCheck(absent.env === ENV_SEED, 'and exports nothing to GITHUB_ENV')

  // `require('./lib/package-delegation.js')` resolves against the SCRIPT, so an
  // action shipped without lib/ dies in module resolution — which node reports
  // as exit 1, the very code this gate uses for a finding. Hence its own
  // preflight and its own message. This action carries its OWN copy of that lib
  // rather than reaching into check-proxy-parity's: github.action_path is per
  // action, and a cross-action reference would resolve to whatever ref that
  // sibling happened to be checked out at.
  const noLib = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-action-without-lib-'))
  fs.copyFileSync(GATE, path.join(noLib, 'check-artifact-trust.js'))
  const libless = runStep(green, { actionPath: noLib })
  actionCheck(libless.status === 1 && /lib\/package-delegation\.js is missing from the action/.test(libless.stdout),
    'an action shipped without lib/ fails naming the lib, not with a module-resolution trace', libless.stdout)
  actionCheck(libless.env === ENV_SEED, 'and exports nothing to GITHUB_ENV')

  // VERBATIM, against a path that is not this repository's. A real directory,
  // so the preflight passes and the export actually happens, and its absolute
  // path is compared byte for byte: a trailing separator, a `dirname`, a
  // `realpath` or a `cd && pwd` would all still look like a path.
  const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact trust fake action-'))
  fs.copyFileSync(GATE, path.join(fake, 'check-artifact-trust.js'))
  fs.cpSync(path.join(ACTION_DIR, 'lib'), path.join(fake, 'lib'), { recursive: true })
  const relocated = runStep(green, { actionPath: fake })
  actionCheck(relocated.status === 0, 'the gate runs from a relocated action directory', relocated.stdout)
  actionCheck(exported(relocated.env) === fake,
    'the exported value is the ACTION_PATH it was handed, byte for byte', `${JSON.stringify(exported(relocated.env))} vs ${JSON.stringify(fake)}`)

  for (const d of [nowhere, noLib, fake]) fs.rmSync(d, { recursive: true, force: true })
}

{
  // WHY THE EXPORT DOES NO ARITHMETIC, AS A MEASUREMENT RATHER THAN A CLAIM.
  // On windows-2025 github.action_path is a Windows path and Git Bash still
  // runs this body. No such directory exists here and the preflight would
  // refuse it, which is why the verbatim case above uses a real directory
  // instead; what this case measures is what the two path operations a reviewer
  // might reach for return when handed that string.
  const WINDOWS_ACTION_PATH = 'D:\\a\\_actions\\4cloudguru\\shared-workflows\\abc\\.github\\actions\\check-artifact-trust'
  const probe = spawnSync('bash', ['-c', 'printf "%s\\n%s\\n" "$(dirname "$AP")" "${AP%/*}"'],
    { encoding: 'utf8', env: { ...process.env, AP: WINDOWS_ACTION_PATH } })
  const [dirnameSays, trimSays] = String(probe.stdout).split('\n')
  actionCheck(dirnameSays === '.', "dirname on a windows-2025 action path returns '.', a directory that exists", JSON.stringify(dirnameSays))
  actionCheck(trimSays === WINDOWS_ACTION_PATH,
    '${AP%/*} returns the input unchanged on the same string — neither operation is safe, so the body performs neither')
  actionCheck(!/dirname|%\/\*|realpath|basename/.test(RUN_BODY),
    'and the shipped body contains no dirname, no ${…%/*}, no realpath and no basename')
}

for (const d of scratch) fs.rmSync(d, { recursive: true, force: true })

// A floor on the action section itself, because a harness that asserted nothing
// would print no failures and exit 0 — the same vacuous green the gate exists
// to make impossible.
const ACTION_ASSERTION_FLOOR = 45
if (actionAssertions < ACTION_ASSERTION_FLOOR) {
  console.error(`  FAIL harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`)
  failures += 1
} else {
  console.log(`  ok   harness: the action-body section made ${actionAssertions} assertion(s), floor is ${ACTION_ASSERTION_FLOOR}`)
}

console.log('')
if (failures > 0) {
  console.error(`FAIL: ${failures} check-artifact-trust self-test case(s) failed.`)
  process.exit(1)
}
console.log('OK: check-artifact-trust.js self-test passed (the delegated verifier is verdicted per task, an unimported or foreign binding is not a site, and staleFloors() still holds the floor level with the fleet).')
