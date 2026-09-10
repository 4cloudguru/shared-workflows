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
function runStep (root, { json = 'false', minScanned = '1', minSites = '0', actionPath } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-trust-step-'))
  const script = path.join(dir, 'step.sh')
  fs.writeFileSync(script, RUN_BODY)
  const envFile = path.join(dir, 'github_env')
  fs.writeFileSync(envFile, '')
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
  return { status: r.status, stdout: `${r.stdout}${r.stderr}`, env: written }
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
  actionCheck(atFloor.env === `SHARED_GATE_CHECK_ARTIFACT_TRUST=${ACTION_DIR}\n`,
    'and writes exactly that one line to GITHUB_ENV, with no second line to be parsed wrong', JSON.stringify(atFloor.env))

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
  actionCheck(zeroScanned.env === '' && !/PINNED-DELEGATE/.test(zeroScanned.stdout),
    'and refused BEFORE the gate runs — nothing in GITHUB_ENV, no report emitted', JSON.stringify(zeroScanned.stdout))

  const junk = runStep(green, { minScanned: '1', minSites: 'many' })
  actionCheck(junk.status === 1 && /min-sites must be a non-negative integer/.test(junk.stdout),
    'a non-numeric floor is refused rather than compared', junk.stdout)
  actionCheck(junk.env === '', 'and it too is refused before anything is exported')
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
  actionCheck(absent.env === '', 'and exports nothing to GITHUB_ENV')

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
  actionCheck(libless.env === '', 'and exports nothing to GITHUB_ENV')

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
const ACTION_ASSERTION_FLOOR = 20
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
