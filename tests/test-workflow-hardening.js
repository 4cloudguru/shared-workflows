#!/usr/bin/env node
'use strict'

// Mutation self-test for scripts/check-workflow-hardening.cjs.
//
// Same contract as scripts/test-gates.js and scripts/test-package-composition.js,
// and the only one worth anything: a gate is unproven until you have broken the
// thing it protects and watched it fail BY NAME. Every case builds a clean
// fixture, proves the gate accepts it, reintroduces exactly one of the four
// findings this gate exists to make durable, and asserts a non-zero exit AND
// the expected wording. Exit code alone is not evidence — a gate failing for an
// unrelated reason looks identical to one working.
//
// Cases, mapped to the findings they re-create:
//   pin-tag / pin-branch     a mutable ref replacing a SHA               (#30)
//   pin-unlabelled           a SHA nobody can review or update           (#30)
//   install-workflow         `npm ci` in a workflow losing the flag      (#21)
//   install-per-task         for-each-task.js losing it, as it had       (#21)
//   per-task-cmd-wrapper     npm.cmd back on the win32 branch            (#45)
//   per-task-shell-option    `shell: true`, the repair that is worse     (#45)
//   per-task-path-lookup     a bare `npm` off PATH                       (#45)
//   no-timeout               a job that can hold a runner for six hours  (#22)
//   no-harden-runner         the one job that skipped it                 (#22)
//   action-before-harden-runner  an action ahead of the egress policy    (#22)
//   job-runs-no-action       a job that never reaches harden-runner      (#22)
//   actionless-step-before-harden-runner  the allowance, asserted as a pass
//   audit-unexplained        egress downgraded with no stated reason     (#23)
//   thin-reason              an exception marker with no real reason     (#23)
//   stale-exception          a reason outliving the audit it explained   (#23)
//   block-no-allowlist       `block` that names no endpoints             (#23)
//   reusable-call-exempt     a workflow_call job needs no timeout        (pass)
//   empty-workflows / empty-jobs   the vacuity contract, both ways
//   script-ref-skewed        the pin and the checker disagreeing
//   script-ref-absent        a required input silently omitted
//   script-ref-matching      the coupling held, asserted as a pass
//
// Nothing is written under this repository's own .github/, which the gate reads
// for real in the "Lint GitHub Actions" job.

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { spawnSync } = require('node:child_process')

const GATE = path.join(__dirname, '..', 'scripts', 'check-workflow-hardening.cjs')
const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'shared-workflows-hardening-'))

const SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1'
const HR_SHA = '05e31511f85b41b11d1cf0ef85d0992719546e2c'

const ALPHA = `---
name: Alpha

"on":
  pull_request:

jobs:
  credentialed:
    name: Holds a stored key
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0
        with:
          egress-policy: block
          allowed-endpoints: >
            api.github.com:443
            github.com:443
      - uses: actions/checkout@${SHA} # v7.0.1
      - run: npm ci --ignore-scripts

  installs:
    name: Resolves a dependency tree
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      # hardening-exception: egress-audit — this job resolves an npm tree, whose
      # destinations belong to the registry rather than to this file.
      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0
        with:
          egress-policy: audit
      - uses: actions/checkout@${SHA} # v7.0.1
      - run: npm install --ignore-scripts
`

const BETA = `---
name: Beta

"on":
  push:
    branches: [main]

jobs:
  called:
    uses: ./.github/workflows/alpha.yml

  plain:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      # hardening-exception: egress-audit — nothing here holds a credential and
      # its egress is the runner's own toolchain fetches.
      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0
        with:
          egress-policy: audit
      - run: echo hello
`

const FOR_EACH_TASK = `#!/usr/bin/env node
'use strict'

const ACTIONS = {
  ci: (dir) => npm(['--prefix', dir, 'ci', '--ignore-scripts', '--no-update-notifier']),
  audit: (dir) => npm(['audit', '--audit-level=high']),
}

function npm(args, options = {}) {
  execFileSync(process.execPath, [npmCli(), ...args], { stdio: 'inherit', ...options })
}
`

function makeCleanTree(name) {
  const dir = path.join(workRoot, name)
  fs.mkdirSync(path.join(dir, '.github', 'workflows'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'scripts'), { recursive: true })
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'alpha.yml'), ALPHA)
  fs.writeFileSync(path.join(dir, '.github', 'workflows', 'beta.yml'), BETA)
  fs.writeFileSync(path.join(dir, 'scripts', 'for-each-task.js'), FOR_EACH_TASK)
  // The gate applies its per-task install family only to an ADO extension, which
  // it detects by this manifest. Without it those cases would report n/a and the
  // mutations below would pass against a check that never ran.
  fs.writeFileSync(path.join(dir, 'azure-devops-extension.json'), '{}\n')
  return dir
}

const editForEachTask = (dir, fn) => {
  const full = path.join(dir, 'scripts', 'for-each-task.js')
  fs.writeFileSync(full, fn(fs.readFileSync(full, 'utf8')))
}

const editWorkflow = (dir, file, fn) => {
  const full = path.join(dir, '.github', 'workflows', file)
  fs.writeFileSync(full, fn(fs.readFileSync(full, 'utf8')))
}

function run(dir) {
  const result = spawnSync(process.execPath, [GATE, dir], { encoding: 'utf8' })
  return { status: result.status, output: `${result.stdout || ''}${result.stderr || ''}` }
}

let failures = 0
const report = (ok, message) => {
  if (ok) console.log(`  OK   ${message}`)
  else {
    console.error(`  FAIL ${message}`)
    failures += 1
  }
}

function expectRejection(label, mutate, expected) {
  const dir = makeCleanTree(`case-${label}`)
  mutate(dir)
  const { status, output } = run(dir)
  if (status === 0) {
    report(false, `${label}: the gate exited 0 on the mutated tree\n${output}`)
    return
  }
  const wanted = Array.isArray(expected) ? expected : [expected]
  const missing = wanted.filter((w) => !output.includes(w))
  if (missing.length > 0) {
    report(false, `${label}: failed but never mentioned ${missing.map((m) => JSON.stringify(m)).join(', ')}\n${output}`)
    return
  }
  report(true, `${label}: exits ${status} naming ${wanted.map((w) => JSON.stringify(w)).join(' + ')}`)
}

function expectPass(label, mutate, mustSay = []) {
  const dir = makeCleanTree(`pass-${label}`)
  if (mutate) mutate(dir)
  const { status, output } = run(dir)
  if (status !== 0) {
    report(false, `${label}: exited ${status} on a tree it should accept\n${output}`)
    return
  }
  const missing = mustSay.filter((w) => !output.includes(w))
  if (missing.length > 0) {
    report(false, `${label}: passed but never said ${missing.map((m) => JSON.stringify(m)).join(', ')}\n${output}`)
    return
  }
  report(true, `${label}: exits 0${mustSay.length ? ` saying ${mustSay.map((w) => JSON.stringify(w)).join(' + ')}` : ''}`)
}

try {
  console.log('the clean fixture:')
  // The counts are asserted, not just the exit code: a gate that enumerated
  // nothing exits 0 exactly like a gate that enumerated everything (#39).
  expectPass('clean', null, ['4 job(s) over 2 workflow(s)', '6 `uses:` ref(s)', '3 npm install invocation(s)', '2 recorded egress exception(s)'])
  // The reusable-workflow call job carries no timeout and no steps, and must
  // not be reported for either — `timeout-minutes` is not valid there.
  expectPass('reusable-call-exempt', null, ['4 job(s)'])

  console.log('\nmutations — full-SHA pinning (#30):')
  expectRejection('pin-tag', (dir) => editWorkflow(dir, 'alpha.yml', (y) => y.replace(`actions/checkout@${SHA}`, 'actions/checkout@v7')), [
    'is not pinned to a full 40-hex commit SHA',
    'actions/checkout@v7',
  ])
  expectRejection('pin-branch', (dir) => editWorkflow(dir, 'beta.yml', (y) => y.replace(`harden-runner@${HR_SHA}`, 'harden-runner@main')), [
    'is not pinned to a full 40-hex commit SHA',
  ])
  expectRejection('pin-unlabelled', (dir) => editWorkflow(dir, 'alpha.yml', (y) => y.replace(`actions/checkout@${SHA} # v7.0.1`, `actions/checkout@${SHA}`)), [
    'pinned but unlabelled',
  ])

  // `$/` is GitHub's self-repository form, shipped 2026-07-30. It resolves to
  // this repository at the exact commit that is running, so it is not merely as
  // pinned as `./` — it is more so: `./` resolves against whatever the runner's
  // filesystem holds, while `$/` cannot be redirected by a job that checked
  // something else out. Treating it as unpinned was the gate's own bug, and it
  // is what blocked the conversion attempted in #46 even after actionlint was
  // no longer the obstacle.
  expectPass('dollar-self-repository-ref', (dir) =>
    editWorkflow(dir, 'beta.yml', (y) => y.replace('uses: ./.github/workflows/alpha.yml', 'uses: $/.github/workflows/alpha.yml')))

  // ...and the exemption must be exactly that prefix and nothing wider. A tree
  // carrying BOTH a `$/` reference and a genuinely mutable ref must still fail,
  // on the mutable one — otherwise the fix is a hole rather than an exemption.
  expectRejection(
    'dollar-self-repository-ref-is-narrow',
    (dir) => {
      editWorkflow(dir, 'beta.yml', (y) => y.replace('uses: ./.github/workflows/alpha.yml', 'uses: $/.github/workflows/alpha.yml'))
      editWorkflow(dir, 'alpha.yml', (y) => y.replace(`actions/checkout@${SHA}`, 'actions/checkout@v7'))
    },
    ['is not pinned to a full 40-hex commit SHA', 'actions/checkout@v7'],
  )

  console.log('\nmutations — install hardening (#21):')
  expectRejection('install-workflow', (dir) => editWorkflow(dir, 'alpha.yml', (y) => y.replace('npm ci --ignore-scripts', 'npm ci')), [
    'runs without --ignore-scripts',
  ])
  expectRejection(
    'install-per-task',
    (dir) => {
      const file = path.join(dir, 'scripts', 'for-each-task.js')
      fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace("'--ignore-scripts', ", ''))
    },
    ['the per-task `npm ci` runs without --ignore-scripts'],
  )
  expectRejection(
    'install-per-task-absent',
    (dir) => fs.rmSync(path.join(dir, 'scripts', 'for-each-task.js')),
    ['the install this gate exists to check is absent'],
  )

  console.log('\nmutations — the per-task npm spawn (#45):')
  // The defect exactly as it stood: a ternary on process.platform whose win32
  // half names a .cmd. execFileSync cannot launch one, and Tasks/ being empty
  // is the only reason the windows-2025 leg has never proved it.
  expectRejection(
    'per-task-cmd-wrapper',
    (dir) => editForEachTask(dir, (js) => js.replace('process.execPath, [npmCli(), ...args]', "process.platform === 'win32' ? 'npm.cmd' : 'npm', args")),
    ['spawns a platform command wrapper', "'npm.cmd'", 'EINVAL'],
  )
  // The repair that suggests itself and must not be taken: `shell: true` makes
  // the .cmd launchable and hands cmd.exe an unescaped args array (DEP0190).
  expectRejection(
    'per-task-shell-option',
    (dir) => editForEachTask(dir, (js) => js.replace("{ stdio: 'inherit', ...options }", "{ stdio: 'inherit', shell: true, ...options }")),
    ['passes a `shell:` option', 'DEP0190'],
  )
  // A spawn that is neither: back to a PATH lookup for a bare `npm`, which is
  // the same class one platform down.
  expectRejection(
    'per-task-path-lookup',
    (dir) => editForEachTask(dir, (js) => js.replace('process.execPath, [npmCli(), ...args]', "'npm', args")),
    ['does not spawn `process.execPath`'],
  )
  // NOT ported from the release-docs copy this test came from: a case asserting
  // the tree "defines no `npm(` helper". That gate could require one because it
  // only ever read one repository. This one serves three declaration styles --
  // a for-each-task.js with an npm() helper, the same file using a shell string,
  // and per-task installs declared in package.json scripts -- and packer has no
  // for-each-task.js at all, so requiring that helper would fail a repository
  // that is correct. What matters is that a per-task `npm ci` exists and refuses
  // dependency scripts, which install-per-task and install-per-task-absent below
  // both still prove.

  console.log('\nmutations — timeouts and harden-runner coverage (#22):')
  expectRejection('no-timeout', (dir) => editWorkflow(dir, 'alpha.yml', (y) => y.replace('    timeout-minutes: 15\n', '')), [
    'declares no `timeout-minutes`',
    'credentialed',
  ])
  expectRejection(
    'no-harden-runner',
    (dir) =>
      editWorkflow(dir, 'alpha.yml', (y) =>
        y.replace(`      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0\n        with:\n          egress-policy: block\n`, ''),
      ),
    ['runs an action before step-security/harden-runner'],
  )
  // The property the "harden-runner is step one" wording used to stand in for,
  // now stated directly: an ACTION ahead of the egress policy is the failure,
  // whatever it is and however innocuous its name. This is the case that would
  // silently start passing if the rule were relaxed to an allowlist of blessed
  // jobs instead of a rule about what a step runs.
  expectRejection(
    'action-before-harden-runner',
    (dir) =>
      editWorkflow(dir, 'alpha.yml', (y) =>
        y.replace(
          `    steps:\n      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0`,
          `    steps:\n      - uses: actions/checkout@${SHA} # v7.0.1\n      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0`,
        ),
      ),
    ['runs an action before step-security/harden-runner'],
  )
  // A job that reaches no harden-runner at all, because it runs no action at
  // all. Without this the zero-action branch of the rule is unreachable in
  // testing and could rot into a pass.
  expectRejection(
    'job-runs-no-action',
    (dir) =>
      editWorkflow(dir, 'beta.yml', (y) =>
        y.replace(
          /      # hardening-exception[\s\S]*?egress-policy: audit\n/,
          '      - name: only shell here\n        run: echo hi\n',
        ),
      ),
    ['runs no action at all'],
  )
  // The allowance, which has to be asserted as a PASS or the rule is only ever
  // exercised in the rejecting direction: a step carrying no `uses:` runs no
  // foreign code, so it may precede harden-runner. That is what lets
  // signature-replay's Dependabot integrity guard hold position one, where it
  // must be to decide before any action — harden-runner's own pin included —
  // executes. The enumeration count is asserted too, so a gate that stopped
  // seeing such steps could not pass this case by ignoring them.
  expectPass(
    'actionless-step-before-harden-runner',
    (dir) =>
      editWorkflow(dir, 'alpha.yml', (y) =>
        y.replace(
          `    steps:\n      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0`,
          `    steps:\n      - name: decides before anything foreign runs\n        run: echo guard\n      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0`,
        ),
      ),
    ['1 actionless step(s) ahead of a harden-runner'],
  )

  console.log('\nmutations — egress policy, both directions (#23):')
  expectRejection(
    'audit-unexplained',
    (dir) =>
      editWorkflow(dir, 'alpha.yml', (y) =>
        y.replace('          egress-policy: block\n          allowed-endpoints: >\n            api.github.com:443\n            github.com:443\n', '          egress-policy: audit\n'),
      ),
    ['with no recorded reason'],
  )
  expectRejection(
    'thin-reason',
    (dir) => editWorkflow(dir, 'beta.yml', (y) => y.replace(/# hardening-exception: egress-audit — nothing here holds a credential and\n      # its egress is the runner's own toolchain fetches\./, '# hardening-exception: egress-audit — meh')),
    ['no usable reason'],
  )
  // The direction that matters: an exception that survives the flip it
  // explained is how "audit everywhere" became the resting state.
  expectRejection(
    'stale-exception',
    (dir) =>
      editWorkflow(dir, 'alpha.yml', (y) =>
        y.replace(
          `      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0\n        with:\n          egress-policy: block`,
          `      # hardening-exception: egress-audit — a reason left behind after the job was flipped to block.\n      - uses: step-security/harden-runner@${HR_SHA} # v2.21.0\n        with:\n          egress-policy: block`,
        ),
      ),
    ['still carries a `hardening-exception: egress-audit` comment'],
  )
  expectRejection(
    'block-no-allowlist',
    (dir) => editWorkflow(dir, 'alpha.yml', (y) => y.replace('          allowed-endpoints: >\n            api.github.com:443\n            github.com:443\n', '')),
    ['no `allowed-endpoints:`'],
  )
  expectRejection('unknown-policy', (dir) => editWorkflow(dir, 'beta.yml', (y) => y.replace('egress-policy: audit', 'egress-policy: relaxed')), [
    'unrecognised `egress-policy: relaxed`',
  ])

  console.log('\nmutations — the vacuity contract:')
  expectRejection('empty-workflows', (dir) => fs.rmSync(path.join(dir, '.github', 'workflows'), { recursive: true }), ['no workflow files found'])
  expectRejection(
    'empty-jobs',
    (dir) => {
      fs.writeFileSync(path.join(dir, '.github', 'workflows', 'alpha.yml'), '---\nname: Alpha\n"on":\n  push:\n')
      fs.writeFileSync(path.join(dir, '.github', 'workflows', 'beta.yml'), '---\nname: Beta\n"on":\n  push:\n')
    },
    ['no jobs parsed'],
  )

  console.log('\nmutations — script-ref coupling:')
  // `script-ref` names the commit the checker is taken from, and must equal the
  // SHA on the `uses:` line beside it. Dependabot rewrites one and not the other
  // and the resulting PR is green, so this is a property no bot can maintain and
  // nothing was checking.
  const CALLER = (usesSha, refLine) => `---
name: Hardening
"on":
  push:
    branches: [main]

jobs:
  workflow-hardening:
    uses: 4cloudguru/shared-workflows/.github/workflows/workflow-hardening.yml@${usesSha} # v1.13.0
    with:
${refLine}
`
  const V13 = '9276df8e0bdb3152e2529ab98c8b99cfb9e22d4b'
  const V161 = '8b7215beac6420881d20d52f9b096edff4238ec9'
  const addCaller = (body) => (dir) =>
    fs.writeFileSync(path.join(dir, '.github', 'workflows', 'hardening.yml'), body)

  expectPass('script-ref-matching', addCaller(CALLER(V13, `      script-ref: ${V13}`)))
  expectRejection(
    'script-ref-skewed',
    addCaller(CALLER(V13, `      script-ref: ${V161}`)),
    ['script-ref', '8b7215be', '9276df8e'],
  )
  expectRejection(
    'script-ref-absent',
    addCaller(`---
name: Hardening
"on":
  push:
    branches: [main]

jobs:
  workflow-hardening:
    uses: 4cloudguru/shared-workflows/.github/workflows/workflow-hardening.yml@${V13} # v1.13.0
`),
    ['passes no `script-ref`'],
  )
} finally {
  fs.rmSync(workRoot, { recursive: true, force: true })
}

if (failures > 0) {
  console.error(`\ntest-workflow-hardening: ${failures} case(s) failed.`)
  process.exit(1)
}
console.log('\ntest-workflow-hardening: the gate rejected every hardening property it claims to enforce, in both directions where it has two.')
