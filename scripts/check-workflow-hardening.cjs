#!/usr/bin/env node
'use strict'

// ===========================================================================
// SIGNATURE for the WORKFLOW-HARDENING-BY-CONVENTION defect class.
//
// The class: a hardening property that every workflow in the tree happens to
// satisfy, enforced by nothing. It survives exactly as long as whoever last
// read the files, and the instance that fails is the one nobody compares
// against the others. Four instances were filed against this repository on the
// same day, all four of them "true today, unenforced":
//
//   #30  every `uses:` is pinned to a full SHA — by hand, with
//        `sha_pinning_required: false` on the repository.
//   #22  every job carries harden-runner and a timeout — except the one that
//        mints a GitHub App token and runs code checked out from 15 repos.
//   #23  every harden-runner is `egress-policy: audit`, so the control is
//        installed everywhere and switched off everywhere.
//   #21  every `npm ci` carries `--ignore-scripts` — except the per-task one
//        in scripts/for-each-task.js, which lost the flag relative to the
//        hardened sibling it was copied from.
//
// #21 is the shape of all four: the flag was present in the source, absent in
// the copy, and nothing noticed because "the convention" is a thing people
// hold in their heads. This script is where it is written down instead.
//
// What this gate enforces
// -----------------------
//   1. PINNING. Every `uses:` resolves to a local path (`./…`) or to a full
//      40-hex commit SHA, and carries a trailing comment naming the version
//      that SHA is. An unlabelled SHA is unreviewable; a tag is mutable.
//   2. INSTALL HARDENING. Every npm install invoked from a workflow, and the
//      per-task install in scripts/for-each-task.js, carries
//      `--ignore-scripts`. `npm ci` runs dependency `preinstall`/`install`/
//      `postinstall`/`prepare` by default (#21).
//
//      And scripts/for-each-task.js runs npm as `node <npm-cli.js>` rather than
//      spawning a platform wrapper. `execFileSync` cannot launch a `.cmd` or
//      `.bat` at all, so the win32 half of a `process.platform === 'win32' ?
//      'npm.cmd' : 'npm'` ternary is a branch that throws — and `Tasks/` being
//      empty is the only reason the windows-2025 matrix leg has never found out
//      (#45). The repair that suggests itself is worse than the defect: node
//      runtime-deprecated passing `args` alongside `shell` for exactly this
//      shape (DEP0190), because the args array is then neither escaped nor
//      quoted, which turns a repository directory name into cmd.exe input. So
//      both directions are checked — no wrapper literal, and the spawn is
//      `process.execPath` with no `shell:`.
//   3. TIMEOUTS. Every job declares `timeout-minutes`. Without one, a hung or
//      deliberately-stalled job holds the runner — and whatever credential it
//      minted — for the platform default of six hours (#22). A job that is a
//      reusable-workflow call (`uses:` at job level) is exempt: the key is not
//      valid there.
//   4. EGRESS. Every job that has `steps:` begins with harden-runner, and that
//      step states an egress policy. `block` must name a non-empty
//      `allowed-endpoints`. `audit` is allowed only where the step carries an
//      exception comment giving the reason:
//
//          # hardening-exception: egress-audit — <why this job cannot block>
//
//      BIDIRECTIONAL, and the second direction is the load-bearing one: an
//      exception comment in a step that is NOT on `audit` fails too, so the
//      reason has to be deleted in the change that flips the job to `block`.
//      An exception that outlives its own justification is how "audit
//      everywhere" became the resting state in the first place.
//   5. VACUITY. A gate that enumerated nothing looks exactly like a gate that
//      found nothing, so the counts are printed and an empty universe fails.
//
// Read as text, not parsed as YAML: this repository carries no YAML dependency
// and a gate that needs one cannot run before `npm ci`. Same choice, for the
// same reason, as scripts/check-audit-scope.js.
//
// Usage:  node scripts/check-workflow-hardening.js [repoRoot] [--json]
// Exit 0 = every hardening property holds. Exit 1 = drift, listed.
//
// Mutation-proved by scripts/test-workflow-hardening.js, which runs beside it.
// ===========================================================================

const fs = require('node:fs')
const path = require('node:path')

const JSON_OUTPUT = process.argv.includes('--json')
const ROOT = path.resolve(process.argv.filter((a) => a !== '--json')[2] || path.join(__dirname, '..'))

const findings = []
const fail = (kind, where, message) => findings.push({ kind, where, message })

const enumerated = { workflows: 0, jobs: 0, uses: 0, installs: 0, hardenRunners: 0, egressExceptions: 0, preHardenActionlessSteps: 0 }

const EXCEPTION_MARKER = 'hardening-exception: egress-audit'
const MIN_REASON_CHARS = 20

/* ------------------------------------------------------------------ *
 * A minimal, indentation-driven view of a workflow file.
 *
 * Enough structure to answer "which job is this line in, and is it the
 * job's first step" — and no more. Anything that needs a real parser
 * needs a YAML dependency, which is the thing this file refuses.
 * ------------------------------------------------------------------ */

function indentOf(line) {
  const m = /^(\s*)/.exec(line)
  return m[1].length
}

const isComment = (line) => /^\s*#/.test(line)
const isBlank = (line) => /^\s*$/.test(line)

/**
 * @returns {{name: string, start: number, end: number, lines: string[]}[]}
 * one entry per key under a top-level `jobs:` mapping.
 */
function parseJobs(lines) {
  const jobsAt = lines.findIndex((line) => /^jobs:\s*$/.test(line))
  if (jobsAt === -1) return []

  const jobs = []
  let current = null
  for (let i = jobsAt + 1; i < lines.length; i++) {
    const line = lines[i]
    if (isBlank(line) || isComment(line)) continue
    const indent = indentOf(line)
    if (indent === 0) break // back out to another top-level key
    const key = /^\s{2}([A-Za-z0-9_.-]+):\s*$/.exec(line)
    if (indent === 2 && key) {
      if (current) current.end = i
      current = { name: key[1], start: i, end: lines.length, lines: [] }
      jobs.push(current)
    }
  }
  for (const job of jobs) job.lines = lines.slice(job.start, job.end)
  return jobs
}

/**
 * Every step of a job, in order, with the comment block above each one
 * attached to it: that is where a reader — and this gate — expects a step's
 * reasoning, and its `hardening-exception` marker, to live. Returns [] for a
 * job with no `steps:` (a reusable-workflow call).
 *
 * @returns {{lines: string[], offset: number}[]}
 */
function stepsOf(jobLines) {
  const stepsAt = jobLines.findIndex((line) => /^\s{4}steps:\s*$/.test(line))
  if (stepsAt === -1) return []
  const starts = []
  for (let i = stepsAt + 1; i < jobLines.length; i++) {
    if (/^\s{6}- /.test(jobLines[i])) starts.push(i)
  }
  return starts.map((start, n) => {
    const end = n + 1 < starts.length ? starts[n + 1] : jobLines.length
    let commentStart = start
    const floor = n === 0 ? stepsAt + 1 : starts[n - 1] + 1
    while (commentStart > floor && (isComment(jobLines[commentStart - 1]) || isBlank(jobLines[commentStart - 1]))) commentStart--
    return { lines: jobLines.slice(commentStart, end), offset: commentStart }
  })
}

/** The lines of a step with its comments stripped — what it actually runs. */
const runnableOf = (step) => step.lines.filter((line) => !isComment(line)).join('\n')

/** Does this step run an action at all? A step with no `uses:` runs no foreign code. */
const runsAnAction = (step) => /^\s*-?\s*uses:\s*\S/m.test(runnableOf(step))

/* ------------------------------------------------------------------ *
 * The workflows themselves.
 * ------------------------------------------------------------------ */

const workflowsDir = path.join(ROOT, '.github', 'workflows')
const workflowFiles = fs.existsSync(workflowsDir)
  ? fs
      .readdirSync(workflowsDir)
      .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
      .sort()
  : []

if (workflowFiles.length === 0) {
  fail('vacuity', '.github/workflows', 'no workflow files found — every check below would report "clean" for the wrong reason')
}

for (const file of workflowFiles) {
  enumerated.workflows++
  const rel = `.github/workflows/${file}`
  const lines = fs.readFileSync(path.join(workflowsDir, file), 'utf8').split(/\r?\n/)

  // ── 1. PINNING ────────────────────────────────────────────────────────────
  lines.forEach((line, index) => {
    if (isComment(line)) return
    const m = /^\s*(?:- )?uses:\s*(.+)$/.exec(line)
    if (!m) return
    enumerated.uses++
    const where = `${rel}:${index + 1}`
    const raw = m[1].trim()
    const [ref, ...commentParts] = raw.split('#')
    const action = ref.trim().replace(/^["']|["']$/g, '')
    const comment = commentParts.join('#').trim()

    if (action.startsWith('./') || action.startsWith('.\\')) return // a workflow in this repository

    if (!/@[0-9a-f]{40}$/.test(action)) {
      fail(
        'pinning',
        where,
        `\`uses: ${action}\` is not pinned to a full 40-hex commit SHA. A tag or branch ref is mutable, so the ` +
          'reviewed action and the executed action are not the same thing',
      )
      return
    }
    if (comment.length === 0) {
      fail(
        'pinning',
        where,
        `\`uses: ${action}\` is pinned but unlabelled. Add a trailing \`# vX.Y.Z\` comment naming the version that ` +
          'SHA is; an unlabelled SHA cannot be reviewed or updated deliberately',
      )
    }
  })

  // ── 2. INSTALL HARDENING ──────────────────────────────────────────────────
  // Blank the contents of quoted strings before matching, length-preserving so
  // column positions survive. An `echo "::notice::... run npm ci && npm run
  // build ..."` is REMEDIATION ADVICE telling a human what to type -- it is not
  // an install this workflow performs, and flagging it demands --ignore-scripts
  // on a sentence.
  //
  // terraform-drift-report and terraform-module-publish both carry exactly that
  // notice, so the gate reported four install findings in each when three were
  // real. This is the same defect as reading call edges out of string literals,
  // which fabricated 53 sites in a Go signature earlier in this programme; the
  // fix is the same one.
  const blankStrings = (text) =>
    text.replace(/(['"])(?:\\.|(?!\1)[^\\])*\1/g, (m) => m[0] + ' '.repeat(m.length - 2) + m[0])

  lines.forEach((line, index) => {
    if (isComment(line)) return
    if (!/\bnpm\s+(ci|install|i)\b/.test(blankStrings(line))) return
    enumerated.installs++
    if (/--ignore-scripts\b/.test(line)) return
    fail(
      'install',
      `${rel}:${index + 1}`,
      `\`${line.trim()}\` runs without --ignore-scripts. npm runs dependency preinstall/install/postinstall/prepare ` +
        'scripts by default, which is arbitrary code execution from the dependency tree on this runner (#21)',
    )
  })

  // ── 3 & 4. PER-JOB TIMEOUT AND EGRESS POLICY ──────────────────────────────
  const jobs = parseJobs(lines)
  if (jobs.length === 0) {
    fail('vacuity', rel, 'no jobs parsed — the timeout and egress checks would pass over nothing for this file')
  }

  for (const job of jobs) {
    enumerated.jobs++
    const jobWhere = `${rel} -> ${job.name}`
    const body = job.lines.filter((line) => !isComment(line))
    const isReusableCall = body.some((line) => /^\s{4}uses:\s*\S/.test(line))

    if (!body.some((line) => /^\s{4}timeout-minutes:\s*\d+/.test(line))) {
      if (isReusableCall) {
        // `timeout-minutes` is not a valid key on a reusable-workflow call job;
        // the called workflow's own jobs carry theirs.
      } else {
        fail(
          'timeout',
          jobWhere,
          'declares no `timeout-minutes`. Without one a hung or stalled job holds the runner — and any credential it ' +
            'minted — for the platform default of six hours (#22)',
        )
      }
    }

    const steps = stepsOf(job.lines)
    if (steps.length === 0) {
      if (!isReusableCall) {
        fail('egress', jobWhere, 'has neither `steps:` nor a reusable-workflow `uses:` — this gate cannot tell what it runs')
      }
      continue
    }

    // WHAT THIS INVARIANT ACTUALLY PROTECTS: that no FOREIGN CODE runs before
    // the egress policy is armed. It used to be stated as "harden-runner is
    // step one", which is the same thing everywhere it had been applied — until
    // signature-replay's Dependabot integrity guard needed position one for a
    // reason of its own. That guard deliberately carries NO `uses:`: it is plain
    // shell over the pre-installed `gh` CLI, so it executes nothing foreign and
    // cannot exfiltrate anything an egress policy would have caught, and it has
    // to decide BEFORE any action runs — including harden-runner's own pin,
    // which Dependabot bumps like any other.
    //
    // So the rule is stated as what it means: harden-runner must be the first
    // step that RUNS AN ACTION. A step carrying a `uses:` before it still fails,
    // which is the whole property. This is a signature taught, not a site
    // exempted — no allowlist of blessed jobs, and a second actionless step
    // added tomorrow needs no edit here.
    const anchorIdx = steps.findIndex(runsAnAction)
    const anchor = anchorIdx === -1 ? null : steps[anchorIdx]
    enumerated.preHardenActionlessSteps += anchorIdx === -1 ? steps.length : anchorIdx

    const stepText = anchor === null ? '' : anchor.lines.join('\n')
    const runnable = anchor === null ? '' : runnableOf(anchor)
    const hasException = stepText.includes(EXCEPTION_MARKER)

    if (!/step-security\/harden-runner@/.test(runnable)) {
      fail(
        'egress',
        jobWhere,
        anchor === null
          ? 'runs no action at all and so never reaches step-security/harden-runner. Every job in this repository ' +
              'arms an egress policy before it runs anything (#22)'
          : 'runs an action before step-security/harden-runner. harden-runner must be the FIRST step that runs an ' +
              'action, so nothing foreign executes before the egress policy is armed; only steps that carry no ' +
              '`uses:` may precede it (#22)',
      )
      if (hasException) enumerated.egressExceptions++
      continue
    }
    enumerated.hardenRunners++

    const policy = /^\s*egress-policy:\s*(\S+)/m.exec(runnable)
    if (!policy) {
      fail('egress', jobWhere, 'runs harden-runner with no `egress-policy:` — the action defaults are not a stated policy')
      continue
    }

    if (policy[1] === 'block') {
      if (hasException) {
        enumerated.egressExceptions++
        fail(
          'egress',
          jobWhere,
          `is on \`egress-policy: block\` but still carries a \`${EXCEPTION_MARKER}\` comment. Delete the exception in ` +
            'the change that flips the job — an exception that outlives its justification is how audit-everywhere became the resting state (#23)',
        )
      }
      if (!/^\s*allowed-endpoints:/m.test(runnable)) {
        fail('egress', jobWhere, 'is on `egress-policy: block` with no `allowed-endpoints:` — state the destinations this job is permitted to reach')
      }
      continue
    }

    if (policy[1] !== 'audit') {
      fail('egress', jobWhere, `unrecognised \`egress-policy: ${policy[1]}\` — this gate knows only \`block\` and \`audit\``)
      continue
    }

    // audit
    if (!hasException) {
      fail(
        'egress',
        jobWhere,
        `is on \`egress-policy: audit\`, which records exfiltration and never prevents it, with no recorded reason. ` +
          `Move it to \`block\` with an \`allowed-endpoints:\` list, or state why it cannot with a ` +
          `\`# ${EXCEPTION_MARKER} — <reason>\` comment on the step (#23)`,
      )
      continue
    }
    enumerated.egressExceptions++
    const reason = new RegExp(`${EXCEPTION_MARKER}\\s*[—:-]?\\s*(.*)$`, 'm').exec(stepText)
    if (!reason || reason[1].trim().length < MIN_REASON_CHARS) {
      fail(
        'egress',
        jobWhere,
        `carries a \`${EXCEPTION_MARKER}\` marker with no usable reason (at least ${MIN_REASON_CHARS} characters). ` +
          'An unexplained exception is the convention this gate replaces, written one level down',
      )
    }
  }
}

/* ------------------------------------------------------------------ *
 * The per-task install, which is not in a workflow at all.
 * ------------------------------------------------------------------ */

// PORTABILITY: the per-task install belongs to Azure DevOps extension repos,
// which package several tasks and run an npm install inside each one. A Go
// backend or a React app has no such thing, and asserting it there would give
// those repos a PERMANENTLY red gate -- which is exactly as uninformative as a
// permanently green one, and is how a gate stops being read at all.
//
// The discriminator is azure-devops-extension.json, the extension manifest.
// Presence of scripts/for-each-task.js is NOT the discriminator: azure-pipelines-packer
// is an extension that does not have the file, and that absence is a real
// finding there rather than a reason to skip the check.
//
// The skip is RECORDED in the enumerated line, not silent. A check that
// quietly does not run reads identically to one that ran and found nothing.
const isAdoExtension = fs.existsSync(path.join(ROOT, 'azure-devops-extension.json'))
const forEachTask = path.join(ROOT, 'scripts', 'for-each-task.js')
if (!isAdoExtension) {
  enumerated.perTaskInstall = 'n/a (no azure-devops-extension.json)'
} else if (!fs.existsSync(forEachTask)) {
  // WHERE the per-task install is declared is not the property; that it refuses
  // dependency scripts is. Three extension repos declare it three ways:
  //
  //   release-docs  scripts/for-each-task.js, `const ACTIONS = {`, npm() helper
  //   terraform     scripts/for-each-task.js, `const COMMANDS = {`, shell string
  //   packer        package.json scripts, `npm --prefix <task> ci ...`
  //
  // Demanding scripts/for-each-task.js made packer permanently red for having a
  // different -- and working -- declaration site. That is the same mistake as
  // slicing on `const ACTIONS = {`: asserting an implementation and calling it a
  // property, which a repo can only satisfy by restructuring code to suit the
  // matcher. So package.json is checked when the script is absent, and the
  // declaration site is RECORDED either way.
  const pkgPath = path.join(ROOT, 'package.json')
  let perTask = []
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
      perTask = Object.entries(pkg.scripts || {}).filter(([, v]) => /npm\s+--prefix\s+\S+\s+ci\b/.test(v))
    } catch {
      fail('install', 'package.json', 'is not parseable, so the per-task install cannot be checked')
    }
  }
  if (!perTask.length) {
    enumerated.perTaskInstall = 'missing'
    fail('install', 'per-task install', 'no per-task `npm ci` found in scripts/for-each-task.js or in package.json scripts — the install this gate exists to check is absent')
  } else {
    enumerated.perTaskInstall = `package.json (${perTask.length} script(s))`
    for (const [name, cmd] of perTask) {
      enumerated.installs++
      if (!/--ignore-scripts/.test(cmd)) {
        fail(
          'install',
          `package.json:${name}`,
          'runs a per-task `npm ci` without --ignore-scripts. The root install is hardened and this one is not, ' +
            'which is where third-party task dependencies actually live — and the release build copies each task ' +
            'directory into the packaged .vsix afterwards (#21)',
        )
      }
    }
  }
} else {
  enumerated.perTaskInstall = 'checked'
  const source = fs.readFileSync(forEachTask, 'utf8')

  // The per-task install table is found by SHAPE, not by a fixed name and
  // indent. Two extension repos implement this file differently and both are
  // correct: release-docs declares `const ACTIONS = {` at two-space indent and
  // spawns through a `npm(` helper; azure-pipelines-terraform declares
  // `const COMMANDS = {` at four-space indent and builds a shell string.
  //
  // The earlier matcher sliced between the literals 'const ACTIONS = {' and
  // 'function npm(' and required exactly two leading spaces, so it reported
  // BOTH "defines no ci action" and "defines no npm helper" against a file
  // whose ci action does carry --ignore-scripts. A gate that reports a false
  // FAIL is as damaging as one that reports a false PASS: it gets satisfied by
  // reformatting code to suit the matcher, which teaches everyone that the gate
  // is about its own shape rather than about the property.
  const bare = source
    .split(/\r?\n/)
    .filter((line) => !/^\s*\/\//.test(line))
    .join('\n')

  const ci = /^\s*ci\s*:\s*(.*)$/m.exec(bare)
  if (!ci) {
    fail('install', 'scripts/for-each-task.js', "defines no `ci` per-task action — the install this gate checks cannot be found")
  } else {
    enumerated.installs++
    if (!/--ignore-scripts/.test(ci[1])) {
      fail(
        'install',
        'scripts/for-each-task.js',
        'the per-task `npm ci` runs without --ignore-scripts. The root install is hardened and this one is ' +
          'not, which is where third-party task dependencies actually live — and `npm run build:release` copies each ' +
          'task directory into the packaged .vsix afterwards (#21)',
      )
    }
  }

  // ── The same file must not spawn a platform command wrapper (#45) ─────────
  // Read with whole-line `//` comments removed, for the same reason the
  // workflow scan skips `#` lines: this file documents the defect it no longer
  // has, and a gate that fired on the explanation would make writing one a
  // build failure.
  const code = bare
  const usesExecFile = /execFileSync|execFile\s*\(/.test(code)

  const wrapper = /(['"])[^'"\n]*\.(?:cmd|bat)\1/.exec(code)
  if (wrapper && usesExecFile) {
    fail(
      'install',
      'scripts/for-each-task.js',
      `spawns a platform command wrapper (${wrapper[0]}). \`execFileSync\` cannot launch a .cmd or .bat — node's own ` +
        'child_process documentation says they "cannot be launched using child_process.execFile()" — so this is a call ' +
        'that throws EINVAL on the windows-2025 leg the moment a task exists to run it against. Run npm as ' +
        '`node <npm-cli.js>` instead (#45)',
    )
  }

  // The `npm(` helper is ONE answer to #45, not the only one. #45 is that
  // execFile cannot launch a .cmd/.bat wrapper, so a repo that spawns npm
  // through execFile needs the `node <npm-cli.js>` form. A repo that builds a
  // shell command string and runs execSync -- which azure-pipelines-terraform
  // does -- never hits that limitation, and demanding the helper there would
  // force working code to be restructured to satisfy a matcher.
  //
  // So these checks run where the concern actually bites. The spawn style is
  // RECORDED either way, because a check that quietly does not run reads
  // identically to one that ran and approved.
  const npmFn = /function npm\s*\([^)]*\)\s*\{[\s\S]*?\n\}/.exec(code)
  enumerated.perTaskSpawn = npmFn ? 'npm() helper' : usesExecFile ? 'execFile (no helper)' : 'shell string'
  if (!npmFn && usesExecFile) {
    fail('install', 'scripts/for-each-task.js', 'spawns npm through execFile with no `npm(` helper — execFile cannot launch a .cmd/.bat wrapper, so this throws EINVAL on Windows (#45)')
  } else if (npmFn) {
    if (!/execFileSync\(\s*process\.execPath/.test(npmFn[0])) {
      fail(
        'install',
        'scripts/for-each-task.js',
        'the `npm(` helper does not spawn `process.execPath`. Running npm as `node <npm-cli.js>` is what removes the ' +
          '.cmd wrapper, the PATH lookup and the shell in one, and makes the POSIX and Windows paths identical (#45)',
      )
    }
    if (/\bshell\s*:/.test(npmFn[0])) {
      fail(
        'install',
        'scripts/for-each-task.js',
        'the `npm(` helper passes a `shell:` option. Node runtime-deprecated passing `args` alongside `shell` for this ' +
          'exact shape (DEP0190) because the args array is then neither escaped nor quoted — which is argument ' +
          'injection through a repository directory name, the BatBadBut class (#45)',
      )
    }
  }
}

/* ------------------------------------------------------------------ *
 * Vacuity guards.
 * ------------------------------------------------------------------ */

if (enumerated.uses === 0 && workflowFiles.length > 0) {
  fail('vacuity', '.github/workflows', 'no `uses:` found in any workflow — the pinning check inspected nothing')
}
if (enumerated.jobs === 0 && workflowFiles.length > 0) {
  fail('vacuity', '.github/workflows', 'no jobs found in any workflow — the timeout and egress checks inspected nothing')
}

/* ------------------------------------------------------------------ */

const summary =
  `enumerated: ${enumerated.jobs} job(s) over ${enumerated.workflows} workflow(s), ${enumerated.uses} \`uses:\` ref(s), ` +
  `${enumerated.installs} npm install invocation(s), ${enumerated.hardenRunners} harden-runner step(s), ` +
  `${enumerated.preHardenActionlessSteps} actionless step(s) ahead of a harden-runner, ` +
  `${enumerated.egressExceptions} recorded egress exception(s), ` +
  `per-task install: ${enumerated.perTaskInstall}` +
  `${enumerated.perTaskSpawn ? `, spawn: ${enumerated.perTaskSpawn}` : ''}.`

if (JSON_OUTPUT) {
  console.log(JSON.stringify({ enumerated, findings, failures: findings.length }, null, 2))
  process.exit(findings.length ? 1 : 0)
}

console.log(summary)

if (findings.length) {
  console.error('')
  for (const f of findings) console.error(`FAIL [${f.kind}] ${f.where}: ${f.message}`)
  console.error(`\n${findings.length} workflow-hardening propert(ies) are convention rather than fact.`)
  process.exit(1)
}

console.log('OK: every workflow-hardening property this gate checks is enforced rather than conventional.')
