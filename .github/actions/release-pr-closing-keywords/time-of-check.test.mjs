// The TIME-OF-CHECK axis: the guard beside this file reads the right universe
// at the wrong moment.
//
// `closingIssuesReferences` changes on a `connected` timeline event -- an issue
// attached through the Development panel -- and `connected` is an activity type
// on NO webhook, neither `pull_request` nor `issues`. So a link made after the
// last push fires nothing, and the pull-request-time guard never looks again.
//
// The incident these cases are cut from, re-measured against the live API:
//
//   22:01:36  last force-push to #243's head branch
//   22:01:39  last `pull_request` workflow runs -- CI, PR Checks x2
//   22:02:09  `connected`, and NO workflow run follows it
//   22:11:28  merge          22:11:29  issue #245 closes
//
// Two halves are tested here. The FIRST is the after-the-fact grade, which is
// the only code that can run at a moment nothing can dodge. The SECOND is the
// wiring, because every mechanism in this fix is a trigger, and a trigger that
// is quietly deleted looks exactly like a trigger that never fired -- which is
// this whole cluster's failure mode.
//
// HALF 2 WAS REWRITTEN FOR THE PORT, and it had to be. In the source repository
// the wiring was one workflow with four jobs, and these cases read that file.
// Here the guard is a composite ACTION and the triggers, permissions and job
// names live in the CONSUMER -- which this repository does not own and cannot
// read. So the artifacts HALF 2 grades are the two this repository does own:
// the action, and the adoption document consumers copy their workflow from.
// The second one is not a lesser target. A shared guard reaches consumers
// through that document; an example in it that forgets `timeout-minutes`, or
// names the required context differently, is a defect that ships to six
// repositories exactly the way the duplicated shell body did.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Blind } from './verify.mjs';
import { stateAtMerge, gradeMergedRelease } from './merge-backstop.mjs';

const O = 'sethbacon';
const R = 'terraform-state-manager-backend';
const U = (n) => `https://github.com/${O}/${R}/issues/${n}`;
const C = (sha) => `https://github.com/${O}/${R}/commit/${sha}`;
const SHA = (p) => (p + '0'.repeat(40)).slice(0, 40);

// The real timestamps. #245 closed ONE SECOND after #243 merged.
const MERGED_AT = '2026-07-23T22:11:28Z';
const CLOSED_AT = '2026-07-23T22:11:29Z';

// #243's body, in the shape the live API returns it: a compare link, one commit
// link, and NOT ONE closing keyword anywhere.
const PR243_BODY =
  ':robot: I have created a release *beep* *boop*\n---\n\n\n' +
  `## [2.6.0](https://github.com/${O}/${R}/compare/v2.5.0...v2.6.0) (2026-07-23)\n\n\n### Bug Fixes\n\n` +
  `* adopt org_owner/org_provisioner scopes ([#246](${U(246)})) ([003d043](${C(SHA('003d043'))}))\n`;

const REFS_TRAILER = 'fix: adopt org_owner scopes\n\nRefs #245. Refs #245.';

const grade = ({ body = PR243_BODY, mergedAt = MERGED_AT, refs, closedAt, message = REFS_TRAILER, hasNextPage = false } = {}) =>
  gradeMergedRelease({
    owner: O,
    repo: R,
    body,
    mergedAt,
    linked: async () => ({ hasNextPage, refs }),
    closedAt: async () => closedAt,
    commitMessage: async () => message,
  });

const ids = (r) => r.results.filter((x) => x.verdict === 'fail').map((x) => x.id);

// -- HALF 1: the clock ------------------------------------------------------

test('TOC: an issue closed one second AFTER the merge was OPEN at the merge', () => {
  assert.equal(stateAtMerge({ closedAt: CLOSED_AT, mergedAt: MERGED_AT }), 'open');
});

test('TOC: an issue closed before the merge was already closed and lost nothing', () => {
  assert.equal(stateAtMerge({ closedAt: '2026-07-20T00:00:00Z', mergedAt: MERGED_AT }), 'closed');
});

test('TOC: closed at the exact merge instant counts as open, because the merge is what closed it', () => {
  assert.equal(stateAtMerge({ closedAt: MERGED_AT, mergedAt: MERGED_AT }), 'open');
});

test('TOC: an issue that was never closed is open', () => {
  assert.equal(stateAtMerge({ closedAt: null, mergedAt: MERGED_AT }), 'open');
});

test('TOC: an unusable merge timestamp is refused, not treated as "closed long ago"', () => {
  assert.throws(() => stateAtMerge({ closedAt: CLOSED_AT, mergedAt: undefined }), Blind);
  assert.throws(() => stateAtMerge({ closedAt: CLOSED_AT, mergedAt: 'whenever' }), Blind);
});

test('TOC: an unusable closed_at is refused rather than assumed safe', () => {
  assert.throws(() => stateAtMerge({ closedAt: 'lunchtime', mergedAt: MERGED_AT }), Blind);
});

// -- HALF 1b: the incident, end to end --------------------------------------

test('TOC: the #243 merge is FAILED after the fact, from a body with no keyword at all', async () => {
  const r = await grade({ refs: [{ owner: O, repo: R, issue: 245 }], closedAt: CLOSED_AT });
  assert.deepEqual(ids(r), [`${O}/${R}#245`]);
  assert.equal(r.results[0].source, 'github-linked');
});

// THE regression case. `evaluate()` short-circuits to the state carried on the
// ref when there is one, and after the merge GitHub reports every issue the
// merge closed as CLOSED -- which grades as "already closed, cannot lose
// anything" and clears the violation. The backstop must DROP that state and
// consult the clock instead. Hand `state: 'CLOSED'` in and it must still fail.
test('TOC: a CLOSED state on the linked ref does not launder the violation', async () => {
  const r = await grade({
    refs: [{ owner: O, repo: R, issue: 245, state: 'CLOSED' }],
    closedAt: CLOSED_AT,
  });
  assert.deepEqual(ids(r), [`${O}/${R}#245`], 'the post-merge state was trusted and the incident vanished');
});

test('TOC: a release whose issue was genuinely closed beforehand stays clean', async () => {
  const r = await grade({
    refs: [{ owner: O, repo: R, issue: 245, state: 'CLOSED' }],
    closedAt: '2026-07-01T00:00:00Z',
  });
  assert.deepEqual(ids(r), []);
});

test('TOC: a release whose commit really does close the issue stays clean', async () => {
  const r = await grade({
    refs: [{ owner: O, repo: R, issue: 245 }],
    closedAt: CLOSED_AT,
    message: 'fix: adopt org_owner scopes\n\nCloses #245',
  });
  assert.deepEqual(ids(r), []);
});

test('TOC: a truncated authoritative set is refused after the merge too', async () => {
  await assert.rejects(
    () => grade({ refs: [{ owner: O, repo: R, issue: 245 }], closedAt: CLOSED_AT, hasNextPage: true }),
    Blind
  );
});

test('TOC: a reader returning no refs array is refused rather than read as nothing to do', async () => {
  await assert.rejects(
    () =>
      gradeMergedRelease({
        owner: O,
        repo: R,
        body: PR243_BODY,
        mergedAt: MERGED_AT,
        linked: async () => ({ hasNextPage: false }),
        closedAt: async () => null,
        commitMessage: async () => REFS_TRAILER,
      }),
    Blind
  );
});

// -- HALF 2: the wiring -----------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ACTION = fs.readFileSync(path.join(HERE, 'action.yml'), 'utf8');
// The re-grade MECHANISM lives in link-regrade.sh so link-regrade.test.mjs can
// EXECUTE it against a stub gh -- outcomes are asserted there. The pins below
// against the script's text are secondary: they catch a rename or a rewiring
// of the action around the script, which the harness cannot see.
const REGRADE_SH = fs.readFileSync(path.join(HERE, 'link-regrade.sh'), 'utf8');
const ADOPTION = fs.readFileSync(path.join(HERE, '..', '..', '..', 'docs', 'release-pr-guard-adoption.md'), 'utf8');
const RESIDUAL = fs.readFileSync(path.join(HERE, '..', '..', '..', 'docs', 'release-pr-guard-residual.md'), 'utf8');

// The step bodies, split on a four-space-indented `- name:` inside `steps:`.
// Used so an assertion can be made against the RIGHT mode.
function stepBlocks(text) {
  const at = text.indexOf('\n  steps:\n');
  assert.ok(at > 0, 'no steps: list in the action');
  const body = text.slice(at);
  const re = /^ {4}- name: /gm;
  const starts = [...body.matchAll(re)];
  const out = new Map();
  starts.forEach((m, i) => {
    const end = i + 1 < starts.length ? starts[i + 1].index : body.length;
    const block = body.slice(m.index, end);
    const id = /^ {6}id: (\S+)$/m.exec(block);
    assert.ok(id, `a step in the action has no id:\n${block.slice(0, 120)}`);
    out.set(id[1], block);
  });
  return out;
}

const STEPS = stepBlocks(ACTION);

test('WIRING: the action enumerates steps at all, and every mode has one', () => {
  assert.ok(STEPS.size > 0, 'parsed zero steps -- the parser broke, not the action');
  for (const id of ['contract', 'pull-request', 'link-regrade', 'merge-backstop']) {
    assert.ok(STEPS.has(id), `the ${id} step is gone`);
  }
});

// A mode that matches no `if:` runs no step, and a composite action that ran no
// step reports success. That is the vacuous pass arriving through the one door
// none of the modules can watch, so it is closed in the action and asserted
// here; the EXECUTED proof is in tests/test-release-pr-closing-keywords.js.
test('WIRING: the contract step is unconditional and rejects an unknown mode', () => {
  const c = STEPS.get('contract');
  assert.doesNotMatch(c, /^ {6}if:/m, 'a conditional contract step can itself be skipped');
  assert.match(c, /Unknown mode/, 'nothing rejects a mode the action does not implement');
});

test('WIRING: each mode step is gated on its own mode and nothing else', () => {
  for (const id of ['pull-request', 'link-regrade', 'merge-backstop']) {
    assert.match(
      STEPS.get(id),
      new RegExp(`^ {6}if: inputs\\.mode == '${id}'$`, 'm'),
      `the ${id} step is not gated on inputs.mode == '${id}'`
    );
  }
});

test('WIRING: the merge backstop invokes the backstop and is handed the merge SHA', () => {
  const b = STEPS.get('merge-backstop');
  assert.match(b, /merge-backstop\.mjs" "\$MERGE_SHA"/);
  assert.match(b, /MERGE_SHA: \$\{\{ inputs\.merge-sha \}\}/);
});

test('WIRING: the re-grade step invokes the extracted script, which runs the SAME verifier', () => {
  const j = STEPS.get('link-regrade');
  assert.match(
    j,
    /bash "\$ACTION_PATH\/link-regrade\.sh"/,
    'the step no longer runs link-regrade.sh, so everything the harness proves about the script proves nothing about CI'
  );
  assert.match(REGRADE_SH, /verify\.mjs/, 're-grading with different code than the PR mode is a second guard to drift');
});

// Branch protection grades a CONTEXT ON THE HEAD SHA. If the two publishers post
// under different names, the cron can never overwrite the pull-request-time
// pass, and the whole bounded-window mechanism is decorative.
test('WIRING: both publishers post under ONE context input, and it is enumerated', () => {
  const bindings = [...ACTION.matchAll(/^ {8}(?:STATUS_)?CONTEXT: \$\{\{ inputs\.status-context \}\}$/gm)];
  assert.ok(bindings.length > 0, 'enumerated zero context bindings -- the matcher is blind, not the file clean');
  assert.equal(bindings.length, 3, `expected contract + pull-request + link-regrade to bind status-context, found ${bindings.length}`);

  assert.match(
    STEPS.get('pull-request'),
    /-X POST "repos\/\$REPO\/statuses\/\$/,
    'the pull-request mode never posts a commit status, so its verdict reaches nothing protection reads'
  );
  assert.match(
    REGRADE_SH,
    /-X POST "repos\/\$REPO\/statuses\/\$/,
    'the re-grade script never posts a commit status, so the cron overwrites nothing'
  );
});

// The default has to be a context name, not a job name. A check run and a commit
// status sharing one context is ambiguous to branch protection.
test('WIRING: the status-context default is not the required check-run name', () => {
  const def = /^ {4}default: (\S+)$/m.exec(ACTION.slice(ACTION.indexOf('status-context:')));
  assert.ok(def, 'status-context has no default');
  assert.notEqual(def[1], 'Release', 'the context must not collide with the job name');
  assert.match(def[1], /\//, 'a slash-namespaced context is what distinguishes it from a check run');
});

// GitHub caps statuses at 1000 per SHA per context. A 5-minute tick that
// re-posts an unchanged verdict reaches that in about three and a half days,
// after which a long-lived pull request silently stops being gradeable -- a
// guard that expires by running normally.
test('WIRING: the re-grade script reads the current status, paginated, before posting', () => {
  assert.match(REGRADE_SH, /commits\/\$_sha\/status\?per_page=100/, 'never reads the existing status, so it re-posts every tick');
  assert.match(REGRADE_SH, /first\(/, 'should select with jq first, not a pipe a closed reader can empty');
  assert.doesNotMatch(REGRADE_SH, /statuses\[\][^\n]*\|\s*head/, 'piping into head can truncate to a silent empty answer');
});

// NOTHING repository-specific may be baked in. Six repositories adopt this
// unchanged, and a literal that was right in the source repository is a silent
// wrong answer in the next one.
test('WIRING: no consumer-specific literal survives in the action or the scripts', () => {
  const SHARED = [
    ['action.yml', ACTION],
    ['link-regrade.sh', REGRADE_SH],
    ['verify.mjs', fs.readFileSync(path.join(HERE, 'verify.mjs'), 'utf8')],
    ['merge-backstop.mjs', fs.readFileSync(path.join(HERE, 'merge-backstop.mjs'), 'utf8')],
  ];
  // Code lines only. The headers cite the incidents by repository ON PURPOSE --
  // that is the evidence the guard is built on, and stripping the provenance to
  // satisfy a grep would be losing the reason anyone should keep the guard.
  const codeOf = (text) =>
    text
      .split('\n')
      .filter((l) => !/^\s*(#|\/\/)/.test(l))
      .join('\n');
  let checked = 0;
  for (const [name, text] of SHARED) {
    const code = codeOf(text);
    assert.ok(code.trim().length > 0, `${name}: stripped to nothing, so the scan is blind`);
    assert.doesNotMatch(code, /terraform-state-manager/, `${name} names a consumer repository in executable text`);
    assert.doesNotMatch(code, /sethbacon/, `${name} names a consumer owner in executable text`);
    assert.doesNotMatch(code, /release-pr-guard\.yml/, `${name} names a workflow path only one repository has`);
    checked += 1;
  }
  assert.equal(checked, SHARED.length, 'the scan skipped a file');
});

// `base=main` was a literal in two places in the source. The count floor exists
// to catch a dropped page; it must not be the thing standing between a consumer
// whose releases target a different branch and a guard that grades nothing.
test('WIRING: the base branch and the release prefix are inputs, not literals', () => {
  // CODE lines only. The script's header QUOTES the unpaginated `base=main`
  // listing it replaced, and a scan that read the commentary would fail on the
  // explanation of the fix rather than on the defect.
  const code = REGRADE_SH.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.ok(code.trim().length > 0, 'stripped to nothing, so the scan is blind');
  // Assert the POSITIVE shape, not the absence of one spelling. The first
  // version of this case was `doesNotMatch(/base=main/)`, and a mutation
  // retargeting the filter to `base=develop` walked straight past it: a scan
  // that names the wrong answer only catches the wrong answer it names.
  assert.match(
    code,
    /pulls\?state=open&base=\$BASE_BRANCH&per_page=100/,
    'the REST listing does not take its base branch from $BASE_BRANCH'
  );
  assert.match(
    code,
    /-f base="\$BASE_BRANCH"/,
    'the GraphQL derivation does not take its base branch from $BASE_BRANCH'
  );
  assert.doesNotMatch(code, /baseRefName:\s*"[a-z]/, 'the GraphQL derivation names a literal branch again');
  assert.match(REGRADE_SH, /"\$RELEASE_BRANCH_PREFIX"\*/, 'the release-please prefix is hardcoded again');
  for (const input of ['base-branch', 'release-branch-prefix', 'status-context']) {
    assert.ok(ACTION.includes(`\n  ${input}:\n`), `the action does not expose ${input} as an input`);
  }
});

// This is the other half of the wiring the previous case leaves unguarded: an
// input existing and a script reading it from the right variable name says
// nothing about whether action.yml's STEP actually forwards it. Three
// separate mutations of the real tree -- the merge-backstop.mjs default
// standing in for the env var, the pull-request step's shell case hardcoded
// instead of reading $RELEASE_BRANCH_PREFIX, and the merge-backstop step's
// `env:` line for it deleted outright -- all passed the entire suite before
// this case existed, including every mjs unit test, because none of them run
// through action.yml. Demonstrated end-to-end: with the merge-backstop step's
// env line gone, a #243-shaped incident under a non-default prefix exits
// status 0 with zero reopens -- a clean pass over the exact defect this
// guard exists to catch.
//
// Walked per STEP rather than counted, so a mutation that drops one step's
// line is named rather than merely lowering a total that could hide behind
// another step's line surviving.
test('WIRING: every step whose script reads RELEASE_BRANCH_PREFIX is handed it', () => {
  const WIRE = 'RELEASE_BRANCH_PREFIX: ${{ inputs.release-branch-prefix }}';
  const stepBounds = [...ACTION.matchAll(/^\s*id: (\S+)/gm)].map((m) => ({ id: m[1], at: m.index }));
  assert.ok(stepBounds.length >= 4, 'fewer steps than expected: the id-based split is not finding them');
  for (let i = 0; i < stepBounds.length; i++) {
    const start = stepBounds[i].at;
    const end = i + 1 < stepBounds.length ? stepBounds[i + 1].at : ACTION.length;
    const body = ACTION.slice(start, end);
    if (!body.includes('RELEASE_BRANCH_PREFIX')) continue;
    assert.ok(
      body.includes(WIRE),
      `step "${stepBounds[i].id}" reads RELEASE_BRANCH_PREFIX but its env: block does not set it ` +
        'from inputs.release-branch-prefix -- it would silently fall back to the compiled-in default'
    );
  }
  // The floor: this action has exactly four steps today, and all four
  // reference the prefix (two by shell interpolation, two inside the script
  // they invoke). If that count drops, the loop above may simply have less
  // to check, which would look identical to a passing scan.
  const wiredSteps = stepBounds.filter((s, i) => {
    const start = s.at;
    const end = i + 1 < stepBounds.length ? stepBounds[i + 1].at : ACTION.length;
    return ACTION.slice(start, end).includes(WIRE);
  });
  assert.equal(wiredSteps.length, 4, `expected all 4 steps to wire the prefix, found ${wiredSteps.length}`);
});

// THE ONE STRING THE WHOLE COMPOSITE-ACTION SHAPE EXISTS TO PRESERVE, pinned.
// Every other property of the example workflow is asserted elsewhere -- the
// triggers, the permissions, the pin, the concurrency key -- but not the job
// NAME whose rename silently un-requires the check on any consumer that has
// made it required. Renaming this one line in the adoption doc passed the
// entire suite before this case existed.
test('WIRING: the adoption example names the job exactly what a consumer requires', () => {
  assert.match(
    ADOPTION,
    /^ {4}name: Release PR closes only what it completes$/m,
    'the example workflow does not carry the exact required-context name -- a consumer who pastes ' +
      'this and has required the old name would silently stop being protected'
  );
});

// -- HALF 3: the artifact consumers actually copy ---------------------------
//
// The triggers and permissions moved into the consumer, so the example workflow
// IS the wiring for six repositories. These are the cases HALF 2 used to run
// against the single workflow file, pointed at the thing that now determines
// whether a consumer gets them.

test('ADOPTION: the example wires all three modes', () => {
  for (const mode of ['pull-request', 'link-regrade', 'merge-backstop']) {
    assert.match(ADOPTION, new RegExp(`mode: ${mode}`), `the example never calls mode: ${mode}`);
  }
});

test('ADOPTION: the example schedules a tick at least every 15 minutes', () => {
  const m = ADOPTION.match(/- cron: "([^"]+)"/);
  assert.ok(m, 'no cron in the example: the time-of-check window is unbounded');
  const minute = m[1].split(/\s+/)[0];
  const step = /^\*\/(\d+)$/.exec(minute);
  assert.ok(step, `cron minute field ${minute} is not a */N step, so the window is not bounded`);
  assert.ok(Number(step[1]) <= 15, `a ${step[1]}-minute tick is wider than the 9m19s gap the incident used`);
});

test('ADOPTION: the example has a push trigger, so the after-the-fact grade runs', () => {
  assert.match(ADOPTION, /\n  push:\n    branches: \[main\]/, 'no push trigger: nothing grades the merge');
});

test('ADOPTION: the backstop job is granted issues: write, which IS the repair', () => {
  const job = ADOPTION.slice(ADOPTION.indexOf('  merge-backstop:'));
  assert.ok(job.length > 0, 'no merge-backstop job in the example');
  assert.match(job.slice(0, 1200), /issues: write/, 'without issues:write the backstop cannot reopen, and reopening is why it exists');
});

// A scheduled tick sharing a concurrency group with the post-merge backstop
// would CANCEL it, and the backstop is the one job that cannot be re-run by
// pushing again.
test('ADOPTION: the concurrency key separates events, so a tick cannot cancel the backstop', () => {
  const m = ADOPTION.match(/\n  group: (.+)/);
  assert.ok(m, 'no concurrency group in the example');
  assert.match(m[1], /github\.event_name/, 'every non-pull_request event collapses to one group and cancels');
  const cancel = ADOPTION.match(/\n  cancel-in-progress: (.+)/);
  assert.ok(cancel, 'no cancel-in-progress in the example');
  assert.notEqual(cancel[1].trim(), 'true', 'unconditional cancellation lets a tick kill the backstop');
});

// The hardening gate in this repository requires these of every job. The example
// is what consumers paste, so a job missing them is a hardening regression
// shipped six times.
test('ADOPTION: every job in the example is bounded by a timeout and hardens the runner', () => {
  const jobsAt = ADOPTION.indexOf('\njobs:\n');
  assert.ok(jobsAt > 0, 'the example has no jobs: map');
  const body = ADOPTION.slice(jobsAt, ADOPTION.indexOf('\n```', jobsAt));
  const starts = [...body.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)];
  assert.ok(starts.length >= 3, `enumerated only ${starts.length} job(s) in the example; the floor is the point`);
  starts.forEach((m, i) => {
    const end = i + 1 < starts.length ? starts[i + 1].index : body.length;
    const job = body.slice(m.index, end);
    assert.match(job, /timeout-minutes: \d+/, `example job ${m[1]} has no timeout`);
    assert.match(job, /step-security\/harden-runner@[0-9a-f]{40} # v/, `example job ${m[1]} lacks a pinned harden-runner`);
  });
});

test('ADOPTION: every uses: in the example is pinned, and the shared one says to fill it in', () => {
  const uses = [...ADOPTION.matchAll(/^\s*(?:- )?uses: (\S+)(.*)$/gm)];
  assert.ok(uses.length >= 4, `enumerated only ${uses.length} uses: lines; the floor is the point`);
  let shared = 0;
  let third = 0;
  for (const [, ref, rest] of uses) {
    if (ref.startsWith('4cloudguru/shared-workflows/')) {
      // This action's own pin CANNOT be a literal SHA in this document: the
      // commit that adds it is the commit being reviewed, so any SHA written
      // here would name a tree where the action does not exist. It must not be
      // `@main` either -- a mutable pin on a guard is the thing this repository
      // was created to stop. So it carries a marker the adopter has to replace,
      // and this case is what keeps the marker there.
      assert.match(ref, /@REPLACE_WITH_THE_MERGE_SHA$/, `${ref} must carry the replace-me marker, not a mutable or invented pin`);
      shared += 1;
      continue;
    }
    assert.match(ref, /@[0-9a-f]{40}$/, `${ref} is not pinned to a full SHA`);
    assert.match(rest, /# v/, `${ref} carries no version comment, so the pin is unreviewable`);
    third += 1;
  }
  assert.equal(shared, 3, `expected three calls to the shared action, found ${shared}`);
  assert.ok(third >= 1, 'enumerated no third-party uses:, so the pinning assertion checked nothing');
});

// The residual is the honest half. Porting the guard without it would overstate
// what a consumer gets, so its presence is asserted rather than assumed.
test('RESIDUAL: the doc still states the limits that make the guard partial', () => {
  // The ENUMERATED residual items, not a substring sweep over the file. The
  // first version of this case asked whether `enforce_admins` appeared
  // ANYWHERE, and a mutation deleting one of its three mentions left the case
  // green -- a check that cannot tell a stated limit from a passing reference
  // to one. Porting the guard without its honest limits would overstate what a
  // consumer gets, so each item is looked for where it is stated.
  const items = [
    ['R1.', 'required status checks'],
    ['R2.', 'enforce_admins'],
    ['R3.', 'cron tick'],
    ['R4.', '60 days'],
    ['R5.', 'repairs, it does not prevent'],
    ['R6.', 'github.sha'],
    ['R7,', 'consumer owns the job names'],
    ['R8,', 'stale in six places'],
  ];
  let checked = 0;
  for (const [heading, claim] of items) {
    const at = RESIDUAL.indexOf(`**${heading}`);
    assert.notEqual(at, -1, `residual item ${heading} is gone from the doc`);
    const next = RESIDUAL.indexOf('\n\n**R', at + 1);
    const block = next === -1 ? RESIDUAL.slice(at) : RESIDUAL.slice(at, next);
    assert.ok(block.includes(claim), `residual item ${heading} no longer states its limit (${claim})`);
    checked += 1;
  }
  assert.equal(checked, items.length, 'the residual scan skipped an item');
  assert.ok(RESIDUAL.includes('merge queue'), 'the only complete answer is no longer named');
  assert.doesNotMatch(
    RESIDUAL,
    /^Code: `\.github\/workflows\/release-pr-guard\.yml`/m,
    'the residual doc still points at a path only one repository has'
  );
});
