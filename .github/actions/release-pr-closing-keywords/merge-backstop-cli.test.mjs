// EXECUTES the merge-backstop CLI -- the file the push trigger runs -- against
// the stub gh, end to end: resolve the pushed SHA to its pull request through
// the paginated listing, grade at the merge instant, and REPAIR. The library
// half is covered in time-of-check.test.mjs; these cases exist because the
// CLI's listing parse is its own mechanism (one compact object per line out
// of --paginate) and broke once, silently, under a different output shape.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'merge-backstop.mjs');
const STUB = path.join(HERE, 'stub-gh.cjs');

const O = 'sethbacon';
const R = 'terraform-state-manager-backend';
const SHA = (p, f = '0') => (p + f.repeat(40)).slice(0, 40);
const COMMIT_SHA = SHA('c0ffee');
const MERGE_SHA = SHA('deadbeef', 'd');

const incident = () => ({
  pulls: [
    {
      number: 243,
      state: 'closed',
      base: 'main',
      headSha: SHA('ab243'),
      headRef: 'release-please--branches--main',
      mergeSha: MERGE_SHA,
      mergedAt: '2026-07-23T22:11:28Z',
      body:
        ':robot: I have created a release *beep* *boop*\n---\n\n' +
        `## [2.6.0](https://github.com/${O}/${R}/compare/v2.5.0...v2.6.0) (2026-07-23)\n\n### Bug Fixes\n\n` +
        `* adopt scopes ([#246](https://github.com/${O}/${R}/issues/246)) ([c0ffee0](https://github.com/${O}/${R}/commit/${COMMIT_SHA}))\n`,
      closingIssuesReferences: {
        pageInfo: { hasNextPage: false },
        nodes: [{ number: 245, state: 'CLOSED', repository: { name: R, owner: { login: O } } }],
      },
    },
  ],
  commits: { [COMMIT_SHA]: 'fix: adopt scopes\n\nRefs #245' },
  issues: { [`${O}/${R}#245`]: { state: 'closed', closed_at: '2026-07-23T22:11:29Z' } },
  statuses: {},
});

function runBackstop(data, sha, envOverrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'merge-backstop-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'gh'), `#!/bin/sh\nexec node "${STUB}" "$@"\n`, { mode: 0o755 });
  const dataFile = path.join(dir, 'data.json');
  const logFile = path.join(dir, 'log.jsonl');
  fs.writeFileSync(dataFile, JSON.stringify(data));
  const r = spawnSync('node', [CLI, sha], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      STUB_DATA: dataFile,
      STUB_LOG: logFile,
      GH_TOKEN: 'stub',
      REPO: `${O}/${R}`,
      ...envOverrides,
    },
  });
  const log = fs.existsSync(logFile)
    ? fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  fs.rmSync(dir, { recursive: true, force: true });
  return { status: r.status, out: `${r.stdout}\n${r.stderr}`, log };
}

test('BACKSTOP CLI: the #243 push fails, reopens #245, and says why', () => {
  const r = runBackstop(incident(), MERGE_SHA);
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /FAIL sethbacon\/terraform-state-manager-backend#245/);
  const reopen = r.log.find((e) => e.method === 'PATCH' && e.path.endsWith('/issues/245'));
  assert.ok(reopen, 'the repair is the reason the job exists, and it never happened');
  assert.equal(reopen.fields.state, 'open');
  const comment = r.log.find((e) => e.method === 'POST' && /issues\/245\/comments$/.test(e.path.split('?')[0]));
  assert.ok(comment, 'a silent reopen is half a repair');
});

test('BACKSTOP CLI: a push that is no release merge grades nothing and exits clean', () => {
  const data = incident();
  data.pulls[0].headRef = 'feature/not-a-release';
  const r = runBackstop(data, MERGE_SHA);
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /does not start with 'release-please--branches--', so release-please did not create it; nothing to check/);
  assert.equal(r.log.filter((e) => e.method === 'PATCH').length, 0);
});

test('BACKSTOP CLI: a SHA with no pull request is named, not silently passed over', () => {
  const r = runBackstop(incident(), SHA('ffff', 'f'));
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /not associated with any pull request; nothing to grade/);
});

// RELEASE_BRANCH_PREFIX must actually reach this CLI. It is an input, not a
// literal -- release-please's default prefix can be overridden in a
// consumer's manifest -- and the SAME #243 incident that FAILS under the
// default prefix must also FAIL under a non-default one once the input is
// wired. Without this pair, a change that stops threading the env var (an
// action.yml edit, a dropped `env:` line) makes every non-default-prefix
// consumer's backstop report "nothing to check" forever, over the exact
// defect this file exists to catch -- and the rest of this suite, which
// never varies the prefix, would not notice.
test('BACKSTOP CLI: a non-default prefix reaches the CLI and still grades the #243 shape', () => {
  const data = incident();
  data.pulls[0].headRef = 'rp--branches--main';
  const r = runBackstop(data, MERGE_SHA, { RELEASE_BRANCH_PREFIX: 'rp--branches--' });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /FAIL sethbacon\/terraform-state-manager-backend#245/);
  const reopen = r.log.find((e) => e.method === 'PATCH' && e.path.endsWith('/issues/245'));
  assert.ok(reopen, 'the non-default prefix must still trigger the repair, not just the report');
});

test('BACKSTOP CLI: a non-default prefix WITHOUT the env var passes an incident it should catch', () => {
  // This is the failure the case above guards against, reproduced directly:
  // the same PR, the same real incident shape, but RELEASE_BRANCH_PREFIX is
  // NOT set -- as it would not be if action.yml stopped threading it. The
  // CLI falls back to the compiled-in default, the PR's head no longer
  // matches, and the backstop reports clean over a merge that should have
  // been reopened.
  const data = incident();
  data.pulls[0].headRef = 'rp--branches--main';
  const r = runBackstop(data, MERGE_SHA);
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /does not start with 'release-please--branches--'/);
  assert.equal(r.log.filter((e) => e.method === 'PATCH').length, 0,
    'this pass documents the exposure when the prefix is unwired -- it must never gain a reopen, ' +
      'or the test stops proving what an unwired prefix actually does');
});

// -- THE REPAIR LOOP'S TWO GAPS (#40) ----------------------------------------
//
// The loop built each reopen path from the referenced issue's OWN coordinates,
// which come from the linked-issue graph's repository node — so a cross-repo
// reference produced a path this job's repo-scoped token cannot write. There
// was no same-repository check and no per-reference error handling, so the 403
// aborted the whole loop: references already reopened stayed reopened, the ones
// after were never attempted, and the summary said neither.
//
// The repair path had never run with a non-empty universe in production across
// 79 push-mode runs, so nothing had ever exercised this.

// A release that closes a LOCAL issue and a FOREIGN one, in that order and in
// the reverse order, so the local repair is asserted on both sides of the
// foreign reference. Under the old loop the second ordering left #245
// unrepaired.
const crossRepoIncident = (foreignFirst) => {
  const local = { number: 245, state: 'CLOSED', repository: { name: R, owner: { login: O } } };
  const foreign = { number: 99, state: 'CLOSED', repository: { name: 'other-repo', owner: { login: 'someone-else' } } };
  const d = incident();
  d.pulls[0].closingIssuesReferences.nodes = foreignFirst ? [foreign, local] : [local, foreign];
  d.issues[`someone-else/other-repo#99`] = { state: 'closed', closed_at: '2026-07-23T22:11:29Z' };
  return d;
};

for (const foreignFirst of [false, true]) {
  test(`BACKSTOP CLI: a cross-repo reference is refused by name, and the local repair still happens (foreign ${foreignFirst ? 'first' : 'second'})`, () => {
    const r = runBackstop(crossRepoIncident(foreignFirst), MERGE_SHA);

    assert.equal(r.status, 1, `the run still fails — the close already happened:\n${r.out}`);

    // The local one is repaired REGARDLESS of where the foreign one sits in the
    // list. This is the assertion the old loop failed when foreign came first.
    const localReopen = r.log.find((e) => e.method === 'PATCH' && e.path.endsWith(`/${R}/issues/245`));
    assert.ok(localReopen, 'the local issue was left unrepaired because another reference came first');
    assert.equal(localReopen.fields.state, 'open');

    // The foreign one is never written to. Not attempted-and-failed: not
    // attempted, because the token is scoped to this repository.
    const foreignWrites = r.log.filter(
      (e) => e.method !== 'GET' && e.path.includes('someone-else/other-repo'),
    );
    assert.deepEqual(foreignWrites, [], 'the job wrote to a repository its token is not scoped to');

    // And it says so, so "nothing to repair" and "could not repair" are
    // distinguishable in the log a human reads.
    assert.match(r.out, /could not repair .*someone-else\/other-repo#99/,
      'a skipped reference that is silently skipped is the same as one that was never found');
  });
}
