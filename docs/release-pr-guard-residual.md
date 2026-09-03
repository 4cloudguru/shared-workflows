# The release-PR closing-keyword guard: what it closes, and what it does not

This documents a **deliberately partial** guard. The gaps below are real, are not
closed by anything in this repository, and two of them need a decision from the
operator of each **consuming** repository. An honest partial guard with a stated
limit is worth more than one that looks total and is not.

Code: [`.github/actions/release-pr-closing-keywords/`](../.github/actions/release-pr-closing-keywords/).
To turn it on: [`release-pr-guard-adoption.md`](release-pr-guard-adoption.md).

> **This document was generalised in the port.** In its original home it named
> one repository's issue numbers, protection settings and workflow path. Those
> were true there and are not claims this repository can make on a consumer's
> behalf — so every limit below is now written as a question about **your**
> settings, with the command to answer it. Where a number is quoted it is
> evidence from the incident, attributed to the repository it happened in.

## The defect

Merging a release pull request closes every issue in GitHub's linked-issue graph
for that pull request — `closingIssuesReferences`. Issues land in that graph two
ways:

1. a closing keyword in the body, which release-please emits for *every* issue
   reference a commit carries, including a deliberately non-closing `Refs #N`;
2. **the Development panel**, which writes a `connected` timeline event and no
   body text whatsoever.

The guard reads `closingIssuesReferences`, so it sees both. The problem was never
*what* it reads. It was *when*.

## Why no pre-merge trigger can be complete

`connected` **is not an activity type on any webhook.** GitHub's `issues`
activity types are `assigned`, `closed`, `deleted`, `demilestoned`, `edited`,
`field_added`, `field_removed`, `labeled`, `locked`, `milestoned`, `opened`,
`pinned`, `reopened`, `transferred`, `typed`, `unassigned`, `unlabeled`,
`unlocked`, `unpinned`, `untyped`. `pull_request` has no `connected` either.
Linking an issue through the panel fires **nothing, anywhere**.

Measured on the real incident — release pull request #243 in
`sethbacon/terraform-state-manager-backend`:

| time | event | workflow run |
|---|---|---|
| 22:01:36 | last force-push | — |
| 22:01:39 | last `pull_request` runs (CI, PR Checks ×2) | yes |
| 22:02:09 | `connected` — the link is made | **none** |
| 22:11:28 | merge | — |
| 22:11:29 | issue #245 closes | — |

Replaying the guard in the state that held at 22:01:39 prints `linked=0
graded=0` and exits 0.

## What was rejected

- **The `issues` event** — impossible, not merely awkward. No `connected` or
  `linked` activity type exists on it. There is nothing to subscribe to.
- **"A required context re-evaluated rather than cached"** — no such mechanism.
  Branch protection grades the latest check run or status **on the head SHA** and
  never re-evaluates at merge time. A verdict only changes when something posts a
  new one, which is a trigger problem again.
- **`merge_group` (merge queue)** — **the only complete answer.** It grades after
  dequeue, at merge time, when the answer is final. It was unavailable in the
  repository this came from and is unavailable in every consumer for the same two
  reasons: no merge queue is configured, enabling one is a repository setting no
  pull request can make, and `enforce_admins: false` plus `--admin` merges would
  bypass a queue outright. It would gate everyone except the actor who actually
  merges releases.

## What is implemented

**1. `schedule` — bounds the window.** `mode: link-regrade` re-grades every open
pull request against the live link graph and publishes the verdict as a commit
status **on the head SHA**, the only place protection looks. `mode: pull-request`
posts the same context immediately, so no pull request waits on a status only the
cron can produce, and the cron can overwrite it — the last status posted for a
context wins.

**The cron asks for every 5 minutes and does not get it.** Measured over twelve
consecutive ticks in `sethbacon/terraform-state-manager-backend`: minimum 1.7h,
median 3.8h, maximum 5.4h — roughly 2% of requested ticks delivered. An earlier
version of this document said a 5-minute tick "would have fired twice inside
#243's 9m19s gap"; at the observed cadence it would very likely have fired
**zero** times. The schedule narrows the window from unbounded to hours, which is
worth having, and is not what "every 5 minutes" suggests to a reader.

Raising the cadence is capped from the other side: `link-regrade.sh` re-posts
only on a CHANGED verdict for exactly this reason, and a true 5-minute cadence
that did re-post each tick would exhaust GitHub's 1000-statuses-per-SHA-per-
context limit in about three and a half days. For a guaranteed-fresh grade before
merging, dispatch the workflow by hand rather than waiting for a tick.

**2. `push` to the release base — grades after the fact and repairs.**
`mode: merge-backstop` re-runs the *same* `evaluate()` with the clock wound back
to the merge instant, and **reopens** any issue the merge closed that no commit
in the release asked to close, with a comment linking the run that decided it. It
cannot prevent the close. It removes the part that did the damage: that the close
was silent.

Verified against live artifacts across the source repository's FULL history — all
70 merged release pull requests, enumerated with pagination (an earlier sweep
claimed "all 22"; 22 was the reach of one unpaginated listing page, the same blind
axis the re-grade itself had). The sweep grades #243 (→ #245) and #480 (→ #459)
as FAIL — the two known incidents — and the remaining 68 as clean, with zero
false positives.

> The post-merge grade reads the **pull request body**, never the merge commit
> message. `squash_merge_commit_message=COMMIT_MESSAGES` means the *branch's*
> commit messages, and a release-please branch has exactly one commit. Re-checked
> on 2026-08-30: the real merge commit of #480 is `chore(main): release 3.13.0
> (#480)` plus a `Co-authored-by` trailer — no changelog, no keyword. Both closes
> came from the link graph alone. A guard aimed at the merge commit message would
> grade an empty universe and report clean on both.
>
> All ten estate repositories are on `COMMIT_MESSAGES` today, so the
> commit-message path is not live in any of them, and the body scan is a
> **secondary widening signal only**. If a consumer sets
> `squash_merge_commit_message=PR_BODY` that path revives and the body scan
> becomes load-bearing — the union the guard grades covers both, which is why it
> is kept.

## THE RESIDUAL — what an operator still has to do

**R1. The contexts are not required until you require them.** Both the
pull-request-time check run and the `release-guard/link-regrade` commit status
have to be added to your branch's required status checks by hand. Until
`release-guard/link-regrade` is required, the bounded window is decorative at
merge time: the cron can turn the status red and nothing forces anyone to look
before merging. Verify by reading the API back **after** the write, because the
response to the write is not evidence the write took:

```
gh api repos/<owner>/<repo>/branches/main/protection/required_status_checks --jq .contexts
```

> Status where it came from, re-derived 2026-08-30:
> `sethbacon/terraform-state-manager-backend` now has **eleven** required
> contexts, and **both** `Release PR closes only what it completes` *and*
> `Release-PR guard self-test` are among them, with `strict: true`. The residual
> doc in that repository still says ten, and still lists the self-test as *not*
> required; both were stale. `release-guard/link-regrade` remains unrequired
> there — R1 is genuinely open, just not for the reason the old text gave.

**R2. `enforce_admins` — the guard binds nobody until it is true.** An `--admin`
merge bypasses every required context, whatever it says, and release pull
requests in this estate are merged that way. So even with R1 finished, **no
required context binds the person who merges releases**; only the post-merge
backstop applies to them.

Where this came from it is a considered decision rather than an oversight:
turning `enforce_admins` on would end `--admin` merges, which is currently the
only way releases get merged with a single maintainer, and the recorded plan is
to flip it when the project gains a second reviewer — at which point every
mechanism here engages with no further work. **A consumer adopting this guard
inherits the decision, not the answer.** Anyone auditing: treat every required
context in a repository with `enforce_admins: false` as advisory, and check the
current state rather than assuming:

```
gh api repos/<owner>/<repo>/branches/main/protection/enforce_admins --jq .enabled
```

**R3. One cron tick is still exploitable, and the tick is hours wide.** A link
made and merged between two ticks merges green. The requested cadence is 5
minutes; the *delivered* cadence measured across twelve consecutive ticks was
1.7h at best and 5.4h at worst, so the exposure is a matter of hours rather than
the ">=5 minutes" this section used to claim. A concrete instance during the
rollout: `sethbacon/azure-pipelines-terraform#1080` carried no guard signal at
all for roughly four and a half hours, until a tick at 12:17:51Z re-graded it.
The backstop catches it after the fact; nothing prevents it. Dispatch the
workflow by hand for a fresh grade before merging.

**R4. Scheduled workflows are disabled after 60 days of repository inactivity.**
If that happens, `link-regrade` stops silently and the window reopens to
infinity, looking exactly like a passing guard. It is worth checking that the
workflow has recent scheduled runs when auditing.

**R5. The backstop repairs, it does not prevent.** Between merge and the `push`
run the issue is genuinely closed. Anything watching issue-closed events in that
window sees the wrong state.

**R6. The backstop grades `github.sha` only — the head of the push.** If a
release merge ever landed in the *middle* of a multi-commit push to the base
branch, the commits behind the head would not be graded. This is deliberate
rather than overlooked: with squash merges onto a protected branch each merge is
its own push, so the head *is* the merge commit; and the alternatives — walking
`github.event.commits`, which is capped at 20 entries and is empty on a
force-push — add failure modes worth more than the case they cover. If direct or
batched pushes to the base branch are ever allowed, this needs revisiting.

**R7, new in the port. The consumer owns the job names, the triggers and the
permissions, and this repository cannot check any of them.** The guard is a
composite action called as a step, which is what keeps a required check from
being renamed — but it means the wiring around it lives in six repositories
this one does not read. A consumer that drops the `schedule:` trigger, or grants
`merge-backstop` no `issues: write`, gets a guard that is quieter than it looks.
Two partial mitigations exist and neither is complete: the action **fails** on a
mode it does not implement or a mode called without its required inputs, rather
than silently running no step; and the example workflow in the adoption doc is
itself under test here, so the thing consumers copy is checked for its cron, its
concurrency key, its `issues: write` and its pinning. Neither of those observes
what a consumer actually merged.

**R8, new in the port. The pin can go stale in six places at once.** A shared
action is one improvement landing everywhere — but only in repositories whose
pin has moved. A consumer sitting on an old SHA looks exactly like one that
adopted the fix. That is the failure mode this repository's README already names
for shared workflows ("repos sitting on different pins is the same defect wearing
a new hat"), and it now applies to this guard too.

### The only way to close R3 completely

Enable a merge queue on the base branch, require `release-guard/link-regrade` in
it, and set `enforce_admins: true`. That moves the grade to dequeue time, after
which no link can be added. It also means release pull requests can no longer be
merged with `--admin`, which is a workflow change, not just a settings change —
which is why it is written down here as a decision rather than made silently.
