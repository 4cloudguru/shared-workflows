# Adopting the release-PR closing-keyword guard

This repository **publishes** the guard. It turns it on **nowhere**. Adoption is a
separate pull request per consumer, and this document is what that pull request
copies.

Read [`release-pr-guard-residual.md`](release-pr-guard-residual.md) first. The
guard is deliberately partial, and two of its limits are settings on **your**
repository rather than anything a pull request can change.

## What it defends against

release-please renders **every** issue reference a commit carries as
`closes [#N](...)` in the changelog — including a line-initial `Refs #N` trailer
written deliberately to link a tracking issue *without* closing it. That
changelog is the release pull request body, GitHub parses the body into its
**linked-issue graph**, and merging the pull request closes everything in that
graph. The non-closing word the author chose is discarded and the next release
closes the issue anyway, attributed to a release nobody reads line by line.

It has fired three times in `sethbacon/terraform-state-manager-backend`, which
until now was the only repository with the guard. One of the three closed a
nine-root migration tracker at 2 of 9 roots.

There is no configuration fix — the verb is hardcoded in the commit partial of
`conventional-changelog-conventionalcommits` and no release-please config key
reaches it. Only a guard.

## The three modes are not the same kind of thing

| mode | trigger | permissions it needs | is it a required context? |
| --- | --- | --- | --- |
| `pull-request` | `pull_request` | `pull-requests: read`, `issues: read`, `statuses: write` | **yes, once you add it** |
| `link-regrade` | `schedule`, `workflow_dispatch` | `pull-requests: read`, `issues: read`, `statuses: write` | no — it publishes a **commit status** |
| `merge-backstop` | `push` to the release base | `pull-requests: read`, **`issues: write`** | no — it runs after the merge |

`merge-backstop` is the only one that writes. Reopening an issue a release closed
by mistake **is** the repair, and it is the reason that mode exists; without
`issues: write` it fails rather than skipping, which is correct but useless.

## The workflow to copy

Put it in its own file — `.github/workflows/release-pr-guard.yml` — rather than
folding it into `pr-checks.yml`, so it can be added, reviewed and rolled back
without touching a file everything else is also editing.

```yaml
---
name: Release PR Guard

"on":
  pull_request:
    branches: [main]
    types: [opened, edited, synchronize, reopened]
  # Bounds the time-of-check window. The cron asks for every 5 minutes; GitHub
  # delivers roughly 2% of scheduled ticks on a busy account, so the REAL window
  # is hours, not minutes -- measured over twelve consecutive ticks in
  # sethbacon/terraform-state-manager-backend: minimum 1.7h, median 3.8h,
  # maximum 5.4h. Keep the 5-minute cron anyway: asking for less does not make
  # delivery more frequent, and asking for more is capped from the other side by
  # GitHub's 1000-statuses-per-SHA-per-context limit, which a true 5-minute
  # cadence would exhaust in about three and a half days.
  #
  # So this NARROWS the exposure; it does not close it. If you need a
  # guaranteed-fresh grade before merging a release, run this workflow by hand
  # (Actions -> Run workflow) rather than waiting for a tick.
  schedule:
    - cron: "*/5 * * * *"
  # Fires after the merge, the one moment the answer is final.
  push:
    branches: [main]
  workflow_dispatch: {}

permissions:
  contents: read

concurrency:
  # The event name is IN THE KEY. Without it every non-pull_request event
  # collapses to one group, and a scheduled tick would CANCEL the post-merge
  # backstop -- a silent miss in the one job that cannot be re-run by pushing
  # again.
  group: release-pr-guard-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  # Runs on EVERY pull request, not only release ones. A required context that
  # reports on some pull requests and not others blocks the ones it skips
  # forever, so this job is always present and the action short-circuits on a
  # head branch release-please did not create -- posting a passing status for it.
  #
  # THE JOB NAME IS THE REQUIRED CONTEXT. Do not change it after adding it to
  # branch protection; a renamed check silently stops being required.
  closing-keywords:
    name: Release PR closes only what it completes
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      pull-requests: read
      issues: read
      # To publish the same verdict as a commit status on the head SHA, so the
      # scheduled re-grade has something to overwrite and a pull request is never
      # left waiting on a context only the cron can post.
      statuses: write
    steps:
      # hardening-exception: egress-audit — this job reaches only api.github.com
      #   through the gh CLI and mints no long-lived credential, but this repository
      #   has no recorded endpoint baseline yet and a block policy written without one
      #   fails closed on its first run
      - name: Harden the runner
        uses: step-security/harden-runner@05e31511f85b41b11d1cf0ef85d0992719546e2c # v2.21.0
        with:
          egress-policy: audit

      # No actions/checkout. The action carries its own implementation at
      # `github.action_path`, and it reads the pull request through the API
      # rather than from the event payload, so it needs nothing from your tree.
      - name: Grade the release pull request
        uses: 4cloudguru/shared-workflows/.github/actions/release-pr-closing-keywords@REPLACE_WITH_THE_MERGE_SHA
        with:
          mode: pull-request
          gh-token: ${{ secrets.GITHUB_TOKEN }}
          repo: ${{ github.repository }}
          pr-number: ${{ github.event.pull_request.number }}

  # The time-of-check half. An issue attached through the Development panel
  # writes a `connected` timeline event, and `connected` is not an activity type
  # on ANY webhook -- so a link made after the last push fires nothing and no
  # event-driven check can see it. Looking again on a clock BOUNDS that window to
  # one tick; it does not remove it.
  link-regrade:
    name: Re-grade open release PRs against the live link graph
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      pull-requests: read
      issues: read
      statuses: write
    steps:
      # hardening-exception: egress-audit — same shape as the job above: gh CLI to
      #   api.github.com only, no long-lived credential, and no endpoint baseline
      #   exists yet for this repository to write a block policy from
      - name: Harden the runner
        uses: step-security/harden-runner@05e31511f85b41b11d1cf0ef85d0992719546e2c # v2.21.0
        with:
          egress-policy: audit

      - name: Re-grade every open pull request and republish the verdict
        uses: 4cloudguru/shared-workflows/.github/actions/release-pr-closing-keywords@REPLACE_WITH_THE_MERGE_SHA
        with:
          mode: link-regrade
          gh-token: ${{ secrets.GITHUB_TOKEN }}
          repo: ${{ github.repository }}

  # Runs once the merge has happened, which is the only moment no link timing, no
  # cancelled run and no admin bypass can dodge. It cannot prevent the close. It
  # makes the close LOUD and puts the issue back.
  merge-backstop:
    name: A merged release closed only what it completes
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      pull-requests: read
      # To reopen an issue the merge closed that no commit in the release asked
      # to close. This is the repair, and it is the reason the job exists.
      issues: write
    steps:
      # hardening-exception: egress-audit — same shape again: gh CLI to
      #   api.github.com only, no long-lived credential, and no endpoint baseline
      #   exists yet for this repository to write a block policy from
      - name: Harden the runner
        uses: step-security/harden-runner@05e31511f85b41b11d1cf0ef85d0992719546e2c # v2.21.0
        with:
          egress-policy: audit

      - name: Grade the merge and reopen anything it closed by mistake
        uses: 4cloudguru/shared-workflows/.github/actions/release-pr-closing-keywords@REPLACE_WITH_THE_MERGE_SHA
        with:
          mode: merge-backstop
          gh-token: ${{ secrets.GITHUB_TOKEN }}
          repo: ${{ github.repository }}
          merge-sha: ${{ github.sha }}
```

Replace `REPLACE_WITH_THE_MERGE_SHA` with the commit of this repository you are
pinning to — **the same SHA on all three lines**, and not a tag or `@main`. All
three modes share one implementation on purpose: `merge-backstop` grades by
calling the *same* `evaluate()` the pull-request guard runs, and one pin is what
makes that true in your repository rather than only in this one.

## Inputs you may need to change

Everything below is defaulted, and the defaults are right for every repository in
this estate today. They exist because they were **literals** in the source and a
literal that is right in one repository is a silent wrong answer in the next.

| input | default | change it when |
| --- | --- | --- |
| `status-context` | `release-guard/link-regrade` | never, unless it collides. Both publishers must share one name or the cron cannot overwrite the pull-request-time pass. |
| `base-branch` | `main` | your releases target something else. `link-regrade` uses it for **both** derivations of its universe. |
| `release-branch-prefix` | `release-please--branches--` | you changed release-please's branch naming. A prefix that matches nothing reports "nothing to check" on every release forever. |

## What you must do outside the pull request

These are repository settings. A pull request cannot make them, and the guard is
advisory until they are made.

1. **Add `Release PR closes only what it completes` to `main`'s required status
   checks.** Until then the job reports on every pull request without blocking
   one.

2. **Add `release-guard/link-regrade` to the required status checks too.** This
   is the commit status the cron overwrites. Without it the bounded window is
   decorative at merge time: the cron can turn the status red and nothing forces
   anyone to look before merging. The pull-request-time context alone grades the
   world as it stood at the last `pull_request` event — which is exactly the
   moment this guard exists to distrust.

3. **Decide about `enforce_admins`.** While it is `false`, an `--admin` merge
   bypasses every required context and **no required context in your repository
   binds the person who merges releases** — only the post-merge backstop applies
   to them. See the residual doc; this is a decision, not a step.

4. **Check the schedule is still running when you audit.** GitHub disables
   scheduled workflows after 60 days of repository inactivity, and a stopped cron
   looks exactly like a passing guard.

Verify 1 and 2 by reading the protection API back after the write, not by
trusting the response to the write:

```
gh api repos/<owner>/<repo>/branches/main/protection/required_status_checks --jq .contexts
```

## Order of adoption

`sethbacon/terraform-state-manager-backend` goes **last**. It is the only
repository where `Release PR closes only what it completes` is already a required
context, so it is the only one where a mistake in the move breaks a gate rather
than merely failing to add one. Everywhere else, the worst case of a botched
adoption is that a new check never becomes required — which is where those
repositories already are.
