# Security

This repository publishes reusable GitHub Actions workflows that run inside the
CI of other repositories. **A change here executes in every caller**, several of
which hold `id-token: write` and release credentials. Treat it as the most
privileged repository in the estate, because it is.

## Why it is public

Not a preference — a constraint. The callers live under `sethbacon` (a user
account); this repo lives under `4cloudguru` (an organization). GitHub's Actions
access policy for private repositories is **same-owner only** (`none` / `user` /
`organization`), so a private repo here could serve `4cloudguru/*` repos and
would lock out every current caller.

Going private would also *remove* protection rather than add it: on the current
free plans, a private repository cannot have branch protection at all
(`Upgrade to GitHub Pro or make this repository public`). The integrity controls
below exist **because** the repo is public.

Nothing secret lives here. Secrets are supplied by the caller at call time and
are never read, stored or logged by these workflows.

## What is enforced

| control | state |
| --- | --- |
| `enforce_admins` | **true** — admins are bound by every rule below |
| required status checks | both lint jobs, `strict` (branch must be current) |
| force pushes | blocked |
| branch deletion | blocked |
| linear history | required |
| conversation resolution | required |
| allowed actions | GitHub-owned plus two named third parties; nothing else may run |
| default `GITHUB_TOKEN` | read |
| secret scanning + push protection | enabled |
| Dependabot security updates | enabled |

`required_approving_review_count` is **0**, deliberately. With a single
maintainer, a required review is a deadlock rather than a control — nobody can
approve their own pull request. The controls that actually bind a solo
maintainer are `enforce_admins: true` and required status checks, and those are
strictly stronger than a review requirement that is bypassed by the same admin
it nominally applies to.

## What callers must do

Pin by **full commit SHA**, never a tag or `@main`. A tag can be moved; a branch
moves by definition. Pin drift across callers is enforced by the
`shared-workflow-pin-parity` signature in `sethbacon/security-orchestration`.

Pass secrets by **name**, never `secrets: inherit` — inheriting forwards every
secret in the calling repository to a workflow in a different owner's
repository. `zizmor`'s `secrets-inherit` rule flags it.

## Reporting

Open an issue, or contact the maintainer directly for anything that should not
be public.
