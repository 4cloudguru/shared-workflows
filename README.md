# shared-workflows

Reusable GitHub Actions workflows for the Terraform suite (`sethbacon/*`) and the
pipeline-task families (`4cloudguru/*`).

Public on purpose: a reusable workflow in a public repository can be called from
any repository, which is what lets repos under **two different owners** share one
definition.

## Why this exists

The estate had **72 workflow files across 14 repositories**, and six filenames
repeated 6–9 times each. Measuring the copies rather than assuming:

| workflow | copies | distinct versions (comments stripped) |
| --- | --- | --- |
| `release.yml` | 9 | 9 |
| `pr-checks.yml` | 9 | 9 |
| `weekly-security.yml` | 8 | 8 |
| `signature-replay.yml` | 9 | 7 |
| `release-please.yml` | 12 | 7 |
| `zizmor.yml` | 6 | 2 |

The important finding is what the divergence turned out to *be*. For
`release-please.yml` — 27 lines of code — every copy used the same config file,
the same manifest file, the same App id variable and the same App key secret.
The only substantive difference was the permission model:

- **least privilege** (7 repos): `contents: read` at the workflow, elevated to
  `contents`/`pull-requests` write on the token step alone
- **broad** (5 repos): `contents: write` for the entire workflow

Nobody decided those five should be more permissive. Someone tightened it in one
family and the others never heard.

That is the same shape as three hand-copies of one HTTP client where the egress
fix reached one, three dev-admin seeds where the carrier fix reached one, and
three marketplace publish scripts where the tfx validation fix would have reached
one. **The value of sharing is not less YAML — it is that an improvement lands
everywhere at once.**

## Using a workflow here

```yaml
jobs:
  release-please:
    uses: 4cloudguru/shared-workflows/.github/workflows/release-please.yml@<full-sha>
    secrets:
      RELEASE_DISPATCH_APP_KEY: ${{ secrets.RELEASE_DISPATCH_APP_KEY }}
```

**Name the secrets; do not use `secrets: inherit`.** Inheriting forwards *every*
secret in the calling repository to a workflow in a different owner's
repository. `zizmor` flags it (`secrets-inherit`), and it would be an odd
over-grant to introduce via workflows whose purpose is least privilege — which
is exactly what the first draft of this did, and what the linter caught.

`vars` resolves against the **caller's** repository, so per-repo values such as
`RELEASE_DISPATCH_APP_ID` stay where they are and nothing about App installations
changes.

## Pin by SHA

Not by a tag, and not by `@main`.

A shared workflow is itself something that drifts. Repos sitting on different
pins is the same defect wearing a new hat, and it is **harder** to see than
divergent files, because every repo looks like it is using "the shared one". The
duplication becomes invisible instead of disappearing.

That is a claim worth enforcing rather than documenting, which is why a
pin-parity signature belongs alongside this repo rather than a note in a README
asking people to remember.

## Composite actions here

Two guards live in `.github/actions/` rather than `.github/workflows/`, and the
reason is the same for both: **a reusable workflow reports as
`<caller-job-id> / <called-job-name>`, which renames the check.** Both are
required status contexts somewhere in the estate, and a required context that
gets renamed silently stops being required — a failure mode where a gate stops
existing and nothing notices. A composite action is called as a **step** inside
the caller's existing job, so the job keeps its name and no branch protection
moves.

| action | what it refuses | required in |
| --- | --- | --- |
| [`breaking-change-footers`](.github/actions/breaking-change-footers/) | a squash that would drop a second breaking-change declaration, or prose release-please reads as one nobody wrote | `azure-pipelines-release-docs` |
| [`release-pr-closing-keywords`](.github/actions/release-pr-closing-keywords/) | a release pull request that would close an issue the release does not complete | `terraform-state-manager-backend` |

### The release-PR closing-keyword guard

release-please renders **every** issue reference a commit carries as
`closes [#N](...)` in the changelog — including a line-initial `Refs #N` written
deliberately to link a tracking issue *without* closing it. GitHub parses that
body into its **linked-issue graph**, and merging closes everything in the
graph. The word the author chose is discarded. It fired three times in
`terraform-state-manager-backend`, which was the only one of **seven**
release-please repositories with a guard for it.

It grades `closingIssuesReferences` over GraphQL — GitHub's own answer to "what
does merging this close?" — and not body text, because an issue attached through
the **Development panel** closes on merge with no body text at all. The body scan
is a clearly-labelled secondary signal.

Three modes, and they are not the same kind of thing:

- `pull-request` — the required context. Grades the pull request and publishes a
  commit status on the head SHA.
- `link-regrade` — a `schedule` tick that re-grades every open pull request
  against the live link graph. `connected` is not an activity type on **any**
  webhook, so a Development-panel link fires nothing and no event-driven check
  can see it; looking again on a clock bounds that window rather than closing it.
- `merge-backstop` — a `push` grade of the merge instant that **reopens** what a
  release closed by mistake. It cannot prevent the close; it removes the part
  that did the damage, which was silence.

**Adopting it:** [`docs/release-pr-guard-adoption.md`](docs/release-pr-guard-adoption.md).
**What it does not close:** [`docs/release-pr-guard-residual.md`](docs/release-pr-guard-residual.md)
— read this one first. Two of its limits are settings on the consuming
repository, and while `enforce_admins` is `false` the guard binds nobody.

### `publish-marketplace`

Not a guard — the other two composite actions here refuse something; this one
does the thing itself. [`publish-marketplace`](.github/actions/publish-marketplace/)
publishes a packaged `.vsix` to the VS Marketplace via `tfx-cli`, with a bounded
retry that survives a transient upstream failure instead of burning the release,
and the token delivered to `tfx` on stdin so it never touches argv. Used by
`azure-pipelines-terraform`, `azure-pipelines-packer` and
`azure-pipelines-release-docs`.

It replaces three byte-identical copies of the same script, kept in sync by
hand — which is exactly how a regression shipped: the retry classifier's
duplicate-version detector false-matched `tfx`'s own routine "Checking if this
extension is already published" preamble, printed before **every** attempt, so
a genuine Gallery API timeout on `azure-pipelines-terraform`'s v1.15.2 release
was misreported as a deterministic rejection and never retried, leaving the
release stuck in draft. The same defect sat unfired, uncopied, in the other two
consumers. Composite action for the same reason as the two guards above: the
`marketplace` GitHub Environment's required-reviewer + deployment-branch gate is
a property of the *calling* job (`environment: marketplace` stays declared in
each consumer's own `release.yml`), and a reusable workflow would run as a
separate job with no way to carry that gate with it.

### `verify-vsix-signature`

Also not a guard in the "what it refuses" sense above.
[`verify-vsix-signature`](.github/actions/verify-vsix-signature/) installs
cosign and verifies a packaged `.vsix` against its keyless sign-blob bundle
before the artifact is published or attached to a release. Used by
`azure-pipelines-terraform`, `azure-pipelines-packer` and
`azure-pipelines-release-docs`, found while comparing all three consumers'
publish jobs line by line to centralize `publish-marketplace` (above):
terraform and release-docs each ran this as a hand-copied shell block, twice
each (once before publishing, once before attaching to the draft GitHub
Release); packer had no equivalent gate anywhere, so a substituted artifact
between the sign job and the publish job would have reached the Marketplace
from packer undetected. Same composite-action reasoning as the other two:
this step runs inside whatever job and Environment gate the caller already
has, and never has to answer which repository's environment protection
would apply if it were a job of its own.

## Releasing this repository

Releases are cut by release-please, from `.github/workflows/release.yml`, which
calls the very `release-please.yml` definition this repository publishes to
twelve others. Before 2026-09-03 nothing called it here and every tag was cut by
hand; four releasable commits sat unreleased behind v1.17.0 while twelve
repositories rolled their pins to an untagged commit because there was no tag on
the fixed tree to roll to.

**Choose the commit type by who is affected, not by which directory the file is
in.** The workflows and composite actions here *are* this repository's product,
and they live under `.github/`, so the usual instinct is wrong:

| change | type | release |
| --- | --- | --- |
| a published workflow or composite action — anything a caller executes | `feat:` / `fix:` | minor / patch |
| this repository's own plumbing: `self-check.yml`, the drift canary, its tests | `ci:` | patch |

**All three release here.** release-please's *default* releasable units are
`feat`, `fix` and `deps`, but that default goes with the default config, where
`ci` is hidden — and a type listed in `changelog-sections` **without**
`hidden: true` becomes releasable, not merely visible.
`.release-please-config.json` lists `ci` unhidden deliberately, so a `ci:` commit
cuts a patch. Verified: the only commit after v1.18.0 was a `ci:` one, and
release-please opened `chore(main): release 1.18.1` from it.

So the table is about **saying the right thing**, not about getting a release.
Pick the type a consumer's changelog should show and the increment they should
see, and the version follows.

Keeping `ci` releasable is the forgiving choice on purpose: hiding it would make
the naming rule load-bearing, and a caller-visible change mislabelled `ci:` would
then silently never release.

If a batch is genuinely unreleasable — all `chore:` and `test:` — and still needs
a tag, run the `Release` workflow by hand (`workflow_dispatch`).

## Tenancy model (estate-wide)

The suite is moving to an explicit tenancy model: **the host is the content tenant**
(modules, providers, binaries belong to a host), **the organisation is the editorial
scope** (who may edit, set policy, approve a version), and the state manager is
**single-host by design**.

**Read [`docs/tenancy-model.md` in terraform-suite-identity](https://github.com/sethbacon/terraform-suite-identity/blob/main/docs/tenancy-model.md) before changing
anything that touches `organization_id`, namespace ownership, the Terraform protocol
surface, or a scoped read.** It also records what must not be done — two of those are
one-way doors that read as ordinary tidy-up.

Most relevant here: **an unscoped read is not automatically a finding.** The registry's
consumption surface is unscoped by design under the current model. A guard should assert
that every unscoped read is *declared*, not that none exists.
