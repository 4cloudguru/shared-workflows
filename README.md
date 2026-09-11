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

The guards below live in `.github/actions/` rather than `.github/workflows/`,
and the reason is the same for all of them: **a reusable workflow reports as
`<caller-job-id> / <called-job-name>`, which renames the check.** Each one runs
inside a job whose context is already required somewhere in the estate, or is
headed for one, and a required context that gets renamed silently stops being
required — a failure mode where a gate stops existing and nothing notices. A
composite action is called as a **step** inside the caller's existing job, so the
job keeps its name and no branch protection moves. The `required in` column says
where each is binding today; "not yet" means the consumers have not adopted it
here, not that it is advisory.

| action | what it refuses | required in |
| --- | --- | --- |
| [`breaking-change-footers`](.github/actions/breaking-change-footers/) | a squash that would drop a second breaking-change declaration, or prose release-please reads as one nobody wrote | `azure-pipelines-release-docs` |
| [`release-pr-closing-keywords`](.github/actions/release-pr-closing-keywords/) | a release pull request that would close an issue the release does not complete | `terraform-state-manager-backend` |
| [`check-docs-claims`](.github/actions/check-docs-claims/) | a document asserting a control, a file table, a referenced path or a required-check provenance the repository does not carry | `azure-pipelines-packer` (`Check Shared Module Provenance`), `azure-pipelines-terraform` (`Check Shared Module Parity`), `azure-pipelines-release-docs` (`Check Documented Claims`) — all three since 2026-09-09, at `v1.23.0` |
| [`check-shared-module-pins`](.github/actions/check-shared-module-pins/) | sibling tasks resolving different versions of one shared `@4cloudguru` package, so a released fix reaches some tasks and not others | `azure-pipelines-packer` (`Check Shared Module Provenance`), `azure-pipelines-terraform` (`Check Shared Module Parity`), `azure-pipelines-release-docs` (`Check Version Consistency`) — all three since 2026-09-09, at `v1.23.0` |
| [`check-enforced-disciplines`](.github/actions/check-enforced-disciplines/) | a rule the repository writes down and nothing asserts — a declared execution handler no CI leg runs, an entry point outside the coverage metric and loaded by no test, a documented Minor-bump rule with no machine behind it, a Marketplace publish with the token on argv and no bounded retry | not yet — released in `v1.24.0` and pinned by nobody; the three ADO extensions still run their own `scripts/` copy, and the consumer pull requests of this phase adopt it |
| [`check-proxy-parity`](.github/actions/check-proxy-parity/) | an outbound HTTP call made through a transport primitive that does not consult the ADO agent's configured proxy, in a repository whose sibling transports do | not yet — the consumer pull requests of this phase adopt it, in the gate jobs and in the `Build and Test …` matrix jobs whose task suites spawn the gate |
| [`check-artifact-trust`](.github/actions/check-artifact-trust/) | a downloaded tool installed, or a cached one admitted, without verification — an unchecked checksum, a signature nobody validates, a cache entry re-used with no re-verification, a delegated verifier pinned below the floor that decides which implementation resolves | not yet — the consumer pull requests of this phase adopt it |
| [`auth-parity-matrix`](.github/actions/auth-parity-matrix/) | a provider-credential branch that does not fail closed the way its siblings do — a raw service-connection field read with no validating accessor, a credential env var left set by a branch that did not populate it, a secret delivered to the tool undeclared, a constant role-session-name | not yet — the consumer pull requests of this phase adopt it |
| [`check-egress-authorization`](.github/actions/check-egress-authorization/) | an outbound request to a destination the process did not fix at build time, issued without routing the host through the shared authorizer — including every redirect hop, which is where an initial-host check alone stops being one | not yet — the consumer pull requests of this phase adopt it |

### The gate actions ported from the extensions

Six now, in two waves. The first three — `check-docs-claims`,
`check-shared-module-pins` and
`check-enforced-disciplines` — arrive here from **four**
places each: a `scripts/` hand-copy in `azure-pipelines-terraform`,
`azure-pipelines-packer` and `azure-pipelines-release-docs`, plus the
**canonical** copy that signature replay runs against all three from
`security-orchestration`'s `remediation/gates/`.

A census on 2026-09-09 found **five of seven** copies of those two scripts
already drifted, and twice that day a fix landed in a hand-copy and never
reached canonical. That direction is the expensive one: the copy the *replay*
runs is the copy that decides whether a defect class is still open, so a
hand-copy that is ahead of canonical makes the replay green about a repository
nobody fixed. `check-docs-claims` is drifted right now —
`azure-pipelines-release-docs` carries an older comment block around the
`osv-scanner` → `osv-scan` detection stem. `check-shared-module-pins` is still
in lockstep across all four, which is exactly what makes this the cheap moment
to move it rather than the expensive one.

`check-enforced-disciplines` was in lockstep too — all four copies `cmp`-clean at
sha256 `9eee3e46…`, and so were all four copies of the `lib/task-dirs.js` it
imports, at `dc5b8f5b…`. That last file is why the count for this gate is
**eight** files and not four: the script's one non-builtin import is
`require('./lib/task-dirs.js')`, resolved relative to the *script*, so `lib/`
ships inside the action here and a checkout carrying the gate without it is a
could-not-run rather than a verdict. The action's preflight says so by name.

**The scripts here are byte-identical to the canonical copies, deliberately.**
Replay's `gatelib` resolves a canonical gate from
`suite/shared-workflows/.github/actions/<gate>/<gate>.js` when it is present and
compares every repository's own copy against it by sha256, so a re-worded
comment is a difference to that comparison exactly as a re-worded condition is —
including the `PROVENANCE. Ported from …` header, which describes the *previous*
move rather than this one, and the `Usage: node scripts/…` line naming a path
that is the consumers' and not this repository's. To change the prose, change
the canonical copy first and re-copy. `signature-replay.yml` gained a checkout of
this repository at `suite/shared-workflows` so that path resolves at all.

All three take the repository root and nothing else, so all three actions expose
one optional `root` (default `.`) and one optional `json` flag, passed through
`env` rather than `${{ }}` — a template substitution happens before bash parses
the line, and a gate step is the last place to model the injection class it
exists to refuse. None has a dependency; all are Node builtins only.

Two things about `check-enforced-disciplines` differ from its siblings, and both
are deliberate. Its `json` input exists for shape parity and is **refused** if
switched on: the script has no `--json` mode and ignores the flag rather than
rejecting it, so forwarding it would hand back the human report to a caller who
believed it had asked for machine output — and a human report piped into `jq`
puts `jq`'s exit code where the gate's used to be. Its human report is a parsed
contract in any case: `security-orchestration`'s
`remediation/signatures/enforced-disciplines.py` reads the `[check]` headers and
`OK`/`FAIL`/`EXEMPT`/`STALE-EXEMPTION` rows out of it and asserts on every run
that its parsed row count equals the total the script prints. And it **fails on
a repository with no `Tasks/` tree** instead of passing quietly, because every
discipline it knows is a property of a task: an empty universe is how a
hard-coded path fails silently, so zero rows is a red flag rather than a clean
bill. Call it only from a repository that has tasks.

#### The second wave: `check-proxy-parity`, `check-artifact-trust`, `auth-parity-matrix`

Same four places each, same byte-identity rule, and every copy still `cmp`-clean
against canonical on the day of the move — which is what makes this the cheap
moment rather than the expensive one. Two things about them are new.

**They ship an asset, and each ships its own.** `check-proxy-parity.js` and
`check-artifact-trust.js` both `require('./lib/package-delegation.js')`, resolved
against the *script*, so the file travels inside each action — two copies of one
lib, deliberately. `github.action_path` is per action, and an action reaching
across to a sibling action's directory would resolve to whatever ref that
sibling happened to be checked out at. Replay's `gatelib` records the pair in
`SHARED_ACTION_ASSETS` and compares both files, so an action published without
its `lib/` is a could-not-run in every replay host at once, not a quiet verdict.
`auth-parity-matrix.cjs` requires `node:fs` and `node:path` and nothing else —
measured, not assumed — so it ships alone and has no assets entry.

**They export their own path, and take a floor.** These three are not only CI
steps: task L0 suites in `azure-pipelines-packer` and `azure-pipelines-terraform`
*spawn* them under `npm test` and assert the whole enumerated set, and one of
those call sites points the gate at a fixture directory built moments earlier.
So each step writes `SHARED_GATE_<ACTION>=<github.action_path>` into
`$GITHUB_ENV`, and the suites resolve the gate from that — which makes the gate
they run the caller's pinned SHA by construction, since nothing in the consumer
chooses a path. The value is written **verbatim**: no `dirname`, no suffix, no
concatenation. On windows-2025 that path is a Windows path, and in Git Bash
`dirname` returns `.` for it — a directory that exists, on one OS only, inside a
required check — while `${AP%/*}` returns the input unchanged. Both are measured
in the self-tests rather than asserted in prose. Node's `path` module is correct
for the platform it runs on, so the arithmetic belongs there and nowhere else.

The floors are the other half. All three gates exit 0 over a repository they
enumerated nothing in, which inside `npm test` is caught by the suite's own
inventory assertion and as a bare CI step is caught by nothing. So the floor
inputs are **required, with no default**: a caller must have measured.
`check-artifact-trust` and `auth-parity-matrix` report a denominator (`scanned`,
the count of source files read), so each takes a `min-scanned` refused below 1
*and* an enumeration floor (`min-sites` / `min-cells`) that may honestly be `0`
— a repository that looked and found none says so deliberately.
`check-proxy-parity`'s `--json` carries no denominator, so its single
`min-sites` is refused below 1; adding a denominator is a change to the
canonical gate, not to the action. Every floor runs **after** the gate's own
verdict run, so a finding aborts first: inline logic in an `action.yml` may turn
a green into a red and never the other way round.

**The first two composites now take one too.** `check-docs-claims` and
`check-shared-module-pins` shipped before that rule existed and could still be
green over a repository they read nothing in, which is
4cloudguru/shared-workflows#75. `check-docs-claims` takes `min-claims`, the sum
of its own `enumerated` counters, and `check-shared-module-pins` takes
`min-scanned`, the task manifests it read; both are required and refused below
1, and both are checked after the verdict run like the others. **This is a
breaking change for the three callers**: an omitted input is refused, because
GitHub does not enforce `required: true` on an action input, so the roll to this
release and the new input lines belong in one pull request per repository.

**And `check-enforced-disciplines` gains one derived check in the same release.**
`scripts/check-enforced-disciplines.js` leaves the three extensions with this
wave, but `scripts/lib/task-dirs.js` cannot: it has four to six *non-gate*
importers per repository, and `copy-build.js` uses `discoverTaskDirs` to decide
what ships in the `.vsix`. `gatelib`'s in-repo comparison is the entry point
alone, so the moment the entry point goes that lib is compared against nothing
in three repositories at once. The action therefore `cmp`s
`<root>/scripts/lib/task-dirs.js` against its own copy whenever that file exists
— derived, with no input and no opt-out, and green today because all four copies
are identical at sha256 `dc5b8f5b…`.

That comparison pins each consumer's copy to the copy at the SHA on that
consumer's `uses:` line, which puts an ordering constraint on the *next* change
to that lib: a fleet pin roll carrying a changed `lib/task-dirs.js` turns the
required gate job red in all three extensions until each re-syncs, and `roll.sh`
rewrites `.github/workflows` pins only, so a blind roll batch cannot carry the
matching `scripts/lib/` re-sync. So a change to that file lands canonical first,
is re-copied here and released, and each consumer's re-sync then rides in the
**same pull request that moves that consumer's pin** — never in a `roll.sh`
batch, and never as a follow-up. The action's `::error::` says where to re-sync
from; this says when.

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
