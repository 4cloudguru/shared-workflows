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
    secrets: inherit
```

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
