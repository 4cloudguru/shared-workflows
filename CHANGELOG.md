# Changelog

## 1.18.0 (2026-09-03)

Cut by hand, and the last one that will be. This file starts here because
release-please was only wired up to this repository in the same change; releases
v1.13.0 through v1.17.0 exist as
[GitHub Releases](https://github.com/4cloudguru/shared-workflows/releases) and
were also cut by hand, with no changelog kept.

### Features

* **osv-scan:** a scan action that reports the exit code it actually got (#43)

### Bug Fixes

* **release-pr-guard:** close four holes found verifying the rollout (#42)
* **signature-replay:** `create-github-app-token`'s `app-id` input is
  deprecated; use `client-id` (#37)

### CI

* bump zizmor 1.29.0 to 1.30.0 and zizmor-action v0.6.2 to v0.6.3, with the
  `self-repository` audit excepted (#47)
