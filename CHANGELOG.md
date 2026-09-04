# Changelog

## [1.18.2](https://github.com/4cloudguru/shared-workflows/compare/v1.18.1...v1.18.2) (2026-09-04)


### CI

* correct what counts as a releasable commit here ([#52](https://github.com/4cloudguru/shared-workflows/issues/52)) ([c28f616](https://github.com/4cloudguru/shared-workflows/commit/c28f61635476e6d9155bd811b9b9757833ff6a1f))

## [1.18.1](https://github.com/4cloudguru/shared-workflows/compare/v1.18.0...v1.18.1) (2026-09-04)


### CI

* release this repository with the definition it publishes ([#49](https://github.com/4cloudguru/shared-workflows/issues/49)) ([556b27f](https://github.com/4cloudguru/shared-workflows/commit/556b27f2381247850732925d494775d42076f4c2))

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
