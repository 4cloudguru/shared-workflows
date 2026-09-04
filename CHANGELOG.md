# Changelog

## [1.20.2](https://github.com/4cloudguru/shared-workflows/compare/v1.20.1...v1.20.2) (2026-09-04)


### CI

* make the tooling-pin canary follow the owner it is pinned to, and say how old upstream is ([#60](https://github.com/4cloudguru/shared-workflows/issues/60)) ([e98739d](https://github.com/4cloudguru/shared-workflows/commit/e98739d6c14c7545d2012cc8abf7e941e0d9dc37))

## [1.20.1](https://github.com/4cloudguru/shared-workflows/compare/v1.20.0...v1.20.1) (2026-09-04)


### CI

* accept $/ as a pinned self-reference, and make the linter prove it enumerated ([#58](https://github.com/4cloudguru/shared-workflows/issues/58)) ([da90381](https://github.com/4cloudguru/shared-workflows/commit/da90381ff169baf4a1a095f20ea323ac63b05f1d))

## [1.20.0](https://github.com/4cloudguru/shared-workflows/compare/v1.19.0...v1.20.0) (2026-09-04)


### Features

* add the verify-vsix-signature composite action ([#56](https://github.com/4cloudguru/shared-workflows/issues/56)) ([98bf550](https://github.com/4cloudguru/shared-workflows/commit/98bf550fb3e2063e17d6872a0b0ff91f8f87de03))

## [1.19.0](https://github.com/4cloudguru/shared-workflows/compare/v1.18.2...v1.19.0) (2026-09-04)


### Features

* add the publish-marketplace composite action ([#54](https://github.com/4cloudguru/shared-workflows/issues/54)) ([498c8e6](https://github.com/4cloudguru/shared-workflows/commit/498c8e6f94c561163810e011e131dd67bfcdcf8f))

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
