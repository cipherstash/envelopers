---
status: accepted
---

# Automate crate releases with release-plz

Use release-plz to prepare and publish Envelopers releases through separate GitHub Actions jobs. Release pull requests remain subject to the repository's normal CI and review controls, and publishing occurs only after a release PR is merged (`release_always = false`). Use a repository-scoped GitHub App for GitHub operations and crates.io Trusted Publishing through a protected `release` environment, avoiding long-lived user and registry credentials.

Roll this out in two phases: first run only the release-PR job and review its version and changelog output; enable the publishing job only after reconciling the existing `0.8.3` manifest/changelog state and validating the authentication path. Preserve the repository's bare version tag and release-name convention (`{{ version }}`), pin both action commits and the release-plz CLI version, and do not grant the App ruleset bypass access unless protected tags demonstrably require it.

## Consequences

Releases gain a visible approval point and reproducible automation, but maintainers must provision and rotate a GitHub App private key, configure the crates.io trusted publisher exactly, and review Conventional Commit-compatible squash titles because they drive versioning and changelog generation. A bad crates.io publication remains irreversible; recovery is to yank it and publish a new version.
