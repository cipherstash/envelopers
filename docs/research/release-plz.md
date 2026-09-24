# Adding release-plz to Envelopers

Research date: 2026-09-22

## Recommendation

Add release-plz with its recommended two-job GitHub Actions workflow, crates.io
Trusted Publishing, and a repository-scoped GitHub App token. Configure releases
to occur only after a release PR is merged, keep the existing changelog, and pin
both the action commit and the release-plz CLI version.

Do not enable publishing immediately. The repository initially declared
`envelopers` 0.8.3 while the latest public documentation was for 0.8.2 and the
repository had no `0.8.3` tag. That ambiguity was resolved when 0.8.3 was
released on 2026-09-23 (confirmed by the maintainer). Continue with
the non-publishing observation phase before release-plz is allowed to publish.
Cargo releases are effectively permanent and a published version cannot be
overwritten
([Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html)).

## Current repository state

This is a single library crate rather than a workspace. It already has the
publishing metadata Cargo expects: package name and version, description,
license file, repository, README, and `rust-version`. It also commits
`Cargo.lock`, maintains a root `CHANGELOG.md` in Keep a Changelog format, and
uses `main` as its default branch. Release-plz looks for `CHANGELOG.md` beside
the package manifest by default, so no custom changelog path is needed
([release-plz configuration](https://release-plz.dev/docs/config)).

The existing `.github/workflows/test.yml` runs on pull requests and pushes to
`main`, with quality, MSRV/stable tests, and benchmarks. Its actions are pinned
to full commit SHAs. The live GitHub settings inspected on 2026-09-22 show:

- Actions are enabled, all actions are allowed, and repository-level SHA
  pinning is not enforced.
- The default `GITHUB_TOKEN` permission is write, and Actions may create/approve
  pull requests.
- The active `main` ruleset requires a PR, one approval, signed commits, and
  blocks deletion/non-fast-forward updates, but does **not** currently require
  status checks.

The workflow should still declare least-privilege permissions per job; GitHub
recommends explicit minimum permissions rather than relying on repository
defaults
([GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)).

## Required behavior

Release-plz's recommended workflow runs on pushes to `main` and separates two
operations:

1. `release-plz release` publishes versions already prepared and merged.
2. `release-plz release-pr` opens or updates the next release PR, including the
   manifest version and changelog.

The jobs should remain separate. Release-plz explicitly does not recommend its
single-job alternative because concurrency choices can run releases in parallel
or skip the commit that merged a release PR
([quickstart](https://release-plz.dev/docs/github/quickstart),
[single-job workflow](https://release-plz.dev/docs/extra/single-job-workflow)).

For this repository, set `release_always = false`. Its default is `true`, which
tries to release unpublished packages after every push to `main`; `false`
restricts publishing to a commit associated with a release-plz release PR. This
provides a visible approval point and avoids publishing an incidental main-branch
commit. Release-plz recognizes these PRs by its `release-plz-` branch prefix
([configuration reference](https://release-plz.dev/docs/config#the-release_always-field)).

Keep these safe defaults explicit or unchanged:

- `semver_check = true` for this library crate. Release-plz uses
  cargo-semver-checks to detect public API breakage, though its documentation
  warns that it cannot catch every violation
  ([semver checks](https://release-plz.dev/docs/semver-check)).
- `publish_no_verify = false`, `publish_allow_dirty = false`, and
  `allow_dirty = false`, preserving Cargo's package build verification and clean
  tree checks
  ([release-plz configuration](https://release-plz.dev/docs/config)).
- Changelog updates, tags, and GitHub Releases enabled. Release-plz defaults to
  `v{{ version }}` for a single public crate, but this repository's existing
  tags and releases use bare versions such as `0.8.2`. Preserve that public
  convention explicitly with `git_tag_name = "{{ version }}"` and
  `git_release_name = "{{ version }}"`
  ([tag configuration](https://release-plz.dev/docs/config#the-git_tag_name-field)).

Release-plz interprets Conventional Commit subjects: `fix:` means patch,
`feat:` minor, and `type!:` breaking/major; unrecognized messages result in a
patch bump. Because this repository accepts squash merges, PR titles (which
usually become squash commit subjects) should follow that convention
([changelog format](https://release-plz.dev/docs/changelog/format)). Existing
history is mixed, so the first generated release PR needs careful review.

## Authentication and permissions

### crates.io: use Trusted Publishing

Prefer crates.io Trusted Publishing over a long-lived
`CARGO_REGISTRY_TOKEN`. Configure a trusted publisher for `envelopers` with the
exact GitHub owner (`cipherstash`), repository (`envelopers`), workflow filename
(`release-plz.yml`), and a `release` GitHub Environment. Then give **only** the
publish job `id-token: write`; omit `CARGO_REGISTRY_TOKEN` and do not add
`rust-lang/crates-io-auth-action`. Release-plz performs the OIDC token exchange
itself
([release-plz quickstart](https://release-plz.dev/docs/github/quickstart),
[crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing),
[Rust RFC 3691](https://github.com/rust-lang/rfcs/blob/master/text/3691-trusted-publishing-cratesio.md#trusted-publisher-configuration-on-cratesio)).

The GitHub Environment is an additional place to restrict deployment branches
or require approval. Its name in the job must exactly match the crates.io
publisher configuration. Trusted Publishing cannot perform a crate's first-ever
publish, but `envelopers` already exists on crates.io
([release-plz quickstart](https://release-plz.dev/docs/github/quickstart)).

If Trusted Publishing cannot be enabled, the fallback is a scoped crates.io
token in `CARGO_REGISTRY_TOKEN` with only the required publish scopes. Cargo
accepts the crates.io token through that environment variable
([Cargo registry authentication](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)).

### GitHub: use a GitHub App token

The default `GITHUB_TOKEN` can let release-plz open its PR, but GitHub suppresses
new workflow runs caused by that token. Consequently the release PR would not
run `test.yml`. Release-plz documents a minimal GitHub App as its own preferred
approach: install it only on this repository and grant Contents and Pull
requests read/write. Administration read/write is needed only if protected tags
require it
([release-plz GitHub token guide](https://release-plz.dev/docs/github/token)).

Store the App's Client ID as an Actions variable or secret and its private key as an
Actions secret (for example, `RELEASE_PLZ_APP_CLIENT_ID` and
`RELEASE_PLZ_APP_PRIVATE_KEY`). Generate a short-lived installation token with
`actions/create-github-app-token` and pass that token as `GITHUB_TOKEN` to both
release-plz jobs. A fine-grained PAT can also trigger CI, but it is a long-lived
credential tied to a user or machine account and is the less desirable fallback.

Suggested job permissions are:

| Job | Permissions |
| --- | --- |
| release | `contents: write`, `pull-requests: read`, `id-token: write` |
| release-pr | `contents: write`, `pull-requests: write` |

Use `actions/checkout` with `fetch-depth: 0`; release-plz needs history and tags.
Use `persist-credentials: false` unless the workflow explicitly needs Git CLI
credentials for signed tag pushes
([quickstart](https://release-plz.dev/docs/github/quickstart),
[token guide](https://release-plz.dev/docs/github/token#use-a-github-app)).

## Branch rules and required checks

The present ruleset requires review but not CI. Independently of release-plz,
the intended "gate CI" policy should add the stable, unique job names from
`test.yml` as required status checks on `main`. GitHub warns that duplicate job
names across workflows can make required checks ambiguous
([protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)).

Do not bypass review or CI for release PRs. The App token ensures the generated
PR triggers normal checks, and the human merges it only after checks and review.
If the `release` GitHub Environment requires approval, that is a second explicit
gate before crates.io publication. Avoid giving the App ruleset bypass access
unless a concrete protected-tag rule requires it
([GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).

## Concurrency and security

Add concurrency only to the release-PR job:

```yaml
concurrency:
  group: release-plz-${{ github.ref }}
  cancel-in-progress: false
```

Do not put the publish job in this concurrency group. GitHub allows only one
pending run in a group and replaces an older pending run, which can skip the run
that should publish a just-merged release PR
([release-plz single-job/concurrency guidance](https://release-plz.dev/docs/extra/single-job-workflow),
[GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)).

Add `if: github.repository == 'cipherstash/envelopers'` to both jobs so a copied
workflow cannot attempt releases from a fork. Pin every action to a full commit
SHA: GitHub says this is the only immutable action reference
([GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)).
Continue the repository's existing Dependabot/update process for those pins.

As of 2026-09-22, suitable reviewed references are:

- `release-plz/action@b8d6b54b02889ff2ae2bb82e8b57c3a8fc1683a5` (`v0.5.139` action tag line).
- `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1` (`v3.2.0`).
- The checkout and Rust toolchain SHAs already used by `test.yml`.

Also set `with: version: 0.3.169` (the current release on the research date) on
the release-plz action. The action's default is the latest CLI, so the action
SHA alone does not make execution reproducible
([action inputs](https://release-plz.dev/docs/github/input)). Review and update
the SHA and CLI version together rather than treating the versions above as
permanent recommendations.

## Proposed files

### `release-plz.toml`

```toml
[workspace]
release_always = false
semver_check = true
pr_labels = ["release"]
git_tag_name = "{{ version }}"
git_release_name = "{{ version }}"
```

The repository is a single package, but release-plz's global configuration
section is named `[workspace]`. Other defaults are already appropriate; keeping
the file minimal reduces configuration drift. Create the `release` label before
using `pr_labels`, or omit that line.

### `.github/workflows/release-plz.yml`

Base it on the official two-job quickstart, with these repository-specific
changes:

- Trigger only on `push` to `main`, plus `workflow_dispatch` for controlled
  validation if desired. The publish job ignores `workflow_dispatch`; only the
  release-PR job runs on it.
- Use the GitHub App token in both jobs.
- Give the release job the `release` environment and `id-token: write` for
  crates.io Trusted Publishing.
- Run the release job only when the push merged a release-plz PR, checked by a
  read-only gate job, so ordinary merges to `main` do not create a pending
  `release` deployment that needs approval.
- Pin action SHAs and `with: version`.
- Add release-PR concurrency only, with `cancel-in-progress: false`.
- Add the repository guard to both jobs.
- Set `command: release` and `command: release-pr` explicitly.

Use separate token-generation steps in the two jobs; outputs and filesystem
state do not cross job boundaries.

No change to `Cargo.toml` is required for release-plz itself. Optionally add
`publish = ["crates-io"]` to document and enforce the intended registry; Cargo's
`publish` field restricts where a package may be published
([Cargo manifest reference](https://doc.rust-lang.org/cargo/reference/manifest.html#the-publish-field)).

## Safe rollout

1. **Reconcile 0.8.3.** Completed on 2026-09-23: the maintainer confirmed that
   0.8.3 was released.
2. **Validate the package locally.** Run `cargo publish --dry-run`, which performs
   publishing checks without uploading, and inspect the generated package
   ([`cargo publish`](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)).
   Also run the full existing CI suite.
3. **Create credentials and controls.** Install/configure the minimal GitHub App,
   add its secrets, create the `release` Environment with appropriate reviewers,
   and configure the exact trusted publisher on crates.io.
4. **Observation phase.** Merge `release-plz.toml` and the release-PR job first,
   with no publish job. Confirm it opens a sensible PR, triggers `test.yml`, uses
   the expected version bump, and updates `CHANGELOG.md` acceptably. This phase
   is genuinely non-publishing; setting `publish = false` while still running
   `release` can continue to create tags, so omitting the release job is safer
   ([configuration](https://release-plz.dev/docs/config#the-publish-field)).
5. **Enable publishing.** Add the release job only after the generated PR and
   authentication path have been reviewed. Merge the release PR normally and
   approve the `release` Environment deployment if configured to require it.
6. **Confirm outputs.** Check the crates.io version, bare `X.Y.Z` tag, GitHub Release,
   and changelog after the first automated release. Document rollback/incident
   handling; a bad crates.io version cannot be replaced, only yanked and followed
   by a new version.

## Implementation checklist

- [x] Resolve the repository's unpublished-looking 0.8.3 state.
- [ ] Confirm crates.io `envelopers` ownership before configuring Trusted Publishing.
- [ ] Run `cargo package --list` and `cargo publish --dry-run`.
- [x] Create a repository-scoped GitHub App with Contents/Pull requests RW.
- [x] Add App Client ID/private-key credentials to GitHub Actions.
- [x] Create and protect the `release` GitHub Environment.
- [x] Configure crates.io Trusted Publishing for
      `cipherstash/envelopers`, workflow `release-plz.yml`, environment
      `release`.
- [x] Add `release-plz.toml` with `release_always = false`.
- [x] Add the SHA-pinned release-PR job and observe its generated PR first.
- [ ] Ensure release PRs trigger `test.yml` and retain ordinary review rules.
- [ ] Add CI job names as required ruleset checks if CI is intended to be a
      true merge gate.
- [x] Add the separate Trusted Publishing release job after observation.
- [x] Pin and record both action SHA and release-plz CLI version.
- [ ] Adopt Conventional Commit-compatible squash PR titles.
- [ ] Verify crates.io, tag, GitHub Release, and changelog after the first run.
