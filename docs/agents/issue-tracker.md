# Issue tracker: GitHub Issues

Issues and specs for this repo live in GitHub Issues on `cipherstash/envelopers`. Use the `gh` CLI for all operations. Linear (team CIP) mirrors these issues automatically; never create or edit issues in Linear directly, and never reference Linear identifiers (`CIP-1234`) in commits, branches, PRs, or docs.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body-file <file>`. Put the spec or description in the body as markdown.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open`, plus `--label <triage-label>` as needed.
- **Comment on an issue**: `gh issue comment <number> --body-file <file>`.
- **Apply / remove labels**: `gh issue edit <number> --add-label <label>` / `--remove-label <label>`. Create a missing label with `gh label create <label>`.
- **Close**: `gh issue close <number> --comment "..."`. For wontfix, use `--reason "not planned"`.

Issues are referenced as `#123`. Branch names include the issue number (e.g. `fix/123-stable-rust`). Commit messages reference the issue in the subject scope or body (e.g. `fix(ci): pin toolchain (#123)`), and PR descriptions use `Closes #123` so merging closes the issue.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external GitHub PRs as feature requests; `/triage` reads this flag.)_

## When a skill says "publish to the issue tracker"

Create a GitHub issue with `gh issue create`.

## When a skill says "fetch the relevant ticket"

`gh issue view <number> --comments`.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single parent issue with **sub-issues** as tickets.

- **Map**: a GitHub issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog description.
- **Child ticket**: a sub-issue of the map (GraphQL `addSubIssue` via `gh api graphql`). Label: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's native "blocked by" issue dependency (GraphQL `addBlockedBy`). A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open sub-issues, drop any with an open blocker or an assignee; first in map order wins.
- **Claim**: `gh issue edit <number> --add-assignee @me`, the session's first write.
- **Resolve**: comment the answer, close the issue, then append a context pointer (gist + `#number`) to the map's Decisions-so-far.
