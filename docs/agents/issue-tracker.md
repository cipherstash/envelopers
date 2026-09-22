# Issue tracker: Linear

Issues and specs for this repo live in Linear, team **CIP**, labelled **`envelopers`**. Use the Linear MCP tools for all operations. If they aren't available or authenticated, set them up before proceeding; don't fall back to GitHub Issues.

## Conventions

- **Create an issue**: create in team CIP with the `envelopers` label. Put the spec or description in the issue description as markdown.
- **Read an issue**: fetch by identifier (e.g. `CIP-3794`), including comments, labels, state, and relations.
- **List issues**: filter by team CIP, label `envelopers`, and state (open = not Done/Canceled), plus any triage label.
- **Comment on an issue**: add a comment to the issue.
- **Apply / remove labels**: update the issue's labels. Create a label in team CIP if it doesn't exist yet.
- **Close**: move to the team's Done state with a closing comment. For wontfix, move to Canceled.

Issues are referenced by identifier (`CIP-1234`). Branch names and commit messages include the lowercased identifier (e.g. `fix/cip-3794-stable-rust`) so Linear links branches and PRs automatically.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external GitHub PRs as feature requests; `/triage` reads this flag.)_

## When a skill says "publish to the issue tracker"

Create a Linear issue in team CIP with the `envelopers` label.

## When a skill says "fetch the relevant ticket"

Fetch the Linear issue by identifier, with comments.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single parent issue with **sub-issues** as tickets.

- **Map**: a Linear issue labelled `envelopers` and `wayfinder:map`, holding the Notes / Decisions-so-far / Fog description.
- **Child ticket**: a sub-issue of the map (set its parent to the map). Labels: `envelopers` plus `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: Linear's native "blocked by" relation. A ticket is unblocked when every blocker is Done or Canceled.
- **Frontier query**: list the map's open sub-issues, drop any with an open blocker or an assignee; first in map order wins.
- **Claim**: assign the issue to me, the session's first write.
- **Resolve**: comment the answer, move to Done, then append a context pointer (gist + identifier) to the map's Decisions-so-far.
