# CLAUDE.md

dns-gate: an MCP server and web page for DNS at several providers. Agents read and propose; a person
signed in with Google accepts before anything reaches a provider. Overview and config: `README.md`.

## How changes land

**Direct pushes to `main` until the first working version exists; branch + PR after that.**
(Steinar, 18 Nov 2026: "Let's do direct pushes until we a have first working version - and then PR's
after that.") This is a Cantara repo, so once that switch is made, every change is a PR, reviewed
before merge, merged with *Rebase and merge*.

"First working version" = it runs on a real host and an agent's proposal on a real domain has been
accepted by a person through the page. When that happens, say so and switch.

## Rules for working here

- **Only `Gate.accept()` writes to a provider.** Never add another write path, and never give the
  MCP side a tool that accepts, rejects or applies. `test/server.test.ts` asserts the tool list.
- **Every guard has a test that fails without it.** When adding one, remove it once and watch a test
  fail before keeping the test.
- **Keep runtime dependencies minimal.** This service holds credentials that can change every
  domain on an account. Pin exact versions, and prefer a version at least two weeks old.
- **No secrets in the repo**: not in the config, the tests or the examples.
- **Provider tests use recorded API shapes**; they prove our translation, not that the live API
  still has those shapes. `check-config` against a real account is that check.
- No build step: Node runs `src/*.ts` directly, so only erasable TypeScript syntax (no enums, no
  parameter properties); imports carry the `.ts` extension.

## Commands

```sh
npm test
npm run typecheck
node src/cli.ts --help
```
