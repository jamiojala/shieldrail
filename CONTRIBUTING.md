# Contributing to ShieldRail

Thanks for contributing to ShieldRail.

## Prerequisites

- Node.js 18.18+
- pnpm 10+

## Setup

```bash
pnpm install
```

## Development Commands

```bash
pnpm test
pnpm test:watch
pnpm typecheck
pnpm build
pnpm example:basic
```

## Project Standards

 Keep APIs strongly typed and backward-compatible when possible.
 Add tests for all behavior changes.
 Keep docs and examples in sync with code changes.
 Never commit provider credentials, API keys, or secrets.

## Adding Rules

1. Add the rule to src/rules.ts or as a custom rule.
2. Add tests covering the new pattern.
3. Update docs with the rule name and severity.
4. Run pnpm check before opening a PR.

## Changesets

ShieldRail uses Changesets for releases. Run pnpm changeset, select the package, choose a version bump, and describe the change.
