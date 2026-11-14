# Contributing

Thanks for considering a contribution. This project is the backend half of
the [CTI platform](https://rinjanianalytics.com) — pair it with the
[dashboard repo](https://github.com/rinjanianalytics/cti-platform-dashboard)
to run the full stack.

## Quick start

```bash
git clone https://github.com/rinjanianalytics/cti-platform-api.git
cd cti-platform-api
pnpm install
cp .env.example .env       # fill in your local secrets
docker compose up -d       # PG + Redis × 2 + OpenSearch + Neo4j
pnpm --filter @rinjani/db push
pnpm dev                   # API on :3001, gateway on :4000, workers in-process
```

If `pnpm install` is your first encounter with this monorepo, see [DEPLOY.md](DEPLOY.md)
for the full prerequisites list (Node 22+ floor, Tailwind 4 oxide binding,
why both Redis ports exist).

## Workflow

1. **Open an issue first** for anything non-trivial. We'd rather discuss the
   design before you spend hours on a PR we'd push back on.
2. **Branch off `master`** with a descriptive name:
   - `feat/<short-desc>` for features
   - `fix/<short-desc>` for bug fixes
   - `chore/<short-desc>` for refactors, tooling, docs
   - `security/<short-desc>` for security work (and please email first per
     [SECURITY.md](SECURITY.md))
3. **Make small commits** that each pass tests. Squash on merge.
4. **Write the commit message** the way our `git log` reads — see below.
5. **Open a PR**. Fill in the template. Link the issue if one exists.

## Commit messages

We use Conventional Commits. The scope is the package or area being changed:

```
feat(workbench): vendor Workbench + scheduler CRUD
fix(nvd): honor NVD_API_KEY across all 7 call sites
security(audit): TanStack supply-chain verification + hono bumps
docs: refresh README + DEPLOY for current architecture
chore(db): move feed_sync_runs to migration 0037
refactor(admin): shared primitives + UI consistency pass
```

Body explains **why**, not what. The diff shows what.

## Code style

- **TypeScript-strict everywhere.** `pnpm lint` and `pnpm --filter @rinjani/api exec tsc --noEmit` must pass.
- **Match the surrounding code.** Naming, comment density, idiom. If your
  diff looks like a different author wrote it, slow down.
- **No `any` without a comment** explaining why. The codebase is
  type-honest; an `any` is a code smell that should be justified.
- **Migrations are forward-only.** New schema lives in a new file under
  `packages/db/drizzle/<NNNN>_<desc>.sql`. Never edit an existing migration.
- **Don't commit `.env`.** Use `.env.example` as the source of truth for
  variable names. The `.gitignore` will save you, but check `git status`
  before pushing anyway.

## Tests

```bash
pnpm test                              # all packages
pnpm --filter @rinjani/api exec vitest run    # just API
```

New features should ship with tests. Bug fixes should ship with a
regression test that fails on `master` and passes on your branch.

## Reviewing

PRs need at least one approving review from a maintainer. We look for:

- Does this solve the stated problem?
- Does it match the existing code conventions?
- Is the diff scoped — no drive-by refactors smuggled in?
- Are tests adequate? Are docs updated if behaviour changed?
- Does CI pass (lint + typecheck + tests)?

If we ask for changes, don't take it personally — the codebase has scars,
and we're paying down past mistakes one PR at a time.

## What we want help with

See [open issues](https://github.com/rinjanianalytics/cti-platform-api/issues)
for things we'd actively welcome PRs on. Anything tagged `good first issue`
should be approachable for a new contributor.

## Code of conduct

Be kind. Assume good faith. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Maintainers may remove, edit, or close contributions that don't meet that
bar.

## Questions

- Open a [GitHub Discussion](https://github.com/rinjanianalytics/cti-platform-api/discussions)
- Or email [rinjanianalytics@gmail.com](mailto:rinjanianalytics@gmail.com)
