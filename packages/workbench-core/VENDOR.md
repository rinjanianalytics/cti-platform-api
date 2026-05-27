# @rinjani/workbench-core

Vendored fork of [pontusab/workbench](https://github.com/pontusab/workbench) (`@getworkbench/core`).

**Pinned to upstream:** `5e1bbf307f160661e8729611774e531df2d3abe7` (main, 2026-05-25)
**Upstream version at fork point:** `0.2.1`
**License:** MIT (upstream preserved in `LICENSE`)

## Why we forked

Upstream's Schedulers tab is read-only. We need edit / disable / run-now to
manage our 13 cron-driven feed-sync jobs from the dashboard without code
redeploys. Vendoring (rather than depending on the npm package) is required
because the UI is shipped pre-bundled — UI changes need a rebuilt
`dist/ui` directory.

## Our changes on top of upstream

API (`src/api/handlers.ts`, `src/core/queue-manager.ts`, `src/core/types.ts`):
- `POST /schedulers/repeatable` — upsert a repeatable job (cron + payload)
- `DELETE /schedulers/repeatable/:queue/:key` — remove a repeatable
- `POST /schedulers/repeatable/:queue/:key/run` — fire one-off run now
- `SchedulerInfo` extended with `jobName` and `payload` so the UI can
  round-trip edits.

UI (`src/ui/pages/schedulers.tsx` + new files):
- Per-row action menu (Edit / Run now / Remove)
- Cron preset selector with raw-expression fallback
- Toast confirmation on success/failure

## Rebasing on upstream

When upstream ships a new release we care about:

```bash
git remote add workbench https://github.com/pontusab/workbench.git  # one-time
git fetch workbench
# Compare changes since our pinned SHA:
git diff 5e1bbf30..workbench/main -- packages/core/src
# Cherry-pick the relevant files into packages/workbench-core/src, resolve
# conflicts in our modified areas (handlers.ts, queue-manager.ts, types.ts,
# schedulers.tsx). Then bump SHA + "Pinned to upstream" line above.
pnpm --filter @rinjani/workbench-core build
```
