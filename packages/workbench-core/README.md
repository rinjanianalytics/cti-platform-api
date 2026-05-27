# @getworkbench/core

Core of [Workbench](https://getworkbench.dev) — `QueueManager`, API router, and bundled React UI.

This package is framework-agnostic. You typically don't depend on it directly — use a framework adapter instead:

- [`@getworkbench/hono`](https://npm.im/@getworkbench/hono)

## What's inside

- `WorkbenchCore` — orchestrates queues, flows, schedulers, metrics, and search.
- `QueueManager` — wraps your BullMQ `Queue` instances and powers list / detail / mutation endpoints.
- HTTP-agnostic API router — handles `/api/*` requests for the dashboard.
- Bundled UI — pre-built React app served as a single HTML entrypoint.

## Install

```bash
npm i @getworkbench/core bullmq
```

## Direct usage (advanced)

Most users should reach for an adapter. If you need to wire Workbench into an unsupported framework, see the source for the request/response contract.

## Documentation

[getworkbench.dev](https://getworkbench.dev) · [GitHub](https://github.com/pontusab/workbench)

## License

MIT
