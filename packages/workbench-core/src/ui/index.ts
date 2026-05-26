/**
 * `@getworkbench/core/ui` — React entrypoint for embedding the Workbench
 * dashboard inside a host Vite/React app (e.g. the Tauri desktop client).
 *
 * Consumers import the `Dashboard` component, render it inside their own
 * provider tree, and optionally point it at a non-relative API base via
 * `setApiBase()` or the global `window.__WORKBENCH_RUNTIME__.apiBase`.
 *
 * The bundled `dist/ui/` build (used by adapters that serve UI from the
 * server) does **not** consume this entrypoint — it goes through
 * `src/ui/main.tsx`.
 */
export { App as Dashboard } from "./app";
export { apiBase, getConfigUrl, joinApi, setApiBase } from "./lib/api-base";
export { createAppRouter } from "./router";
