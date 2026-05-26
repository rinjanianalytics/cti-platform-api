import type { Queue } from "bullmq";
import type { WorkbenchOptions } from "../core/types";
import { WorkbenchCore } from "../core/workbench";
import { buildWorkbenchApp } from "../server/hono-app";

export interface FetchHandlerResult {
  /**
   * Web-standard fetch handler. Accepts a `Request` and returns a `Response`.
   * Suitable for Elysia's `.mount(path, handler)`, Next.js route handlers,
   * Bun.serve, and any other web-standards-friendly runtime.
   */
  fetch: (req: Request) => Promise<Response>;
  /**
   * The underlying `WorkbenchCore` instance. Exposed so adapters can read
   * config, query state, or wire up custom auth strategies.
   */
  core: WorkbenchCore;
}

/**
 * Build a self-contained web-fetch handler for Workbench: API routes,
 * `/config`, static `/assets/:file`, an `index.html` catch-all with a
 * correct `<base href>`, CORS on `/api/*`, and optional Basic Auth on
 * everything.
 *
 * This is the engine shared by every fetch-native adapter (Elysia, Next.js).
 * Express and Fastify adapters use {@link buildRouteTable} directly instead.
 *
 * When `options.basePath` is set, the handler rewrites the incoming Request
 * URL to strip that prefix before routing. This makes the bridge work
 * uniformly for both fetch hosts:
 *
 * - `Elysia.mount()` already strips the prefix before calling us — the
 *   strip below is a no-op in that case.
 * - Next.js App Router preserves the full path — the strip is what lets
 *   our internal routes (`/api/*`, `/config`, …) match.
 */
export function createFetchHandler(
  options: WorkbenchOptions | Queue[],
): FetchHandlerResult {
  const core = new WorkbenchCore(options);
  const app = buildWorkbenchApp(core);
  const basePath = normalizeBasePath(core.options.basePath);

  const fetchHandler = async (req: Request): Promise<Response> => {
    if (basePath) {
      const url = new URL(req.url);
      if (
        url.pathname === basePath ||
        url.pathname.startsWith(`${basePath}/`)
      ) {
        const rewritten = url.pathname.slice(basePath.length) || "/";
        url.pathname = rewritten;
        const init: RequestInit = {
          method: req.method,
          headers: req.headers,
          body:
            req.method === "GET" || req.method === "HEAD"
              ? undefined
              : req.body,
          // @ts-expect-error duplex is required for streaming bodies in Node 18+
          duplex: "half",
          redirect: req.redirect,
        };
        return app.fetch(new Request(url.toString(), init));
      }
    }
    return app.fetch(req);
  };

  return {
    fetch: fetchHandler,
    core,
  };
}

/**
 * Normalize a base path: trim trailing slashes so we can do exact prefix
 * comparisons without double-slashes. Returns `null` for the default mount
 * (`""` or `"/"`) so the no-strip fast path runs.
 */
function normalizeBasePath(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.endsWith("/") ? value.slice(0, -1) : value;
  if (trimmed === "" || trimmed === "/") return null;
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}
