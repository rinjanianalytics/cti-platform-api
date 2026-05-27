import { Hono } from "hono";
import type { WorkbenchCore } from "../core/workbench";
import { buildRouteTable, type HandlerInput } from "./handlers";

/**
 * Create API routes for Workbench as a Hono app.
 *
 * Iterates the framework-agnostic `buildRouteTable(core)` and registers
 * each route on a fresh Hono instance. Adapters that don't speak Hono can
 * use `buildRouteTable` directly — see `@getworkbench/express` and
 * `@getworkbench/fastify`.
 */
export function createApiRoutes(core: WorkbenchCore): Hono {
  const app = new Hono();

  for (const route of buildRouteTable(core)) {
    app[route.method](route.path, async (c) => {
      let body: unknown;
      const method = c.req.method;
      if (method !== "GET" && method !== "HEAD") {
        const contentType = c.req.header("content-type") ?? "";
        if (contentType.includes("application/json")) {
          try {
            body = await c.req.json();
          } catch {
            body = undefined;
          }
        }
      }

      const input: HandlerInput = {
        params: c.req.param() as Record<string, string>,
        query: c.req.query(),
        body,
      };

      const result = await route.handler(input);
      return new Response(JSON.stringify(result.body), {
        status: result.status,
        headers: { "Content-Type": "application/json" },
      });
    });
  }

  return app;
}
