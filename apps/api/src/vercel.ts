import { chmodSync, copyFileSync, existsSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

/**
 * Vercel serverless entry point. One Fastify instance is built per warm
 * container and reused across invocations; each request is handed to its
 * underlying HTTP server.
 */
let app: Promise<FastifyInstance> | undefined;

/**
 * Point the Rust adapter at the engine bundled by build-vercel.mjs. Files
 * shipped with a function may lose their executable bit and live on a
 * read-only filesystem, so the binary is copied to /tmp and chmod'ed once
 * per container. Without it the adapter fails open (regex rules only).
 */
function prepareEngine(): void {
  if (process.env.CODEGATE_SCAN_BIN) return;
  const bundled = join(process.cwd(), "bin", "codegate-scan");
  if (!existsSync(bundled)) return;
  const runnable = "/tmp/codegate-scan";
  try {
    if (!existsSync(runnable)) copyFileSync(bundled, runnable);
    chmodSync(runnable, 0o755);
    process.env.CODEGATE_SCAN_BIN = runnable;
  } catch {
    // Leave it unset: the adapter fails open.
  }
}

export default async function handler(req: IncomingMessage, res: ServerResponse) {
  prepareEngine();
  app ??= buildApp(loadConfig())
    .then(async (instance) => {
      await instance.ready();
      return instance;
    })
    .catch((err: unknown) => {
      app = undefined; // don't cache a failed boot; retry on the next request
      throw err;
    });
  const instance = await app;
  instance.server.emit("request", req, res);
}
