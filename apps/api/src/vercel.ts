import type { IncomingMessage, ServerResponse } from "node:http";
import type { FastifyInstance } from "fastify";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";

/**
 * Vercel serverless entry point. One Fastify instance is built per warm
 * container and reused across invocations; each request is handed to its
 * underlying HTTP server.
 */
let app: Promise<FastifyInstance> | undefined;

export default async function handler(req: IncomingMessage, res: ServerResponse) {
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
