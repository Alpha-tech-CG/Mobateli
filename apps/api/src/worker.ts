import { loadConfig } from "./config.js";
import { getRedis } from "./lib/redis.js";
import { createPrAnalysisWorker } from "./workers/pr-analysis.worker.js";
import { startDbKeepAlive } from "@codegate/db";
import pino from "pino";

/**
 * Standalone worker process. Runs independently of the API so analysis load
 * never blocks the request path.
 */
function main() {
  const config = loadConfig();
  const log = pino({ level: config.NODE_ENV === "production" ? "info" : "debug" });
  const connection = getRedis(config.REDIS_URL);
  startDbKeepAlive();

  const worker = createPrAnalysisWorker(connection, config);

  worker.on("completed", (job) => log.info({ jobId: job.id }, "pr-analysis completed"));
  worker.on("failed", (job, err) =>
    log.error({ jobId: job?.id, err: err.message }, "pr-analysis failed"),
  );

  log.info("pr-analysis worker started");

  const shutdown = async (signal: string) => {
    log.info({ signal }, "worker shutting down");
    await worker.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main();
