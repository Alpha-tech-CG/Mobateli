import { Worker } from "bullmq";
import type { Redis } from "ioredis";
import { PR_ANALYSIS_QUEUE, type PrAnalysisJob } from "../queues/pr-analysis.js";
import { processPrAnalysis } from "./pr-analysis.processor.js";
import type { AppConfig } from "../config.js";

/** Consumes pr-analysis jobs from Redis; failures are retried by BullMQ. */
export function createPrAnalysisWorker(
  connection: Redis,
  config: AppConfig,
): Worker<PrAnalysisJob> {
  return new Worker<PrAnalysisJob>(
    PR_ANALYSIS_QUEUE,
    (job) => processPrAnalysis(config, job.data),
    { connection, concurrency: 5 },
  );
}
