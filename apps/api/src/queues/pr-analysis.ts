import { Queue } from "bullmq";
import type { Redis } from "ioredis";

export const PR_ANALYSIS_QUEUE = "pr-analysis";

/** Payload enqueued when a pull request needs (re)analysis. */
export interface PrAnalysisJob {
  pullRequestId: string;
  reason: "opened" | "synchronize" | "reopened" | "manual_rescan";
}

let queue: Queue<PrAnalysisJob> | undefined;

export function getPrAnalysisQueue(connection: Redis): Queue<PrAnalysisJob> {
  if (!queue) {
    queue = new Queue<PrAnalysisJob>(PR_ANALYSIS_QUEUE, {
      connection,
      defaultJobOptions: {
        attempts: 3,
        backoff: { type: "exponential", delay: 2_000 },
        removeOnComplete: 1_000,
        removeOnFail: 5_000,
      },
    });
  }
  return queue;
}

export async function enqueuePrAnalysis(
  connection: Redis,
  data: PrAnalysisJob,
): Promise<void> {
  // Deduplicate on PR + reason so a burst of synchronize events collapses.
  // BullMQ forbids ":" in a custom job id, so use "__" as separator.
  await getPrAnalysisQueue(connection).add("analyze", data, {
    jobId: `${data.pullRequestId}__${data.reason}`,
  });
}
