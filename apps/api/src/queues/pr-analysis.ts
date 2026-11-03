import { Queue } from "bullmq";
import type { Redis } from "ioredis";

export const PR_ANALYSIS_QUEUE = "pr-analysis";

/** Payload enqueued when a pull request needs (re)analysis. */
export interface PrAnalysisJob {
  pullRequestId: string;
  reason: "opened" | "synchronize" | "reopened" | "manual_rescan";
  /** Head commit being analyzed — part of the dedup key. */
  headSha?: string | null;
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
  // Deduplicate on PR + head commit so duplicate events for the same commit
  // collapse. BullMQ ignores an add whose jobId still exists — completed jobs
  // included (removeOnComplete keeps them) — so the key must change with each
  // new push, and a manual rescan must always be unique.
  // BullMQ forbids ":" in a custom job id, so use "__" as separator.
  const key =
    data.reason !== "manual_rescan" && data.headSha
      ? data.headSha
      : `${data.reason}__${Date.now()}`;
  await getPrAnalysisQueue(connection).add("analyze", data, {
    jobId: `${data.pullRequestId}__${key}`,
  });
}
