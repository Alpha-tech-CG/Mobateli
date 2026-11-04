import type { FastifyBaseLogger } from "fastify";
import type { Redis } from "ioredis";
import { waitUntil } from "@vercel/functions";
import { Prisma, prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { claimDelivery, releaseDelivery } from "./redis.js";
import { enqueuePrAnalysis, type PrAnalysisJob } from "../queues/pr-analysis.js";
import { processPrAnalysis } from "../workers/pr-analysis.processor.js";

/**
 * Background work seen from the request path: webhook idempotence and PR
 * analysis dispatch. Two backends, picked by ANALYSIS_MODE:
 * - queue: Redis claims + BullMQ queue, consumed by the worker process;
 * - inline: Postgres claims + analysis run in this process once the response
 *   is sent (kept alive on Vercel with waitUntil).
 */
export interface Jobs {
  /** True the first time a delivery id is seen, false on replays. */
  claimDelivery(deliveryId: string): Promise<boolean>;
  /** Forget a claim so the provider's retry of a failed delivery is processed. */
  releaseDelivery(deliveryId: string): Promise<void>;
  dispatchPrAnalysis(job: PrAnalysisJob): Promise<void>;
}

const DELIVERY_TTL_MS = 7 * 24 * 3600 * 1000;

export function createJobs(
  config: AppConfig,
  connection: Redis,
  log: FastifyBaseLogger,
): Jobs {
  if (config.ANALYSIS_MODE === "queue") {
    return {
      claimDelivery: (id) => claimDelivery(connection, id),
      releaseDelivery: (id) => releaseDelivery(connection, id),
      dispatchPrAnalysis: (job) => enqueuePrAnalysis(connection, job),
    };
  }

  return {
    async claimDelivery(id) {
      try {
        await prisma.webhookDelivery.create({ data: { id } });
      } catch (err) {
        if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
          return false;
        }
        throw err;
      }
      // Opportunistic purge of old claims (no cron needed).
      if (Math.random() < 0.02) {
        void prisma.webhookDelivery
          .deleteMany({ where: { createdAt: { lt: new Date(Date.now() - DELIVERY_TTL_MS) } } })
          .catch(() => {});
      }
      return true;
    },
    async releaseDelivery(id) {
      await prisma.webhookDelivery.deleteMany({ where: { id } });
    },
    async dispatchPrAnalysis(job) {
      waitUntil(
        processPrAnalysis(config, job).catch((err: unknown) => {
          log.error({ err, pullRequestId: job.pullRequestId }, "inline pr-analysis failed");
        }),
      );
    },
  };
}
