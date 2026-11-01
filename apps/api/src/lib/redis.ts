import { Redis } from "ioredis";

/**
 * Shared ioredis connection factory. BullMQ requires `maxRetriesPerRequest:
 * null` on the connection it uses for blocking commands.
 */
let connection: Redis | undefined;

export function getRedis(url: string): Redis {
  if (!connection) {
    connection = new Redis(url, { maxRetriesPerRequest: null });
  }
  return connection;
}

/**
 * Idempotency guard for webhook deliveries. Returns true the first time a
 * delivery id is seen, false on replays (GitHub retries deliveries).
 * cahier §13.4 — "idempotence des webhooks".
 */
export async function claimDelivery(
  redis: Redis,
  deliveryId: string,
  ttlSeconds = 86_400,
): Promise<boolean> {
  const res = await redis.set(`gh:delivery:${deliveryId}`, "1", "EX", ttlSeconds, "NX");
  return res === "OK";
}

/**
 * Release a delivery claim so a failed webhook can be retried by GitHub.
 * (Without this, a handler error would make every retry look like a replay.)
 */
export async function releaseDelivery(redis: Redis, deliveryId: string): Promise<void> {
  await redis.del(`gh:delivery:${deliveryId}`);
}
