import { PrismaClient, Prisma } from "@prisma/client";

export * from "@prisma/client";

/**
 * Transient connection errors. On Docker Desktop (Windows) an idle Postgres
 * connection is silently dropped by the NAT, and Prisma then hands out a dead
 * connection — the next query fails with P1001/P1017 instead of reconnecting.
 * We retry those (and pool/timeout blips) transparently.
 */
const TRANSIENT_CODES = new Set(["P1001", "P1002", "P1008", "P1017", "P2024"]);

function isTransient(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientInitializationError) return true;
  if (err instanceof Prisma.PrismaClientKnownRequestError && TRANSIENT_CODES.has(err.code)) {
    return true;
  }
  const msg = err instanceof Error ? err.message : "";
  return /Can't reach database server|Server has closed the connection|Timed out fetching a new connection/i.test(
    msg,
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Run a DB operation, retrying transient connection failures with exponential
 * backoff. Use it to wrap `$transaction` calls (the per-operation retry below
 * does not safely cover an aborted transaction).
 */
export async function withDbRetry<T>(fn: () => Promise<T>, attempts = 4): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      if (!isTransient(err) || i === attempts - 1) throw err;
      lastErr = err;
      await sleep(50 * 2 ** i); // 50, 100, 200ms
    }
  }
  throw lastErr;
}

function createClient() {
  const base = new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

  // Retry individual model operations on transient connection errors. Safe:
  // standalone ops get a fresh connection on retry; ops inside an aborted
  // transaction simply fail again (atomicity preserved).
  return base.$extends({
    query: {
      async $allOperations({ args, query }) {
        return withDbRetry(() => query(args));
      },
    },
  });
}

type ExtendedPrisma = ReturnType<typeof createClient>;

const globalForPrisma = globalThis as unknown as { prisma?: ExtendedPrisma };

export const prisma: ExtendedPrisma = globalForPrisma.prisma ?? createClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

/**
 * Keep the connection warm so the NAT does not drop it while idle. Returns a
 * stopper. The timer is unref'd so it never keeps the process alive.
 */
export function startDbKeepAlive(intervalMs = 30_000): () => void {
  const timer = setInterval(() => {
    void prisma.$queryRaw`SELECT 1`.catch(() => {
      /* keepalive ping failed — the next real query's retry will recover */
    });
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
