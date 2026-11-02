import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { startDbKeepAlive } from "@codegate/db";

async function main() {
  const config = loadConfig();
  const app = await buildApp(config);

  // Keep the DB connection warm (Docker/NAT idle-drop mitigation).
  startDbKeepAlive();

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "shutting down");
    await app.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  try {
    await app.listen({ port: config.API_PORT, host: "0.0.0.0" });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

void main();
