import { prisma } from "@codegate/db";
import { decrypt } from "./crypto.js";
import { sendSlackAlert, type AlertInput } from "./slack.js";

/**
 * Send a Slack incident alert for an org, if Slack is connected. Best-effort:
 * never throws — a Slack problem must not affect analysis or deployments.
 */
export async function notifySlack(
  organizationId: string,
  encryptionKey: string,
  alert: AlertInput,
): Promise<void> {
  try {
    const conn = await prisma.slackConnection.findUnique({ where: { organizationId } });
    if (!conn) return;
    await sendSlackAlert(decrypt(conn.webhookUrlEncrypted, encryptionKey), alert);
  } catch {
    /* swallow — alerting is non-critical */
  }
}
