/**
 * Slack incident alerts via an incoming webhook (cahier §9.5). The webhook URL
 * is passed in already decrypted. Fire-and-forget: a Slack outage must never
 * affect analysis or deployment decisions.
 */

export type AlertSeverity = "info" | "warning" | "critical";

export interface AlertInput {
  title: string;
  severity: AlertSeverity;
  repository: string;
  detail: string;
  url?: string;
}

const EMOJI: Record<AlertSeverity, string> = {
  info: ":information_source:",
  warning: ":warning:",
  critical: ":rotating_light:",
};

/** Build a Slack Block Kit message for an incident. */
export function buildSlackAlert(a: AlertInput): {
  text: string;
  blocks: unknown[];
} {
  const text = `${EMOJI[a.severity]} CodeGate: ${a.title} — ${a.repository}`;
  const blocks: unknown[] = [
    {
      type: "header",
      text: { type: "plain_text", text: `${EMOJI[a.severity]} ${a.title}`, emoji: true },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Dépôt:*\n${a.repository}` },
        { type: "mrkdwn", text: `*Sévérité:*\n${a.severity}` },
      ],
    },
    { type: "section", text: { type: "mrkdwn", text: a.detail } },
  ];
  if (a.url) {
    blocks.push({
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "Voir dans CodeGate" },
          url: a.url,
        },
      ],
    });
  }
  blocks.push({
    type: "context",
    elements: [{ type: "mrkdwn", text: "CodeGate — sécurité du code généré par IA" }],
  });
  return { text, blocks };
}

/** Post an alert to a Slack incoming webhook. Throws on non-2xx. */
export async function sendSlackAlert(webhookUrl: string, alert: AlertInput): Promise<void> {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(buildSlackAlert(alert)),
  });
  if (!res.ok) throw new Error(`Slack webhook ${res.status}`);
}
