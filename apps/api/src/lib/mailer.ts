import type { AppConfig } from "../config.js";

/**
 * Transactional email. Production sends through Resend's HTTP API (no SDK,
 * no SMTP socket — works on serverless). Without a key, development prints
 * the message to the log so links can be followed locally; production
 * refuses silently (logged) rather than pretending it sent.
 */

export interface EmailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
  /** Short tag for logs and provider analytics, e.g. "reset_password". */
  tag: string;
}

export type MailTransport = (msg: EmailMessage) => Promise<{ sent: boolean; id?: string }>;

let override: MailTransport | null = null;

/** Tests swap the transport to capture messages. */
export function setMailTransport(transport: MailTransport | null): void {
  override = transport;
}

export function mailConfigured(config: Pick<AppConfig, "RESEND_API_KEY">): boolean {
  return !!override || !!config.RESEND_API_KEY;
}

export async function sendEmail(
  config: Pick<AppConfig, "RESEND_API_KEY" | "EMAIL_FROM" | "NODE_ENV">,
  msg: EmailMessage,
  fetchImpl: typeof fetch = fetch,
): Promise<{ sent: boolean; id?: string }> {
  if (override) return override(msg);
  if (!config.RESEND_API_KEY) {
    if (config.NODE_ENV === "production") {
      console.warn(`[mail] RESEND_API_KEY absent : email « ${msg.tag} » non envoyé.`);
    } else {
      console.info(`[mail:dev] → ${msg.to} · ${msg.subject}\n${msg.text}`);
    }
    return { sent: false };
  }
  try {
    const res = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${config.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: config.EMAIL_FROM,
        to: [msg.to],
        subject: msg.subject,
        html: msg.html,
        text: msg.text,
        tags: [{ name: "type", value: msg.tag }],
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      console.warn(`[mail] Resend a refusé « ${msg.tag} » (${res.status}).`);
      return { sent: false };
    }
    const body = (await res.json().catch(() => ({}))) as { id?: string };
    return body.id ? { sent: true, id: body.id } : { sent: true };
  } catch (err) {
    console.warn(`[mail] envoi « ${msg.tag} » impossible : ${err instanceof Error ? err.message : "erreur"}`);
    return { sent: false };
  }
}
