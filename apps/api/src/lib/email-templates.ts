import type { EmailMessage } from "./mailer.js";

/**
 * Transactional email templates (French). Plain, table-free HTML that renders
 * in every client, with a text part for accessibility and spam scoring.
 * Every user-provided value is escaped.
 */

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function layout(title: string, paragraphs: string[], cta: { label: string; url: string } | null, footer: string): string {
  return `<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title></head>
<body style="margin:0;background:#f4f5f6;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#15181a">
<div style="max-width:520px;margin:0 auto;padding:32px 16px">
<p style="font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:600;font-size:18px;margin:0 0 24px">CodeGate</p>
<div style="background:#ffffff;border:1px solid #e4e7e9;border-radius:10px;padding:28px">
<h1 style="font-size:20px;margin:0 0 16px">${esc(title)}</h1>
${paragraphs.map((p) => `<p style="font-size:15px;line-height:1.55;margin:0 0 14px">${p}</p>`).join("\n")}
${
  cta
    ? `<p style="margin:24px 0"><a href="${esc(cta.url)}" style="display:inline-block;background:#bb3e2c;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:8px">${esc(cta.label)}</a></p>
<p style="font-size:12px;line-height:1.5;color:#5b6468;margin:0;word-break:break-all">Si le bouton ne fonctionne pas, copiez ce lien : ${esc(cta.url)}</p>`
    : ""
}
</div>
<p style="font-size:12px;line-height:1.5;color:#5b6468;margin:16px 4px 0">${footer}</p>
</div></body></html>`;
}

const NOT_YOU = "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email : rien ne changera sur votre compte.";

export function verifyEmailMessage(to: string, name: string, url: string): EmailMessage {
  const title = "Confirmez votre adresse email";
  return {
    to,
    tag: "verify_email",
    subject: "CodeGate — confirmez votre adresse email",
    html: layout(
      title,
      [`Bonjour ${esc(name)},`, "Confirmez votre adresse pour sécuriser votre compte CodeGate et recevoir les alertes de sécurité. Le lien est valable 48 heures."],
      { label: "Confirmer mon email", url },
      NOT_YOU,
    ),
    text: `Bonjour ${name},\n\nConfirmez votre adresse email CodeGate (lien valable 48 heures) :\n${url}\n\n${NOT_YOU}`,
  };
}

export function resetPasswordMessage(to: string, name: string, url: string): EmailMessage {
  const title = "Réinitialisez votre mot de passe";
  return {
    to,
    tag: "reset_password",
    subject: "CodeGate — réinitialisation du mot de passe",
    html: layout(
      title,
      [
        `Bonjour ${esc(name)},`,
        "Une réinitialisation du mot de passe de votre compte CodeGate a été demandée. Le lien est valable 1 heure et ne fonctionne qu'une fois.",
        "Après le changement, toutes les sessions ouvertes seront déconnectées.",
      ],
      { label: "Choisir un nouveau mot de passe", url },
      NOT_YOU,
    ),
    text: `Bonjour ${name},\n\nRéinitialisez le mot de passe de votre compte CodeGate (lien valable 1 heure, usage unique) :\n${url}\n\nToutes les sessions ouvertes seront déconnectées.\n\n${NOT_YOU}`,
  };
}

export function inviteMessage(to: string, inviter: string, organization: string, role: string, url: string): EmailMessage {
  const title = `Rejoignez ${organization} sur CodeGate`;
  return {
    to,
    tag: "invite",
    subject: `CodeGate — ${inviter} vous invite à rejoindre ${organization}`,
    html: layout(
      title,
      [
        `${esc(inviter)} vous invite à rejoindre l'organisation <strong>${esc(organization)}</strong> sur CodeGate, avec le rôle <strong>${esc(role)}</strong>.`,
        "CodeGate vérifie la sécurité de chaque modification de code avant la production. Choisissez votre mot de passe pour activer votre compte ; le lien est valable 7 jours.",
      ],
      { label: "Activer mon compte", url },
      "Vous ne connaissez pas cette organisation ? Ignorez cet email : aucun compte ne sera activé.",
    ),
    text: `${inviter} vous invite à rejoindre ${organization} sur CodeGate (rôle : ${role}).\n\nActivez votre compte (lien valable 7 jours) :\n${url}\n\nVous ne connaissez pas cette organisation ? Ignorez cet email.`,
  };
}

export function passwordChangedMessage(to: string, name: string, supportUrl: string): EmailMessage {
  const title = "Votre mot de passe a été modifié";
  const warn = "Si ce n'est pas vous, réinitialisez immédiatement votre mot de passe et prévenez l'administrateur de votre organisation.";
  return {
    to,
    tag: "password_changed",
    subject: "CodeGate — votre mot de passe a été modifié",
    html: layout(
      title,
      [`Bonjour ${esc(name)},`, "Le mot de passe de votre compte CodeGate vient d'être modifié.", esc(warn)],
      { label: "Réinitialiser mon mot de passe", url: supportUrl },
      "Cet email de sécurité est envoyé à chaque changement de mot de passe.",
    ),
    text: `Bonjour ${name},\n\nLe mot de passe de votre compte CodeGate vient d'être modifié.\n${warn}\n${supportUrl}`,
  };
}
