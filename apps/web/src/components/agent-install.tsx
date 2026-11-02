"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { API_URL } from "@/lib/api";

/** One-time display of the agent token with the install commands. */
export function AgentInstall({ token }: { token: string }) {
  const agentUrl =
    typeof window !== "undefined" ? `${window.location.origin}/agent/codegate-agent.py` : "";
  const install = [
    `sudo mkdir -p /etc/codegate /opt/codegate`,
    `echo '${token}' | sudo tee /etc/codegate/agent.token >/dev/null && sudo chmod 600 /etc/codegate/agent.token`,
    `sudo curl -fsSL ${agentUrl} -o /opt/codegate/codegate-agent.py`,
    `sudo CODEGATE_URL=${API_URL} python3 /opt/codegate/codegate-agent.py --token-file /etc/codegate/agent.token`,
    `echo '17 */6 * * * root CODEGATE_URL=${API_URL} python3 /opt/codegate/codegate-agent.py --token-file /etc/codegate/agent.token >/dev/null 2>&1' | sudo tee /etc/cron.d/codegate-agent`,
  ].join("\n");

  return (
    <div className="space-y-3">
      <p className="text-sm">
        Copiez ce token maintenant : il ne sera <strong>plus jamais affiché</strong>.
      </p>
      <CodeBlock text={token} />
      <p className="text-sm text-muted-foreground">
        Sur le serveur, installez l&apos;agent (lecture seule, aucun changement du système) et
        planifiez un audit toutes les 6 heures. Vous pouvez d&apos;abord vérifier ce qu&apos;il envoie
        avec <code className="font-mono">--dry-run</code>.
      </p>
      <CodeBlock text={install} />
    </div>
  );
}

function CodeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-md border border-border bg-muted p-3 pr-10 font-mono text-xs leading-relaxed">
        {text}
      </pre>
      <button
        type="button"
        aria-label="Copier"
        onClick={() => {
          void navigator.clipboard.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
        className="absolute right-2 top-2 cursor-pointer rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </button>
    </div>
  );
}
