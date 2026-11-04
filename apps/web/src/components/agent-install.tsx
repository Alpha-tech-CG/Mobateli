"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { API_URL } from "@/lib/api";
import { AGENT_RELEASE } from "@/lib/agent-release";

/** One-time display of the agent token with the install commands. */
export function AgentInstall({ token }: { token: string }) {
  const [mode, setMode] = useState<"root" | "least">("least");
  const agentUrl =
    typeof window !== "undefined" ? `${window.location.origin}/agent/${AGENT_RELEASE.file}` : "";
  const agent = "/opt/codegate/codegate-agent.py";
  // Pinned file + verified checksum, never `curl | python` (P2-5).
  const download = [
    `curl -fsSL ${agentUrl} -o /tmp/codegate-agent.py`,
    `echo '${AGENT_RELEASE.sha256}  /tmp/codegate-agent.py' | sha256sum -c -`,
    `sudo install -D -m 755 -o root -g root /tmp/codegate-agent.py ${agent}`,
  ];
  const tokenSetup = (owner: string) =>
    `echo '${token}' | sudo tee /etc/codegate/agent.token >/dev/null && sudo chown ${owner} /etc/codegate/agent.token && sudo chmod 600 /etc/codegate/agent.token`;
  const env = `CODEGATE_URL=${API_URL}`;

  const install =
    mode === "root"
      ? [
          `sudo mkdir -p /etc/codegate`,
          tokenSetup("root:root"),
          ...download,
          `sudo ${env} python3 ${agent} --token-file /etc/codegate/agent.token`,
          `echo '*/15 * * * * root ${env} python3 ${agent} --token-file /etc/codegate/agent.token --scheduled >/dev/null 2>&1' | sudo tee /etc/cron.d/codegate-agent`,
        ]
      : [
          `sudo useradd --system --no-create-home --shell /usr/sbin/nologin codegate 2>/dev/null; sudo mkdir -p /etc/codegate`,
          tokenSetup("codegate:codegate"),
          ...download,
          `sudo tee /etc/sudoers.d/codegate-agent >/dev/null <<'EOF'`,
          `# CodeGate agent: read-only probes that need root, nothing else.`,
          `codegate ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/sbin/ufw status, /usr/sbin/nft list ruleset, /usr/sbin/iptables -S, /usr/bin/docker ps -q, /usr/bin/docker inspect *`,
          `EOF`,
          `sudo chmod 440 /etc/sudoers.d/codegate-agent && sudo visudo -cf /etc/sudoers.d/codegate-agent`,
          `sudo -u codegate ${env} python3 ${agent} --token-file /etc/codegate/agent.token --sudo`,
          `echo '*/15 * * * * codegate ${env} python3 ${agent} --token-file /etc/codegate/agent.token --sudo --scheduled >/dev/null 2>&1' | sudo tee /etc/cron.d/codegate-agent`,
        ];

  return (
    <div className="space-y-3">
      <p className="text-sm">
        Copiez ce token maintenant : il ne sera <strong>plus jamais affiché</strong>.
      </p>
      <CodeBlock text={token} />
      <div className="inline-flex rounded-md border border-border p-0.5 text-xs">
        {(
          [
            ["least", "Moindre privilège (recommandé)"],
            ["root", "En root"],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            onClick={() => setMode(value)}
            className={`cursor-pointer rounded px-2.5 py-1 ${mode === value ? "bg-muted font-medium" : "text-muted-foreground"}`}
          >
            {label}
          </button>
        ))}
      </div>
      <p className="text-sm text-muted-foreground">
        L&apos;agent v{AGENT_RELEASE.version} est en lecture seule : il ne modifie rien et n&apos;envoie ni
        contenu de fichier ni valeur de variable. Son empreinte SHA-256 est vérifiée avant installation.{" "}
        {mode === "least"
          ? "Il tourne sous un utilisateur dédié ; seules les commandes qui exigent root (sshd -T, ufw, nft, iptables, docker ps / inspect) passent par sudo, et rien d'autre."
          : "Il tourne en root, ce qui est plus simple mais moins cloisonné."}{" "}
        Le cron vérifie toutes les 15 minutes si un audit est dû (toutes les 6 h) ou demandé depuis
        CodeGate. Vérifiez d&apos;abord ce qu&apos;il envoie avec <code className="font-mono">--dry-run</code>.
      </p>
      <CodeBlock text={install.join("\n")} />
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
