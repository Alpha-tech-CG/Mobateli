"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { API_URL } from "@/lib/api";

/** One-time display of a backup report token with the setup commands. */
export function BackupInstall({ token }: { token: string }) {
  const helperUrl =
    typeof window !== "undefined" ? `${window.location.origin}/agent/codegate-backup.py` : "";
  const env = `CODEGATE_URL=${API_URL}`;
  const blocks = [
    {
      title: "Installation sur le serveur qui produit la sauvegarde",
      text: [
        `sudo mkdir -p /etc/codegate`,
        `echo '${token}' | sudo tee /etc/codegate/backup.token >/dev/null && sudo chmod 600 /etc/codegate/backup.token`,
        `sudo curl -fsSL ${helperUrl} -o /usr/local/bin/codegate-backup && sudo chmod +x /usr/local/bin/codegate-backup`,
      ].join("\n"),
    },
    {
      title: "À la fin de votre script de sauvegarde (adaptez les options à votre stockage)",
      text:
        `${env} codegate-backup --token-file /etc/codegate/backup.token report \\\n` +
        `  --file /var/backups/app.dump.age --storage-provider s3 --storage-location offsite \\\n` +
        `  --in-transit tls1.3 --key-location external_kms --immutable yes \\\n` +
        `  --versioning yes --separate-account yes --retention-days 90`,
    },
    {
      title: "Chaque semaine : intégrité d'une copie re-téléchargée + restauration isolée",
      text:
        `${env} codegate-backup --token-file /etc/codegate/backup.token verify --file /tmp/copie.dump.age\n` +
        `${env} codegate-backup --token-file /etc/codegate/backup.token restore-test \\\n` +
        `  --file /tmp/copie.dump.age --decrypt-cmd 'age -d -i /chemin/cle.txt'`,
    },
  ];

  return (
    <div className="space-y-3">
      <p className="text-sm">
        Copiez ce token maintenant : il ne sera <strong>plus jamais affiché</strong>.
      </p>
      <CodeBlock text={token} />
      <p className="text-sm text-muted-foreground">
        CodeGate ne reçoit que des métadonnées (empreinte, taille, protections, durées), jamais
        vos données. La restauration se fait dans un conteneur jetable sans réseau : la production
        n&apos;est jamais touchée.
      </p>
      {blocks.map((b) => (
        <div key={b.title} className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">{b.title}</p>
          <CodeBlock text={b.text} />
        </div>
      ))}
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
