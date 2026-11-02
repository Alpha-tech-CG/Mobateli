import type { Severity } from "@codegate/shared";

/**
 * Backup Shield rules (extension §5.4): from a job's latest run, integrity
 * check and restore test, decide what is missing and how recoverable the data
 * really is. Freshness is computed at evaluation time, so a backup that stops
 * running is flagged on the next read — no scheduler needed (§12: < 24 h).
 */

export interface RunFacts {
  finishedAt: Date;
  status: string;
  sha256: string | null;
  encrypted: boolean;
  encryptionAlgorithm: string | null;
  inTransit: string | null;
  keyLocation: string;
  signed: boolean;
  storageLocation: string;
  immutable: boolean | null;
  versioning: boolean | null;
  separateAccount: boolean | null;
  retentionDays: number | null;
  integrityCheckedAt: Date | null;
  integrityOk: boolean | null;
}

export interface RestoreFacts {
  completedAt: Date;
  result: string;
  durationSeconds: number;
}

export interface BackupCheck {
  id: string;
  label: string;
  ok: boolean;
  severity: Severity;
  detail: string;
  recommendation: string | null;
}

export type BackupStatus = "healthy" | "attention" | "critical";

export interface BackupEvaluation {
  score: number;
  status: BackupStatus;
  ransomwareReady: boolean;
  checks: BackupCheck[];
}

const WEIGHT: Record<Severity, number> = { critical: 30, high: 12, medium: 6, low: 2, info: 0 };
const STRONG_CIPHERS = /aes-?256|chacha20|age|restic|borg|gpg|pgp|xchacha/i;
const DAY = 86_400_000;

export function evaluateBackup(
  job: { frequencyHours: number },
  run: RunFacts | null,
  restore: RestoreFacts | null,
  now = new Date(),
): BackupEvaluation {
  const checks: BackupCheck[] = [];
  const check = (
    id: string,
    label: string,
    ok: boolean,
    severity: Severity,
    detail: string,
    recommendation: string | null = null,
  ) => checks.push({ id, label, ok, severity: ok ? "info" : severity, detail, recommendation: ok ? null : recommendation });

  if (!run) {
    check(
      "exists",
      "Sauvegarde reçue",
      false,
      "critical",
      "Aucune exécution n'a encore été déclarée pour ce job.",
      "Ajoutez `codegate-backup report` à la fin de votre script de sauvegarde.",
    );
    return finish(checks, false);
  }

  // ── Existence & fraîcheur ──
  const ageHours = (now.getTime() - run.finishedAt.getTime()) / 3_600_000;
  const late = ageHours > job.frequencyHours * 1.5;
  check(
    "freshness",
    "Exécution récente",
    !late,
    "critical",
    late
      ? `Dernière exécution il y a ${Math.round(ageHours)} h pour une fréquence de ${job.frequencyHours} h : sauvegarde manquante.`
      : `Dernière exécution il y a ${Math.max(0, Math.round(ageHours))} h.`,
    "Vérifiez le cron / timer et les logs du job de sauvegarde.",
  );
  check(
    "last_status",
    "Dernière exécution réussie",
    run.status === "success",
    "critical",
    run.status === "success" ? "Succès." : "La dernière exécution a échoué.",
    "Corrigez l'erreur du job puis relancez une sauvegarde.",
  );

  // ── Chiffrement ──
  check(
    "encryption_at_rest",
    "Chiffrement au repos",
    run.encrypted && STRONG_CIPHERS.test(run.encryptionAlgorithm ?? ""),
    run.encrypted ? "medium" : "critical",
    run.encrypted
      ? `Chiffré (${run.encryptionAlgorithm ?? "algorithme non identifié"}).`
      : "La sauvegarde est stockée en clair.",
    "Chiffrez avant envoi : `age -r <clé publique>`, restic ou rclone crypt (AES-256-GCM / ChaCha20).",
  );
  const transitOk = run.inTransit === "tls1.3" || run.inTransit === "tls1.2" || run.inTransit === "ssh";
  check(
    "encryption_in_transit",
    "Chiffrement en transit",
    transitOk || run.storageLocation === "local_disk",
    run.inTransit === "none" ? "high" : "low",
    transitOk ? `Transfert ${run.inTransit}.` : "Protocole de transfert non chiffré ou inconnu.",
    "Transférez en HTTPS (TLS 1.2 minimum, 1.3 recommandé) ou SFTP.",
  );
  const keyIsolated = ["external_kms", "secret_manager", "offline"].includes(run.keyLocation);
  check(
    "key_isolation",
    "Clé hors du serveur",
    keyIsolated || !run.encrypted,
    run.keyLocation === "same_server" ? "high" : "medium",
    !run.encrypted
      ? "Sans objet : la sauvegarde n'est pas chiffrée."
      : run.keyLocation === "same_server"
      ? "La clé de chiffrement est sur le même serveur : un attaquant qui le compromet lit les sauvegardes."
      : keyIsolated
        ? `Clé stockée : ${run.keyLocation}.`
        : "Emplacement de la clé non déclaré.",
    "Gardez la clé privée dans un KMS / gestionnaire de secrets ou hors ligne ; le serveur n'a besoin que de la clé publique.",
  );

  // ── Intégrité ──
  check(
    "integrity_hash",
    "Empreinte SHA-256",
    run.sha256 !== null,
    "high",
    run.sha256 ? `sha256 ${run.sha256.slice(0, 12)}…` : "Aucune empreinte enregistrée.",
    "`codegate-backup report --file <archive>` calcule l'empreinte automatiquement.",
  );
  if (run.integrityOk === false) {
    check(
      "integrity_verified",
      "Intégrité vérifiée",
      false,
      "critical",
      "La copie stockée ne correspond plus à l'empreinte d'origine : altérée ou corrompue.",
      "Isolez cette copie, restaurez depuis une version antérieure et cherchez la cause.",
    );
  } else {
    check(
      "integrity_verified",
      "Intégrité vérifiée",
      run.integrityOk === true,
      "low",
      run.integrityOk ? "La copie stockée correspond à son empreinte." : "La copie stockée n'a jamais été revérifiée.",
      "Re-téléchargez la copie et lancez `codegate-backup verify --file <copie>`.",
    );
  }

  // ── Stockage, rétention, immutabilité ──
  check(
    "isolation",
    "Copie hors du serveur de production",
    run.storageLocation === "offsite",
    run.storageLocation === "unknown" ? "medium" : "high",
    run.storageLocation === "offsite"
      ? "Stockée hors du serveur."
      : run.storageLocation === "unknown"
        ? "Emplacement de stockage non déclaré."
        : "La sauvegarde reste sur le serveur de production : perdue avec lui.",
    "Externalisez vers un stockage objet (S3, Backblaze B2, Wasabi) dans un compte séparé.",
  );
  check(
    "separate_account",
    "Compte de stockage séparé",
    run.separateAccount === true,
    "medium",
    run.separateAccount ? "Accès isolé du compte de production." : "Même compte / mêmes identifiants que la production.",
    "Utilisez un compte ou projet cloud dédié, avec des identifiants en écriture seule.",
  );
  const retention = run.retentionDays;
  check(
    "retention",
    "Rétention ≥ 30 jours",
    retention !== null && retention >= 30,
    retention === null ? "medium" : "high",
    retention === null ? "Rétention non déclarée." : `${retention} jours de rétention (90 recommandés).`,
    "Conservez au moins 30 jours de versions (90 recommandés).",
  );
  check(
    "immutability",
    "Stockage immuable",
    run.immutable === true,
    "medium",
    run.immutable ? "Verrou d'immutabilité actif." : "Les sauvegardes peuvent être supprimées ou chiffrées par un attaquant.",
    "Activez S3 Object Lock / WORM (7 à 30 jours) et le versioning.",
  );

  // ── Restauration ──
  if (!restore) {
    check(
      "restore_test",
      "Restauration testée",
      false,
      "high",
      "Aucun test de restauration : rien ne prouve que la sauvegarde est exploitable.",
      "Lancez `codegate-backup restore-test` (conteneur isolé, la production n'est jamais touchée).",
    );
  } else {
    const days = (now.getTime() - restore.completedAt.getTime()) / DAY;
    const okRestore = restore.result === "success";
    check(
      "restore_test",
      "Restauration testée",
      okRestore && days <= 30,
      okRestore ? "medium" : "critical",
      okRestore
        ? `Restaurée en ${restore.durationSeconds} s il y a ${Math.round(days)} jour(s).`
        : "Le dernier test de restauration a échoué.",
      okRestore ? "Testez la restauration au moins une fois par mois." : "Corrigez la sauvegarde : elle n'est pas restaurable.",
    );
  }

  const ransomwareReady =
    run.storageLocation === "offsite" &&
    run.immutable === true &&
    run.separateAccount === true &&
    (keyIsolated || !run.encrypted) &&
    run.encrypted;
  return finish(checks, ransomwareReady);
}

const ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function finish(checks: BackupCheck[], ransomwareReady: boolean): BackupEvaluation {
  // Most severe failures first; passing checks keep their natural order.
  checks.sort((a, b) => Number(a.ok) - Number(b.ok) || (a.ok ? 0 : ORDER[a.severity] - ORDER[b.severity]));
  const failed = checks.filter((c) => !c.ok);
  const score = Math.max(0, 100 - failed.reduce((s, c) => s + WEIGHT[c.severity], 0));
  const status: BackupStatus = failed.some((c) => c.severity === "critical")
    ? "critical"
    : failed.some((c) => c.severity === "high" || c.severity === "medium")
      ? "attention"
      : "healthy";
  return { score, status, ransomwareReady, checks };
}
