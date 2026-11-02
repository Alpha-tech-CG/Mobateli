/**
 * Guided revocation (cahier §5.2 « guider la révocation de la clé
 * compromise », US03). Per secret type: where to revoke, then the steps every
 * leak needs (history, rotation, audit of usage).
 */

export interface RevocationGuide {
  provider: string;
  url: string | null;
  steps: string[];
}

const COMMON_AFTER = [
  "Remplacez la valeur dans le code par une variable d'environnement ou un gestionnaire de secrets (jamais dans le dépôt).",
  "Considérez l'ancienne valeur comme publique : elle reste dans l'historique Git même après suppression du fichier.",
  "Vérifiez les journaux du fournisseur pour toute utilisation suspecte depuis la date du commit.",
  "Marquez le secret comme révoqué dans CodeGate pour garder la preuve de remédiation.",
];

const GUIDES: Record<string, Omit<RevocationGuide, "steps"> & { first: string[] }> = {
  aws_access_key_id: {
    provider: "AWS",
    url: "https://console.aws.amazon.com/iam/home#/security_credentials",
    first: [
      "IAM → utilisateur concerné → « Security credentials » → désactivez puis supprimez la clé d'accès.",
      "Créez une nouvelle clé (ou mieux : un rôle IAM / OIDC sans clé longue durée).",
      "Consultez CloudTrail pour les appels effectués avec l'ancienne clé.",
    ],
  },
  stripe_secret_key: {
    provider: "Stripe",
    url: "https://dashboard.stripe.com/apikeys",
    first: [
      "Dashboard Stripe → Développeurs → Clés API → « Faire pivoter la clé » (expiration immédiate).",
      "Préférez une clé restreinte (restricted key) limitée aux ressources nécessaires.",
    ],
  },
  openai_api_key: {
    provider: "OpenAI",
    url: "https://platform.openai.com/api-keys",
    first: ["Supprimez la clé dans « API keys » puis créez-en une nouvelle, limitée au projet."],
  },
  anthropic_api_key: {
    provider: "Anthropic",
    url: "https://console.anthropic.com/settings/keys",
    first: ["Console Anthropic → API Keys → désactivez puis supprimez la clé, créez-en une nouvelle."],
  },
  github_token: {
    provider: "GitHub",
    url: "https://github.com/settings/tokens",
    first: ["Settings → Developer settings → Personal access tokens → « Delete » sur le jeton exposé."],
  },
  github_pat: {
    provider: "GitHub",
    url: "https://github.com/settings/personal-access-tokens",
    first: ["Settings → Developer settings → Fine-grained tokens → révoquez le jeton exposé."],
  },
  google_api_key: {
    provider: "Google Cloud",
    url: "https://console.cloud.google.com/apis/credentials",
    first: [
      "APIs & Services → Identifiants → régénérez ou supprimez la clé.",
      "Ajoutez des restrictions (API autorisées, référents HTTP ou IP).",
    ],
  },
  slack_token: {
    provider: "Slack",
    url: "https://api.slack.com/apps",
    first: ["Votre app Slack → OAuth & Permissions → « Revoke tokens », puis réinstallez l'app."],
  },
  private_key: {
    provider: "Clé privée",
    url: null,
    first: [
      "Générez une nouvelle paire de clés et remplacez la clé publique partout où elle est autorisée (serveurs, GitHub, certificats).",
      "Retirez l'ancienne clé publique des `authorized_keys` / révoquez le certificat associé.",
    ],
  },
  postgres_url: {
    provider: "Base de données",
    url: null,
    first: [
      "Changez immédiatement le mot de passe de l'utilisateur : `ALTER ROLE <user> WITH PASSWORD '…';`",
      "Vérifiez que la base n'est pas joignable depuis Internet (voir Infra Shield).",
    ],
  },
};

export function revocationGuide(secretType: string): RevocationGuide {
  const g = GUIDES[secretType];
  if (g) return { provider: g.provider, url: g.url, steps: [...g.first, ...COMMON_AFTER] };
  return {
    provider: "Fournisseur du secret",
    url: null,
    steps: [
      "Révoquez ou régénérez ce secret dans la console du service concerné.",
      ...COMMON_AFTER,
    ],
  };
}
