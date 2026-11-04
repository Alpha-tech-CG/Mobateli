/**
 * Identity of the publisher, used by every legal page. Fill in the fields
 * marked TODO before publishing (they render as « à compléter » until then),
 * and have the texts reviewed by a lawyer for your jurisdiction.
 *
 * Bump LEGAL_VERSION whenever the terms change: signups record the version
 * they accepted.
 */
export const LEGAL_VERSION = "2026-11-05";

export const COMPANY = {
  /** Brand of the service. */
  brand: "CodeGate",
  /** TODO: exact legal name of the company operating CodeGate. */
  legalName: "",
  /** TODO: legal form and share capital, e.g. « SARL au capital de … ». */
  legalForm: "",
  /** TODO: registered office address. */
  address: "",
  /** TODO: trade register number (RCCM, RCS…) and tax id. */
  registration: "",
  /** TODO: name of the publication director. */
  publicationDirector: "",
  /** TODO: contact address for legal and privacy requests. */
  contactEmail: "",
  /** TODO: country whose law governs the contract, and competent courts. */
  governingLaw: "",
  courts: "",
};

/** Hosting and sub-processors actually used by the code (keep in sync). */
export const SUBPROCESSORS: { name: string; purpose: string; location: string; required: boolean }[] = [
  { name: "Vercel Inc.", purpose: "Hébergement de l'application web et de l'API", location: "Union européenne (Francfort, fra1)", required: true },
  { name: "Neon Inc.", purpose: "Base de données PostgreSQL (comptes, résultats d'analyse, journal d'audit)", location: "Union européenne", required: true },
  { name: "Resend Inc.", purpose: "Envoi des emails transactionnels (vérification, réinitialisation, invitations)", location: "États-Unis", required: true },
  { name: "Google LLC (API Gemini)", purpose: "Rédaction de la synthèse des rapports PDF à partir des constats, sans code ni secret", location: "États-Unis / Union européenne", required: false },
  { name: "GitHub Inc. / GitLab", purpose: "Lecture des dépôts et publication des résultats, via l'application que vous installez", location: "Selon votre fournisseur", required: false },
  { name: "OSV.dev, npm, PyPI, Go proxy", purpose: "Vérification publique des dépendances (nom et version du paquet uniquement)", location: "Services publics", required: true },
];

export const missing = (value: string) => value.trim() === "";
