import { SAML } from "@node-saml/node-saml";
import type { AppConfig } from "../config.js";

/**
 * SAML SSO service-provider helper (cahier §12.2 P3). Builds a node-saml
 * instance for an organization's IdP config. One SP endpoint set per org,
 * keyed by orgId in the URL.
 */

export interface SamlConfig {
  idpEntityId: string;
  idpSsoUrl: string;
  idpCert: string;
}

export function spIssuer(config: AppConfig, orgId: string): string {
  return `${config.PUBLIC_API_URL}/saml/${orgId}/metadata`;
}

export function spAcsUrl(config: AppConfig, orgId: string): string {
  return `${config.PUBLIC_API_URL}/saml/${orgId}/acs`;
}

export function buildSaml(config: AppConfig, conn: SamlConfig, orgId: string): SAML {
  const issuer = spIssuer(config, orgId);
  return new SAML({
    callbackUrl: spAcsUrl(config, orgId),
    issuer,
    audience: issuer,
    entryPoint: conn.idpSsoUrl,
    idpCert: conn.idpCert,
    // The IdP must sign assertions; we don't sign AuthnRequests (no SP key).
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
  });
}
