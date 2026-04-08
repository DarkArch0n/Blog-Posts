// T1606.002 — SAML Tokens — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1606.002", name: "SAML Tokens", tactic: "Credential Access", platform: "Azure AD, AD FS, Okta", version: "v1.0" },
  layout: { svgWidth: 1400, svgHeight: 380, rows: [{ label: "KEY THEFT", y: 80 }, { label: "TOKEN FORGE", y: 200 }, { label: "ACCESS", y: 310 }] },
  nodes: [
    { id: "adfs_access", label: "AD FS / IdP", sub: "Admin access", x: 60, y: 140, r: 38, type: "entry", desc: "Administrative access to identity provider: AD FS server, Azure AD, Okta.", src: "MITRE ATT&CK T1606.002" },
    { id: "dkm_key", label: "DKM Key Export", sub: "AD attribute", x: 240, y: 80, r: 36, type: "op", desc: "Read AD FS Distributed Key Manager (DKM) key from Active Directory container object.", src: "AD FS; AADInternals" },
    { id: "token_signing", label: "Token-Signing Cert", sub: "Private key", x: 440, y: 80, r: 38, type: "api", desc: "Export AD FS token-signing certificate private key using DKM decryption key.", src: "AD FS; AADInternals Export-AADIntADFSSigningCertificate" },
    { id: "adconnect", label: "Azure AD Connect", sub: "Sync credentials", x: 440, y: 140, r: 34, type: "op", desc: "Azure AD Connect stores sync account creds — can be extracted to access Azure AD.", src: "AADInternals; MITRE T1606.002" },
    { id: "forge_saml", label: "Forge SAML Token", sub: "Any user, any RP", x: 240, y: 200, r: 40, type: "op", desc: "Use stolen token-signing cert to forge SAML 2.0 assertions for any user to any relying party.", src: "MITRE T1606.002; Golden SAML" },
    { id: "aadinternals", label: "AADInternals", sub: "Open-AADIntOffice365", x: 440, y: 200, r: 36, type: "op", desc: "AADInternals: New-AADIntSAMLToken / Open-AADIntOffice365 with forged SAML.", src: "AADInternals" },
    { id: "saml_post", label: "SAML POST", sub: "to SP ACS URL", x: 640, y: 200, r: 34, type: "protocol", desc: "HTTP POST forged SAMLResponse to Service Provider Assertion Consumer Service URL.", src: "SAML 2.0 Bindings" },
    { id: "o365_access", label: "Office 365", sub: "Any mailbox", x: 240, y: 310, r: 34, type: "artifact", desc: "Access any Office 365 mailbox, SharePoint, Teams via forged SAML.", src: "MITRE T1606.002" },
    { id: "aws_access", label: "AWS Console", sub: "Federated access", x: 440, y: 310, r: 34, type: "artifact", desc: "AWS SSO via SAML federation — access AWS console and APIs as any role.", src: "AWS SAML; MITRE T1606.002" },
    { id: "adfs_events", label: "AD FS Events", sub: "411/412 mismatch", x: 640, y: 80, r: 38, type: "detect", desc: "Compare AD FS authentication events (411/412) with token presentations — forged tokens leave no IdP-side log.", src: "Microsoft AD FS Audit" },
    { id: "sentinel", label: "Azure Sentinel", sub: "Token anomaly", x: 640, y: 310, r: 38, type: "detect", desc: "OPTIMAL: Azure Sentinel: SAML token use without corresponding IdP authentication event. Token lifetime/claim anomalies.", src: "Microsoft Sentinel; DART" },
    { id: "all_rps", label: "All Relying Parties", sub: "Persistent access", x: 860, y: 200, r: 42, type: "artifact", desc: "Persistent access to ALL federated services. Survives password resets and MFA. Requires cert rotation to remediate.", src: "MITRE T1606.002; SolarWinds" },
  ],
  edges: [
    { f: "adfs_access", t: "dkm_key" }, { f: "adfs_access", t: "adconnect" },
    { f: "dkm_key", t: "token_signing" }, { f: "token_signing", t: "forge_saml" },
    { f: "forge_saml", t: "aadinternals" }, { f: "aadinternals", t: "saml_post" },
    { f: "saml_post", t: "o365_access" }, { f: "saml_post", t: "aws_access" },
    { f: "o365_access", t: "all_rps" }, { f: "aws_access", t: "all_rps" },
    { f: "token_signing", t: "adfs_events" }, { f: "saml_post", t: "sentinel" },
  ],
};
export default model;
