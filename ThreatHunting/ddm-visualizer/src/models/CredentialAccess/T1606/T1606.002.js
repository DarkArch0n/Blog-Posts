// T1606.002 — SAML Tokens — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1606.002",
    name: "SAML Tokens",
    tactic: "Credential Access",
    platform: "Cloud, SaaS, Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 500,
    columns: [
      { label: "PREREQUISITE",  x: 70  },
      { label: "FORGE TOKEN",  x: 250 },
      { label: "USE TOKEN",    x: 440 },
      { label: "DETECTION",    x: 650 },
      { label: "OUTCOME",      x: 880 },
    ],
    separators: [160, 345, 545, 765],
    annotations: [
      { text: "Golden SAML — like Golden Ticket for cloud services", x: 250, y: 430, color: "#c62828", fontStyle: "italic" },
      { text: "NOBELIUM/SolarWinds attack used this technique", x: 650, y: 420, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "signing_cert", label: "Token Signing", sub: "Certificate stolen", x: 70, y: 160, r: 40, type: "source",
      tags: ["AD FS signing cert", "Azure AD Connect", "SAML signing key"],
      telemetry: [],
      api: "AD FS token-signing certificate private key (stored in AD FS DB or HSM)",
      artifact: "Token-signing certificate extracted from AD FS · private key compromised",
      desc: "Golden SAML requires the SAML token-signing certificate's private key. Typically stored in the AD FS database (WID or SQL). Attackers extract it via: Mimikatz (export certificate), AADInternals (Export-AADIntADFSSigningCertificate), or direct database access. The NOBELIUM/SolarWinds attackers used this technique for persistent cloud access.",
      src: "MITRE ATT&CK T1606.002; NOBELIUM/SolarWinds analysis; Sygnia Golden SAML" },

    { id: "adfs_access", label: "AD FS Access", sub: "Admin on server", x: 70, y: 370, r: 36, type: "source",
      tags: ["AD FS server admin", "DA", "DKM key from AD"],
      telemetry: [],
      api: "Local admin on AD FS server, or Domain Admin to extract DKM key from AD",
      artifact: "Admin access to AD FS server · DKM key exported from AD LDAP",
      desc: "Accessing the token-signing certificate requires: (1) Local admin on the AD FS server to export from the certificate store, or (2) Domain Admin to extract the Distributed Key Manager (DKM) key from Active Directory (used to protect the cert in AD FS DB). AADInternals automates the DKM key extraction.",
      src: "MITRE T1606.002; AADInternals; Sygnia" },

    { id: "forge_saml", label: "Forge SAML", sub: "Golden SAML", x: 250, y: 200, r: 42, type: "blind",
      tags: ["ADFSpoof", "AADInternals", "Golden SAML", "Any identity"],
      telemetry: [],
      api: "ADFSpoof / AADInternals New-AADIntSAMLToken — forge SAML token for any federated user",
      artifact: "⚠ Forging is offline — zero AD FS/IdP telemetry during creation",
      desc: "BLIND SPOT. ADFSpoof and AADInternals forge SAML tokens offline using the stolen signing certificate. The forged token asserts any identity with any claims (UPN, groups, roles). The IdP (AD FS) is never contacted — there are NO authentication events on the identity provider during forgery. The token is cryptographically valid.",
      src: "mandiant/ADFSpoof; Gerenios/AADInternals; Sygnia Golden SAML" },

    { id: "use_token", label: "Present Token", sub: "To service provider", x: 440, y: 200, r: 38, type: "source",
      tags: ["Azure AD", "O365", "AWS", "Any SAML SP"],
      telemetry: ["Azure AD logs", "SP logs"],
      api: "POST forged SAML token to service provider (Azure AD, O365, AWS) assertion consumer URL",
      artifact: "SAML token presented to SP · authentication accepted · session issued",
      desc: "The forged SAML token is presented directly to the service provider (Azure AD, O365, AWS, or any SAML-federated service). The SP validates the token signature using the legitimate signing certificate's public key — it's valid. A session is issued without any authentication on the IdP.",
      src: "MITRE T1606.002; Sygnia" },

    { id: "ev_detect", label: "Token Anomaly", sub: "IdP gap detection", x: 650, y: 260, r: 50, type: "detect",
      tags: ["No IdP login event", "Token without auth", "Anomalous claims", "Azure AD"],
      telemetry: ["Azure AD logs"],
      api: "Detect SAML assertion accepted by SP with NO corresponding IdP authentication event",
      artifact: "OPTIMAL: SP accepted token but IdP has no matching auth event · anomalous token claims · unusual issuing time",
      desc: "OPTIMAL DETECTION NODE. (1) Missing IdP authentication: SP logs show accepted SAML assertion but AD FS/IdP has no corresponding authentication event for that user at that time. (2) Token anomaly: assertion issued time doesn't match AD FS service uptime. (3) Azure AD: 'Unfamiliar sign-in properties' risk event. (4) Claims anomaly: unusual group memberships or attributes. (5) PREVENTION: Regularly rotate the AD FS token-signing certificate, store it in HSM, limit AD FS server access, enable Azure AD Conditional Access.",
      src: "MITRE T1606.002; Microsoft Golden SAML detection; CISA Alert AA21-008A" },

    { id: "cloud_access", label: "Cloud Access", sub: "Any service", x: 880, y: 160, r: 38, type: "source",
      tags: ["O365 access", "Azure portal", "AWS console", "Any federated service"],
      telemetry: ["Azure AD logs"],
      api: "Full access to any SAML-federated service as the forged identity",
      artifact: "Authenticated access to O365, Azure, AWS, or any federated cloud service",
      desc: "The forged SAML token provides access to ANY service federated with the compromised IdP. This typically includes: O365 (email, SharePoint, Teams), Azure Portal (cloud infrastructure), AWS (if SAML-federated), and internal SAML-integrated applications. The attacker can impersonate any user.",
      src: "MITRE T1606.002" },

    { id: "persist_saml", label: "Persistence", sub: "Re-forge anytime", x: 880, y: 370, r: 36, type: "source",
      tags: ["Signing cert persists", "Forge tokens anytime", "Survives password reset"],
      telemetry: [],
      api: "With signing cert, forge new tokens at will — survives password resets, MFA changes",
      artifact: "⚠ Persistent access until signing cert is rotated · password resets don't help",
      desc: "Golden SAML provides persistent access: the attacker can forge new SAML tokens at any time using the stolen signing certificate. Survives password resets, MFA changes, and account remediation. Only remediated by rotating the token-signing certificate and all associated trust relationships.",
      src: "MITRE T1606.002; CISA Golden SAML remediation guidance" },
  ],

  edges: [
    { f: "signing_cert", t: "forge_saml" },
    { f: "adfs_access", t: "signing_cert" },
    { f: "forge_saml", t: "use_token", blind: true },
    { f: "use_token", t: "ev_detect" },
    { f: "ev_detect", t: "cloud_access" },
    { f: "ev_detect", t: "persist_saml" },
  ],
};

export default model;
