// T1649 — Steal or Forge Authentication Certificates — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1649",
    name: "Steal or Forge Authentication Certificates",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1020,
    svgHeight: 540,
    columns: [
      { label: "PREREQUISITE", x: 70  },
      { label: "ATTACK PATH",  x: 250 },
      { label: "CERT OBTAIN",  x: 450 },
      { label: "DETECTION",    x: 660 },
      { label: "OUTCOME",      x: 890 },
    ],
    separators: [160, 350, 555, 775],
    annotations: [
      { text: "AD CS misconfigurations are extremely common", x: 250, y: 480, color: "#c62828", fontStyle: "italic" },
      { text: "Certificates persist beyond password resets", x: 660, y: 450, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "adcs", label: "AD CS", sub: "Certificate Services", x: 70, y: 160, r: 38, type: "source",
      tags: ["Active Directory Certificate Services", "PKI", "Enterprise CA"],
      telemetry: [],
      api: "Misconfigured AD CS environment — Enterprise CA with vulnerable certificate templates",
      artifact: "AD CS deployed · certificate templates with dangerous configurations",
      desc: "Active Directory Certificate Services (AD CS) provides PKI infrastructure for Windows environments. Misconfigurations in certificate templates, CA settings, and access controls create attack paths that enable account impersonation and domain compromise. The SpecterOps 'Certified Pre-Owned' research identified 8+ (ESC1-ESC8) abuse scenarios.",
      src: "MITRE ATT&CK T1649; SpecterOps Certified Pre-Owned whitepaper" },

    { id: "domain_user", label: "Domain User", sub: "Authenticated", x: 70, y: 380, r: 36, type: "source",
      tags: ["Any domain user", "Low-privilege", "Enroll permission"],
      telemetry: [],
      api: "Any authenticated domain user with Enroll permission on a vulnerable template",
      artifact: "Standard domain user account — often sufficient for ESC1/ESC6/ESC8",
      desc: "Many AD CS attacks require only a standard domain user account with 'Enroll' permissions on a misconfigured certificate template. No admin access needed. The CommonName or SAN can be used to specify an arbitrary identity (e.g., Domain Admin).",
      src: "MITRE T1649; SpecterOps ESC1" },

    { id: "esc1", label: "ESC1", sub: "SAN Impersonation", x: 250, y: 80, r: 36, type: "source",
      tags: ["ESC1", "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT", "SAN=DA", "Certipy"],
      telemetry: ["4886", "4887"],
      api: "Template allows requester to specify SAN → request cert as Domain Admin",
      artifact: "Certificate request with arbitrary SAN · Event 4886/4887 on CA",
      desc: "ESC1: Certificate template has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag + Client Authentication EKU + Domain Users can enroll. Attacker specifies SAN=administrator@corp.local to impersonate Domain Admin. Most common and impactful AD CS misconfiguration.",
      src: "SpecterOps ESC1; Certipy; Certify" },

    { id: "esc6", label: "ESC6", sub: "EDITF_ATTRIBUTESUBJECTALTNAME2", x: 250, y: 230, r: 34, type: "source",
      tags: ["ESC6", "EDITF flag on CA", "Any template abusable"],
      telemetry: ["4886", "4887"],
      api: "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag — any template can specify SAN",
      artifact: "CA-level misconfiguration · all certificate requests can include arbitrary SAN",
      desc: "ESC6: The CA itself has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, meaning ANY certificate request can include a Subject Alternative Name regardless of template configuration. Makes every template with client auth EKU exploitable for impersonation.",
      src: "SpecterOps ESC6; certutil -getreg policy\\EditFlags" },

    { id: "esc8", label: "ESC8", sub: "NTLM Relay to CA", x: 250, y: 370, r: 34, type: "source",
      tags: ["ESC8", "PetitPotam + relay", "NTLM relay to HTTP enrollment"],
      telemetry: ["4624"],
      api: "Relay DC NTLM auth (via PetitPotam) to AD CS HTTP enrollment → cert as DC machine",
      artifact: "NTLM relay to CA web endpoint · certificate issued for relayed identity",
      desc: "ESC8: AD CS HTTP enrollment endpoint accepts NTLM. Attacker coerces DC authentication (PetitPotam) and relays it to the CA web enrollment. CA issues a certificate for the DC's machine account. Attacker uses the cert to DCSync. No prior AD CS enrollment needed.",
      src: "SpecterOps ESC8; PetitPotam; ntlmrelayx" },

    { id: "cert_theft", label: "Cert Theft", sub: "DPAPI/export", x: 250, y: 490, r: 32, type: "source",
      tags: ["Mimikatz crypto::certificates", "DPAPI cert export", "THEFT1-THEFT5"],
      telemetry: ["Sysmon 1"],
      api: "Mimikatz crypto::certificates /export · DPAPI certificate private key theft",
      artifact: "Sysmon EID 1: mimikatz crypto module · certificate export events",
      desc: "Steal existing certificates from user/machine stores. Mimikatz crypto::certificates exports certificates with private keys. DPAPI backupkey enables decrypting any user's certificate private keys. Can steal certificates already issued to Domain Admins or other high-privilege accounts.",
      src: "SpecterOps THEFT1-THEFT5; Mimikatz crypto" },

    { id: "cert_obtain", label: "Certificate", sub: "Obtained/Forged", x: 450, y: 260, r: 42, type: "source",
      tags: ["PFX/PEM with private key", "Identity impersonation", "PKINIT-capable"],
      telemetry: ["4886", "4887"],
      api: "X.509 certificate with private key (PFX) for target identity — usable for PKINIT",
      artifact: "Certificate file (.pfx/.pem) · CA issuance event 4887 · identity claim in cert SAN",
      desc: "Attacker obtains an X.509 certificate with private key that claims a high-privilege identity (Domain Admin, DC machine account). The certificate is valid for Kerberos PKINIT authentication. Represents the target identity for authentication purposes.",
      src: "MITRE T1649; SpecterOps" },

    { id: "ev_detect", label: "Cert Events", sub: "4886/4887/PKINIT", x: 660, y: 260, r: 50, type: "detect",
      tags: ["Event 4886", "Event 4887", "Event 4768", "PKINIT alert"],
      telemetry: ["4886", "4887", "4768"],
      api: "CA events 4886 (request) + 4887 (issue) + DC event 4768 (PKINIT auth) monitoring",
      artifact: "OPTIMAL: Event 4887 with unusual SAN · 4768 with PKINIT from abnormal source · Certipy enum alerts",
      desc: "OPTIMAL DETECTION NODE. (1) CA Event 4886: certificate request received — check for SAN specifying another user. (2) CA Event 4887: certificate issued — check template used and SAN value. (3) DC Event 4768: Kerberos authentication via PKINIT (certificate) — alert on unusual sources. (4) Template audit: regularly check for CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth + broad enrollment permissions. (5) Certipy find or Certify find to inventory vulnerable templates.",
      src: "MITRE T1649; SpecterOps; Microsoft CA auditing; Sigma rules" },

    { id: "pkinit_auth", label: "PKINIT Auth", sub: "As target identity", x: 890, y: 170, r: 38, type: "source",
      tags: ["PKINIT Kerberos", "Certipy auth", "Rubeus asktgt /certificate"],
      telemetry: ["4768"],
      api: "Certipy auth -pfx admin.pfx · Rubeus asktgt /certificate:admin.pfx /ptt",
      artifact: "Event 4768 with certificate auth · TGT for impersonated identity · NTLM hash via U2U",
      desc: "Attacker authenticates via Kerberos PKINIT using the forged/stolen certificate. Certipy auth -pfx admin.pfx or Rubeus asktgt /certificate. Yields a TGT for the impersonated identity. Can also extract the NTLM hash via User-to-User (U2U) Kerberos — known as UnPAC-the-Hash.",
      src: "SpecterOps; Certipy; Rubeus" },

    { id: "persist_cert", label: "Persistence", sub: "Cert valid for years", x: 890, y: 370, r: 36, type: "source",
      tags: ["Certificate lifetime", "Survives password reset", "Re-authenticate anytime"],
      telemetry: [],
      api: "Certificate valid for template-defined lifetime (often 1-5 years) — survives password resets",
      artifact: "⚠ Certificate persists beyond password changes · only revocation stops it",
      desc: "Certificates provide long-term persistence. Default template validity is 1-5 years. Unlike passwords, the certificate remains valid even after the target account's password is reset. Attacker can re-authenticate whenever the certificate is valid. Remediation requires: CA template remediation, certificate revocation, and potentially CA key rotation.",
      src: "MITRE T1649; SpecterOps persistence tradecraft" },
  ],

  edges: [
    { f: "adcs", t: "esc1" },
    { f: "adcs", t: "esc6" },
    { f: "adcs", t: "esc8" },
    { f: "domain_user", t: "esc1" },
    { f: "domain_user", t: "esc6" },
    { f: "domain_user", t: "cert_theft" },
    { f: "esc1", t: "cert_obtain" },
    { f: "esc6", t: "cert_obtain" },
    { f: "esc8", t: "cert_obtain" },
    { f: "cert_theft", t: "cert_obtain" },
    { f: "cert_obtain", t: "ev_detect" },
    { f: "ev_detect", t: "pkinit_auth" },
    { f: "ev_detect", t: "persist_cert" },
  ],
};

export default model;
