// T1556.006 — Multi-Factor Authentication — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.006", name: "Multi-Factor Authentication", tactic: "Credential Access", platform: "Cloud, Identity Providers", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 340, rows: [{ label: "DISABLE MFA", y: 80 }, { label: "MODIFY MFA", y: 200 }] },
  nodes: [
    { id: "admin_access", label: "Admin Access", sub: "Identity provider", x: 60, y: 130, r: 36, type: "entry", desc: "Administrative access to identity provider (Azure AD Global Admin, Okta Admin, Duo Admin).", src: "MITRE ATT&CK T1556.006" },
    { id: "disable_mfa", label: "Disable MFA", sub: "Per-user/conditional", x: 220, y: 80, r: 36, type: "op", desc: "Disable MFA for target user or modify conditional access policy to exempt attacker IPs.", src: "MITRE T1556.006" },
    { id: "az_api", label: "Graph API", sub: "Update authMethods", x: 420, y: 80, r: 34, type: "api", desc: "Microsoft Graph API: DELETE /users/{id}/authentication/methods/{id} to remove MFA method.", src: "Microsoft Graph API" },
    { id: "cond_access", label: "Conditional Access", sub: "Policy modify", x: 600, y: 80, r: 36, type: "op", desc: "Modify Conditional Access policy: add trusted location/IP exclusion for attacker.", src: "Microsoft Entra; MITRE T1556.006" },
    { id: "register_device", label: "Register Device", sub: "Attacker MFA device", x: 220, y: 200, r: 38, type: "op", desc: "Register attacker's phone/TOTP as additional MFA method for compromised user.", src: "MITRE T1556.006" },
    { id: "token_modify", label: "Token Modify", sub: "SAML/OAuth claims", x: 420, y: 200, r: 34, type: "op", desc: "Modify SAML assertions or OAuth token claims to indicate MFA completed.", src: "MITRE T1556.006; T1606.002" },
    { id: "duo_bypass", label: "Duo Bypass", sub: "API integration", x: 420, y: 260, r: 30, type: "op", desc: "Modify Duo integration to allow bypass codes or disable for specific users.", src: "Duo Security" },
    { id: "az_audit", label: "Azure Audit Log", sub: "MFA changes", x: 600, y: 200, r: 40, type: "detect", desc: "OPTIMAL: Azure AD Audit Log: 'User registered security info', 'Admin disabled MFA', policy changes.", src: "Microsoft Entra Audit" },
    { id: "okta_syslog", label: "Okta Syslog", sub: "Factor events", x: 600, y: 280, r: 34, type: "detect", desc: "Okta System Log: user.mfa.factor.deactivate, policy.lifecycle.update events.", src: "Okta System Log" },
    { id: "bypass_mfa", label: "MFA Bypassed", x: 800, y: 130, r: 38, type: "artifact", desc: "Attacker can authenticate without MFA or with attacker-controlled MFA device.", src: "MITRE T1556.006" },
  ],
  edges: [
    { f: "admin_access", t: "disable_mfa" }, { f: "disable_mfa", t: "az_api" },
    { f: "admin_access", t: "cond_access" },
    { f: "admin_access", t: "register_device" }, { f: "register_device", t: "az_api" },
    { f: "admin_access", t: "token_modify" }, { f: "admin_access", t: "duo_bypass" },
    { f: "az_api", t: "bypass_mfa" }, { f: "cond_access", t: "bypass_mfa" },
    { f: "token_modify", t: "bypass_mfa" }, { f: "duo_bypass", t: "bypass_mfa" },
    { f: "az_api", t: "az_audit" }, { f: "cond_access", t: "az_audit" },
    { f: "duo_bypass", t: "okta_syslog" },
  ],
};
export default model;
