// T1556.006 — Multi-Factor Authentication — Detection Data Model
// Tactic: Credential Access / Persistence / Defense Evasion

const model = {
  metadata: {
    tcode: "T1556.006",
    name: "Multi-Factor Authentication",
    tactic: "Credential Access",
    platform: "Windows, Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "MFA TARGET",  x: 80 },
      { label: "MODIFICATION", x: 270 },
      { label: "DETECTION",    x: 500 },
      { label: "OUTCOME",      x: 760 },
    ],
    separators: [175, 385, 630],
    annotations: [
      { text: "Modifying MFA at the authentication layer — not MFA fatigue (T1621)", x: 270, y: 440, color: "#f57f17", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "mfa_system", label: "MFA System", sub: "Server/config", x: 80, y: 130, r: 38, type: "source",
      tags: ["Azure MFA", "Duo", "RSA SecurID", "ADFS MFA adapter"],
      telemetry: [],
      api: "Administrative access to MFA infrastructure: Azure MFA, Duo admin, ADFS MFA adapter",
      artifact: "Admin access to MFA provider or MFA integration point",
      desc: "Attacker gains administrative access to the MFA system itself. This could be: Azure AD MFA settings, Duo admin panel, RSA SecurID admin console, AD FS MFA adapter configuration, or any identity provider's MFA configuration. Requires elevated privileges on the identity platform.",
      src: "MITRE ATT&CK T1556.006" },

    { id: "disable_mfa", label: "Disable MFA", sub: "Remove requirement", x: 270, y: 110, r: 38, type: "source",
      tags: ["Disable MFA policy", "Exclude from CA policy", "Register new device"],
      telemetry: ["Azure AD audit"],
      api: "Disable MFA for target accounts or modify Conditional Access to exclude accounts",
      artifact: "Azure AD: MFA disabled for user · Conditional Access policy modified · new MFA device registered",
      desc: "Disable MFA requirement: remove MFA from user account, modify Conditional Access to exclude specific accounts, or change authentication strength to allow single-factor. Can also register a new MFA device for the attacker (phone/authenticator).",
      src: "MITRE T1556.006; Azure AD documentation" },

    { id: "mod_mfa_code", label: "Modify MFA", sub: "Patch validation", x: 270, y: 280, r: 36, type: "source",
      tags: ["Patch MFA validator", "Accept any code", "Hardcode bypass"],
      telemetry: [],
      api: "Modify MFA validation to accept any code, bypass validation, or hardcode a master code",
      artifact: "Modified MFA validator binary/config · any OTP code accepted",
      desc: "Modify the MFA validation component to: always return 'valid', accept a hardcoded master bypass code, or skip MFA validation entirely. On-premises MFA servers: patch the validation DLL/module. Cloud: modify the MFA integration adapter or custom authentication extension.",
      src: "MITRE T1556.006" },

    { id: "register_device", label: "Register Device", sub: "New auth method", x: 270, y: 430, r: 34, type: "source",
      tags: ["Register new MFA device", "Phone number change", "FIDO2 key"],
      telemetry: ["Azure AD audit"],
      api: "Register attacker-controlled MFA device (phone, authenticator, FIDO2 key) for target account",
      artifact: "New authentication method registered · phone number added · MFA device enrolled",
      desc: "Register an attacker-controlled MFA device (phone number, authenticator app, FIDO2 key) for the target user account. The attacker then receives MFA prompts and codes on their own device. Less intrusive than disabling MFA — the account still 'has MFA enabled'.",
      src: "MITRE T1556.006" },

    { id: "ev_detect", label: "MFA Audit", sub: "Policy + device", x: 500, y: 250, r: 50, type: "detect",
      tags: ["MFA policy change", "New MFA device", "CA policy change", "Azure AD audit"],
      telemetry: ["Azure AD audit"],
      api: "Monitor MFA policy changes + new device registrations + Conditional Access modifications",
      artifact: "OPTIMAL: Azure AD audit: MFA disabled · new auth method registered · CA policy excluded account · MFA bypass",
      desc: "OPTIMAL DETECTION NODE. (1) Azure AD audit: 'User registered security info' — new MFA device registered for account. (2) MFA policy changes: MFA requirement removed for user/group. (3) Conditional Access: policy modified to exclude accounts or weaken authentication strength. (4) MFA validation anomaly: successful auth without expected MFA challenge. (5) PREVENTION: Privileged Identity Management, MFA registration policy requiring existing MFA, Conditional Access baseline monitoring.",
      src: "MITRE T1556.006; Microsoft Entra ID audit logs" },

    { id: "bypass", label: "MFA Bypass", sub: "Password-only auth", x: 760, y: 250, r: 42, type: "source",
      tags: ["No MFA required", "Single-factor", "Credential access"],
      telemetry: [],
      api: "MFA bypassed — attacker authenticates with only password · no second factor needed",
      artifact: "Authentication succeeds without MFA challenge",
      desc: "With MFA disabled, bypassed, or using an attacker-registered device, the attacker authenticates with just the stolen password or by approving MFA on their own device. This undermines the primary control designed to prevent credential-based attacks.",
      src: "MITRE T1556.006" },
  ],

  edges: [
    { f: "mfa_system", t: "disable_mfa" },
    { f: "mfa_system", t: "mod_mfa_code" },
    { f: "mfa_system", t: "register_device" },
    { f: "disable_mfa", t: "ev_detect" },
    { f: "mod_mfa_code", t: "ev_detect" },
    { f: "register_device", t: "ev_detect" },
    { f: "ev_detect", t: "bypass" },
  ],
};

export default model;
