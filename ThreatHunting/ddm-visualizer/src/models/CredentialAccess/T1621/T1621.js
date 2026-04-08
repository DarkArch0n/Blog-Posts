// T1621 — Multi-Factor Authentication Request Generation — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1621",
    name: "Multi-Factor Authentication Request Generation",
    tactic: "Credential Access",
    platform: "Windows, Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 420,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "FATIGUE ATTACK",x: 270},
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
    annotations: [
      { text: "Number matching defeats MFA fatigue", x: 480, y: 360, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "valid_creds", label: "Valid Creds", sub: "Password known", x: 80, y: 200, r: 40, type: "source",
      tags: ["Stolen password", "Phished creds", "Sprayed password", "Stuffed creds"],
      telemetry: [],
      api: "Attacker has valid username + password but is blocked by MFA",
      artifact: "Previously obtained credentials via phishing, spraying, stuffing, or breach data",
      desc: "MFA fatigue/bombing requires the attacker to already have the victim's username and password (obtained via phishing, password spraying, credential stuffing, or breach data). The attacker can authenticate successfully but is blocked by the MFA requirement.",
      src: "MITRE ATT&CK T1621; Lapsus$ attack on Uber (2022)" },

    { id: "bomb", label: "MFA Bombing", sub: "Repeated push", x: 270, y: 120, r: 38, type: "source",
      tags: ["Push spam", "Repeated login attempts", "Night/early morning"],
      telemetry: ["Azure AD logs"],
      api: "Repeatedly initiate login → trigger push notification flood → user approves to stop annoyance",
      artifact: "Multiple MFA push denials followed by single approval · off-hours timing",
      desc: "Attacker repeatedly initiates authentication (triggering push MFA each time) hoping the user will eventually approve to stop the notification flood. Often done at night or early morning when users are likely to approve without thinking. Uber breach (2022): Lapsus$ used social engineering + MFA bombing.",
      src: "MITRE T1621; Uber breach analysis (2022); Cisco breach (2022)" },

    { id: "social_eng", label: "Social Engineer", sub: "IT impersonation", x: 270, y: 300, r: 36, type: "source",
      tags: ["IT helpdesk call", "SMS/WhatsApp", "Approve to fix issue"],
      telemetry: [],
      api: "Attacker contacts victim by phone/chat claiming to be IT — 'approve the MFA prompt to fix your account'",
      artifact: "Phone/message to victim · impersonation of IT staff · combined with push timing",
      desc: "More sophisticated variant: attacker contacts the victim via phone, SMS, or messaging, impersonating IT support. 'We're seeing issues with your account, approve the MFA prompt to verify it's working.' Victim approves the attacker's MFA prompt. Used in Uber (2022) and Cisco (2022) breaches.",
      src: "MITRE T1621; Uber breach; Cisco Yanluowang breach" },

    { id: "ev_detect", label: "MFA Denials", sub: "Pattern Alert", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Multiple MFA denials", "Approval after denials", "Azure AD risky sign-in", "Number matching"],
      telemetry: ["Azure AD logs"],
      api: "Alert on N+ MFA denials followed by approval · Azure AD risky sign-in detection",
      artifact: "OPTIMAL: Pattern: N MFA denials then 1 approval · Azure AD risk event · off-hours auth",
      desc: "OPTIMAL DETECTION NODE. (1) Pattern detection: multiple MFA denials (user hitting 'Deny') followed by a single approval — classic fatigue pattern. (2) Azure AD Identity Protection: 'anomalous token' and 'MFA fraud' risk events. (3) Off-hours timing: MFA prompts outside normal working hours. (4) PREVENTION: Number matching (user must enter code shown on login screen, not just approve). Report suspicious activity button in Authenticator app. Disable push MFA for high-privilege accounts — use FIDO2.",
      src: "MITRE T1621; Microsoft Number Matching; Azure AD Identity Protection" },

    { id: "approved", label: "MFA Approved", sub: "User fatigued", x: 730, y: 130, r: 38, type: "source",
      tags: ["Approved by user", "Full auth complete", "Session token issued"],
      telemetry: ["Azure AD logs"],
      api: "User approves MFA prompt → attacker receives authenticated session",
      artifact: "Event: MFA satisfied · session token issued · attacker has full access",
      desc: "Once the user approves the MFA prompt (whether through fatigue or social engineering), the attacker's authentication completes. A session token is issued. The attacker now has full authenticated access to the account. From here: email access, lateral movement, persistence.",
      src: "MITRE T1621" },

    { id: "persist", label: "Persistence", sub: "Add MFA device", x: 730, y: 300, r: 36, type: "source",
      tags: ["Register new MFA", "Add phone number", "Maintain access"],
      telemetry: ["Azure AD audit logs"],
      api: "Attacker registers their own MFA device → persistent MFA-authenticated access",
      artifact: "New MFA method registered · new device enrolled · audit log entry",
      desc: "After gaining access, the attacker registers their own MFA device (phone number, authenticator app, or FIDO2 key) on the compromised account. This provides persistent MFA-authenticated access even if the user's password changes. Always investigate new MFA registrations after suspicious activity.",
      src: "MITRE T1621; T1098.005" },
  ],

  edges: [
    { f: "valid_creds", t: "bomb" },
    { f: "valid_creds", t: "social_eng" },
    { f: "bomb", t: "ev_detect" },
    { f: "social_eng", t: "ev_detect" },
    { f: "ev_detect", t: "approved" },
    { f: "approved", t: "persist" },
  ],
};

export default model;
