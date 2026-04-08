// T1111 — Multi-Factor Authentication Interception — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1111",
    name: "Multi-Factor Authentication Interception",
    tactic: "Credential Access",
    platform: "Windows, Linux",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "MFA TYPE",    x: 80  },
      { label: "INTERCEPT",   x: 260 },
      { label: "DETECTION",   x: 470 },
      { label: "BYPASS",      x: 680 },
      { label: "OUTCOME",     x: 880 },
    ],
    separators: [170, 365, 575, 780],
    annotations: [
      { text: "Hardware FIDO2 keys resist most interception", x: 680, y: 400, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "smartcard", label: "Smart Card", sub: "PIV/CAC", x: 80, y: 120, r: 34, type: "source",
      tags: ["Smart card", "PIV", "CAC", "PKCS#11"],
      telemetry: [],
      api: "Physical smart card with X.509 certificate for authentication",
      artifact: "Smart card reader device · certificate-based auth flow",
      desc: "Smart cards (PIV/CAC) use X.509 certificates stored on a physical card. Require a PIN to unlock. Interceptable via keylogger capturing the PIN + physical card theft, or via driver-level hooks that intercept the signing operation.",
      src: "MITRE ATT&CK T1111" },

    { id: "otp_token", label: "OTP Token", sub: "RSA SecurID", x: 80, y: 260, r: 34, type: "source",
      tags: ["RSA SecurID", "TOTP/HOTP", "Hardware token"],
      telemetry: [],
      api: "One-time password tokens: hardware (RSA SecurID) or software (Google Authenticator)",
      artifact: "OTP value displayed on token or software app · time-based validity",
      desc: "Hardware OTP tokens (RSA SecurID) or software TOTP apps generate time-based codes. Interceptable via: real-time phishing proxy (Evilginx2/Modlishka), keylogger capturing the OTP, or seed theft from the MFA server (RSA breach 2011).",
      src: "MITRE T1111; RSA SecurID breach (2011)" },

    { id: "push_mfa", label: "Push MFA", sub: "Authenticator", x: 80, y: 400, r: 34, type: "source",
      tags: ["MS Authenticator", "Duo push", "Push notification"],
      telemetry: [],
      api: "Push notification MFA: user approves via phone app",
      artifact: "Push approval flow · can be bypassed via MFA fatigue/bombing",
      desc: "Push-based MFA sends an approval request to the user's phone. Vulnerable to MFA fatigue/bombing: attacker repeatedly triggers push notifications until the user approves to stop the alerts. Microsoft now requires number matching to mitigate this.",
      src: "MITRE T1111; Lapsus$ MFA bombing" },

    { id: "phish_proxy", label: "Phishing Proxy", sub: "Evilginx2", x: 260, y: 130, r: 38, type: "source",
      tags: ["Evilginx2", "Modlishka", "Muraena", "Reverse proxy phishing"],
      telemetry: [],
      api: "Evilginx2 acts as reverse proxy to real login page — captures credentials + MFA token + session cookie",
      artifact: "Phishing domain proxying to real auth endpoint · session token captured in real-time",
      desc: "Evilginx2, Modlishka, and Muraena act as reverse proxies to the real authentication page. User sees legitimate login page through the proxy. The proxy captures: username, password, MFA code/approval, AND the resulting session cookie. Bypasses any MFA method that doesn't verify the origin (only FIDO2 resists).",
      src: "kgretzky/evilginx2; drk1wi/Modlishka; MITRE T1111" },

    { id: "keylog", label: "Keylogger", sub: "Capture OTP", x: 260, y: 310, r: 36, type: "source",
      tags: ["Keylogger", "PIN capture", "OTP capture", "Screen capture"],
      telemetry: ["Sysmon 1"],
      api: "Keylogger captures MFA PIN/OTP as typed · screen capture for push approval",
      artifact: "Keylogger process · captured OTP codes · real-time exfiltration needed",
      desc: "A keylogger (T1056.001) on the victim's system captures MFA credentials as they are typed: smart card PINs, OTP codes, or passwords. The captured MFA code must be used within its validity window (typically 30-60 seconds), requiring real-time exfiltration.",
      src: "MITRE T1111; T1056.001" },

    { id: "ev_detect", label: "Phish + Anomaly", sub: "Multi-signal", x: 470, y: 230, r: 50, type: "detect",
      tags: ["Phishing domain detection", "Anomalous login location", "MFA fatigue alerts", "Token replay"],
      telemetry: ["Azure AD logs"],
      api: "Phishing domain detection + anomalous login geo + MFA fatigue pattern + session anomaly",
      artifact: "OPTIMAL: Phishing domain alerts · impossible travel after MFA · MFA fatigue (many denials) · token reuse",
      desc: "OPTIMAL DETECTION NODE. (1) Phishing domain detection: typosquatting, newly registered domains proxying to real login pages. (2) Post-MFA-bypass: impossible travel (login from unusual geo after MFA completion). (3) MFA fatigue: many denied push notifications followed by an approval. (4) Session token replay: same token used from different IPs. (5) PREVENTION: FIDO2 hardware keys are phishing-resistant — origin binding prevents proxy attacks.",
      src: "MITRE T1111; Azure AD Conditional Access; FIDO2 specification" },

    { id: "session", label: "Session Token", sub: "Captured", x: 680, y: 230, r: 38, type: "source",
      tags: ["Session cookie", "Bearer token", "Post-MFA session"],
      telemetry: [],
      api: "Captured authenticated session token — bypasses MFA for session duration",
      artifact: "Valid session cookie/token usable until expiry · no re-authentication needed",
      desc: "The captured session token (cookie or bearer token) allows the attacker to access the account without re-authenticating through MFA. Token remains valid until expiry (often hours to days). This is the primary value of phishing proxy attacks — the session, not just the password.",
      src: "MITRE T1111; T1539" },

    { id: "access", label: "Account Access", sub: "MFA bypassed", x: 880, y: 230, r: 38, type: "source",
      tags: ["Full account access", "MFA bypassed", "Post-auth session"],
      telemetry: ["Azure AD logs"],
      api: "Full authenticated access to the account — MFA has been bypassed",
      artifact: "Account access from attacker infrastructure · data exfiltration · persistence setup",
      desc: "Attacker has full authenticated access with the captured session. Can read email, access cloud storage, modify settings (set up persistence via OAuth app consent, email forwarding rules, or adding additional MFA devices for persistent access).",
      src: "MITRE T1111" },
  ],

  edges: [
    { f: "smartcard", t: "keylog" },
    { f: "otp_token", t: "phish_proxy" },
    { f: "otp_token", t: "keylog" },
    { f: "push_mfa", t: "phish_proxy" },
    { f: "phish_proxy", t: "ev_detect" },
    { f: "keylog", t: "ev_detect" },
    { f: "phish_proxy", t: "session" },
    { f: "ev_detect", t: "session" },
    { f: "session", t: "access" },
  ],
};

export default model;
