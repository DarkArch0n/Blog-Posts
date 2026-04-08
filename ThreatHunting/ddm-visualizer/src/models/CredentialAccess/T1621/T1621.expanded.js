// T1621 — Multi-Factor Authentication Request Generation — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "Credential Access", platform: "Azure AD, Okta, Duo", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 340, rows: [{ label: "MFA BOMBING", y: 80 }, { label: "SOCIAL ENG", y: 200 }, { label: "DETECTION", y: 280 }] },
  nodes: [
    { id: "valid_creds", label: "Valid Credentials", sub: "Password known", x: 60, y: 130, r: 38, type: "entry", desc: "Adversary has valid username + password (from phishing, breach, spray) but blocked by MFA.", src: "MITRE ATT&CK T1621" },
    { id: "repeated_push", label: "Repeated Push", sub: "MFA bombing", x: 240, y: 80, r: 38, type: "op", desc: "Repeatedly initiate login to trigger MFA push notifications. User approves from fatigue or confusion.", src: "MITRE T1621; Lapsus$" },
    { id: "auth_api", label: "Auth API", sub: "/authorize endpoint", x: 440, y: 80, r: 32, type: "api", desc: "Automate login attempts via OAuth /authorize or direct authentication API.", src: "Azure AD; Okta API" },
    { id: "push_notif", label: "Push Notification", sub: "Approve/Deny", x: 640, y: 80, r: 34, type: "protocol", desc: "MFA push sent to authenticator app. Simple approve/deny with no context.", src: "Microsoft Authenticator; Duo" },
    { id: "social_eng", label: "Social Engineering", sub: "IT helpdesk call", x: 240, y: 200, r: 36, type: "op", desc: "Call target pretending to be IT: 'You'll see a prompt, please approve it for a security update.'", src: "MITRE T1621; Lapsus$" },
    { id: "night_timing", label: "Night/Weekend", sub: "Off-hours push", x: 440, y: 200, r: 32, type: "op", desc: "Send pushes during off-hours when user is groggy or wants to stop the notifications.", src: "Lapsus$ TTPs" },
    { id: "number_match", label: "Number Matching", sub: "Phishing-resistant", x: 440, y: 280, r: 34, type: "system", desc: "MITIGATION: Number matching requires user to enter number shown on login screen. Blocks blind approval.", src: "Microsoft; Duo; Okta" },
    { id: "push_deny_log", label: "Push Deny Log", sub: "Multiple denials", x: 640, y: 200, r: 38, type: "detect", desc: "OPTIMAL: Alert on 3+ MFA denials followed by approval within short window.", src: "Azure AD Sign-in; Duo Admin" },
    { id: "anomalous_auth", label: "Auth Anomaly", sub: "Rate/geo/time", x: 640, y: 280, r: 36, type: "detect", desc: "Anomalous authentication patterns: rapid repeated attempts, unusual source IP, off-hours.", src: "UEBA; Azure AD" },
    { id: "mfa_bypass", label: "MFA Bypass", sub: "Full session", x: 860, y: 130, r: 40, type: "artifact", desc: "User approves push → attacker receives authenticated session. Full access achieved.", src: "MITRE T1621" },
  ],
  edges: [
    { f: "valid_creds", t: "repeated_push" }, { f: "valid_creds", t: "social_eng" },
    { f: "repeated_push", t: "auth_api" }, { f: "auth_api", t: "push_notif" },
    { f: "social_eng", t: "night_timing" }, { f: "night_timing", t: "push_notif" },
    { f: "push_notif", t: "mfa_bypass" },
    { f: "push_notif", t: "number_match" },
    { f: "repeated_push", t: "push_deny_log" }, { f: "auth_api", t: "anomalous_auth" },
  ],
};
export default model;
