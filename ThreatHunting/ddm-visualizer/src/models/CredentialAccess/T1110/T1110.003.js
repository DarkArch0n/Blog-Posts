// T1110.003 — Password Spraying — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1110.003",
    name: "Password Spraying",
    tactic: "Credential Access",
    platform: "Windows, Linux, Cloud",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 520,
    columns: [
      { label: "RECON",       x: 70  },
      { label: "SPRAY TOOL",  x: 240 },
      { label: "AUTH TARGET", x: 430 },
      { label: "DETECTION",   x: 640 },
      { label: "OUTCOME",     x: 880 },
    ],
    separators: [155, 335, 535, 760],
    annotations: [
      { text: "1 password × N users — evades per-account lockout", x: 240, y: 460, color: "#c62828", fontStyle: "italic" },
      { text: "Correlate: many accounts failing with same password", x: 640, y: 430, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "user_list", label: "User List", sub: "All domain users", x: 70, y: 170, r: 38, type: "source",
      tags: ["net user /domain", "LDAP query", "OWA enumeration", "LinkedIn scrape"],
      telemetry: [],
      api: "net user /domain · LDAP (Get-ADUser) · O365 user enumeration · OSINT",
      artifact: "Full domain user list via LDAP or O365 enumeration",
      desc: "Password spraying requires a comprehensive user list. Sources: 'net user /domain', Get-ADUser (LDAP), OWA/O365 username enumeration (timing-based), OSINT (LinkedIn employee list → derive email format). Larger user lists increase probability of finding weak passwords.",
      src: "MITRE ATT&CK T1110.003" },

    { id: "password", label: "Common Pwd", sub: "1 password", x: 70, y: 370, r: 34, type: "source",
      tags: ["Season+Year", "Company+2024!", "Welcome1!", "Password1!"],
      telemetry: [],
      api: "Single high-probability password tested against all users: Company2024!, Fall2024!",
      artifact: "One password per spray round · wait between rounds to avoid lockout",
      desc: "Key differentiator from brute force: spray tests ONE password against MANY accounts per round, then waits before trying the next password. Evades per-account lockout thresholds (e.g., 5 attempts). Common passwords: Season+Year!, Company+Year!, Welcome1!, Password1!, Changeme1!",
      src: "MITRE T1110.003; US-CERT AA18-009A" },

    { id: "spray_tool", label: "Spray Tools", sub: "Automated", x: 240, y: 130, r: 36, type: "source",
      tags: ["Spray", "DomainPasswordSpray", "Ruler", "MailSniper"],
      telemetry: ["4625"],
      api: "DomainPasswordSpray (PowerShell) · Spray.sh · Ruler · MailSniper · kerbrute",
      artifact: "Sysmon EID 1: PowerShell with DomainPasswordSpray · rapid auth attempts",
      desc: "DomainPasswordSpray.ps1 performs LDAP-based spraying within a domain. kerbrute sprays via Kerberos pre-auth (no logon failure events if user doesn't exist). Ruler and MailSniper target Exchange/OWA. Spray.sh targets SMB/LDAP. All implement inter-round delays to avoid lockout.",
      src: "dafthack/DomainPasswordSpray; ropnop/kerbrute; sensepost/ruler" },

    { id: "cloud_spray", label: "Cloud Spray", sub: "AAD/O365", x: 240, y: 310, r: 36, type: "source",
      tags: ["MSOLSpray", "CredMaster", "Fireprox", "IP rotation"],
      telemetry: ["Azure AD logs"],
      api: "MSOLSpray against login.microsoftonline.com · CredMaster with IP rotation via API gateway",
      artifact: "Azure AD Sign-in logs: numerous failures · risk event: password spray detected",
      desc: "Cloud-focused spray tools target Azure AD/O365 endpoints. MSOLSpray uses autodiscover endpoint. CredMaster rotates source IPs via AWS API Gateway (Fireprox) to evade IP-based rate limiting. Azure AD Identity Protection may flag the spray as a risk event.",
      src: "dafthack/MSOLSpray; ustayready/CredMaster; MITRE T1110.003" },

    { id: "kerberos_spray", label: "kerbrute", sub: "Kerberos AS-REQ", x: 240, y: 460, r: 34, type: "source",
      tags: ["kerbrute", "AS-REQ pre-auth", "No 4625 for invalid users"],
      telemetry: ["4768", "4771"],
      api: "kerbrute passwordspray --dc <DC> -d corp.local users.txt 'Password1!'",
      artifact: "Event 4771 (pre-auth failure) · no 4625 · no lockout contribution if user invalid",
      desc: "kerbrute sprays via Kerberos AS-REQ pre-authentication. Advantages: faster than LDAP/SMB, no 4625 events (only 4771), and invalid usernames don't generate failures — also enables user enumeration. Generates Event 4768 on success, 4771 on failure.",
      src: "ropnop/kerbrute; MITRE T1110.003" },

    { id: "auth_svc", label: "Domain Controller", sub: "KDC/NTLM", x: 430, y: 260, r: 40, type: "source",
      tags: ["KDC", "NTLM auth", "Azure AD", "Authentication processing"],
      telemetry: ["4625", "4771", "4768"],
      api: "DC processes Kerberos pre-auth or NTLM authentication for each spray attempt",
      artifact: "Event 4625/4771 for each failure · 4624/4768 for success",
      desc: "The Domain Controller (or Azure AD) processes each spray attempt. Kerberos spray → Event 4771 (pre-auth failure). NTLM spray → Event 4625 (logon failure). Success → Event 4624/4768. Each failure is logged with source IP, target account, and failure reason.",
      src: "Microsoft Event ID documentation" },

    { id: "ev_detect", label: "Spray Pattern", sub: "1-pwd-N-users", x: 640, y: 260, r: 50, type: "detect",
      tags: ["4625 from 1 IP to N accounts", "4771 burst", "Smart Lockout", "MDI spray alert"],
      telemetry: ["4625", "4771", "4768"],
      api: "Detect pattern: single source IP → 4625/4771 for many distinct accounts in short window",
      artifact: "OPTIMAL: N accounts × 4625 from 1 IP in X minutes · Azure Smart Lockout · MDI alert",
      desc: "OPTIMAL DETECTION NODE. Spray detection requires CORRELATION across accounts: (1) Single source IP generating 4625/4771 for MANY different accounts in a time window. (2) All failures share the same failure reason (bad password, not account issues). (3) Azure AD Smart Lockout + Identity Protection detects spray patterns. (4) Microsoft Defender for Identity (MDI) has built-in password spray detection. (5) PREVENTION: MFA defeats sprayed passwords; Azure AD Password Protection blocks common passwords.",
      src: "MITRE T1110.003; Azure AD Smart Lockout; MDI; US-CERT AA18-009A" },

    { id: "success", label: "Valid Account", sub: "Compromised", x: 880, y: 180, r: 38, type: "source",
      tags: ["4624 after spray", "Compromised account", "Initial access"],
      telemetry: ["4624"],
      api: "One or more accounts found with the sprayed password — valid credentials",
      artifact: "Event 4624 (success) from spray source IP · same password worked on weak accounts",
      desc: "In a large organization, password spraying often succeeds against at least one account per common password. That single success provides valid domain credentials for initial access. Key indicator: Event 4624 from the same IP that generated the spray pattern.",
      src: "MITRE T1110.003" },

    { id: "no_mfa", label: "MFA Bypass", sub: "Legacy auth", x: 880, y: 360, r: 34, type: "source",
      tags: ["Legacy protocols", "IMAP/POP3", "No MFA enforcement"],
      telemetry: [],
      api: "Sprayed creds used via legacy protocols (IMAP, SMTP, POP3) that bypass MFA",
      artifact: "Authentication via legacy protocol · MFA not triggered",
      desc: "Even with MFA, sprayed credentials may work via legacy authentication protocols (IMAP, POP3, SMTP, ActiveSync) that don't support MFA. Azure AD Conditional Access should block legacy authentication. Many spraying campaigns specifically target these protocols.",
      src: "MITRE T1110.003; Microsoft legacy auth blocking" },
  ],

  edges: [
    { f: "user_list", t: "spray_tool" },
    { f: "user_list", t: "cloud_spray" },
    { f: "user_list", t: "kerberos_spray" },
    { f: "password", t: "spray_tool" },
    { f: "password", t: "cloud_spray" },
    { f: "password", t: "kerberos_spray" },
    { f: "spray_tool", t: "auth_svc" },
    { f: "cloud_spray", t: "auth_svc" },
    { f: "kerberos_spray", t: "auth_svc" },
    { f: "auth_svc", t: "ev_detect" },
    { f: "ev_detect", t: "success" },
    { f: "ev_detect", t: "no_mfa" },
  ],
};

export default model;
