// T1110.004 — Credential Stuffing — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1110.004",
    name: "Credential Stuffing",
    tactic: "Credential Access",
    platform: "Windows, Linux, Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "CREDENTIAL SRC", x: 70  },
      { label: "PREPARATION",    x: 250 },
      { label: "TARGET AUTH",    x: 440 },
      { label: "DETECTION",      x: 650 },
      { label: "OUTCOME",        x: 880 },
    ],
    separators: [160, 345, 545, 765],
    annotations: [
      { text: "Leverages password reuse across services", x: 250, y: 400, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "breach_db", label: "Breach Data", sub: "Leaked creds", x: 70, y: 150, r: 38, type: "source",
      tags: ["Breached databases", "Dark web", "Combo lists", "Collection #1-5"],
      telemetry: [],
      api: "Leaked credential databases from prior breaches — username:password pairs",
      artifact: "Combo lists from dark web · millions of email:password pairs",
      desc: "Credential stuffing uses username:password pairs from prior data breaches (LinkedIn, Adobe, Collection #1-5, etc.). These combo lists contain billions of credentials. Attacker obtains them from dark web markets, paste sites, or public dumps. The attack relies on password reuse — users using the same password across multiple services.",
      src: "MITRE ATT&CK T1110.004; haveibeenpwned.com" },

    { id: "cracked", label: "Cracked Hashes", sub: "From target env", x: 70, y: 340, r: 34, type: "source",
      tags: ["Previously cracked", "From SAM/NTDS", "Internal → external reuse"],
      telemetry: [],
      api: "Passwords cracked from target environment hashes — tried against other services",
      artifact: "Previously cracked passwords from T1110.002 tried against additional targets",
      desc: "Passwords cracked from the target environment (SAM, NTDS.dit, Kerberoasting) are tried against additional services where users may reuse passwords. Internal password → tried against VPN, cloud, SaaS. Cross-service credential reuse is extremely common.",
      src: "MITRE T1110.004" },

    { id: "prep", label: "Pair Matching", sub: "Email → domain", x: 250, y: 230, r: 36, type: "source",
      tags: ["Email format matching", "user@target.com filter", "Dedup"],
      telemetry: [],
      api: "Filter breach data for target domain emails · match formats (first.last, flast)",
      artifact: "Targeted credential pairs for the victim organization",
      desc: "Attacker filters breach data for the target organization's email domain (user@target.com) or derives usernames from email formats. De-duplicates and prioritizes recent breaches. Some tools automatically match emails to the target authentication endpoint.",
      src: "MITRE T1110.004" },

    { id: "stuff_tool", label: "Stuffing Tool", sub: "Automated", x: 440, y: 140, r: 36, type: "source",
      tags: ["SentryMBA", "OpenBullet", "Custom scripts", "Selenium"],
      telemetry: [],
      api: "SentryMBA, OpenBullet, STORM, or custom Python scripts with proxy rotation",
      artifact: "High-volume auth attempts · distributed via proxy/botnet · rotating IPs",
      desc: "Specialized credential stuffing tools (SentryMBA, OpenBullet, STORM) automate high-volume authentication attempts with proxy rotation, CAPTCHA solving, and user-agent randomization. Distribute attempts across thousands of IPs to evade rate limiting.",
      src: "OWASP Credential Stuffing; MITRE T1110.004" },

    { id: "cloud_auth", label: "Auth Endpoint", sub: "Login page", x: 440, y: 330, r: 36, type: "source",
      tags: ["O365 login", "VPN portal", "Web application", "SSO"],
      telemetry: ["Azure AD logs", "Application logs"],
      api: "login.microsoftonline.com · VPN portal · web app login · ADFS · Okta · SSO",
      artifact: "Auth endpoint logs: failed attempts, geo-anomalies, user-agent diversity",
      desc: "Stuffing targets any authentication endpoint: Azure AD/O365, corporate VPN, web applications, Okta/SSO, email services. Cloud endpoints are popular targets due to internet accessibility. Each endpoint may have different rate limiting and detection capabilities.",
      src: "MITRE T1110.004" },

    { id: "ev_detect", label: "Anomaly + Rate", sub: "Multi-signal", x: 650, y: 230, r: 50, type: "detect",
      tags: ["Impossible travel", "High failure rate", "Distributed IPs", "Known breach creds"],
      telemetry: ["4625", "Azure AD logs"],
      api: "Anomaly detection: distributed failures, impossible travel, known-breached credential alerts",
      artifact: "OPTIMAL: High failure ratio · distributed source IPs · impossible travel · breached cred alerts",
      desc: "OPTIMAL DETECTION NODE. (1) High authentication failure ratio across many accounts. (2) Distributed source IPs (proxy/botnet) — unlike spray which often uses 1 IP. (3) Azure AD Identity Protection: leaked credentials risk detection (checks passwords against known breaches). (4) Impossible travel: successful auth from geographic anomaly. (5) User-agent anomalies: non-browser UAs on web endpoints. (6) PREVENTION: MFA, Azure AD Password Protection, credential monitoring (haveibeenpwned API integration).",
      src: "MITRE T1110.004; Azure AD Identity Protection; OWASP" },

    { id: "reuse_hit", label: "Account Hit", sub: "Password reused", x: 880, y: 160, r: 38, type: "source",
      tags: ["Password reuse confirmed", "Valid credentials", "Account takeover"],
      telemetry: ["4624"],
      api: "Breached credential matched current password — valid authentication",
      artifact: "Successful auth with breached credential · account compromise",
      desc: "When a user has reused a password from a breached service, the stuffed credential works. Attacker gains authenticated access to the target service. This confirms the password reuse — attacker now has valid credentials for the corporate environment.",
      src: "MITRE T1110.004" },

    { id: "ato", label: "Account Takeover", sub: "Full access", x: 880, y: 330, r: 36, type: "source",
      tags: ["Email access", "Data exfil", "Persistence", "BEC"],
      telemetry: [],
      api: "Full account access → email reading, data exfiltration, business email compromise",
      artifact: "Mailbox access · inbox rule changes · data download · lateral movement",
      desc: "Successful credential stuffing enables full account takeover: read/send email (BEC), access cloud storage (OneDrive, SharePoint), modify account settings (forward email, add MFA device), or use the valid credential for lateral movement into internal networks via VPN.",
      src: "MITRE T1110.004; FBI IC3 BEC reports" },
  ],

  edges: [
    { f: "breach_db", t: "prep" },
    { f: "cracked", t: "prep" },
    { f: "prep", t: "stuff_tool" },
    { f: "prep", t: "cloud_auth" },
    { f: "stuff_tool", t: "cloud_auth" },
    { f: "cloud_auth", t: "ev_detect" },
    { f: "ev_detect", t: "reuse_hit" },
    { f: "reuse_hit", t: "ato" },
  ],
};

export default model;
