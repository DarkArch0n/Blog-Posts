// T1110.001 — Password Guessing — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1110.001",
    name: "Password Guessing",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS, Cloud",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "RECON",       x: 80  },
      { label: "GUESS METHOD", x: 260 },
      { label: "AUTH TARGET", x: 460 },
      { label: "DETECTION",   x: 670 },
      { label: "OUTCOME",     x: 880 },
    ],
    separators: [170, 360, 565, 775],
    annotations: [
      { text: "Account lockout policies limit effectiveness", x: 670, y: 410, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "user_enum", label: "User Enum", sub: "Identify targets", x: 80, y: 150, r: 36, type: "source",
      tags: ["LDAP query", "Email harvest", "LinkedIn OSINT", "Spray list"],
      telemetry: [],
      api: "LDAP enumeration, email harvest, OSINT, or AD user listing for target accounts",
      artifact: "User list gathered from LDAP, OSINT, or email format guessing",
      desc: "Attacker identifies valid usernames via LDAP queries (if authenticated), OSINT (LinkedIn, company website), email format deduction (first.last@corp.com), or user enumeration vulnerabilities. Enables targeted guessing rather than blind attempts.",
      src: "MITRE ATT&CK T1110.001" },

    { id: "context", label: "Context Clues", sub: "Password patterns", x: 80, y: 340, r: 34, type: "source",
      tags: ["Company name", "Season+year", "Welcome1!", "Common patterns"],
      telemetry: [],
      api: "Derive common password patterns: CompanyName2024!, Season+Year, Welcome1, Password1",
      artifact: "Targeted password list based on organizational patterns",
      desc: "Password guessing (vs. brute force) uses small, targeted password lists based on organizational patterns: company name + year (Corp2024!), seasons (Fall2024!), common defaults (Welcome1!, Password1!). Fewer attempts = less likely to trigger lockout.",
      src: "MITRE T1110.001; NIST SP 800-63B" },

    { id: "manual", label: "Manual Guess", sub: "Interactive", x: 260, y: 130, r: 34, type: "source",
      tags: ["Interactive logon", "RDP login", "OWA sign-in"],
      telemetry: ["4625", "4624"],
      api: "Manual interactive logon attempts via RDP, web portal, or console",
      artifact: "Event 4625 failed logon · 4624 on success · RDP brute visible in TerminalServices",
      desc: "Attacker manually tries a small number of guessed passwords via interactive login (RDP, OWA, VPN portal). Low volume — may not trigger automated detection. Target: accounts likely to have weak/default passwords (service accounts, shared mailboxes, new hires).",
      src: "MITRE T1110.001" },

    { id: "tool_guess", label: "Hydra/Medusa", sub: "Multi-protocol", x: 260, y: 280, r: 36, type: "source",
      tags: ["Hydra", "Medusa", "Ncrack", "Multi-protocol"],
      telemetry: ["4625"],
      api: "hydra -l admin -P guesses.txt rdp://<target> · medusa -u admin -P guesses.txt -M ssh",
      artifact: "Rapid successive 4625 events · source IP consistent · multi-protocol",
      desc: "Automated password guessing tools (Hydra, Medusa, Ncrack) systematically try a small password list against target accounts across protocols (SSH, RDP, SMB, HTTP, FTP). Generates failed logon events (4625) in rapid succession from a single source.",
      src: "THC Hydra; Medusa; Ncrack" },

    { id: "cloud_guess", label: "Cloud Portal", sub: "AAD/O365", x: 260, y: 420, r: 34, type: "source",
      tags: ["Azure AD", "O365", "MSOLSpray", "Legacy auth"],
      telemetry: ["Azure Sign-in logs"],
      api: "MSOLSpray against login.microsoftonline.com · legacy auth protocols (IMAP, SMTP)",
      artifact: "Azure AD Sign-in logs: failed attempts · Conditional Access blocks · risk events",
      desc: "Cloud-focused guessing targets Azure AD / O365 login endpoints. MSOLSpray, CredMaster, or Ruler test passwords against Microsoft cloud services. Legacy authentication protocols (IMAP, SMTP) may bypass MFA. Azure AD logs all attempts in sign-in logs.",
      src: "MITRE T1110.001; MSOLSpray; Microsoft Azure AD" },

    { id: "auth_svc", label: "Auth Service", sub: "DC/Server", x: 460, y: 230, r: 40, type: "source",
      tags: ["Domain Controller KDC", "SSH daemon", "Web app", "VPN gateway"],
      telemetry: ["4625", "4771"],
      api: "Authentication requests processed by DC (Kerberos/NTLM), SSH, web, or VPN service",
      artifact: "Event 4625/4771 on DC · auth.log on Linux · access.log on web · VPN logs",
      desc: "Guessed credentials are validated by the authentication service. Windows: DC processes Kerberos (4771 pre-auth failure) or NTLM (4625 logon failure). Linux: PAM logs to auth.log. Web: application login failures. Cloud: Azure AD sign-in events. Each failure generates telemetry.",
      src: "MITRE T1110.001; Microsoft Event ID reference" },

    { id: "ev_detect", label: "Failed Logons", sub: "4625/4771", x: 670, y: 230, r: 50, type: "detect",
      tags: ["Event 4625", "Event 4771", "Account lockout 4740", "Rate-based alert"],
      telemetry: ["4625", "4771", "4740"],
      api: "Monitor 4625 (NTLM fail) + 4771 (Kerberos pre-auth fail) per source IP + per account",
      artifact: "OPTIMAL: Multiple 4625/4771 per account from same IP · 4740 lockout · anomalous hours",
      desc: "OPTIMAL DETECTION NODE. (1) Event 4625 (NTLM failed logon) + Event 4771 (Kerberos pre-auth failure): alert on N+ failures per account per time window. (2) Event 4740: Account lockout — direct indicator. (3) Source IP analysis: many failures from single IP. (4) Time-of-day anomaly: guessing during off-hours. (5) Account lockout policies (N attempts → lock) limit attack but also cause DoS risk.",
      src: "MITRE T1110.001; Sigma rules; CIS benchmark" },

    { id: "access", label: "Valid Creds", sub: "Account Access", x: 880, y: 160, r: 36, type: "source",
      tags: ["Successful guess", "4624 after 4625s", "Initial access"],
      telemetry: ["4624"],
      api: "Successful authentication after guessing — Event 4624 following series of 4625",
      artifact: "Event 4624 success from same source as prior 4625 failures · compromised account",
      desc: "Successful guess yields valid credentials. Key indicator: Event 4624 (success) from the same source IP that generated prior 4625 (failure) events. Attacker now has valid domain credentials for lateral movement, data access, or privilege escalation.",
      src: "MITRE T1110.001" },

    { id: "lockout", label: "Lockout DoS", sub: "Account locked", x: 880, y: 320, r: 34, type: "source",
      tags: ["Account lockout", "Denial of service", "4740 events"],
      telemetry: ["4740"],
      api: "Too many failed guesses → account lockout policy triggers → denial of service",
      artifact: "Event 4740: account locked out · user unable to authenticate",
      desc: "Side effect: if account lockout policy is configured (common: 5 attempts, 30-min lockout), guessing may lock out legitimate users. This creates a denial-of-service condition. Attackers may intentionally lock out admin accounts during an operation.",
      src: "MITRE T1110.001; Microsoft Account Lockout Policy" },
  ],

  edges: [
    { f: "user_enum", t: "manual" },
    { f: "user_enum", t: "tool_guess" },
    { f: "user_enum", t: "cloud_guess" },
    { f: "context", t: "manual" },
    { f: "context", t: "tool_guess" },
    { f: "context", t: "cloud_guess" },
    { f: "manual", t: "auth_svc" },
    { f: "tool_guess", t: "auth_svc" },
    { f: "cloud_guess", t: "auth_svc" },
    { f: "auth_svc", t: "ev_detect" },
    { f: "ev_detect", t: "access" },
    { f: "ev_detect", t: "lockout" },
  ],
};

export default model;
