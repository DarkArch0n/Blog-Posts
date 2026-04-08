// T1539 — Steal Web Session Cookie — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1539",
    name: "Steal Web Session Cookie",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "COOKIE SOURCE", x: 80  },
      { label: "THEFT METHOD",  x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
    annotations: [
      { text: "Session cookies bypass MFA — post-authentication", x: 270, y: 400, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "browser_db", label: "Browser DB", sub: "Cookie database", x: 80, y: 120, r: 36, type: "source",
      tags: ["Chrome Cookies DB", "Firefox cookies.sqlite", "Edge Cookies"],
      telemetry: ["Sysmon 1"],
      api: "Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies (SQLite)",
      artifact: "Sysmon EID 1: process accessing browser cookie database files",
      desc: "Browsers store cookies in SQLite databases. Chrome: Cookies DB in user profile directory (encrypted with DPAPI on Windows, Keychain on macOS). Firefox: cookies.sqlite in profile. Attacker with local access can copy and decrypt these databases to extract session cookies.",
      src: "MITRE ATT&CK T1539; Chrome cookie encryption" },

    { id: "evilginx", label: "Evilginx2", sub: "Proxy capture", x: 80, y: 260, r: 34, type: "source",
      tags: ["Evilginx2", "Reverse proxy", "Real-time capture", "Post-MFA"],
      telemetry: [],
      api: "Evilginx2 captures session cookies in real-time from phishing proxy",
      artifact: "Phishing domain proxying to real service · session cookie captured after MFA",
      desc: "Evilginx2/Modlishka reverse proxy phishing captures session cookies after the user completes full authentication (including MFA). The post-authentication session cookie is the primary target — it provides access without re-authenticating.",
      src: "kgretzky/evilginx2; MITRE T1539" },

    { id: "malware", label: "Infostealer", sub: "Cookie exfil", x: 80, y: 400, r: 34, type: "source",
      tags: ["Raccoon", "RedLine", "Vidar", "Cookie stealer"],
      telemetry: ["Sysmon 1", "Sysmon 3"],
      api: "Infostealer malware extracts browser cookies, passwords, crypto wallets, session tokens",
      artifact: "Sysmon EID 1: stealer process · EID 3: C2 exfiltration · browser DB access",
      desc: "Information stealer malware (Raccoon, RedLine, Vidar, Lumma) specifically targets browser cookie databases. Decrypts cookies using DPAPI or Keychain access, exfiltrates to C2. Often distributed via phishing, fake software, or cracked applications.",
      src: "MITRE T1539; Raccoon Stealer analysis" },

    { id: "extract", label: "Cookie Extract", sub: "Decrypt + Export", x: 270, y: 160, r: 36, type: "source",
      tags: ["DPAPI decrypt", "Chromium decrypt", "SharpChromium"],
      telemetry: ["Sysmon 1"],
      api: "SharpChromium / Mimikatz dpapi::chrome · decrypt AES-256-GCM encrypted cookies",
      artifact: "Sysmon EID 1: SharpChromium · DPAPI key access · decrypted cookie data",
      desc: "Chrome cookies on Windows are encrypted with AES-256-GCM using a key protected by DPAPI. Tools: SharpChromium (C#), Mimikatz dpapi::chrome, or custom Python scripts with pycryptodome. Requires user context or SYSTEM for DPAPI key access. Exports cookies in usable format.",
      src: "SharpChromium; Mimikatz DPAPI; MITRE T1539" },

    { id: "inject", label: "Cookie Inject", sub: "Browser import", x: 270, y: 330, r: 36, type: "source",
      tags: ["Cookie editor", "Browser dev tools", "Burp Suite", "curl --cookie"],
      telemetry: [],
      api: "Import stolen cookies into attacker's browser via extension, dev tools, or HTTP client",
      artifact: "Attacker browser with injected cookies · session access from new IP/UA",
      desc: "Attacker imports stolen cookies into their browser using cookie editor extensions, Chrome DevTools (Application → Cookies), or HTTP clients (curl, Burp Suite). The injected session cookie provides authenticated access to the victim's accounts without needing credentials or MFA.",
      src: "MITRE T1539" },

    { id: "ev_detect", label: "Session Anomaly", sub: "IP/UA change", x: 480, y: 230, r: 50, type: "detect",
      tags: ["Session IP change", "User-Agent mismatch", "Impossible travel", "Cookie DB access"],
      telemetry: ["Sysmon 1", "Web app logs"],
      api: "Detect session used from new IP/UA + browser DB access by non-browser process",
      artifact: "OPTIMAL: Session used from different IP/UA · impossible travel · non-browser cookie DB access",
      desc: "OPTIMAL DETECTION NODE. (1) Session anomaly: same session cookie used from a different IP address or User-Agent than the original authentication. (2) Impossible travel: session used from geographically distant location. (3) Sysmon: non-browser process accessing browser cookie database files. (4) PREVENTION: Token binding, Continuous Access Evaluation (CAE), short session lifetimes, device compliance policies.",
      src: "MITRE T1539; Azure AD CAE; Chrome token binding" },

    { id: "account_access", label: "Account Access", sub: "Authenticated", x: 730, y: 150, r: 38, type: "source",
      tags: ["Full web session", "Email access", "Cloud storage", "SaaS access"],
      telemetry: [],
      api: "Full authenticated access to victim's web accounts — MFA already satisfied",
      artifact: "Authenticated session in victim's accounts · data access · setting changes",
      desc: "Stolen session cookies provide full authenticated access to the victim's web accounts. Since the session is post-MFA, no additional authentication is required. Attacker can access email, cloud storage, SaaS applications, and internal web tools.",
      src: "MITRE T1539" },

    { id: "persist_sess", label: "Persistence", sub: "Refresh/extend", x: 730, y: 330, r: 36, type: "source",
      tags: ["Extend session", "Add persistence", "OAuth app consent", "Email forwarding"],
      telemetry: [],
      api: "Use session to establish persistence: OAuth consent, email forwarding, new MFA device",
      artifact: "New OAuth consent · email forwarding rule · MFA device registration",
      desc: "While the session is active, the attacker establishes persistence: register OAuth apps for token-based access, set email forwarding rules, add new MFA devices, create API keys, or modify account settings. These persist beyond the session cookie's lifetime.",
      src: "MITRE T1539; T1114.003" },
  ],

  edges: [
    { f: "browser_db", t: "extract" },
    { f: "evilginx", t: "inject" },
    { f: "malware", t: "extract" },
    { f: "extract", t: "inject" },
    { f: "extract", t: "ev_detect" },
    { f: "inject", t: "ev_detect" },
    { f: "ev_detect", t: "account_access" },
    { f: "account_access", t: "persist_sess" },
  ],
};

export default model;
