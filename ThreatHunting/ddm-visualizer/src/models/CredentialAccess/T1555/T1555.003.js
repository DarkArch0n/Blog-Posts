// T1555.003 — Credentials from Web Browsers — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.003",
    name: "Credentials from Web Browsers",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 520,
    columns: [
      { label: "BROWSER DATA", x: 70  },
      { label: "EXTRACTION",   x: 250 },
      { label: "DECRYPTION",   x: 440 },
      { label: "DETECTION",    x: 640 },
      { label: "OUTCOME",      x: 880 },
    ],
    separators: [160, 345, 540, 760],
    annotations: [
      { text: "DPAPI key required for Chrome/Edge on Windows", x: 440, y: 440, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "chrome_db", label: "Chrome", sub: "Login Data DB", x: 70, y: 120, r: 34, type: "source",
      tags: ["Login Data SQLite", "Local State (key)", "DPAPI encrypted"],
      telemetry: [],
      api: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data (SQLite)",
      artifact: "SQLite DB with origin_url, username_value, password_value (AES-GCM encrypted)",
      desc: "Chrome stores saved passwords in a SQLite database 'Login Data'. Passwords are encrypted with AES-256-GCM using a key stored in 'Local State' file, which itself is protected by Windows DPAPI. On macOS, the key is stored in macOS Keychain.",
      src: "MITRE T1555.003; Chrome credential storage" },

    { id: "firefox_db", label: "Firefox", sub: "logins.json", x: 70, y: 260, r: 34, type: "source",
      tags: ["logins.json", "key4.db", "NSS PK11", "Optional master password"],
      telemetry: [],
      api: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\logins.json + key4.db",
      artifact: "logins.json (encrypted credentials) + key4.db (NSS key store)",
      desc: "Firefox stores passwords in logins.json, encrypted using NSS (Network Security Services) with keys from key4.db. If a master password is set, the keys are additionally encrypted. Without a master password, any process running as the user can decrypt the passwords.",
      src: "MITRE T1555.003; Firefox credential storage" },

    { id: "edge_db", label: "Edge/Brave", sub: "Chromium-based", x: 70, y: 400, r: 34, type: "source",
      tags: ["Edge Login Data", "Brave Login Data", "Same as Chrome", "DPAPI"],
      telemetry: [],
      api: "Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
      artifact: "Same SQLite + AES-GCM + DPAPI structure as Chrome",
      desc: "All Chromium-based browsers (Edge, Brave, Opera, Vivaldi) use the same credential storage format as Chrome. Same extraction and decryption tools work across all Chromium browsers. Only the profile directory path differs.",
      src: "MITRE T1555.003" },

    { id: "sharp_chrome", label: "SharpChromium", sub: ".NET extraction", x: 250, y: 120, r: 36, type: "source",
      tags: ["SharpChromium", "SharpWeb", "C# tool", "In-memory"],
      telemetry: ["Sysmon 1"],
      api: "SharpChromium.exe logins · SharpWeb.exe all — .NET credential extraction tools",
      artifact: "Sysmon EID 1: SharpChromium/SharpWeb process · DPAPI usage",
      desc: "SharpChromium and SharpWeb are C# tools that extract Chrome/Edge saved passwords in-memory. They read the Login Data SQLite database, extract the AES key from Local State, decrypt via DPAPI, and output plaintext credentials. Popular in C2 frameworks (Cobalt Strike, Sliver).",
      src: "djhohnstein/SharpChromium; djhohnstein/SharpWeb" },

    { id: "lazagne", label: "LaZagne", sub: "Multi-browser", x: 250, y: 260, r: 36, type: "source",
      tags: ["LaZagne", "Python", "All browsers", "All credential stores"],
      telemetry: ["Sysmon 1"],
      api: "lazagne.exe browsers — extracts credentials from all installed browsers",
      artifact: "Sysmon EID 1: lazagne process · accesses multiple browser profile dirs",
      desc: "LaZagne is an open-source Python/compiled tool that extracts credentials from multiple browsers (Chrome, Firefox, Edge, Opera, IE), as well as other stores (WiFi, mail clients, databases, sysadmin tools). One-stop credential harvesting tool.",
      src: "AlessandroZ/LaZagne; MITRE T1555.003" },

    { id: "infostealer", label: "Infostealer", sub: "Malware", x: 250, y: 400, r: 34, type: "source",
      tags: ["Raccoon", "RedLine", "Vidar", "Lumma"],
      telemetry: ["Sysmon 1", "Sysmon 3"],
      api: "Commercial infostealers extract browser creds + cookies + crypto wallets → exfil to C2",
      artifact: "Sysmon: stealer process · browser DB file access · C2 connection",
      desc: "Infostealer malware (Raccoon, RedLine, Vidar, Lumma) is commercially available on dark web. Automatically extracts browser passwords, cookies, autofill data, crypto wallet keys, and session tokens. Exfiltrates to C2 server. Distributed via phishing, fake software, or exploit kits.",
      src: "MITRE T1555.003; Threat intel analyses" },

    { id: "dpapi_decrypt", label: "DPAPI Decrypt", sub: "Key extraction", x: 440, y: 200, r: 38, type: "source",
      tags: ["DPAPI", "CryptUnprotectData", "User master key"],
      telemetry: ["Sysmon 1"],
      api: "CryptUnprotectData() or Mimikatz dpapi::chrome · requires user context",
      artifact: "DPAPI master key usage · CryptUnprotectData calls from non-browser process",
      desc: "Chrome/Edge passwords on Windows require DPAPI decryption. The AES key from Local State is decrypted via CryptUnprotectData(), which requires running in the target user's context. Mimikatz dpapi::chrome automates this. Running as SYSTEM with the DPAPI backup key can decrypt any user's data.",
      src: "MITRE T1555.003; Windows DPAPI; Mimikatz dpapi" },

    { id: "nss_decrypt", label: "NSS Decrypt", sub: "Firefox keys", x: 440, y: 380, r: 34, type: "source",
      tags: ["NSS PK11SDR_Decrypt", "key4.db", "No master password = trivial"],
      telemetry: [],
      api: "NSS PK11SDR_Decrypt() with key4.db — trivial if no master password set",
      artifact: "NSS library usage by non-Firefox process · key4.db file access",
      desc: "Firefox credentials are decrypted via NSS PK11SDR_Decrypt(). If no master password is set (default), decryption is trivial — just requires the key4.db file and running as the user. Tools: firefox_decrypt.py, firepwd.py, LaZagne.",
      src: "MITRE T1555.003; NSS documentation" },

    { id: "ev_detect", label: "Browser DB", sub: "Access Monitor", x: 640, y: 270, r: 50, type: "detect",
      tags: ["Login Data access", "Non-browser process", "DPAPI from non-browser", "Sysmon 1"],
      telemetry: ["Sysmon 1", "Sysmon 11"],
      api: "Alert when non-browser processes access browser credential databases or DPAPI keys",
      artifact: "OPTIMAL: Non-browser process reading Login Data/logins.json · DPAPI usage from unknown · stealer signatures",
      desc: "OPTIMAL DETECTION NODE. (1) File access: non-browser process (not chrome.exe/firefox.exe) accessing Login Data, logins.json, key4.db, or Local State files. (2) DPAPI: CryptUnprotectData called by non-browser process. (3) Sysmon EID 1: SharpChromium, LaZagne, or known stealer process names. (4) EDR: behavioral detection for credential store access patterns. (5) PREVENTION: Browser-level password manager alternatives, enterprise password managers, credential guard.",
      src: "MITRE T1555.003; Sigma rules; EDR behavioral detection" },

    { id: "creds", label: "Credentials", sub: "All saved logins", x: 880, y: 270, r: 42, type: "source",
      tags: ["Web logins", "SSO creds", "Internal app creds", "Autofill data"],
      telemetry: [],
      api: "All saved browser credentials: URLs, usernames, plaintext passwords, autofill",
      artifact: "Plaintext passwords for all saved web logins · often includes corporate SSO · VPN · internal apps",
      desc: "Extracted browser credentials include all saved web logins with full URL, username, and plaintext password. Commonly yields: corporate SSO credentials, internal application logins, cloud service passwords, VPN credentials, personal accounts (email, banking, social media). Often the richest single source of credentials on a compromised workstation.",
      src: "MITRE T1555.003" },
  ],

  edges: [
    { f: "chrome_db", t: "sharp_chrome" },
    { f: "chrome_db", t: "lazagne" },
    { f: "chrome_db", t: "infostealer" },
    { f: "firefox_db", t: "lazagne" },
    { f: "firefox_db", t: "infostealer" },
    { f: "edge_db", t: "sharp_chrome" },
    { f: "edge_db", t: "lazagne" },
    { f: "sharp_chrome", t: "dpapi_decrypt" },
    { f: "lazagne", t: "dpapi_decrypt" },
    { f: "lazagne", t: "nss_decrypt" },
    { f: "infostealer", t: "dpapi_decrypt" },
    { f: "infostealer", t: "nss_decrypt" },
    { f: "dpapi_decrypt", t: "ev_detect" },
    { f: "nss_decrypt", t: "ev_detect" },
    { f: "ev_detect", t: "creds" },
  ],
};

export default model;
