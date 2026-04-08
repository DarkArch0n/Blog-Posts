// T1555.003 — Credentials from Web Browsers — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.003",
    name: "Credentials from Web Browsers",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 480,
    rows: [
      { label: "CHROME",   y: 80 },
      { label: "FIREFOX",  y: 200 },
      { label: "EDGE",     y: 320 },
      { label: "SAFARI",   y: 420 },
    ],
  },

  nodes: [
    { id: "user_ctx", label: "User Context", sub: "Local execution", x: 60, y: 200, r: 36, type: "entry",
      desc: "Runs in user context. Browser credentials accessible to any process running as the user.",
      src: "MITRE ATT&CK T1555.003" },

    // Row 1: Chrome/Chromium
    { id: "sharpchrome", label: "SharpChromium", sub: "/ HackBrowserData", x: 200, y: 80, r: 36, type: "op",
      desc: "SharpChromium or HackBrowserData extracts Chrome credentials, cookies, history.",
      src: "djhohnstein/SharpChromium" },
    { id: "login_data", label: "Login Data", sub: "SQLite DB", x: 380, y: 80, r: 34, type: "artifact",
      desc: "Chrome password DB: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data (SQLite).",
      src: "Chromium source" },
    { id: "dpapi_decrypt", label: "DPAPI Decrypt", sub: "CryptUnprotectData", x: 540, y: 80, r: 38, type: "api",
      desc: "CryptUnprotectData() decrypts Chrome passwords. Requires user's DPAPI master key (available in user context).",
      src: "Microsoft DPAPI; Chromium" },
    { id: "aes_gcm", label: "AES-256-GCM", sub: "Chrome v80+", x: 540, y: 140, r: 30, type: "api",
      desc: "Chrome v80+: passwords encrypted with AES-256-GCM. Key stored in Local State file, DPAPI-protected.",
      src: "Chromium source; HackBrowserData" },
    { id: "chrome_pwds", label: "Chrome Passwords", x: 700, y: 80, r: 34, type: "artifact",
      desc: "Plaintext website passwords from Chrome credential store.",
      src: "MITRE T1555.003" },

    // Row 2: Firefox
    { id: "ff_decrypt", label: "firefox_decrypt", sub: "unode/firefox_decrypt", x: 200, y: 200, r: 36, type: "op",
      desc: "firefox_decrypt.py extracts Firefox saved passwords from logins.json + key4.db.",
      src: "unode/firefox_decrypt" },
    { id: "key4_db", label: "key4.db", sub: "NSS keystore", x: 380, y: 200, r: 34, type: "artifact",
      desc: "Firefox NSS key database: %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\key4.db",
      src: "Mozilla NSS" },
    { id: "logins_json", label: "logins.json", sub: "Encrypted creds", x: 380, y: 260, r: 30, type: "artifact",
      desc: "Encrypted login entries: hostname, username, encrypted password.",
      src: "Mozilla Firefox" },
    { id: "nss_decrypt", label: "NSS Decrypt", sub: "PK11SDR_Decrypt", x: 540, y: 200, r: 36, type: "api",
      desc: "Mozilla NSS PK11SDR_Decrypt() with master password (often empty) decrypts saved passwords.",
      src: "Mozilla NSS documentation" },
    { id: "ff_pwds", label: "Firefox Passwords", x: 700, y: 200, r: 34, type: "artifact",
      desc: "Plaintext website passwords from Firefox NSS store.",
      src: "MITRE T1555.003" },

    // Row 3: Edge (Chromium-based)
    { id: "edge_steal", label: "SharpChromium", sub: "Edge profile", x: 200, y: 320, r: 34, type: "op",
      desc: "Same tools work for Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
      src: "djhohnstein/SharpChromium" },
    { id: "edge_db", label: "Login Data", sub: "Edge SQLite", x: 380, y: 320, r: 32, type: "artifact",
      desc: "Edge Chromium uses identical SQLite + DPAPI encryption as Chrome.",
      src: "Microsoft Edge" },
    { id: "dpapi_edge", label: "DPAPI Decrypt", x: 540, y: 320, r: 32, type: "api",
      desc: "Same CryptUnprotectData / AES-GCM decryption path as Chrome.",
      src: "Microsoft DPAPI" },

    // Row 4: Safari (macOS)
    { id: "safari_steal", label: "chainbreaker", sub: "Safari keychain", x: 200, y: 420, r: 34, type: "op",
      desc: "Safari stores passwords in macOS Keychain. Use security command or chainbreaker.",
      src: "Apple; n0fate/chainbreaker" },
    { id: "keychain_api", label: "SecItemCopy", sub: "Matching()", x: 380, y: 420, r: 32, type: "api",
      desc: "Security.framework API to query Safari passwords from keychain.",
      src: "Apple Security Framework" },

    // ── Cookies (bonus) ──
    { id: "cookies", label: "Cookies DB", sub: "Session tokens", x: 700, y: 320, r: 34, type: "artifact",
      desc: "Browser cookies (session tokens) extracted alongside passwords. Enables session hijacking.",
      src: "MITRE T1539" },

    // ── Detection ──
    { id: "sysmon_11", label: "Sysmon 11", sub: "Login Data access", x: 380, y: 400, r: 34, type: "detect",
      desc: "Sysmon EID 11: File access to Login Data / key4.db by unexpected process.",
      src: "Sysmon documentation" },
    { id: "edr_dpapi", label: "EDR", sub: "DPAPI call from non-browser", x: 700, y: 420, r: 40, type: "detect",
      desc: "OPTIMAL: EDR detects CryptUnprotectData on browser credential files by non-browser process.",
      src: "CrowdStrike; Carbon Black" },

    // ── Output ──
    { id: "all_creds", label: "All Browser", sub: "Passwords", x: 900, y: 200, r: 40, type: "artifact",
      desc: "All saved website passwords across all browsers. Often includes corporate SSO, email, banking.",
      src: "MITRE T1555.003" },
  ],

  edges: [
    // Chrome
    { f: "user_ctx", t: "sharpchrome" },
    { f: "sharpchrome", t: "login_data" },
    { f: "login_data", t: "dpapi_decrypt" },
    { f: "login_data", t: "aes_gcm" },
    { f: "dpapi_decrypt", t: "chrome_pwds" },
    { f: "aes_gcm", t: "chrome_pwds" },
    // Firefox
    { f: "user_ctx", t: "ff_decrypt" },
    { f: "ff_decrypt", t: "key4_db" },
    { f: "ff_decrypt", t: "logins_json" },
    { f: "key4_db", t: "nss_decrypt" },
    { f: "logins_json", t: "nss_decrypt" },
    { f: "nss_decrypt", t: "ff_pwds" },
    // Edge
    { f: "user_ctx", t: "edge_steal" },
    { f: "edge_steal", t: "edge_db" },
    { f: "edge_db", t: "dpapi_edge" },
    { f: "dpapi_edge", t: "cookies" },
    // Safari
    { f: "user_ctx", t: "safari_steal" },
    { f: "safari_steal", t: "keychain_api" },
    // Detection
    { f: "login_data", t: "sysmon_11" },
    { f: "dpapi_decrypt", t: "edr_dpapi" },
    { f: "key4_db", t: "sysmon_11" },
    // Output
    { f: "chrome_pwds", t: "all_creds" },
    { f: "ff_pwds", t: "all_creds" },
    { f: "cookies", t: "all_creds" },
    { f: "keychain_api", t: "all_creds" },
  ],
};

export default model;
