// T1555.001 — Keychain — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.001",
    name: "Keychain",
    tactic: "Credential Access",
    platform: "macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 380,
    rows: [
      { label: "SECURITY",  y: 80 },
      { label: "CHAINBREAK", y: 180 },
      { label: "KEYCHAINDUMP", y: 280 },
    ],
  },

  nodes: [
    { id: "user_access", label: "User Session", sub: "or root", x: 60, y: 150, r: 36, type: "entry",
      desc: "Logged-in user session (keychain unlocked) or root access on macOS.",
      src: "MITRE ATT&CK T1555.001" },

    // Row 1: security command
    { id: "security_cmd", label: "security", sub: "find-generic-password", x: 200, y: 80, r: 36, type: "op",
      desc: "security find-generic-password -w -s 'label' — dumps plaintext password from keychain.",
      src: "Apple security(1)" },
    { id: "security_dump", label: "security", sub: "dump-keychain -d", x: 200, y: 140, r: 32, type: "op",
      desc: "security dump-keychain -d ~/Library/Keychains/login.keychain-db — dumps all items.",
      src: "Apple security(1)" },
    { id: "secitem_api", label: "SecItemCopyMatching", x: 380, y: 80, r: 36, type: "api",
      desc: "Security.framework SecItemCopyMatching() — programmatic keychain query API.",
      src: "Apple Security Framework" },
    { id: "keychain_db", label: "Keychain DB", sub: "login.keychain-db", x: 550, y: 80, r: 36, type: "system",
      desc: "SQLite database at ~/Library/Keychains/login.keychain-db encrypted with user password.",
      src: "Apple macOS" },

    // Row 2: Chainbreaker (offline)
    { id: "chainbreaker", label: "chainbreaker", x: 200, y: 180, r: 34, type: "op",
      desc: "chainbreaker: offline keychain database parser. Requires user password or decryption key.",
      src: "n0fate/chainbreaker" },
    { id: "pbkdf2_derive", label: "PBKDF2", sub: "Derive master key", x: 380, y: 180, r: 34, type: "api",
      desc: "PBKDF2 with user password derives keychain master key for decryption.",
      src: "Apple; chainbreaker" },
    { id: "sqlite_parse", label: "SQLite Parse", sub: "Keychain records", x: 550, y: 180, r: 34, type: "api",
      desc: "Parse SQLite keychain database, decrypt individual password entries.",
      src: "chainbreaker" },

    // Row 3: keychaindump (memory)
    { id: "keychaindump", label: "keychaindump", sub: "Memory extraction", x: 200, y: 280, r: 34, type: "op",
      desc: "keychaindump extracts keychain master key from securityd process memory.",
      src: "juuso/keychaindump" },
    { id: "vm_read", label: "mach_vm_read", x: 380, y: 280, r: 32, type: "api",
      desc: "mach_vm_read() Mach API to read securityd process memory for master key.",
      src: "Apple Mach API" },

    // ── Detection ──
    { id: "es_notify", label: "Endpoint Security", sub: "ES_EVENT_TYPE_AUTH_OPEN", x: 700, y: 80, r: 40, type: "detect",
      desc: "OPTIMAL: macOS Endpoint Security framework detects keychain access by unexpected processes.",
      src: "Apple Endpoint Security" },
    { id: "tcc_prompt", label: "TCC Prompt", sub: "Keychain access", x: 700, y: 180, r: 34, type: "system",
      desc: "macOS TCC prompts user when non-entitled app accesses keychain items. User must approve.",
      src: "Apple TCC" },
    { id: "unified_log", label: "Unified Log", sub: "subsystem Security", x: 700, y: 280, r: 34, type: "detect",
      desc: "macOS Unified Log: log show --predicate 'subsystem==\"com.apple.securityd\"' for keychain events.",
      src: "Apple Unified Logging" },

    // ── Output ──
    { id: "wifi_pwd", label: "WiFi Passwords", x: 900, y: 80, r: 30, type: "artifact",
      desc: "Saved WiFi passwords stored in System keychain.",
      src: "MITRE T1555.001" },
    { id: "web_pwd", label: "Website Passwords", x: 900, y: 150, r: 32, type: "artifact",
      desc: "Safari/browser saved passwords and auto-fill credentials.",
      src: "MITRE T1555.001" },
    { id: "app_pwd", label: "App Passwords", sub: "Mail, VPN, etc.", x: 900, y: 230, r: 32, type: "artifact",
      desc: "Application-stored credentials: Mail accounts, VPN, certificates, tokens.",
      src: "MITRE T1555.001" },
    { id: "certs", label: "Certificates", sub: "+ Private Keys", x: 900, y: 300, r: 30, type: "artifact",
      desc: "Identity certificates and associated private keys stored in keychain.",
      src: "MITRE T1555.001" },
  ],

  edges: [
    // security command
    { f: "user_access", t: "security_cmd" },
    { f: "user_access", t: "security_dump" },
    { f: "security_cmd", t: "secitem_api" },
    { f: "security_dump", t: "secitem_api" },
    { f: "secitem_api", t: "keychain_db" },
    // chainbreaker
    { f: "user_access", t: "chainbreaker" },
    { f: "chainbreaker", t: "pbkdf2_derive" },
    { f: "pbkdf2_derive", t: "sqlite_parse" },
    { f: "sqlite_parse", t: "keychain_db" },
    // keychaindump
    { f: "user_access", t: "keychaindump" },
    { f: "keychaindump", t: "vm_read" },
    { f: "vm_read", t: "keychain_db" },
    // Detection
    { f: "secitem_api", t: "es_notify" },
    { f: "secitem_api", t: "tcc_prompt" },
    { f: "vm_read", t: "unified_log" },
    // Output
    { f: "keychain_db", t: "wifi_pwd" },
    { f: "keychain_db", t: "web_pwd" },
    { f: "keychain_db", t: "app_pwd" },
    { f: "keychain_db", t: "certs" },
  ],
};

export default model;
