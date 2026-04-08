// T1555.005 — Password Managers — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.005",
    name: "Password Managers",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 440,
    rows: [
      { label: "KEEPASS",   y: 80 },
      { label: "1PASSWORD", y: 180 },
      { label: "LASTPASS",  y: 280 },
      { label: "MEMORY",    y: 380 },
    ],
  },

  nodes: [
    { id: "user_ctx", label: "User Context", sub: "PM running", x: 60, y: 200, r: 36, type: "entry",
      desc: "Password manager open/unlocked in user session. Attack while vault is unlocked in memory.",
      src: "MITRE ATT&CK T1555.005" },

    // Row 1: KeePass
    { id: "keepass_db", label: "KeePass DB", sub: ".kdbx file", x: 200, y: 80, r: 34, type: "op",
      desc: "Locate .kdbx database file. Often on desktop, Documents, or synced cloud folder.",
      src: "KeePass; MITRE T1555.005" },
    { id: "kp_trigger", label: "KeePass Trigger", sub: "Export config", x: 360, y: 80, r: 36, type: "op",
      desc: "CVE-2023-24055: KeePass trigger abuse — add export trigger to config.xml for plaintext dump.",
      src: "CVE-2023-24055; KeePass" },
    { id: "keepass_dump", label: "keepass-dump", sub: "CVE-2023-32784", x: 360, y: 140, r: 34, type: "op",
      desc: "CVE-2023-32784: Extract master password from KeePass process memory (partial recovery).",
      src: "CVE-2023-32784; vdohney/keepass-password-dumper" },
    { id: "kdbx_crack", label: "hashcat", sub: "-m 13400", x: 530, y: 80, r: 34, type: "blind",
      desc: "BLIND: Offline KeePass database cracking. hashcat -m 13400. Argon2 makes this very slow.",
      src: "hashcat.net" },

    // Row 2: 1Password
    { id: "onepass_db", label: "1Password Vault", sub: "Local cache", x: 200, y: 180, r: 34, type: "op",
      desc: "1Password local vault: %LOCALAPPDATA%\\1Password\\data\\. SQLite + encrypted blobs.",
      src: "1Password" },
    { id: "onepass_mem", label: "Memory Dump", sub: "1Password process", x: 360, y: 180, r: 34, type: "op",
      desc: "Dump 1Password process memory while unlocked — vault key may be resident.",
      src: "MITRE T1555.005" },
    { id: "srp_key", label: "SRP/PBKDF2", sub: "Key derivation", x: 530, y: 180, r: 32, type: "api",
      desc: "1Password uses SRP + PBKDF2 with account password + secret key for vault decryption.",
      src: "1Password security design" },

    // Row 3: LastPass
    { id: "lastpass_ext", label: "LastPass Ext", sub: "Browser extension", x: 200, y: 280, r: 34, type: "op",
      desc: "LastPass browser extension stores vault data in browser profile. Decrypt from local cache.",
      src: "LastPass; MITRE T1555.005" },
    { id: "lastpass_vault", label: "LastPass Vault", sub: "Cloud sync", x: 360, y: 280, r: 34, type: "artifact",
      desc: "Encrypted vault blob from LastPass breach (2022). AES-256-CBC with PBKDF2-derived key.",
      src: "LastPass breach 2022-2023" },
    { id: "lp_crack", label: "hashcat", sub: "-m 26600", x: 530, y: 280, r: 34, type: "blind",
      desc: "BLIND: LastPass vault cracking. hashcat -m 26600. PBKDF2 iterations vary (5K-600K).",
      src: "hashcat.net" },

    // Row 4: Memory attacks (generic)
    { id: "proc_dump", label: "Process Dump", sub: "PM process", x: 200, y: 380, r: 34, type: "op",
      desc: "MiniDumpWriteDump on password manager process while vault is unlocked.",
      src: "MITRE T1555.005" },
    { id: "readmem_api", label: "ReadProcess", sub: "Memory()", x: 360, y: 380, r: 32, type: "api",
      desc: "ReadProcessMemory to scan for plaintext passwords in PM process heap.",
      src: "Microsoft Win32 API" },
    { id: "clipboard", label: "Clipboard", sub: "Monitor", x: 530, y: 380, r: 30, type: "op",
      desc: "Monitor clipboard for password copy operations. PMs clear clipboard after timeout.",
      src: "MITRE T1115" },

    // ── Detection ──
    { id: "sysmon_10", label: "Sysmon 10", sub: "PM process access", x: 530, y: 430, r: 34, type: "detect",
      desc: "Sysmon EID 10: Cross-process access to password manager process.",
      src: "Sysmon documentation" },
    { id: "sysmon_11", label: "Sysmon 11", sub: ".kdbx access", x: 200, y: 430, r: 30, type: "detect",
      desc: "Sysmon EID 11: File access to .kdbx files by unexpected processes.",
      src: "Sysmon documentation" },
    { id: "edr_alert", label: "EDR", sub: "PM credential theft", x: 700, y: 380, r: 38, type: "detect",
      desc: "OPTIMAL: EDR behavioral detection: non-PM process accessing PM vault files or memory.",
      src: "CrowdStrike; Defender" },

    // ── Output ──
    { id: "all_passwords", label: "All Vault", sub: "Passwords", x: 730, y: 180, r: 40, type: "artifact",
      desc: "Complete password vault: all websites, credentials, notes, TOTP seeds, credit cards.",
      src: "MITRE T1555.005" },
  ],

  edges: [
    // KeePass
    { f: "user_ctx", t: "keepass_db" },
    { f: "keepass_db", t: "kp_trigger" },
    { f: "keepass_db", t: "keepass_dump" },
    { f: "keepass_db", t: "kdbx_crack", blind: true },
    { f: "kp_trigger", t: "all_passwords" },
    // 1Password
    { f: "user_ctx", t: "onepass_db" },
    { f: "onepass_db", t: "onepass_mem" },
    { f: "onepass_mem", t: "srp_key" },
    { f: "srp_key", t: "all_passwords" },
    // LastPass
    { f: "user_ctx", t: "lastpass_ext" },
    { f: "lastpass_ext", t: "lastpass_vault" },
    { f: "lastpass_vault", t: "lp_crack", blind: true },
    { f: "lp_crack", t: "all_passwords", blind: true },
    // Memory
    { f: "user_ctx", t: "proc_dump" },
    { f: "proc_dump", t: "readmem_api" },
    { f: "readmem_api", t: "clipboard" },
    { f: "clipboard", t: "all_passwords" },
    // Detection
    { f: "proc_dump", t: "sysmon_10" },
    { f: "keepass_db", t: "sysmon_11" },
    { f: "readmem_api", t: "edr_alert" },
    // Output connections
    { f: "keepass_dump", t: "all_passwords" },
    { f: "kdbx_crack", t: "all_passwords", blind: true },
  ],
};

export default model;
