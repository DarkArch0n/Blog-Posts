// T1555.005 — Password Managers — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.005",
    name: "Password Managers",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 440,
    columns: [
      { label: "PM TARGET",   x: 80 },
      { label: "ATTACK",      x: 270 },
      { label: "DETECTION",   x: 480 },
      { label: "OUTCOME",     x: 730 },
    ],
    separators: [175, 375, 605],
    annotations: [
      { text: "All vault contents compromised at once", x: 270, y: 380, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "keepass", label: "KeePass", sub: "Local vault", x: 80, y: 120, r: 34, type: "source",
      tags: ["KeePass", ".kdbx database", "Local file", "Master password"],
      telemetry: [],
      api: "KeePass .kdbx database file protected by master password and/or key file",
      artifact: ".kdbx file location · KeePass process in memory",
      desc: "KeePass stores credentials in a local .kdbx encrypted database file. Protected by master password and optionally a key file. Attackable via: keylogger for master password, memory dump with KeePass open, or CVE-2023-32784 (master password extraction from memory dump).",
      src: "MITRE T1555.005; CVE-2023-32784" },

    { id: "lastpass", label: "LastPass/1Pass", sub: "Cloud vault", x: 80, y: 260, r: 34, type: "source",
      tags: ["LastPass", "1Password", "Bitwarden", "Cloud-synced"],
      telemetry: [],
      api: "Cloud-synced password managers with browser extensions and desktop apps",
      artifact: "Browser extension data · cached vault · API keys · session tokens",
      desc: "Cloud password managers (LastPass, 1Password, Bitwarden) cache decrypted vaults locally. Browser extensions hold decrypted entries in memory during active sessions. The 2022 LastPass breach demonstrated vault database theft — encrypted vaults were exfiltrated and cracked offline.",
      src: "MITRE T1555.005; LastPass breach (2022)" },

    { id: "keylog_master", label: "Keylog Master", sub: "Password capture", x: 270, y: 100, r: 36, type: "source",
      tags: ["Keylogger", "Master password capture", "Clipboard monitor"],
      telemetry: ["Sysmon 1"],
      api: "T1056.001 keylogger captures master password · clipboard monitor for copy/paste",
      artifact: "Keylogger capturing master password · clipboard monitoring for pasted passwords",
      desc: "Keylogger (T1056.001) captures the master password as the user types it. Clipboard monitoring captures credentials as users copy/paste from the password manager. Both provide plaintext access to the master password or individual stored credentials.",
      src: "MITRE T1555.005; T1056.001" },

    { id: "mem_dump", label: "Memory Dump", sub: "Decrypted vault", x: 270, y: 260, r: 36, type: "source",
      tags: ["Process dump", "KeeThief", "CVE-2023-32784", "Vault in memory"],
      telemetry: ["Sysmon 10"],
      api: "Dump KeePass/password manager process memory → extract decrypted vault entries or master key",
      artifact: "Sysmon EID 10: password manager process access · memory dump file",
      desc: "When a password manager is unlocked, decrypted credentials exist in process memory. KeeThief extracts KeePass entries from memory. CVE-2023-32784 allows recovering the KeePass master password from a process dump. Browser extension processes also hold decrypted entries.",
      src: "GhostPack/KeeThief; CVE-2023-32784; MITRE T1555.005" },

    { id: "ev_detect", label: "PM Process", sub: "Access Monitor", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Sysmon 10", "PM process access", "Keylogger detection", "Vault file access"],
      telemetry: ["Sysmon 10", "Sysmon 1"],
      api: "Sysmon EID 10 on password manager processes + keylogger detection + vault file access",
      artifact: "OPTIMAL: Sysmon 10 on KeePass/PM process · suspicious DLL injection · vault file copy/access",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 10: process access to password manager processes (KeePass.exe, 1Password.exe, etc.). (2) DLL injection or memory read access to PM processes. (3) Vault file access: .kdbx file being copied or accessed by non-PM process. (4) Clipboard monitoring process detection. (5) PREVENTION: Hardware key integration (YubiKey + KeePass), auto-type restrictions, vault timeout policies.",
      src: "MITRE T1555.005; Sysmon; EDR behavioral detection" },

    { id: "all_creds", label: "All Vault", sub: "Credentials", x: 730, y: 200, r: 42, type: "source",
      tags: ["Every stored credential", "Hundreds of passwords", "Notes/secrets", "MFA seeds"],
      telemetry: [],
      api: "Complete vault dump: all stored credentials, notes, TOTP seeds, API keys",
      artifact: "Every credential in the vault — often hundreds of entries across all services",
      desc: "A compromised password manager yields ALL stored credentials at once — potentially hundreds of unique passwords across corporate, cloud, personal, and financial services. May also contain secure notes with API keys, SSH keys, license keys, and TOTP seeds. Single point of total credential compromise.",
      src: "MITRE T1555.005" },
  ],

  edges: [
    { f: "keepass", t: "keylog_master" },
    { f: "keepass", t: "mem_dump" },
    { f: "lastpass", t: "keylog_master" },
    { f: "lastpass", t: "mem_dump" },
    { f: "keylog_master", t: "ev_detect" },
    { f: "mem_dump", t: "ev_detect" },
    { f: "ev_detect", t: "all_creds" },
  ],
};

export default model;
