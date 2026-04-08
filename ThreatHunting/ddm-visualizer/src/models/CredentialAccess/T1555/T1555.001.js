// T1555.001 — Keychain — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.001",
    name: "Keychain",
    tactic: "Credential Access",
    platform: "macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "PREREQUISITE", x: 80 },
      { label: "DUMP METHOD",  x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "access", label: "User Context", sub: "or root", x: 80, y: 200, r: 40, type: "source",
      tags: ["User session", "root", "Keychain password known"],
      telemetry: [],
      api: "Requires user's login password (keychain unlock password) or root access",
      artifact: "Active user session or root/sudo access on macOS",
      desc: "macOS Keychain is unlocked with the user's login password. Extracting secrets requires: (1) Running as the target user (keychain already unlocked), (2) Knowing the user's password for security::dump-keychain -d, or (3) Root access to directly read the keychain database file.",
      src: "MITRE ATT&CK T1555.001" },

    { id: "security_cli", label: "security", sub: "dump-keychain", x: 270, y: 120, r: 36, type: "source",
      tags: ["security dump-keychain -d", "security find-generic-password", "CLI tool"],
      telemetry: ["es_log"],
      api: "security dump-keychain -d · security find-generic-password -ga <service>",
      artifact: "Process: security CLI · user prompted for keychain access (unless automated)",
      desc: "macOS security CLI can dump all keychain items (dump-keychain -d) or find specific passwords (find-generic-password -ga). The -d flag triggers a password prompt unless the keychain is already unlocked. The -g flag displays the password in plaintext.",
      src: "MITRE T1555.001; macOS security(1) man page" },

    { id: "keychainaccess", label: "Chainbreaker", sub: "DB parsing", x: 270, y: 300, r: 36, type: "source",
      tags: ["Chainbreaker", "KeychainDB parse", "Offline extraction"],
      telemetry: [],
      api: "chainbreaker --dump-all --db ~/Library/Keychains/login.keychain-db --key <key>",
      artifact: "Keychain DB file access · offline parsing of encrypted entries",
      desc: "Chainbreaker (Python tool) parses macOS keychain database files offline. Can decrypt entries with the user's password or the raw decryption key. Useful for analyzing copied keychain files off the target system. Extracts passwords, certificates, private keys.",
      src: "n0fate/chainbreaker; MITRE T1555.001" },

    { id: "ev_detect", label: "ES/Unified Log", sub: "Keychain access", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Endpoint Security", "Unified Log", "security CLI usage", "TCCd prompt"],
      telemetry: ["es_log", "unified_log"],
      api: "Endpoint Security framework events + Unified Log for security CLI + TCC prompt logging",
      artifact: "OPTIMAL: ES process events for security CLI · Unified Log keychain access · TCC dialog for keychain access",
      desc: "OPTIMAL DETECTION NODE. (1) Endpoint Security (ES) framework: process execution events for 'security' binary with dump-keychain args. (2) macOS Unified Log: keychain access events (subsystem: com.apple.securityd). (3) TCC (Transparency, Consent, Control): user-facing dialog when apps request keychain access. (4) EDR: detect non-standard processes accessing ~/Library/Keychains/. (5) File access monitoring on keychain-db files.",
      src: "MITRE T1555.001; Apple Endpoint Security; macOS Unified Logging" },

    { id: "creds", label: "Credentials", sub: "All keychain items", x: 730, y: 200, r: 40, type: "source",
      tags: ["WiFi passwords", "Login credentials", "SSH keys", "Certificates", "API tokens"],
      telemetry: [],
      api: "All stored credentials: WiFi, web logins, SSH keys, certificates, application passwords",
      artifact: "Plaintext passwords, certificates, private keys from keychain",
      desc: "macOS Keychain stores: WiFi passwords, website credentials (Safari), SSH keys and passphrases, application-specific passwords (Mail, Calendar), certificates with private keys, and API tokens. A complete keychain dump provides comprehensive credential access.",
      src: "MITRE T1555.001" },
  ],

  edges: [
    { f: "access", t: "security_cli" },
    { f: "access", t: "keychainaccess" },
    { f: "security_cli", t: "ev_detect" },
    { f: "keychainaccess", t: "ev_detect" },
    { f: "ev_detect", t: "creds" },
  ],
};

export default model;
