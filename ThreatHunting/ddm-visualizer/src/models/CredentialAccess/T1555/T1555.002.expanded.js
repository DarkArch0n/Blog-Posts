// T1555.002 — Securityd Memory — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.002",
    name: "Securityd Memory",
    tactic: "Credential Access",
    platform: "macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1300,
    svgHeight: 320,
    rows: [
      { label: "MEMORY",  y: 80 },
      { label: "EXTRACT",  y: 200 },
    ],
  },

  nodes: [
    { id: "root", label: "Root Access", x: 60, y: 130, r: 36, type: "entry",
      desc: "Root access required to read securityd process memory on macOS.",
      src: "MITRE ATT&CK T1555.002" },

    // Row 1: Memory access
    { id: "keychaindump", label: "keychaindump", x: 200, y: 80, r: 36, type: "op",
      desc: "keychaindump scans securityd heap for keychain master key patterns.",
      src: "juuso/keychaindump" },
    { id: "mach_vm", label: "mach_vm_read", sub: "securityd PID", x: 380, y: 80, r: 34, type: "api",
      desc: "mach_vm_read() reads securityd process memory via Mach kernel API.",
      src: "Apple Mach API" },
    { id: "heap_scan", label: "Heap Scan", sub: "Master key search", x: 540, y: 80, r: 36, type: "op",
      desc: "Scan securityd heap for master decryption key — key material kept in memory when keychain unlocked.",
      src: "juuso/keychaindump" },
    { id: "master_key", label: "Master Key", sub: "AES-256", x: 700, y: 80, r: 34, type: "artifact",
      desc: "Keychain master decryption key extracted from securityd process memory.",
      src: "Apple; keychaindump" },

    // Row 2: Decrypt keychain
    { id: "open_kc", label: "Open keychain-db", sub: "SQLite", x: 540, y: 200, r: 34, type: "op",
      desc: "Open ~/Library/Keychains/login.keychain-db as SQLite database.",
      src: "Apple; chainbreaker" },
    { id: "decrypt_items", label: "Decrypt Items", sub: "With master key", x: 700, y: 200, r: 38, type: "api",
      desc: "Decrypt individual keychain items using extracted master key. No user password needed.",
      src: "keychaindump; chainbreaker" },

    // ── Detection ──
    { id: "es_proc_access", label: "Endpoint Security", sub: "Process access", x: 380, y: 200, r: 38, type: "detect",
      desc: "OPTIMAL: ES_EVENT_TYPE_NOTIFY_PROC_ATTACH on securityd. Unexpected accessor = suspicious.",
      src: "Apple Endpoint Security" },
    { id: "sip", label: "SIP Protection", sub: "System Integrity", x: 380, y: 280, r: 34, type: "system",
      desc: "System Integrity Protection may restrict access to securityd on newer macOS versions.",
      src: "Apple SIP" },

    // ── Output ──
    { id: "all_creds", label: "All Keychain", sub: "Credentials", x: 880, y: 140, r: 40, type: "artifact",
      desc: "All credentials from user's keychain: passwords, certificates, keys, tokens.",
      src: "MITRE T1555.002" },
  ],

  edges: [
    { f: "root", t: "keychaindump" },
    { f: "keychaindump", t: "mach_vm" },
    { f: "mach_vm", t: "heap_scan" },
    { f: "heap_scan", t: "master_key" },
    { f: "master_key", t: "open_kc" },
    { f: "open_kc", t: "decrypt_items" },
    { f: "decrypt_items", t: "all_creds" },
    { f: "mach_vm", t: "es_proc_access" },
    { f: "es_proc_access", t: "sip" },
  ],
};

export default model;
