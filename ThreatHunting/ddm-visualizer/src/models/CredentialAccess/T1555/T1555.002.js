// T1555.002 — Securityd Memory — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.002",
    name: "Securityd Memory",
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
      { label: "ATTACK",      x: 270 },
      { label: "DETECTION",   x: 480 },
      { label: "OUTCOME",     x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "root", label: "Root Access", sub: "on macOS", x: 80, y: 200, r: 40, type: "source",
      tags: ["root", "sudo", "SIP bypass"],
      telemetry: [],
      api: "Root access on macOS to read securityd process memory",
      artifact: "Root shell or sudo access on target macOS system",
      desc: "securityd is the macOS security daemon that manages Keychain operations. Its process memory contains decrypted Keychain master keys and cached credentials. Reading its memory requires root privileges and may be blocked by SIP (System Integrity Protection) on modern macOS.",
      src: "MITRE ATT&CK T1555.002" },

    { id: "mem_read", label: "Memory Read", sub: "securityd PID", x: 270, y: 130, r: 36, type: "source",
      tags: ["vmmap", "lldb attach", "task_for_pid()", "heap dump"],
      telemetry: ["es_log"],
      api: "lldb -p <securityd_pid> · task_for_pid() + vm_read() on securityd process",
      artifact: "ES event: process attach to securityd · task_for_pid() call",
      desc: "Attacker attaches to the securityd process via debugger (lldb) or directly calls task_for_pid() + vm_read() to read process memory. Extracts decrypted Keychain master keys and cached credential data from the daemon's heap. SIP must be disabled for this to work on modern macOS.",
      src: "MITRE T1555.002; macOS internals" },

    { id: "keychaindump", label: "keychaindump", sub: "Automated tool", x: 270, y: 300, r: 36, type: "source",
      tags: ["keychaindump", "juuso/keychaindump", "Automated extraction"],
      telemetry: ["es_log"],
      api: "keychaindump — reads securityd memory to extract Keychain master keys + decrypt entries",
      artifact: "ES event: keychaindump process · securityd memory access",
      desc: "keychaindump is a specialized tool that reads securityd's heap memory, locates the Keychain master keys, and uses them to decrypt all Keychain entries. Outputs credentials in plaintext. Requires root and SIP disabled. Works on older macOS versions — blocked by SIP on modern versions.",
      src: "juuso/keychaindump; MITRE T1555.002" },

    { id: "ev_detect", label: "ES + Audit", sub: "securityd attach", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Endpoint Security", "task_for_pid", "SIP enforcement", "Process attach"],
      telemetry: ["es_log"],
      api: "Endpoint Security: ES_EVENT_TYPE_AUTH_TASK_FOR_PID on securityd · SIP blocks by default",
      artifact: "OPTIMAL: ES events for securityd access · SIP violations · debugger attach to system daemon",
      desc: "OPTIMAL DETECTION NODE. (1) Endpoint Security framework: ES_EVENT_TYPE_AUTH_TASK_FOR_PID events targeting securityd. (2) SIP (System Integrity Protection) blocks debugger attachment to system-protected processes by default — if SIP is disabled, that itself is an alert. (3) Process creation of keychaindump or debugger targeting securityd. (4) PREVENTION: Keep SIP enabled (blocks this technique entirely on modern macOS).",
      src: "MITRE T1555.002; Apple Endpoint Security; SIP documentation" },

    { id: "creds", label: "Keychain Items", sub: "Decrypted", x: 730, y: 200, r: 40, type: "source",
      tags: ["All Keychain entries", "Plaintext passwords", "Private keys", "Certificates"],
      telemetry: [],
      api: "All Keychain entries decrypted from securityd memory: passwords, keys, certificates",
      artifact: "Complete Keychain contents in plaintext",
      desc: "Successfully reading securityd memory yields the master keys needed to decrypt all Keychain entries without requiring the user's login password. Provides the same access as T1555.001 but bypasses the password requirement by extracting keys from memory.",
      src: "MITRE T1555.002" },
  ],

  edges: [
    { f: "root", t: "mem_read" },
    { f: "root", t: "keychaindump" },
    { f: "mem_read", t: "ev_detect" },
    { f: "keychaindump", t: "ev_detect" },
    { f: "ev_detect", t: "creds" },
  ],
};

export default model;
