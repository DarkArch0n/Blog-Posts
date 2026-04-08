// T1003.007 — Proc Filesystem — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.007",
    name: "Proc Filesystem",
    tactic: "Credential Access",
    platform: "Linux",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 480,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "TARGET PROC",  x: 260 },
      { label: "DUMP METHOD",  x: 440 },
      { label: "DETECTION",    x: 640 },
      { label: "OUTCOME",      x: 850 },
    ],
    separators: [170, 350, 540, 745],
    annotations: [
      { text: "Root required for cross-process /proc access", x: 80, y: 420, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "root", label: "Root Access", sub: "or ptrace CAP", x: 80, y: 230, r: 40, type: "source",
      tags: ["root", "CAP_SYS_PTRACE", "sudo"],
      telemetry: [],
      api: "Requires root or CAP_SYS_PTRACE capability for cross-process memory access",
      artifact: "Privileged session on Linux host · sudo or root shell",
      desc: "Reading /proc/<pid>/mem of another process requires root privileges or the CAP_SYS_PTRACE capability. The Yama ptrace_scope sysctl setting may further restrict access even for root (ptrace_scope=3 disables ptrace entirely).",
      src: "MITRE ATT&CK T1003.007; Linux kernel /proc documentation" },

    { id: "sshd", label: "sshd", sub: "SSH daemon", x: 260, y: 120, r: 34, type: "source",
      tags: ["sshd process", "Plaintext passwords", "SSH auth"],
      telemetry: [],
      api: "sshd child process retains plaintext password in memory after authentication",
      artifact: "sshd child PID in /proc · password in heap memory",
      desc: "After SSH password authentication, the sshd child process may retain the plaintext password in memory. The credentials persist in the process heap until the session ends or memory is reallocated. Target PID found via 'pgrep sshd' or /proc enumeration.",
      src: "MITRE T1003.007; research by Brendan Dolan-Gavitt" },

    { id: "httpd", label: "Web Server", sub: "httpd/nginx", x: 260, y: 250, r: 34, type: "source",
      tags: ["Apache httpd", "nginx", "Basic auth creds"],
      telemetry: [],
      api: "Web server processes may hold Basic Auth credentials or session tokens in memory",
      artifact: "httpd/nginx worker PID · HTTP Basic Auth passwords · session data",
      desc: "Web servers handling Basic Authentication or other credential-bearing requests may retain credentials in process memory. Apache httpd worker processes and nginx workers are common targets.",
      src: "MITRE T1003.007" },

    { id: "gnome_keyring", label: "gnome-keyring", sub: "Desktop creds", x: 260, y: 380, r: 34, type: "source",
      tags: ["gnome-keyring-daemon", "Desktop passwords", "Unlocked keyring"],
      telemetry: [],
      api: "gnome-keyring-daemon stores unlocked credentials in process memory",
      artifact: "gnome-keyring-daemon PID · unlocked keyring secrets in heap",
      desc: "On Linux desktops, gnome-keyring-daemon holds unlocked keyring contents (WiFi passwords, saved credentials, SSH keys) in process memory. If the keyring is unlocked (user logged in), credentials are accessible via /proc.",
      src: "MITRE T1003.007" },

    { id: "proc_maps", label: "/proc/PID/maps", sub: "Memory layout", x: 440, y: 140, r: 36, type: "source",
      tags: ["/proc/<pid>/maps", "Memory regions", "Heap identification"],
      telemetry: ["auditd"],
      api: "cat /proc/<pid>/maps → identify heap and stack regions for credential scanning",
      artifact: "File read: /proc/<pid>/maps · identifies [heap] and [stack] regions",
      desc: "First step: read /proc/<pid>/maps to identify memory regions, particularly [heap] and [stack] segments where credentials are most likely stored. Provides base addresses and sizes for targeted memory reads.",
      src: "Linux kernel /proc/[pid]/maps documentation" },

    { id: "proc_mem", label: "/proc/PID/mem", sub: "Read memory", x: 440, y: 330, r: 36, type: "source",
      tags: ["/proc/<pid>/mem", "dd if=/proc/", "gdb attach", "strings | grep"],
      telemetry: ["auditd"],
      api: "dd if=/proc/<pid>/mem bs=1 skip=<offset> count=<size> · or gdb attach -p <pid>",
      artifact: "File read: /proc/<pid>/mem · dd or gdb process · strings output",
      desc: "Read target process memory via /proc/<pid>/mem using dd with calculated offsets from maps, or attach via gdb/ptrace. Extract memory contents and scan with strings/grep for password patterns. Tools like MimiPenguin automate this for common services.",
      src: "MITRE T1003.007; huntergregal/mimipenguin" },

    { id: "ev_detect", label: "auditd + ptrace", sub: "File/Process", x: 640, y: 230, r: 50, type: "detect",
      tags: ["auditd", "PTRACE_ATTACH", "/proc/*/mem access", "Sysdig"],
      telemetry: ["auditd"],
      api: "auditd rules: -w /proc -k proc_access · -a always,exit -S ptrace -k ptrace_attach",
      artifact: "OPTIMAL: auditd /proc access + ptrace syscall monitoring · Falco/Sysdig alerts",
      desc: "OPTIMAL DETECTION NODE. (1) auditd file watch rules on /proc/*/mem access by non-standard processes. (2) ptrace syscall monitoring: PTRACE_ATTACH or PTRACE_PEEKDATA to service processes. (3) Falco/Sysdig rules for /proc memory reads. (4) Process creation of dd/gdb targeting /proc paths. (5) Yama ptrace_scope hardening to prevent the attack entirely.",
      src: "MITRE T1003.007; Linux auditd; Falco rules; Yama LSM" },

    { id: "creds", label: "Credentials", sub: "Plaintext", x: 850, y: 230, r: 38, type: "source",
      tags: ["Plaintext passwords", "SSH creds", "HTTP creds", "Tokens"],
      telemetry: [],
      api: "Plaintext credentials extracted from target process memory",
      artifact: "Plaintext passwords and tokens → lateral movement, privilege escalation",
      desc: "Extracted credentials from process memory yield plaintext passwords, authentication tokens, and session material. SSH passwords enable lateral movement. Web application credentials may escalate access. Keyring contents expose stored secrets. MimiPenguin automates extraction from common Linux services.",
      src: "MITRE T1003.007; huntergregal/mimipenguin" },
  ],

  edges: [
    { f: "root", t: "sshd" },
    { f: "root", t: "httpd" },
    { f: "root", t: "gnome_keyring" },
    { f: "sshd", t: "proc_maps" },
    { f: "httpd", t: "proc_maps" },
    { f: "gnome_keyring", t: "proc_maps" },
    { f: "proc_maps", t: "proc_mem" },
    { f: "proc_mem", t: "ev_detect" },
    { f: "ev_detect", t: "creds" },
  ],
};

export default model;
