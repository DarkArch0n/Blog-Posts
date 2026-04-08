// T1003.007 — Proc Filesystem — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.007",
    name: "Proc Filesystem",
    tactic: "Credential Access",
    platform: "Linux",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1350,
    svgHeight: 380,
    rows: [
      { label: "PROC MEM",   y: 80 },
      { label: "PROC MAPS",  y: 180 },
      { label: "GDB ATTACH", y: 280 },
    ],
  },

  nodes: [
    { id: "root", label: "root / CAP", sub: "SYS_PTRACE", x: 60, y: 150, r: 36, type: "entry",
      desc: "Root or CAP_SYS_PTRACE required. ptrace_scope sysctl controls access to other processes' memory.",
      src: "MITRE ATT&CK T1003.007" },

    // Row 1: /proc/PID/mem direct read
    { id: "find_pid", label: "Find Target PID", sub: "ps aux | grep sshd", x: 200, y: 80, r: 34, type: "op",
      desc: "Identify target process (sshd, apache, gnome-keyring, etc.) with credentials in memory.",
      src: "MITRE T1003.007" },
    { id: "proc_maps", label: "/proc/PID/maps", sub: "Read heap ranges", x: 360, y: 80, r: 34, type: "api",
      desc: "Read /proc/PID/maps to find heap, stack, and mmap regions containing credentials.",
      src: "Linux proc(5) man page" },
    { id: "proc_mem", label: "/proc/PID/mem", sub: "Read memory", x: 520, y: 80, r: 34, type: "api",
      desc: "Read /proc/PID/mem (with lseek to correct offset) to extract credential data from process memory.",
      src: "Linux proc(5) man page" },
    { id: "strings_grep", label: "strings | grep", sub: "password patterns", x: 680, y: 80, r: 36, type: "op",
      desc: "Search extracted memory for plaintext passwords, tokens, keys using pattern matching.",
      src: "MITRE T1003.007" },

    // Row 2: /proc/PID/maps + mimipenguin
    { id: "mimipenguin", label: "mimipenguin", sub: "huntergregal", x: 200, y: 180, r: 36, type: "op",
      desc: "mimipenguin reads credentials from gnome-keyring-daemon, sshd, vsftpd, Apache processes.",
      src: "huntergregal/mimipenguin" },
    { id: "ptrace_attach", label: "ptrace", sub: "PTRACE_ATTACH", x: 360, y: 180, r: 32, type: "api",
      desc: "ptrace(PTRACE_ATTACH, pid) — attaches to target process for memory inspection.",
      src: "Linux ptrace(2)" },
    { id: "ptrace_peek", label: "ptrace", sub: "PTRACE_PEEKDATA", x: 520, y: 180, r: 32, type: "api",
      desc: "ptrace(PTRACE_PEEKDATA) reads words from target process memory.",
      src: "Linux ptrace(2)" },

    // Row 3: GDB attach
    { id: "gdb_attach", label: "gdb -p PID", x: 200, y: 280, r: 34, type: "op",
      desc: "GDB attaches to target process. Can dump memory regions interactively.",
      src: "GNU GDB" },
    { id: "gdb_dump", label: "dump memory", sub: "GDB command", x: 360, y: 280, r: 36, type: "op",
      desc: "GDB: dump memory /tmp/mem.bin 0x7f... 0x7f... — dumps heap region to file.",
      src: "GNU GDB" },
    { id: "process_vm", label: "process_vm_readv", sub: "syscall", x: 520, y: 280, r: 36, type: "api",
      desc: "process_vm_readv() syscall — efficient cross-process memory read (kernel 3.2+).",
      src: "Linux process_vm_readv(2)" },

    // ── Detection ──
    { id: "auditd_ptrace", label: "auditd", sub: "ptrace syscall", x: 680, y: 200, r: 38, type: "detect",
      desc: "OPTIMAL: auditd rule: -a always,exit -F arch=b64 -S ptrace -k proc_access. Detects ptrace attachment.",
      src: "Linux auditd; MITRE T1003.007" },
    { id: "auditd_open", label: "auditd", sub: "/proc/*/mem open", x: 680, y: 300, r: 34, type: "detect",
      desc: "auditd: monitor open() on /proc/*/mem paths. -w /proc -p r -k proc_mem_read",
      src: "Linux auditd" },
    { id: "syslog", label: "Syslog", sub: "PTRACE deny", x: 840, y: 250, r: 30, type: "detect",
      desc: "If ptrace_scope=1+, denied ptrace attempts may be logged to syslog/dmesg.",
      src: "Linux Yama LSM" },

    // ── Protections ──
    { id: "ptrace_scope", label: "ptrace_scope", sub: "Yama LSM", x: 840, y: 140, r: 34, type: "system",
      desc: "/proc/sys/kernel/yama/ptrace_scope: 0=classic, 1=parent-only, 2=admin-only, 3=disabled.",
      src: "Linux Yama LSM" },

    // ── Output ──
    { id: "ssh_keys", label: "SSH Keys", sub: "In agent memory", x: 1000, y: 80, r: 30, type: "artifact",
      desc: "SSH private keys from ssh-agent or sshd process memory.",
      src: "MITRE T1003.007" },
    { id: "plaintext_pwd", label: "Plaintext Pwd", sub: "sshd/gnome-keyring", x: 1000, y: 180, r: 34, type: "artifact",
      desc: "Plaintext passwords from sshd, gnome-keyring-daemon, vsftpd, Apache2 basic auth.",
      src: "MITRE T1003.007; mimipenguin" },
    { id: "tokens", label: "Auth Tokens", sub: "Session cookies", x: 1000, y: 280, r: 32, type: "artifact",
      desc: "Session tokens, JWT tokens, API keys found in web server or application process memory.",
      src: "MITRE T1003.007" },
  ],

  edges: [
    // Proc mem path
    { f: "root", t: "find_pid" },
    { f: "find_pid", t: "proc_maps" },
    { f: "proc_maps", t: "proc_mem" },
    { f: "proc_mem", t: "strings_grep" },
    // mimipenguin
    { f: "root", t: "mimipenguin" },
    { f: "mimipenguin", t: "ptrace_attach" },
    { f: "ptrace_attach", t: "ptrace_peek" },
    { f: "ptrace_peek", t: "strings_grep" },
    // GDB
    { f: "root", t: "gdb_attach" },
    { f: "gdb_attach", t: "gdb_dump" },
    { f: "gdb_dump", t: "process_vm" },
    { f: "process_vm", t: "strings_grep" },
    // Detection
    { f: "ptrace_attach", t: "auditd_ptrace" },
    { f: "proc_mem", t: "auditd_open" },
    { f: "auditd_ptrace", t: "syslog" },
    // Protection
    { f: "auditd_ptrace", t: "ptrace_scope" },
    // Output
    { f: "strings_grep", t: "ssh_keys" },
    { f: "strings_grep", t: "plaintext_pwd" },
    { f: "strings_grep", t: "tokens" },
  ],
};

export default model;
