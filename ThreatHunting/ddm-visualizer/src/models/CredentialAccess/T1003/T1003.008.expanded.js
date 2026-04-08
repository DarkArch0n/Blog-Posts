// T1003.008 — /etc/passwd and /etc/shadow — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.008",
    name: "/etc/passwd and /etc/shadow",
    tactic: "Credential Access",
    platform: "Linux",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1300,
    svgHeight: 360,
    rows: [
      { label: "SHADOW",    y: 80 },
      { label: "PASSWD",    y: 180 },
      { label: "UNSHADOW",  y: 280 },
    ],
  },

  nodes: [
    { id: "root", label: "root Access", x: 60, y: 130, r: 36, type: "entry",
      desc: "Root or shadow group membership required to read /etc/shadow. /etc/passwd is world-readable.",
      src: "MITRE ATT&CK T1003.008" },

    // Row 1: /etc/shadow access
    { id: "cat_shadow", label: "cat /etc/shadow", x: 200, y: 80, r: 34, type: "op",
      desc: "Read /etc/shadow containing password hashes. Requires root or shadow group.",
      src: "MITRE T1003.008" },
    { id: "open_shadow", label: "open()", sub: "/etc/shadow", x: 360, y: 80, r: 30, type: "api",
      desc: "open('/etc/shadow', O_RDONLY) — file permission check enforced by kernel.",
      src: "Linux open(2)" },
    { id: "shadow_file", label: "/etc/shadow", sub: "user:$id$salt$hash", x: 520, y: 80, r: 38, type: "artifact",
      desc: "Shadow file format: user:$6$salt$hash:... ($6$=SHA-512, $5$=SHA-256, $y$=yescrypt).",
      src: "Linux shadow(5)" },

    // Row 2: /etc/passwd (world-readable)
    { id: "cat_passwd", label: "cat /etc/passwd", x: 200, y: 180, r: 34, type: "op",
      desc: "World-readable. Contains usernames, UIDs, shells. Occasionally contains hashes on legacy systems.",
      src: "MITRE T1003.008" },
    { id: "getpwent", label: "getpwent()", x: 360, y: 180, r: 28, type: "api",
      desc: "C library function to enumerate passwd entries. Used by id, finger, etc.",
      src: "Linux getpwent(3)" },
    { id: "passwd_file", label: "/etc/passwd", sub: "user:x:UID:GID:...", x: 520, y: 180, r: 36, type: "artifact",
      desc: "Password field 'x' = shadowed. If actual hash present (legacy), direct cracking possible.",
      src: "Linux passwd(5)" },

    // Row 3: Combine and crack
    { id: "unshadow", label: "unshadow", sub: "passwd shadow", x: 360, y: 280, r: 34, type: "op",
      desc: "John the Ripper's unshadow combines passwd and shadow into crackable format.",
      src: "John the Ripper; Openwall" },
    { id: "exfil", label: "Exfiltrate", sub: "scp/base64", x: 200, y: 280, r: 30, type: "op",
      desc: "Copy shadow file off-host: scp, base64 encoding, or embed in HTTP request.",
      src: "MITRE T1041" },

    // ── Detection ──
    { id: "auditd_shadow", label: "auditd", sub: "/etc/shadow read", x: 520, y: 280, r: 38, type: "detect",
      desc: "OPTIMAL: auditd -w /etc/shadow -p r -k shadow_read. Alerts on any read of shadow file.",
      src: "Linux auditd" },
    { id: "auditd_cat", label: "auditd", sub: "execve cat/shadow", x: 200, y: 340, r: 32, type: "detect",
      desc: "auditd: -a always,exit -F exe=/usr/bin/cat -F path=/etc/shadow -k shadow_cat",
      src: "Linux auditd" },
    { id: "inotify", label: "inotifywait", sub: "IN_ACCESS", x: 680, y: 280, r: 30, type: "detect",
      desc: "File access monitoring via inotify on /etc/shadow for real-time alerts.",
      src: "Linux inotify(7)" },

    // ── Cracking (BLIND) ──
    { id: "john", label: "john", sub: "--wordlist", x: 700, y: 80, r: 36, type: "blind",
      desc: "BLIND: John the Ripper. Offline cracking supports all crypt formats ($6$, $5$, $y$, etc.).",
      src: "Openwall John the Ripper" },
    { id: "hashcat_1800", label: "hashcat", sub: "-m 1800 (SHA-512)", x: 700, y: 180, r: 36, type: "blind",
      desc: "BLIND: hashcat -m 1800 for SHA-512crypt. Default 5000 rounds. GPU-intensive.",
      src: "hashcat.net" },
    { id: "plaintext", label: "User Passwords", x: 880, y: 130, r: 36, type: "artifact",
      desc: "Cracked local user and service account passwords. Enables login, lateral movement.",
      src: "MITRE T1003.008" },
  ],

  edges: [
    // Shadow read
    { f: "root", t: "cat_shadow" },
    { f: "cat_shadow", t: "open_shadow" },
    { f: "open_shadow", t: "shadow_file" },
    // Passwd read
    { f: "root", t: "cat_passwd" },
    { f: "cat_passwd", t: "getpwent" },
    { f: "getpwent", t: "passwd_file" },
    // Combine
    { f: "shadow_file", t: "unshadow" },
    { f: "passwd_file", t: "unshadow" },
    { f: "shadow_file", t: "exfil" },
    // Detection
    { f: "open_shadow", t: "auditd_shadow" },
    { f: "cat_shadow", t: "auditd_cat" },
    { f: "auditd_shadow", t: "inotify" },
    // Cracking
    { f: "shadow_file", t: "john", blind: true },
    { f: "unshadow", t: "hashcat_1800", blind: true },
    { f: "john", t: "plaintext", blind: true },
    { f: "hashcat_1800", t: "plaintext", blind: true },
  ],
};

export default model;
