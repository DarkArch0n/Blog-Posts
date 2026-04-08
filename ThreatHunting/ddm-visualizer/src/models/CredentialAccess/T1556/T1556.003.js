// T1556.003 — Pluggable Authentication Modules — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.003",
    name: "Pluggable Authentication Modules",
    tactic: "Credential Access",
    platform: "Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "PAM MODULE",   x: 80 },
      { label: "AUTH FLOW",    x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "mod_pam", label: "Modify PAM", sub: "Replace module", x: 80, y: 130, r: 38, type: "source",
      tags: ["pam_unix.so replacement", "/lib/security/", "Backdoored module"],
      telemetry: ["auditd"],
      api: "Replace pam_unix.so or add new PAM module to /lib/security/ (or /lib64/security/)",
      artifact: "File modification in /lib/security/ · pam_unix.so hash change · new .so file",
      desc: "Attacker replaces the standard pam_unix.so module with a backdoored version, or adds a new PAM module. The modified module (1) accepts a hardcoded backdoor password alongside real passwords, and/or (2) logs plaintext credentials to a file. Requires root access.",
      src: "MITRE ATT&CK T1556.003; Linux PAM documentation" },

    { id: "pam_config", label: "PAM Config", sub: "/etc/pam.d/", x: 80, y: 320, r: 36, type: "source",
      tags: ["/etc/pam.d/", "pam.conf", "auth sufficient", "Module stacking"],
      telemetry: ["auditd"],
      api: "Modify /etc/pam.d/sshd or /etc/pam.d/login to add malicious module to auth stack",
      artifact: "Modified PAM config · new 'auth sufficient' line with custom module",
      desc: "Instead of replacing a module, the attacker modifies PAM configuration files in /etc/pam.d/ to add a malicious module to the authentication stack. Using 'auth sufficient pam_malicious.so' ensures the backdoor module is checked first. If it succeeds, subsequent modules are skipped.",
      src: "MITRE T1556.003; Linux PAM guides" },

    { id: "login_event", label: "User Login", sub: "SSH/su/sudo", x: 270, y: 200, r: 38, type: "source",
      tags: ["SSH login", "su/sudo", "Console login", "Any PAM auth"],
      telemetry: ["auth.log", "secure.log"],
      api: "Any authentication event using PAM: SSH, su, sudo, console, login, FTP",
      artifact: "Authentication via PAM triggers backdoor module · plaintext password captured",
      desc: "Every PAM-based authentication triggers the backdoor module: SSH logins, su/sudo, console logins, FTP, and any service using PAM. The backdoor module receives the plaintext password from the authenticating user. Can both log credentials and accept the backdoor password.",
      src: "MITRE T1556.003" },

    { id: "ev_detect", label: "FIM + Hash", sub: "PAM integrity", x: 480, y: 200, r: 50, type: "detect",
      tags: ["File integrity", "pam_unix.so hash", "PAM config change", "auditd"],
      telemetry: ["auditd", "AIDE/OSSEC"],
      api: "File integrity monitoring on /lib/security/ and /etc/pam.d/ + package verification",
      artifact: "OPTIMAL: pam_unix.so hash mismatch · /etc/pam.d/ config change · rpm -V pam or dpkg -V libpam-modules",
      desc: "OPTIMAL DETECTION NODE. (1) File integrity monitoring (AIDE, OSSEC, auditd): detect modifications to /lib/security/*.so and /etc/pam.d/* files. (2) Package verification: rpm -V pam / dpkg -V libpam-modules — reports modified files. (3) auditd: watch /lib/security/ for writes. (4) Compare pam_unix.so hash against known-good value. (5) PREVENTION: Read-only /lib/security/, SELinux/AppArmor restricting PAM file modification.",
      src: "MITRE T1556.003; auditd; AIDE" },

    { id: "backdoor", label: "Backdoor Login", sub: "Root anywhere", x: 730, y: 130, r: 36, type: "source",
      tags: ["Backdoor password", "Any user", "Root access"],
      telemetry: [],
      api: "Backdoor password works for any account — instant root via su/sudo",
      artifact: "Universal login capability with hardcoded password",
      desc: "A backdoored PAM module provides a universal password that works for any account including root. The attacker can SSH as any user, su to root, or sudo any command. The real passwords continue working so users are unaware.",
      src: "MITRE T1556.003" },

    { id: "cred_log", label: "Credential Log", sub: "All logins", x: 730, y: 310, r: 36, type: "source",
      tags: ["Plaintext passwords", "All users", "SSH/su/sudo creds"],
      telemetry: [],
      api: "Modified PAM logs every plaintext password to file (e.g., /tmp/.pam_log)",
      artifact: "Hidden log file with plaintext passwords for all authenticating users",
      desc: "The modified PAM module logs plaintext passwords for every authentication event to a hidden file. Captures credentials for all users who log in via SSH, use su/sudo, or authenticate through any PAM-enabled service.",
      src: "MITRE T1556.003" },
  ],

  edges: [
    { f: "mod_pam", t: "login_event" },
    { f: "pam_config", t: "login_event" },
    { f: "login_event", t: "ev_detect" },
    { f: "ev_detect", t: "backdoor" },
    { f: "ev_detect", t: "cred_log" },
  ],
};

export default model;
