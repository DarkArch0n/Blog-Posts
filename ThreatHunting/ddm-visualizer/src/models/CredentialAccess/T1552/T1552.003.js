// T1552.003 — Bash History — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.003",
    name: "Bash History",
    tactic: "Credential Access",
    platform: "Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "HISTORY SOURCE",  x: 80 },
      { label: "ACCESS METHOD",  x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "bash_hist", label: ".bash_history", sub: "User histories", x: 80, y: 130, r: 38, type: "source",
      tags: [".bash_history", ".zsh_history", ".sh_history", "HISTFILE"],
      telemetry: ["auditd"],
      api: "~/.bash_history, ~/.zsh_history — every command typed in the shell",
      artifact: "Shell history files containing previously typed commands",
      desc: "Shell history files record every command typed by the user: ~/.bash_history (bash), ~/.zsh_history (zsh), ~/.sh_history (sh/ksh). Commands containing passwords are recorded verbatim. HISTFILE environment variable controls the location. Root + all user accounts have separate history files.",
      src: "MITRE ATT&CK T1552.003" },

    { id: "other_hist", label: "Other Histories", sub: "MySQL, PSReadline", x: 80, y: 310, r: 34, type: "source",
      tags: [".mysql_history", "PSReadline", ".python_history", ".lesshst"],
      telemetry: [],
      api: "Other command histories: .mysql_history, PSReadline\\ConsoleHost_history.txt, .python_history",
      artifact: "Application-specific history files with credentials",
      desc: "Beyond shell history: .mysql_history (SQL commands with passwords), PowerShell PSReadline (ConsoleHost_history.txt on Windows), .python_history, .psql_history (PostgreSQL), .lesshst (less pager), .node_repl_history. These often contain credentials from interactive database sessions or admin tasks.",
      src: "MITRE T1552.003" },

    { id: "cat_hist", label: "Read History", sub: "cat/grep", x: 270, y: 200, r: 40, type: "source",
      tags: ["cat .bash_history", "grep password", "strings HISTFILE"],
      telemetry: ["Sysmon 1", "auditd"],
      api: "cat ~/.bash_history | grep -i 'password\\|secret\\|token\\|mysql -u.*-p'",
      artifact: "Process reading .bash_history or .zsh_history files · grep for credential keywords",
      desc: "Attacker reads history files and searches for credentials. Common patterns: 'mysql -u root -p<password>', 'sshpass -p <password>', 'curl -u user:pass', 'export API_KEY=...', 'echo <password> | sudo -S', 'passwd' followed by credential strings. Any command with inline credentials is captured.",
      src: "MITRE T1552.003" },

    { id: "ev_detect", label: "File Access", sub: "History monitor", x: 480, y: 200, r: 50, type: "detect",
      tags: ["auditd file access", "History file read", "Credential grep", "File read audit"],
      telemetry: ["auditd"],
      api: "auditd: monitor access to *_history files + Sysmon for Linux (FileOpen)",
      artifact: "OPTIMAL: auditd watch on .bash_history/.zsh_history · cat/grep of history files · non-owner access",
      desc: "OPTIMAL DETECTION NODE. (1) auditd: -w /home/*/.bash_history -p r -k hist_access — alert on reads. (2) Sysmon for Linux: process accessing history files. (3) Non-owner access: user reading another user's history file. (4) Pattern: grep/cat/strings command targeting history files. (5) PREVENTION: HISTCONTROL=ignorespace (commands starting with space not recorded), HISTIGNORE for sensitive patterns, unset HISTFILE for sensitive sessions.",
      src: "MITRE T1552.003; auditd" },

    { id: "creds_found", label: "Inline Creds", sub: "From commands", x: 730, y: 200, r: 38, type: "source",
      tags: ["MySQL passwords", "SSH passwords", "API keys", "Export secrets"],
      telemetry: [],
      api: "Credentials found in command history: DB passwords, SSH, API keys, environment variables",
      artifact: "Plaintext credentials from historical commands",
      desc: "Common credential finds in history: mysql/psql -p<password>, sshpass -p <pass>, curl -H 'Authorization: Bearer <token>', docker login -p <pass>, AWS_SECRET_ACCESS_KEY exports, openssl commands with passphrases, and any other commands where credentials were passed as arguments.",
      src: "MITRE T1552.003" },
  ],

  edges: [
    { f: "bash_hist", t: "cat_hist" },
    { f: "other_hist", t: "cat_hist" },
    { f: "cat_hist", t: "ev_detect" },
    { f: "ev_detect", t: "creds_found" },
  ],
};

export default model;
