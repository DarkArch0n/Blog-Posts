// T1552.003 — Bash History — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.003", name: "Bash History", tactic: "Credential Access", platform: "Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1200, svgHeight: 300, rows: [{ label: "HISTORY", y: 80 }, { label: "OTHER SHELLS", y: 200 }] },
  nodes: [
    { id: "access", label: "User Access", x: 60, y: 130, r: 36, type: "entry", desc: "Access as user or root. Shell history files readable by the owning user.", src: "MITRE ATT&CK T1552.003" },
    { id: "cat_history", label: "cat ~/.bash_history", x: 220, y: 80, r: 38, type: "op", desc: "Read bash history for passwords passed on command line: mysql -p'password', sshpass, curl -u.", src: "MITRE T1552.003" },
    { id: "read_api", label: "open() / read()", x: 420, y: 80, r: 28, type: "api", desc: "Standard file read operations on history files.", src: "Linux syscalls" },
    { id: "grep_pwd", label: "grep -i 'pass'", sub: ".bash_history", x: 420, y: 140, r: 34, type: "op", desc: "Search history for password-related commands: pass, token, key, secret, curl -u, sshpass.", src: "MITRE T1552.003" },
    { id: "zsh_history", label: ".zsh_history", x: 220, y: 200, r: 30, type: "op", desc: "Zsh history: ~/.zsh_history or ~/.histfile.", src: "Zsh" },
    { id: "mysql_history", label: ".mysql_history", x: 380, y: 200, r: 32, type: "op", desc: "MySQL client history may contain ALTER USER, SET PASSWORD statements.", src: "MySQL" },
    { id: "psql_history", label: ".psql_history", x: 540, y: 200, r: 30, type: "op", desc: "PostgreSQL psql history may contain password commands.", src: "PostgreSQL" },
    { id: "auditd", label: "auditd", sub: "~/.bash_history read", x: 600, y: 80, r: 36, type: "detect", desc: "OPTIMAL: auditd -w ~/.bash_history -p r -k history_read for each user.", src: "Linux auditd" },
    { id: "creds", label: "Cmd-line Creds", x: 760, y: 130, r: 36, type: "artifact", desc: "Passwords, tokens, API keys typed on command line and saved in history.", src: "MITRE T1552.003" },
  ],
  edges: [
    { f: "access", t: "cat_history" }, { f: "cat_history", t: "read_api" }, { f: "read_api", t: "grep_pwd" },
    { f: "access", t: "zsh_history" }, { f: "access", t: "mysql_history" }, { f: "access", t: "psql_history" },
    { f: "grep_pwd", t: "creds" }, { f: "zsh_history", t: "creds" }, { f: "mysql_history", t: "creds" }, { f: "psql_history", t: "creds" },
    { f: "read_api", t: "auditd" },
  ],
};
export default model;
