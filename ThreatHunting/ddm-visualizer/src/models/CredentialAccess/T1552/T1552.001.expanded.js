// T1552.001 — Credentials In Files — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.001", name: "Credentials In Files", tactic: "Credential Access", platform: "Windows, Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 380, rows: [{ label: "CONFIG FILES", y: 80 }, { label: "SCRIPTS", y: 180 }, { label: "LOGS", y: 280 }] },
  nodes: [
    { id: "access", label: "File System", sub: "Access", x: 60, y: 180, r: 36, type: "entry", desc: "Any file system access — local user, remote share, or post-exploitation shell.", src: "MITRE ATT&CK T1552.001" },
    { id: "find_configs", label: "Search Configs", sub: "web.config / .env", x: 200, y: 80, r: 36, type: "op", desc: "Search for configuration files: web.config, .env, appsettings.json, wp-config.php, etc.", src: "MITRE T1552.001" },
    { id: "grep_search", label: "grep -r", sub: "password|secret|key", x: 400, y: 80, r: 36, type: "op", desc: "grep -ri 'password\\|secret\\|api_key\\|token' /var/www/ /opt/ /home/ — recursive search.", src: "MITRE T1552.001" },
    { id: "findstr", label: "findstr /si", sub: "*.config *.xml *.json", x: 400, y: 140, r: 32, type: "op", desc: "Windows: findstr /si password *.config *.xml *.json *.ini *.txt", src: "MITRE T1552.001" },
    { id: "find_scripts", label: "Search Scripts", sub: ".ps1 / .sh / .py", x: 200, y: 180, r: 34, type: "op", desc: "Search scripts with hardcoded credentials: PowerShell, Bash, Python, batch files.", src: "MITRE T1552.001" },
    { id: "git_history", label: "Git History", sub: "git log -p", x: 400, y: 200, r: 32, type: "op", desc: "git log -p --all -S 'password' — search git history for committed secrets.", src: "MITRE T1552.001; truffleHog" },
    { id: "search_logs", label: "Search Logs", sub: "Debug/error logs", x: 200, y: 280, r: 34, type: "op", desc: "Application logs may contain credentials in debug output, connection strings, stack traces.", src: "MITRE T1552.001" },
    { id: "snaffler", label: "Snaffler", sub: "Automated search", x: 200, y: 340, r: 34, type: "op", desc: "Snaffler: automated credential/secret finder for Windows file shares and local file systems.", src: "SnaffCon/Snaffler" },
    { id: "sysmon_1", label: "Sysmon 1", sub: "findstr/grep exec", x: 600, y: 180, r: 34, type: "detect", desc: "Sysmon EID 1: Process creation for findstr, grep, or known credential search tools.", src: "Sysmon documentation" },
    { id: "honeypot_file", label: "Honey Files", sub: "Canary credentials", x: 600, y: 280, r: 36, type: "detect", desc: "OPTIMAL: Deploy honey config files with canary credentials that alert on use.", src: "Thinkst Canary" },
    { id: "creds", label: "Plaintext Creds", sub: "DB/API/service", x: 800, y: 180, r: 38, type: "artifact", desc: "Database passwords, API keys, service account credentials found in files.", src: "MITRE T1552.001" },
  ],
  edges: [
    { f: "access", t: "find_configs" }, { f: "access", t: "find_scripts" }, { f: "access", t: "search_logs" }, { f: "access", t: "snaffler" },
    { f: "find_configs", t: "grep_search" }, { f: "find_configs", t: "findstr" },
    { f: "find_scripts", t: "git_history" },
    { f: "grep_search", t: "creds" }, { f: "findstr", t: "creds" }, { f: "git_history", t: "creds" },
    { f: "search_logs", t: "creds" }, { f: "snaffler", t: "creds" },
    { f: "grep_search", t: "sysmon_1" }, { f: "findstr", t: "sysmon_1" },
    { f: "creds", t: "honeypot_file" },
  ],
};
export default model;
