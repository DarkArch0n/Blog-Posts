// T1552.001 — Credentials In Files — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.001",
    name: "Credentials In Files",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 460,
    columns: [
      { label: "FILE SOURCE",  x: 80 },
      { label: "SEARCH",       x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "config_files", label: "Config Files", sub: "App configs", x: 80, y: 100, r: 34, type: "source",
      tags: ["web.config", "appsettings.json", ".env", "wp-config.php"],
      telemetry: ["Sysmon 1"],
      api: "Application config files containing hardcoded credentials: .env, web.config, appsettings.json",
      artifact: "Config files with connection strings, API keys, database passwords",
      desc: "Application configuration files frequently contain hardcoded credentials: database connection strings (web.config, appsettings.json), environment files (.env), PHP configs (wp-config.php), and deployment scripts. Often left with default permissions readable by any authenticated user.",
      src: "MITRE ATT&CK T1552.001" },

    { id: "scripts", label: "Scripts", sub: "Automation creds", x: 80, y: 240, r: 34, type: "source",
      tags: ["PowerShell scripts", "Batch files", "Python scripts", "Ansible playbooks"],
      telemetry: ["Sysmon 1"],
      api: "Automation scripts with embedded credentials: .ps1, .bat, .py, .sh, .yml",
      artifact: "Scripts containing plaintext passwords, API keys, or tokens",
      desc: "Automation and deployment scripts often contain embedded credentials: PowerShell scripts (ConvertTo-SecureString with plaintext key), batch files, Python scripts, shell scripts, Ansible playbooks with vault passwords, Terraform files with provider credentials.",
      src: "MITRE T1552.001" },

    { id: "logs_notes", label: "Logs / Notes", sub: "Plaintext stored", x: 80, y: 380, r: 34, type: "source",
      tags: ["Log files", "Text notes", "password.txt", "IT documentation"],
      telemetry: [],
      api: "Log files, text notes, IT documentation with recorded passwords",
      artifact: "Files named passwords.txt, creds.txt, or logs containing credentials",
      desc: "Plaintext credentials in: log files (debug logs containing auth headers), text files (passwords.txt, notes.txt on desktops/shares), IT documentation (runbooks, SOPs with service account passwords), browser download history, and user-created credential notes.",
      src: "MITRE T1552.001" },

    { id: "search", label: "File Search", sub: "findstr/grep", x: 270, y: 220, r: 42, type: "source",
      tags: ["findstr password", "grep -r password", "dir /s password*", "Select-String"],
      telemetry: ["Sysmon 1"],
      api: "findstr /si password *.xml *.ini *.txt · grep -r 'password' /etc/ · Select-String -Path C:\\ -Pattern 'password'",
      artifact: "Sysmon 1: findstr.exe, grep, or Select-String with password-related terms",
      desc: "Attacker searches the filesystem for files containing credential keywords. Common commands: findstr /si password *.xml *.txt *.config, grep -rn 'password\\|secret\\|api_key' /, dir /s *password* *cred*, Get-ChildItem -Recurse | Select-String 'password'. May also search network shares.",
      src: "MITRE T1552.001" },

    { id: "ev_detect", label: "Search + Access", sub: "File monitoring", x: 480, y: 220, r: 50, type: "detect",
      tags: ["Sysmon 1 findstr", "Credential keyword search", "Config file access", "Sensitive dirs"],
      telemetry: ["Sysmon 1"],
      api: "Detect credential search commands + access to sensitive config files",
      artifact: "OPTIMAL: Sysmon 1 findstr/grep with password keywords · access to .env/web.config files · bulk file enumeration",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1: findstr.exe, grep, or Select-String with credential-related keywords (password, secret, credential, api_key). (2) File access monitoring: access to .env, web.config, appsettings.json by non-application processes. (3) Behavioral: rapid enumeration of multiple config files. (4) PREVENTION: Use secret management (Azure Key Vault, HashiCorp Vault), avoid hardcoded credentials, credential scanning in CI/CD.",
      src: "MITRE T1552.001; Sysmon" },

    { id: "creds_found", label: "Credentials", sub: "Harvested", x: 730, y: 220, r: 40, type: "source",
      tags: ["DB passwords", "API keys", "Service accounts", "Plaintext creds"],
      telemetry: [],
      api: "Harvested credentials: database passwords, API keys, service account credentials, SSH keys",
      artifact: "Plaintext credentials for databases, APIs, service accounts, cloud services",
      desc: "Yields variety of credentials: database connection strings, API keys and tokens, service account passwords, cloud provider credentials, SSH private keys, application secrets, and admin passwords stored in documentation.",
      src: "MITRE T1552.001" },
  ],

  edges: [
    { f: "config_files", t: "search" },
    { f: "scripts", t: "search" },
    { f: "logs_notes", t: "search" },
    { f: "search", t: "ev_detect" },
    { f: "ev_detect", t: "creds_found" },
  ],
};

export default model;
