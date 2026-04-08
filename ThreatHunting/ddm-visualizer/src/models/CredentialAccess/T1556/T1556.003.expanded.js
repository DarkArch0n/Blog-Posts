// T1556.003 — Pluggable Authentication Modules — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.003", name: "Pluggable Authentication Modules", tactic: "Credential Access", platform: "Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 340, rows: [{ label: "PAM BACKDOOR", y: 80 }, { label: "PAM LOGGING", y: 200 }] },
  nodes: [
    { id: "root", label: "Root Access", x: 60, y: 130, r: 36, type: "entry", desc: "Root required to modify PAM configuration or replace PAM modules.", src: "MITRE ATT&CK T1556.003" },
    { id: "pam_patch", label: "Patch pam_unix.so", sub: "Add backdoor", x: 220, y: 80, r: 38, type: "op", desc: "Modify pam_unix.so to accept a hardcoded master password in addition to real password.", src: "MITRE T1556.003" },
    { id: "pam_conf", label: "/etc/pam.d/", sub: "Add module", x: 220, y: 140, r: 30, type: "op", desc: "Add malicious PAM module to /etc/pam.d/common-auth or specific service config.", src: "Linux PAM" },
    { id: "pam_sm_auth", label: "pam_sm_authenticate", x: 420, y: 80, r: 38, type: "api", desc: "PAM calls pam_sm_authenticate() in module. Backdoored version accepts master password.", src: "Linux PAM API" },
    { id: "ssh_login", label: "SSH/su Login", sub: "PAM stack", x: 600, y: 80, r: 34, type: "system", desc: "SSH, su, sudo, login all use PAM stack. Backdoor grants access to any account.", src: "OpenSSH PAM; Linux login" },
    { id: "pam_log", label: "Logging Module", sub: "pam_log_creds.so", x: 220, y: 200, r: 36, type: "op", desc: "Custom PAM module that logs credentials to file: username + plaintext password on every auth.", src: "MITRE T1556.003" },
    { id: "pam_get_item", label: "pam_get_item", sub: "PAM_AUTHTOK", x: 420, y: 200, r: 34, type: "api", desc: "pam_get_item(PAM_AUTHTOK) retrieves plaintext password from PAM conversation.", src: "Linux PAM API" },
    { id: "write_log", label: "Write /tmp/.log", sub: "user:password", x: 600, y: 200, r: 34, type: "artifact", desc: "Credentials written to hidden log file. Can be exfiltrated by attacker.", src: "MITRE T1556.003" },
    { id: "auditd", label: "auditd", sub: "/lib/security/ modify", x: 420, y: 280, r: 38, type: "detect", desc: "OPTIMAL: auditd or AIDE: monitor /lib/security/ and /lib64/security/ for PAM module changes.", src: "Linux auditd; AIDE" },
    { id: "fim", label: "FIM", sub: "File Integrity", x: 600, y: 280, r: 34, type: "detect", desc: "File integrity monitoring on PAM config files and module binaries. Hash comparison.", src: "OSSEC; Wazuh; AIDE" },
    { id: "auth_log", label: "auth.log", sub: "Anomalies", x: 220, y: 280, r: 30, type: "detect", desc: "Monitor /var/log/auth.log for authentication from unusual sources while PAM is modified.", src: "Linux syslog" },
    { id: "all_accounts", label: "All Accounts", sub: "Master password", x: 800, y: 80, r: 36, type: "artifact", desc: "Access any account with master password. SSH, su, sudo all compromised.", src: "MITRE T1556.003" },
    { id: "all_pwds", label: "All Passwords", sub: "Plaintext log", x: 800, y: 200, r: 36, type: "artifact", desc: "Continuous plaintext password capture for every authentication event.", src: "MITRE T1556.003" },
  ],
  edges: [
    { f: "root", t: "pam_patch" }, { f: "root", t: "pam_conf" },
    { f: "pam_patch", t: "pam_sm_auth" }, { f: "pam_conf", t: "pam_sm_auth" },
    { f: "pam_sm_auth", t: "ssh_login" }, { f: "ssh_login", t: "all_accounts" },
    { f: "root", t: "pam_log" }, { f: "pam_log", t: "pam_get_item" },
    { f: "pam_get_item", t: "write_log" }, { f: "write_log", t: "all_pwds" },
    { f: "pam_patch", t: "auditd" }, { f: "pam_conf", t: "fim" },
    { f: "pam_log", t: "auditd" }, { f: "ssh_login", t: "auth_log" },
  ],
};
export default model;
