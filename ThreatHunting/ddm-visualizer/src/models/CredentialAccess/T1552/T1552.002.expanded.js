// T1552.002 — Credentials in Registry — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.002", name: "Credentials in Registry", tactic: "Credential Access", platform: "Windows", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 340, rows: [{ label: "AUTOLOGON", y: 80 }, { label: "VNCTIGHT", y: 180 }, { label: "CUSTOM", y: 260 }] },
  nodes: [
    { id: "access", label: "Local Access", x: 60, y: 150, r: 36, type: "entry", desc: "Local access to Windows system. Registry readable by local users (some keys need admin).", src: "MITRE ATT&CK T1552.002" },
    { id: "autologon", label: "reg query", sub: "Winlogon AutoAdminLogon", x: 220, y: 80, r: 38, type: "op", desc: "reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v DefaultPassword", src: "MITRE T1552.002" },
    { id: "regquery_api", label: "RegQueryValueEx", x: 420, y: 80, r: 32, type: "api", desc: "RegQueryValueEx() reads DefaultUserName and DefaultPassword values.", src: "Microsoft Win32 API" },
    { id: "autologon_pwd", label: "Autologon Password", sub: "Plaintext!", x: 600, y: 80, r: 36, type: "artifact", desc: "Plaintext domain or local password stored for auto-logon. Common in kiosks, shared machines.", src: "MITRE T1552.002" },
    { id: "vnc_reg", label: "VNC Registry", sub: "Password value", x: 220, y: 180, r: 34, type: "op", desc: "VNC stores password in HKCU\\SOFTWARE\\TightVNC or RealVNC\\WinVNC4. 3DES-encrypted with known key.", src: "MITRE T1552.002" },
    { id: "vnc_decrypt", label: "VNC Decrypt", sub: "Known fixed key", x: 420, y: 180, r: 34, type: "op", desc: "VNC password encrypted with hardcoded DES key. Trivially decryptable.", src: "VNC; HackTricks" },
    { id: "putty_reg", label: "PuTTY Registry", sub: "ProxyPassword", x: 220, y: 260, r: 32, type: "op", desc: "PuTTY stores proxy passwords in HKCU\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions\\.", src: "PuTTY" },
    { id: "winreg_scan", label: "Seatbelt", sub: "Registry scan", x: 420, y: 260, r: 34, type: "op", desc: "GhostPack Seatbelt: automated registry credential scanning across all known locations.", src: "GhostPack/Seatbelt" },
    { id: "sysmon_1", label: "Sysmon 1", sub: "reg.exe queries", x: 600, y: 180, r: 34, type: "detect", desc: "Sysmon EID 1: reg.exe query on known credential registry paths.", src: "Sysmon documentation" },
    { id: "ev_4663", label: "Event 4663", sub: "Registry audit", x: 600, y: 260, r: 34, type: "detect", desc: "OPTIMAL: Event 4663 with SACLs on Winlogon DefaultPassword key. Alerts on reads.", src: "Microsoft Event 4663; Registry SACL" },
    { id: "reg_creds", label: "Registry Creds", x: 800, y: 170, r: 36, type: "artifact", desc: "Autologon passwords, VNC passwords, PuTTY proxy passwords, service credentials.", src: "MITRE T1552.002" },
  ],
  edges: [
    { f: "access", t: "autologon" }, { f: "access", t: "vnc_reg" }, { f: "access", t: "putty_reg" }, { f: "access", t: "winreg_scan" },
    { f: "autologon", t: "regquery_api" }, { f: "regquery_api", t: "autologon_pwd" },
    { f: "vnc_reg", t: "vnc_decrypt" }, { f: "vnc_decrypt", t: "reg_creds" },
    { f: "autologon_pwd", t: "reg_creds" }, { f: "putty_reg", t: "reg_creds" }, { f: "winreg_scan", t: "reg_creds" },
    { f: "autologon", t: "sysmon_1" }, { f: "regquery_api", t: "ev_4663" },
  ],
};
export default model;
