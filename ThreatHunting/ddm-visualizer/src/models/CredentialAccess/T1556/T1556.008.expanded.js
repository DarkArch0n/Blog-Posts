// T1556.008 — Network Provider DLL — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.008", name: "Network Provider DLL", tactic: "Credential Access", platform: "Windows", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "INSTALL", y: 80 }, { label: "CAPTURE", y: 200 }] },
  nodes: [
    { id: "admin", label: "Admin Access", x: 60, y: 130, r: 36, type: "entry", desc: "Local administrator to register custom Network Provider DLL.", src: "MITRE ATT&CK T1556.008" },
    { id: "drop_dll", label: "Drop DLL", sub: "System32\\", x: 200, y: 80, r: 32, type: "op", desc: "Place malicious Network Provider DLL in C:\\Windows\\System32\\.", src: "MITRE T1556.008" },
    { id: "reg_add", label: "Registry Add", sub: "NetworkProvider key", x: 380, y: 80, r: 36, type: "op", desc: "Add DLL to HKLM\\SYSTEM\\CCS\\Control\\NetworkProvider\\Order (ProviderOrder value).", src: "Microsoft; MITRE T1556.008" },
    { id: "nplogonnotify", label: "NPLogonNotify", sub: "MPR callback", x: 560, y: 80, r: 38, type: "api", desc: "MPR.dll calls NPLogonNotify() on each registered provider at logon — receives plaintext credentials.", src: "Microsoft MPR API" },
    { id: "winlogon", label: "Winlogon", sub: "Interactive logon", x: 380, y: 200, r: 36, type: "system", desc: "Winlogon calls MPR → NPLogonNotify with username, domain, and PLAINTEXT password.", src: "Microsoft Winlogon" },
    { id: "log_creds", label: "Log Credentials", x: 560, y: 200, r: 34, type: "op", desc: "DLL captures plaintext username:password and writes to file or sends to C2.", src: "MITRE T1556.008" },
    { id: "sysmon_13", label: "Sysmon 13", sub: "NetworkProvider reg", x: 380, y: 270, r: 36, type: "detect", desc: "OPTIMAL: Sysmon EID 13: Registry modification of NetworkProvider\\Order ProviderOrder value.", src: "Sysmon documentation" },
    { id: "sysmon_7", label: "Sysmon 7", sub: "DLL load mpnotify", x: 560, y: 270, r: 32, type: "detect", desc: "Sysmon EID 7: Unsigned DLL loaded by mpnotify.exe process at logon.", src: "Sysmon documentation" },
    { id: "plaintext", label: "Plaintext Creds", sub: "Every interactive logon", x: 760, y: 140, r: 38, type: "artifact", desc: "Plaintext password for every interactive logon (RDP, console, unlock).", src: "MITRE T1556.008" },
  ],
  edges: [
    { f: "admin", t: "drop_dll" }, { f: "admin", t: "reg_add" },
    { f: "reg_add", t: "nplogonnotify" }, { f: "drop_dll", t: "nplogonnotify" },
    { f: "winlogon", t: "nplogonnotify" }, { f: "nplogonnotify", t: "log_creds" },
    { f: "log_creds", t: "plaintext" },
    { f: "reg_add", t: "sysmon_13" }, { f: "nplogonnotify", t: "sysmon_7" },
  ],
};
export default model;
