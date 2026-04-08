// T1556.008 — Network Provider DLL — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.008",
    name: "Network Provider DLL",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "INSTALL",      x: 80 },
      { label: "LOGON EVENT",  x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "reg_provider", label: "Register DLL", sub: "Network Provider", x: 80, y: 130, r: 38, type: "source",
      tags: ["HKLM\\...\\NetworkProvider\\ProviderOrder", "NPLogonNotify", "Network Provider DLL"],
      telemetry: ["Sysmon 13"],
      api: "Register malicious DLL as network provider: HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\NetworkProvider",
      artifact: "Sysmon EID 13: registry key created under Services with NetworkProvider subkey · ProviderOrder modified",
      desc: "Windows Network Providers are DLLs loaded by mpnotify.exe during logon to handle network authentication (mapping drives, etc.). Attacker registers a malicious DLL as a new network provider. The DLL exports NPLogonNotify() which receives the user's plaintext credentials at logon.",
      src: "MITRE ATT&CK T1556.008; Microsoft Network Provider API" },

    { id: "dll_deploy", label: "Deploy DLL", sub: "System32 or path", x: 80, y: 320, r: 34, type: "source",
      tags: ["DLL in system32", "Custom path", "Signed/unsigned"],
      telemetry: ["Sysmon 11"],
      api: "Place malicious DLL in system32 or custom path referenced by ProviderPath registry value",
      artifact: "Sysmon EID 11: new DLL file created · hash of DLL for reputation lookup",
      desc: "The malicious DLL must be deployed to the filesystem. Typically placed in C:\\Windows\\System32 (matching legitimate providers) or a custom path specified in the ProviderPath registry value. The DLL must export NPLogonNotify() and NPGetCaps().",
      src: "MITRE T1556.008" },

    { id: "logon", label: "User Logon", sub: "Interactive", x: 270, y: 200, r: 40, type: "source",
      tags: ["Interactive logon", "RDP", "Console", "mpnotify.exe"],
      telemetry: ["Windows 4624"],
      api: "mpnotify.exe loads network providers and calls NPLogonNotify(username, password) at each logon",
      artifact: "Windows 4624: logon event · mpnotify.exe loads the malicious DLL · plaintext creds passed",
      desc: "At every interactive logon (console, RDP, unlock), mpnotify.exe loads all registered network provider DLLs and calls NPLogonNotify() with the user's plaintext username and password. The malicious provider captures these credentials. Called BEFORE the user's desktop appears.",
      src: "MITRE T1556.008; Microsoft Network Provider documentation" },

    { id: "ev_detect", label: "Registry + DLL", sub: "Provider audit", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Sysmon 13 registry", "Sysmon 7 DLL load", "ProviderOrder baseline", "mpnotify DLLs"],
      telemetry: ["Sysmon 13", "Sysmon 7", "Sysmon 11"],
      api: "Monitor ProviderOrder registry + DLL loads by mpnotify.exe + baseline network providers",
      artifact: "OPTIMAL: Sysmon 13 new network provider registered · EID 7 unknown DLL loaded by mpnotify.exe · non-baseline ProviderOrder",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 13: registry modification — new service with NetworkProvider subkey or ProviderOrder change. (2) Sysmon EID 7: DLL loads by mpnotify.exe — compare against known legitimate providers. (3) Baseline: standard ProviderOrder typically contains 'LanmanWorkstation,WebClient'. New entries are suspicious. (4) Sysmon EID 11: new DLL file in system32. (5) PREVENTION: Monitor ProviderOrder, application whitelisting.",
      src: "MITRE T1556.008; Sysmon" },

    { id: "creds_harvest", label: "Plaintext Pwd", sub: "Every logon", x: 730, y: 200, r: 40, type: "source",
      tags: ["Plaintext passwords", "Every interactive logon", "Continuous capture"],
      telemetry: [],
      api: "Plaintext credentials captured at every interactive logon via NPLogonNotify",
      artifact: "Credential log file or exfiltration via C2 · all interactive logon passwords",
      desc: "The malicious network provider captures plaintext credentials at every interactive logon event. Provides continuous credential harvesting: every time a user logs in, unlocks their workstation, or connects via RDP, their plaintext password is captured. Survives reboots (persists via registry).",
      src: "MITRE T1556.008" },
  ],

  edges: [
    { f: "reg_provider", t: "logon" },
    { f: "dll_deploy", t: "logon" },
    { f: "logon", t: "ev_detect" },
    { f: "ev_detect", t: "creds_harvest" },
  ],
};

export default model;
