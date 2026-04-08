// T1556.001 — Domain Controller Authentication — Detection Data Model
// Tactic: Credential Access / Defense Evasion / Persistence

const model = {
  metadata: {
    tcode: "T1556.001",
    name: "Domain Controller Authentication",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "DC ACCESS",    x: 80 },
      { label: "MODIFICATION", x: 270 },
      { label: "DETECTION",    x: 500 },
      { label: "OUTCOME",      x: 750 },
    ],
    separators: [175, 385, 625],
    annotations: [
      { text: "Skeleton Key turns DC into a backdoor", x: 270, y: 420, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "dc_admin", label: "DC Admin", sub: "Domain Admin", x: 80, y: 200, r: 40, type: "source",
      tags: ["Domain Admin", "LSASS access", "Kernel driver"],
      telemetry: ["Windows 4624"],
      api: "Domain Admin or equivalent access to Domain Controller",
      artifact: "Interactive or remote logon to DC · DA-level privilege",
      desc: "Modifying DC authentication requires Domain Admin or equivalent privileges. The attacker must be able to execute code on the Domain Controller with sufficient privileges to patch LSASS memory or load a DLL into the LSASS process.",
      src: "MITRE ATT&CK T1556.001" },

    { id: "skeleton", label: "Skeleton Key", sub: "Patch LSASS", x: 270, y: 130, r: 40, type: "source",
      tags: ["Mimikatz misc::skeleton", "LSASS patch", "Master password"],
      telemetry: ["Sysmon 7", "Sysmon 10"],
      api: "mimikatz misc::skeleton — patches NTLM and Kerberos auth in LSASS",
      artifact: "Sysmon 10: LSASS access · EID 7: DLL injection to LSASS · master password 'mimikatz'",
      desc: "Skeleton Key (Mimikatz misc::skeleton) patches the authentication routines in LSASS memory on a Domain Controller. It injects a master password ('mimikatz' by default) that works alongside all real passwords. Any account can authenticate with either their real password or the skeleton key password. Does not survive reboot.",
      src: "gentilkiwi/mimikatz; Dell SecureWorks Skeleton Key analysis; MITRE T1556.001" },

    { id: "custom_dll", label: "Custom Auth DLL", sub: "Replace/Hook", x: 270, y: 320, r: 36, type: "source",
      tags: ["Custom LSASS DLL", "Authentication filter", "Persist-through-reboot"],
      telemetry: ["Sysmon 7", "Sysmon 11"],
      api: "Replace or hook authentication DLLs loaded by LSASS on the DC",
      artifact: "Modified DLL in system32 · new DLL loaded by LSASS · hash mismatch",
      desc: "More persistent method: replace or patch authentication DLLs in system32 that LSASS loads at boot. This survives reboots unlike the in-memory Skeleton Key. The modified DLL accepts a backdoor password or logs plaintext credentials for the attacker.",
      src: "MITRE T1556.001" },

    { id: "ev_detect", label: "DC Integrity", sub: "DLL + memory", x: 500, y: 200, r: 50, type: "detect",
      tags: ["LSASS DLL integrity", "Sysmon 7 DLL loads", "Memory scanning", "File integrity"],
      telemetry: ["Sysmon 7", "Sysmon 10", "Sysmon 11"],
      api: "Monitor LSASS DLL loads + system32 file integrity + LSASS memory scanning",
      artifact: "OPTIMAL: Sysmon 7 unsigned DLL in LSASS · Sysmon 10 LSASS access · system32 file hash change · unusual auth patterns",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 7: unsigned or unknown DLL loaded by lsass.exe on DC. (2) Sysmon EID 10: cross-process access to LSASS with PROCESS_VM_WRITE (memory patching). (3) File integrity monitoring: changes to authentication DLLs in system32. (4) Behavioral: single account authenticating successfully from many sources with same pattern. (5) PREVENTION: Credential Guard, RunAsPPL for LSASS, restrict DC logon.",
      src: "MITRE T1556.001; Sysmon; Windows Credential Guard" },

    { id: "master_pwd", label: "Master Password", sub: "Any account", x: 750, y: 130, r: 38, type: "source",
      tags: ["Universal password", "Any domain account", "Skeleton Key password"],
      telemetry: [],
      api: "Skeleton key password authenticates as ANY domain user — bypasses real password",
      artifact: "Master password works for all accounts · used alongside real passwords",
      desc: "Skeleton Key provides a universal master password that authenticates as ANY domain account. The real passwords continue to work, so users don't notice anything. The attacker can use the skeleton key password to authenticate as any admin, access any resource, and move laterally to any system.",
      src: "MITRE T1556.001; Dell SecureWorks" },

    { id: "cred_log", label: "Cred Logging", sub: "Plaintext harvest", x: 750, y: 320, r: 36, type: "source",
      tags: ["Plaintext password log", "All authentication events", "Continuous harvest"],
      telemetry: [],
      api: "Modified auth DLL logs all plaintext passwords during legitimate authentication",
      artifact: "Log file with plaintext credentials for every user who authenticates",
      desc: "A modified authentication DLL on the DC can log plaintext credentials for every authentication event. Since all domain authentication flows through the DC, this captures credentials for every user in the domain as they log on, access resources, or renew tickets.",
      src: "MITRE T1556.001" },
  ],

  edges: [
    { f: "dc_admin", t: "skeleton" },
    { f: "dc_admin", t: "custom_dll" },
    { f: "skeleton", t: "ev_detect" },
    { f: "custom_dll", t: "ev_detect" },
    { f: "ev_detect", t: "master_pwd" },
    { f: "ev_detect", t: "cred_log" },
  ],
};

export default model;
