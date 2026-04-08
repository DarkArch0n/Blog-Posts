// T1556.002 — Password Filter DLL — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.002",
    name: "Password Filter DLL",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "REGISTER",     x: 80 },
      { label: "TRIGGER",      x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "reg_filter", label: "Register DLL", sub: "Notification Pkgs", x: 80, y: 130, r: 38, type: "source",
      tags: ["HKLM\\...\\Lsa\\Notification Packages", "DLL in System32"],
      telemetry: ["Sysmon 13", "Sysmon 11"],
      api: "Add DLL name to HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages + copy DLL to system32",
      artifact: "Sysmon EID 13: registry value change · EID 11: new DLL in system32",
      desc: "Windows calls registered password filter DLLs during password change operations. Attacker registers a malicious DLL by: (1) adding the DLL name to the 'Notification Packages' REG_MULTI_SZ value, (2) placing the DLL in C:\\Windows\\System32. The DLL is loaded by LSASS on next boot or policy refresh.",
      src: "MITRE ATT&CK T1556.002; Microsoft Password Filters" },

    { id: "mal_dll", label: "Malicious DLL", sub: "PasswordChangeNotify", x: 80, y: 320, r: 34, type: "source",
      tags: ["PasswordChangeNotify()", "PasswordFilter()", "Plaintext capture"],
      telemetry: [],
      api: "DLL exports PasswordChangeNotify(UserName, Password) and PasswordFilter()",
      artifact: "DLL receives plaintext new password every time user changes password",
      desc: "The malicious DLL implements PasswordChangeNotify() which receives the username and new plaintext password, and PasswordFilter() which receives the username, old password, and new password. Both are called by LSASS during password change operations with the plaintext passwords.",
      src: "MITRE T1556.002; Microsoft Password Filter reference" },

    { id: "pwd_change", label: "Password Change", sub: "Any user", x: 270, y: 200, r: 38, type: "source",
      tags: ["Password rotation", "User password change", "Admin reset"],
      telemetry: ["Windows 4723", "Windows 4724"],
      api: "Any domain user password change triggers the filter: user self-service + admin resets",
      artifact: "Windows 4723: user changed password · 4724: admin reset password",
      desc: "Every password change in the domain triggers all registered password filter DLLs. This includes: user self-service password changes, admin password resets, scheduled password rotations. The malicious filter DLL receives the plaintext new password for every change event.",
      src: "MITRE T1556.002" },

    { id: "ev_detect", label: "Registry + DLL", sub: "LSASS loads", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Sysmon 13 Reg", "Sysmon 7 DLL load", "Notification Packages", "LSASS DLL audit"],
      telemetry: ["Sysmon 13", "Sysmon 7", "Sysmon 11"],
      api: "Sysmon 13: monitor Notification Packages registry + Sysmon 7: DLL loads in LSASS",
      artifact: "OPTIMAL: Sysmon 13 Notification Packages change · EID 7 new DLL in LSASS · new file in system32",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 13: modification of HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages — compare against baseline. (2) Sysmon EID 7: new or unsigned DLL loaded by lsass.exe. (3) Sysmon EID 11: new DLL file created in system32. (4) Baseline: known-good Notification Packages values (typically just 'scecli'). (5) PREVENTION: Application whitelisting for DLLs loaded by LSASS, RunAsPPL.",
      src: "MITRE T1556.002; Sysmon; ACSC advisory" },

    { id: "harvest", label: "Plaintext Pwd", sub: "On every change", x: 730, y: 200, r: 38, type: "source",
      tags: ["New plaintext passwords", "Continuous capture", "Exfiltrated"],
      telemetry: [],
      api: "Every password change yields plaintext old + new password — logged or exfiltrated",
      artifact: "Plaintext passwords captured from every password change event",
      desc: "The malicious password filter captures plaintext passwords from every change event. Credentials may be logged to a file on disk, sent to an attacker's C2 server, or stored in an alternate data stream. Since password rotation is common in enterprise environments, provides a steady stream of fresh credentials.",
      src: "MITRE T1556.002" },
  ],

  edges: [
    { f: "reg_filter", t: "pwd_change" },
    { f: "mal_dll", t: "pwd_change" },
    { f: "pwd_change", t: "ev_detect" },
    { f: "ev_detect", t: "harvest" },
  ],
};

export default model;
