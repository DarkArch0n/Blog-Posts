// T1556.002 — Password Filter DLL — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1556.002",
    name: "Password Filter DLL",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1350,
    svgHeight: 300,
    rows: [
      { label: "INSTALL",  y: 80 },
      { label: "CAPTURE",  y: 200 },
    ],
  },

  nodes: [
    { id: "admin", label: "Admin on DC", x: 60, y: 130, r: 36, type: "entry",
      desc: "Local admin on DC to register password filter DLL and place it in System32.",
      src: "MITRE ATT&CK T1556.002" },

    // Row 1: Installation
    { id: "drop_dll", label: "Drop DLL", sub: "System32\\", x: 200, y: 80, r: 34, type: "op",
      desc: "Place malicious password filter DLL in C:\\Windows\\System32\\.",
      src: "MITRE T1556.002" },
    { id: "reg_modify", label: "Registry Modify", sub: "Notification Packages", x: 380, y: 80, r: 38, type: "op",
      desc: "Add DLL name to HKLM\\SYSTEM\\CCS\\Control\\Lsa\\Notification Packages (REG_MULTI_SZ).",
      src: "Microsoft; MITRE T1556.002" },
    { id: "regsetvalue", label: "RegSetValueEx", x: 560, y: 80, r: 30, type: "api",
      desc: "RegSetValueEx() modifies Notification Packages registry value.",
      src: "Microsoft Win32 API" },
    { id: "reboot", label: "DC Reboot", sub: "DLL loaded", x: 700, y: 80, r: 30, type: "system",
      desc: "DLL loaded into LSASS on next DC reboot. Password filter activated.",
      src: "Microsoft" },

    // Row 2: Password capture
    { id: "lsass_load", label: "LSASS Loads", sub: "Password filter", x: 380, y: 200, r: 38, type: "system",
      desc: "LSASS loads DLL and calls PasswordChangeNotify() on every password change.",
      src: "Microsoft Password Filter API" },
    { id: "pwd_notify", label: "PasswordChange", sub: "Notify()", x: 560, y: 200, r: 38, type: "api",
      desc: "PasswordChangeNotify(AccountName, FullName, NewPassword) — receives plaintext new password!",
      src: "Microsoft Password Filter API" },
    { id: "log_capture", label: "Log / Exfil", sub: "Plaintext passwords", x: 720, y: 200, r: 36, type: "op",
      desc: "DLL logs plaintext password to file, writes to registry, or sends to attacker C2.",
      src: "MITRE T1556.002" },

    // ── Detection ──
    { id: "sysmon_13", label: "Sysmon 13", sub: "Registry modify", x: 380, y: 270, r: 36, type: "detect",
      desc: "OPTIMAL: Sysmon EID 13: Registry value set on Notification Packages. Critical alert.",
      src: "Sysmon documentation" },
    { id: "sysmon_7", label: "Sysmon 7", sub: "DLL load LSASS", x: 560, y: 270, r: 32, type: "detect",
      desc: "Sysmon EID 7: New DLL loaded into LSASS. Cross-reference with Notification Packages.",
      src: "Sysmon documentation" },
    { id: "sysmon_11", label: "Sysmon 11", sub: "System32 FileCreate", x: 200, y: 270, r: 30, type: "detect",
      desc: "Sysmon EID 11: New DLL file created in System32 directory.",
      src: "Sysmon documentation" },

    // ── Output ──
    { id: "all_pwds", label: "All New Passwords", x: 900, y: 200, r: 38, type: "artifact",
      desc: "Plaintext password for every password change in the domain. Continuous collection.",
      src: "MITRE T1556.002" },
  ],

  edges: [
    // Installation
    { f: "admin", t: "drop_dll" },
    { f: "admin", t: "reg_modify" },
    { f: "reg_modify", t: "regsetvalue" },
    { f: "regsetvalue", t: "reboot" },
    { f: "drop_dll", t: "reboot" },
    // Capture
    { f: "reboot", t: "lsass_load" },
    { f: "lsass_load", t: "pwd_notify" },
    { f: "pwd_notify", t: "log_capture" },
    { f: "log_capture", t: "all_pwds" },
    // Detection
    { f: "reg_modify", t: "sysmon_13" },
    { f: "lsass_load", t: "sysmon_7" },
    { f: "drop_dll", t: "sysmon_11" },
  ],
};

export default model;
