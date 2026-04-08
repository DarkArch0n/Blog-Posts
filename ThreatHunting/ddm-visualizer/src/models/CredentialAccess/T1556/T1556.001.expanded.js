// T1556.001 — Domain Controller Authentication — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1556.001",
    name: "Domain Controller Authentication",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 340,
    rows: [
      { label: "SKELETON",  y: 80 },
      { label: "PATCH DC",  y: 200 },
    ],
  },

  nodes: [
    { id: "da_access", label: "DA on DC", sub: "SYSTEM access", x: 60, y: 130, r: 36, type: "entry",
      desc: "Domain Admin with SYSTEM access on Domain Controller. Can patch LSASS in-memory.",
      src: "MITRE ATT&CK T1556.001" },

    // Row 1: Skeleton Key
    { id: "mimi_skeleton", label: "Mimikatz", sub: "misc::skeleton", x: 220, y: 80, r: 38, type: "op",
      desc: "Mimikatz misc::skeleton — patches LSASS on DC to add universal password ('mimikatz' by default).",
      src: "gentilkiwi/mimikatz" },
    { id: "patch_lsass", label: "Patch LSASS", sub: "In-memory", x: 400, y: 80, r: 36, type: "api",
      desc: "Patches msv1_0!MsvpPasswordValidate and kerberos!KdcVerifyEncryptedTimeStamp in LSASS memory.",
      src: "gentilkiwi/mimikatz; MITRE T1556.001" },
    { id: "auth_bypass", label: "Auth Bypass", sub: "Any user + skeleton pwd", x: 600, y: 80, r: 40, type: "system",
      desc: "Any domain account now accepts BOTH real password AND skeleton key password for authentication.",
      src: "MITRE T1556.001" },

    // Row 2: DC LSASS patching (generic)
    { id: "custom_patch", label: "Custom Patch", sub: "Auth validation", x: 220, y: 200, r: 34, type: "op",
      desc: "Custom LSASS patches: modify authentication validation to accept backdoor credentials.",
      src: "MITRE T1556.001" },
    { id: "writeproc", label: "WriteProcess", sub: "Memory()", x: 400, y: 200, r: 32, type: "api",
      desc: "WriteProcessMemory() to patch authentication functions in LSASS on the DC.",
      src: "Microsoft Win32 API" },
    { id: "ssp_custom", label: "Custom SSP", sub: "Backdoor DLL", x: 400, y: 260, r: 32, type: "op",
      desc: "Load custom Security Support Provider DLL that logs and/or accepts master credentials.",
      src: "MITRE T1547.005" },

    // ── Detection ──
    { id: "sysmon_10", label: "Sysmon 10", sub: "LSASS write access", x: 600, y: 200, r: 38, type: "detect",
      desc: "OPTIMAL: Sysmon EID 10 on DC: Process writing to lsass.exe with PROCESS_VM_WRITE.",
      src: "Sysmon documentation" },
    { id: "sysmon_7", label: "Sysmon 7", sub: "DLL load in LSASS", x: 600, y: 270, r: 32, type: "detect",
      desc: "Sysmon EID 7: Unsigned DLL loaded into LSASS on DC.",
      src: "Sysmon documentation" },
    { id: "mdi_skeleton", label: "MDI Alert", sub: "Skeleton key", x: 800, y: 130, r: 38, type: "detect",
      desc: "Microsoft Defender for Identity specifically detects Skeleton Key attack on DCs.",
      src: "Microsoft Defender for Identity" },
    { id: "reboot_clear", label: "DC Reboot", sub: "Clears patch", x: 800, y: 230, r: 30, type: "system",
      desc: "Skeleton Key only persists in memory. DC reboot removes the backdoor.",
      src: "MITRE T1556.001" },

    // ── Impact ──
    { id: "any_user", label: "Any User Access", sub: "Master password", x: 1000, y: 80, r: 36, type: "artifact",
      desc: "Authenticate as ANY domain user with the skeleton key password. Full domain access.",
      src: "MITRE T1556.001" },
    { id: "stealth", label: "Stealth Access", sub: "No password change", x: 1000, y: 200, r: 34, type: "artifact",
      desc: "Real user passwords still work. No password changes occur. Extremely stealthy persistence.",
      src: "MITRE T1556.001" },
  ],

  edges: [
    // Skeleton Key
    { f: "da_access", t: "mimi_skeleton" },
    { f: "mimi_skeleton", t: "patch_lsass" },
    { f: "patch_lsass", t: "auth_bypass" },
    // Custom patch
    { f: "da_access", t: "custom_patch" },
    { f: "custom_patch", t: "writeproc" },
    { f: "custom_patch", t: "ssp_custom" },
    { f: "writeproc", t: "auth_bypass" },
    // Detection
    { f: "patch_lsass", t: "sysmon_10" },
    { f: "writeproc", t: "sysmon_10" },
    { f: "ssp_custom", t: "sysmon_7" },
    { f: "auth_bypass", t: "mdi_skeleton" },
    { f: "auth_bypass", t: "reboot_clear" },
    // Impact
    { f: "auth_bypass", t: "any_user" },
    { f: "auth_bypass", t: "stealth" },
  ],
};

export default model;
