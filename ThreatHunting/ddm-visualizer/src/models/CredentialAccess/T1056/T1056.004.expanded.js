// T1056.004 — Credential API Hooking — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1056.004",
    name: "Credential API Hooking",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 380,
    rows: [
      { label: "IAT HOOK",   y: 80 },
      { label: "INLINE",     y: 180 },
      { label: "SSP",        y: 280 },
    ],
  },

  nodes: [
    { id: "admin", label: "Admin Access", sub: "Code injection", x: 60, y: 180, r: 36, type: "entry",
      desc: "Administrator/SYSTEM access for DLL injection into LSASS or authentication processes.",
      src: "MITRE ATT&CK T1056.004" },

    // Row 1: IAT Hooking
    { id: "dll_inject", label: "DLL Injection", sub: "CreateRemoteThread", x: 220, y: 80, r: 36, type: "op",
      desc: "Inject DLL into target process (LSASS, WinLogon) via CreateRemoteThread / NtCreateThreadEx.",
      src: "MITRE T1055.001" },
    { id: "iat_patch", label: "IAT Patch", sub: "Import Address Table", x: 400, y: 80, r: 36, type: "api",
      desc: "Overwrite Import Address Table entries for credential APIs (LsaLogonUser, LogonUser, CredUIPrompt).",
      src: "Microsoft PE format" },
    { id: "hook_func", label: "Hook Function", sub: "Log + call original", x: 580, y: 80, r: 38, type: "op",
      desc: "Hook function captures parameters (username, password), logs them, then calls original API.",
      src: "MITRE T1056.004" },

    // Row 2: Inline Hooking
    { id: "detours", label: "Detours", sub: "MS Research", x: 220, y: 180, r: 34, type: "op",
      desc: "Microsoft Detours library or MinHook for inline function hooking in target process.",
      src: "Microsoft Research Detours" },
    { id: "jmp_patch", label: "JMP Patch", sub: "First 5 bytes", x: 400, y: 180, r: 34, type: "api",
      desc: "Overwrites first 5 bytes of target function with JMP to hook. VirtualProtect + WriteProcessMemory.",
      src: "Inline hooking technique" },
    { id: "trampoline", label: "Trampoline", sub: "Original + hook", x: 580, y: 180, r: 34, type: "api",
      desc: "Trampoline preserves original function bytes so hook can call through to real implementation.",
      src: "MinHook; Detours" },

    // Row 3: SSP (Security Support Provider)
    { id: "mimi_memssp", label: "Mimikatz", sub: "misc::memssp", x: 220, y: 280, r: 36, type: "op",
      desc: "Mimikatz misc::memssp patches LSASS in-memory to log plaintext credentials on authentication.",
      src: "gentilkiwi/mimikatz" },
    { id: "addssp", label: "AddSecurityPackage", x: 400, y: 280, r: 36, type: "api",
      desc: "AddSecurityPackage() loads custom SSP DLL into LSASS. Captures all future logon credentials.",
      src: "Microsoft SSPI; MITRE T1547.005" },
    { id: "ssp_log", label: "SSP Logging", sub: "SpAcceptCredentials", x: 580, y: 280, r: 36, type: "api",
      desc: "Custom SSP implements SpAcceptCredentials() — called by LSASS with plaintext username:password on every logon.",
      src: "Microsoft SSPI; mimilib" },

    // ── Log output ──
    { id: "log_file", label: "Credential Log", sub: "C:\\Windows\\Temp\\", x: 740, y: 180, r: 36, type: "artifact",
      desc: "Captured credentials logged to file (mimilsa.log for memssp, custom path for SSP DLL).",
      src: "gentilkiwi/mimikatz" },

    // ── Detection ──
    { id: "sysmon_7", label: "Sysmon 7", sub: "DLL Load in LSASS", x: 400, y: 350, r: 36, type: "detect",
      desc: "OPTIMAL: Sysmon EID 7: Image loaded into lsass.exe. Unsigned/unknown DLL = highly suspicious.",
      src: "Sysmon documentation" },
    { id: "sysmon_10", label: "Sysmon 10", sub: "LSASS access", x: 220, y: 350, r: 32, type: "detect",
      desc: "Sysmon EID 10: Process access to lsass.exe with write permissions for injection.",
      src: "Sysmon documentation" },
    { id: "edr_hook", label: "EDR", sub: "API hook detection", x: 740, y: 300, r: 38, type: "detect",
      desc: "EDR detects inline/IAT hooks in credential-related DLLs. Memory integrity scanning.",
      src: "CrowdStrike; Carbon Black" },
    { id: "reg_ssp", label: "Registry", sub: "Security Packages", x: 580, y: 350, r: 30, type: "detect",
      desc: "Monitor HKLM\\SYSTEM\\CCS\\Control\\Lsa\\Security Packages for new SSP DLL additions.",
      src: "Microsoft; Sysmon 13" },

    // ── Output ──
    { id: "plaintext", label: "Plaintext Creds", sub: "All logons", x: 920, y: 180, r: 38, type: "artifact",
      desc: "Plaintext credentials for every authentication event — interactive, network, RDP, service logons.",
      src: "MITRE T1056.004" },
  ],

  edges: [
    // IAT hooking
    { f: "admin", t: "dll_inject" },
    { f: "dll_inject", t: "iat_patch" },
    { f: "iat_patch", t: "hook_func" },
    { f: "hook_func", t: "log_file" },
    // Inline hooking
    { f: "admin", t: "detours" },
    { f: "detours", t: "jmp_patch" },
    { f: "jmp_patch", t: "trampoline" },
    { f: "trampoline", t: "log_file" },
    // SSP
    { f: "admin", t: "mimi_memssp" },
    { f: "mimi_memssp", t: "addssp" },
    { f: "addssp", t: "ssp_log" },
    { f: "ssp_log", t: "log_file" },
    // Detection
    { f: "dll_inject", t: "sysmon_10" },
    { f: "dll_inject", t: "sysmon_7" },
    { f: "addssp", t: "sysmon_7" },
    { f: "addssp", t: "reg_ssp" },
    { f: "hook_func", t: "edr_hook" },
    // Output
    { f: "log_file", t: "plaintext" },
  ],
};

export default model;
