// T1003.001 — LSASS Memory — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.001",
    name: "LSASS Memory",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1550,
    svgHeight: 560,
    rows: [
      { label: "MIMIKATZ",   y: 80 },
      { label: "PROCDUMP",   y: 180 },
      { label: "COMSVCS",    y: 280 },
      { label: "NANODUMP",   y: 380 },
      { label: "DIRECT",     y: 480 },
    ],
  },

  nodes: [
    // ── Entry ──
    { id: "admin", label: "Local Admin", sub: "SeDebugPrivilege", x: 60, y: 280, r: 36, type: "entry",
      desc: "Local administrator or SeDebugPrivilege required to access LSASS process memory.",
      src: "MITRE ATT&CK T1003.001" },

    // Row 1: Mimikatz sekurlsa
    { id: "mimi_sekurlsa", label: "Mimikatz", sub: "sekurlsa::logonpasswords", x: 190, y: 80, r: 34, type: "op",
      desc: "Reads LSASS memory in-process. Extracts NTLM hashes, Kerberos tickets, plaintext passwords.",
      src: "gentilkiwi/mimikatz" },
    { id: "openprocess_1", label: "OpenProcess", sub: "PROCESS_VM_READ", x: 340, y: 80, r: 34, type: "api",
      desc: "OpenProcess() with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ on lsass.exe PID.",
      src: "Microsoft Win32 API" },
    { id: "readmem_1", label: "ReadProcess", sub: "Memory()", x: 480, y: 80, r: 34, type: "api",
      desc: "ReadProcessMemory() reads credential structures from LSASS virtual memory.",
      src: "Microsoft Win32 API" },
    { id: "bcrypt_decrypt", label: "BCryptDecrypt", sub: "(LSA keys)", x: 620, y: 80, r: 34, type: "api",
      desc: "BCryptDecrypt() with extracted LSA session keys to decrypt cached credentials.",
      src: "Microsoft Crypto API; mimikatz" },

    // Row 2: Procdump
    { id: "procdump", label: "procdump.exe", sub: "-ma lsass", x: 190, y: 180, r: 34, type: "op",
      desc: "Sysinternals ProcDump: procdump -ma lsass.exe lsass.dmp — creates full memory dump.",
      src: "Microsoft Sysinternals ProcDump" },
    { id: "minidump_2", label: "MiniDumpWriteDump", x: 340, y: 180, r: 38, type: "api",
      desc: "dbghelp!MiniDumpWriteDump() creates minidump file of LSASS process memory.",
      src: "Microsoft Debug Help Library" },
    { id: "dmp_file", label: "lsass.dmp", sub: "File on disk", x: 500, y: 180, r: 30, type: "artifact",
      desc: "LSASS memory dump file written to disk. Can be exfiltrated for offline analysis.",
      src: "MITRE T1003.001" },
    { id: "mimi_offline", label: "Mimikatz", sub: "sekurlsa::minidump", x: 640, y: 180, r: 36, type: "op",
      desc: "Offline: sekurlsa::minidump lsass.dmp — parse dump on attacker machine.",
      src: "gentilkiwi/mimikatz" },

    // Row 3: comsvcs.dll MiniDump
    { id: "comsvcs", label: "rundll32", sub: "comsvcs.dll,MiniDump", x: 190, y: 280, r: 36, type: "op",
      desc: "LOTL: rundll32 comsvcs.dll,MiniDump <PID> dump.bin full — uses built-in DLL.",
      src: "LOLBAS; MITRE T1003.001" },
    { id: "minidump_3", label: "MiniDumpWriteDump", x: 340, y: 280, r: 36, type: "api",
      desc: "comsvcs.dll internally calls MiniDumpWriteDump() — same API path as ProcDump.",
      src: "Microsoft comsvcs.dll" },

    // Row 4: nanodump (direct syscalls)
    { id: "nanodump", label: "nanodump", sub: "Direct syscalls", x: 190, y: 380, r: 34, type: "op",
      desc: "nanodump uses direct NT syscalls (NtReadVirtualMemory) to bypass API hooking by EDR.",
      src: "helpsystems/nanodump" },
    { id: "ntread_vm", label: "NtReadVirtual", sub: "Memory()", x: 340, y: 380, r: 34, type: "api",
      desc: "Direct NT syscall NtReadVirtualMemory — bypasses user-mode API hooks from EDR.",
      src: "Windows NT syscalls; nanodump" },
    { id: "custom_dump", label: "Custom Dump", sub: "No dbghelp", x: 500, y: 380, r: 32, type: "op",
      desc: "nanodump creates custom-format dump without using MiniDumpWriteDump, evading signatures.",
      src: "helpsystems/nanodump" },

    // Row 5: Direct registry SAM fallback / Task Manager
    { id: "taskmgr", label: "Task Manager", sub: "Create dump file", x: 190, y: 480, r: 34, type: "op",
      desc: "Right-click lsass.exe → Create dump file. Built-in Windows functionality.",
      src: "Microsoft Task Manager" },
    { id: "minidump_5", label: "MiniDumpWriteDump", x: 340, y: 480, r: 34, type: "api",
      desc: "Task Manager uses same MiniDumpWriteDump() API path.",
      src: "Microsoft" },

    // ── Detection Layer ──
    { id: "sysmon_10", label: "Sysmon 10", sub: "LSASS Access", x: 760, y: 180, r: 42, type: "detect",
      desc: "OPTIMAL: Sysmon EID 10 — ProcessAccess to lsass.exe. Key fields: SourceImage, GrantedAccess (0x1010, 0x1FFFFF).",
      src: "Sysmon documentation; MITRE T1003.001" },
    { id: "sysmon_1", label: "Sysmon 1", sub: "Process Create", x: 760, y: 80, r: 34, type: "detect",
      desc: "Sysmon EID 1: Process creation for mimikatz.exe, procdump.exe, or rundll32 comsvcs.",
      src: "Sysmon documentation" },
    { id: "sysmon_11", label: "Sysmon 11", sub: "FileCreate .dmp", x: 760, y: 300, r: 34, type: "detect",
      desc: "Sysmon EID 11: File creation of .dmp files. Detects dump-to-disk operations.",
      src: "Sysmon documentation" },
    { id: "ev_4656", label: "Event 4656", sub: "Handle Request", x: 760, y: 410, r: 34, type: "detect",
      desc: "Security Event 4656: A handle was requested to lsass.exe object.",
      src: "Microsoft Event 4656" },

    // ── LSASS Process ──
    { id: "lsass", label: "lsass.exe", sub: "Credential Store", x: 900, y: 250, r: 44, type: "system",
      desc: "LSASS process holds: NTLM hashes, Kerberos tickets/keys, WDigest plaintext (if enabled), TSPKG, etc.",
      src: "Microsoft LSASS; MITRE T1003.001" },

    // ── Protection Mechanisms ──
    { id: "ppl", label: "RunAsPPL", sub: "LSA Protection", x: 1050, y: 150, r: 34, type: "system",
      desc: "LSASS Protected Process Light (PPL) — blocks unsigned code from opening LSASS. Bypassable with kernel driver.",
      src: "Microsoft LSA Protection" },
    { id: "cred_guard", label: "Credential Guard", sub: "VBS Isolation", x: 1050, y: 300, r: 36, type: "system",
      desc: "Credential Guard uses Hyper-V VBS to isolate NTLM/Kerberos secrets from LSASS. Best mitigation.",
      src: "Microsoft Credential Guard" },

    // ── Credential Output ──
    { id: "ntlm_hash", label: "NTLM Hashes", x: 1200, y: 100, r: 32, type: "artifact",
      desc: "NT hash (MD4 of password). Used for pass-the-hash, relay attacks.",
      src: "MITRE T1003.001" },
    { id: "krb_tickets", label: "Kerberos TGTs", x: 1200, y: 200, r: 32, type: "artifact",
      desc: "Cached TGTs/TGS tickets. Used for pass-the-ticket attacks.",
      src: "MITRE T1003.001; T1550.003" },
    { id: "plaintext", label: "Plaintext Pwd", sub: "WDigest/TSPKG", x: 1200, y: 300, r: 34, type: "artifact",
      desc: "Plaintext passwords if WDigest auth enabled (pre-2012R2 default) or TSPKG (RDP).",
      src: "MITRE T1003.001" },
    { id: "dpapi_keys", label: "DPAPI Keys", x: 1200, y: 400, r: 30, type: "artifact",
      desc: "DPAPI master key backups cached in LSASS. Used to decrypt user secrets offline.",
      src: "MITRE T1003.001; T1555" },
  ],

  edges: [
    // Mimikatz path
    { f: "admin", t: "mimi_sekurlsa" },
    { f: "mimi_sekurlsa", t: "openprocess_1" },
    { f: "openprocess_1", t: "readmem_1" },
    { f: "readmem_1", t: "bcrypt_decrypt" },
    { f: "bcrypt_decrypt", t: "lsass" },

    // Procdump path
    { f: "admin", t: "procdump" },
    { f: "procdump", t: "minidump_2" },
    { f: "minidump_2", t: "dmp_file" },
    { f: "dmp_file", t: "mimi_offline" },
    { f: "mimi_offline", t: "lsass" },

    // comsvcs path
    { f: "admin", t: "comsvcs" },
    { f: "comsvcs", t: "minidump_3" },
    { f: "minidump_3", t: "dmp_file" },

    // nanodump path
    { f: "admin", t: "nanodump" },
    { f: "nanodump", t: "ntread_vm" },
    { f: "ntread_vm", t: "custom_dump" },
    { f: "custom_dump", t: "lsass" },

    // Task Manager path
    { f: "admin", t: "taskmgr" },
    { f: "taskmgr", t: "minidump_5" },
    { f: "minidump_5", t: "dmp_file" },

    // Detection
    { f: "openprocess_1", t: "sysmon_10" },
    { f: "minidump_2", t: "sysmon_10" },
    { f: "minidump_3", t: "sysmon_10" },
    { f: "ntread_vm", t: "ev_4656" },
    { f: "mimi_sekurlsa", t: "sysmon_1" },
    { f: "procdump", t: "sysmon_1" },
    { f: "comsvcs", t: "sysmon_1" },
    { f: "dmp_file", t: "sysmon_11" },

    // Protections
    { f: "lsass", t: "ppl" },
    { f: "lsass", t: "cred_guard" },

    // Output
    { f: "lsass", t: "ntlm_hash" },
    { f: "lsass", t: "krb_tickets" },
    { f: "lsass", t: "plaintext" },
    { f: "lsass", t: "dpapi_keys" },
  ],
};

export default model;
