// T1003.004 — LSA Secrets — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.004",
    name: "LSA Secrets",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 420,
    rows: [
      { label: "MIMIKATZ",  y: 80 },
      { label: "REG SAVE",  y: 180 },
      { label: "IMPACKET",  y: 280 },
      { label: "REMOTE",    y: 380 },
    ],
  },

  nodes: [
    { id: "admin", label: "SYSTEM / Admin", x: 60, y: 180, r: 36, type: "entry",
      desc: "SYSTEM or local administrator privilege. LSA Secrets stored in SECURITY registry hive.",
      src: "MITRE ATT&CK T1003.004" },

    // Row 1: Mimikatz direct
    { id: "mimi_lsa", label: "Mimikatz", sub: "lsadump::secrets", x: 200, y: 80, r: 34, type: "op",
      desc: "Mimikatz lsadump::secrets — reads LSA Secrets directly from running system.",
      src: "gentilkiwi/mimikatz" },
    { id: "lsaopen", label: "LsaOpenPolicy", x: 340, y: 80, r: 30, type: "api",
      desc: "LsaOpenPolicy() opens local LSA handle with POLICY_GET_PRIVATE_INFORMATION.",
      src: "Microsoft Win32 API" },
    { id: "lsaretrieve", label: "LsaRetrieve", sub: "PrivateData()", x: 480, y: 80, r: 34, type: "api",
      desc: "LsaRetrievePrivateData() retrieves individual LSA Secrets by name.",
      src: "Microsoft Win32 API" },

    // Row 2: reg save offline
    { id: "reg_security", label: "reg save", sub: "HKLM\\SECURITY", x: 200, y: 180, r: 34, type: "op",
      desc: "reg save HKLM\\SECURITY security.hiv — export SECURITY hive containing LSA Secrets.",
      src: "Microsoft reg.exe" },
    { id: "reg_system", label: "reg save", sub: "HKLM\\SYSTEM", x: 340, y: 180, r: 30, type: "op",
      desc: "Also need SYSTEM hive for boot key to decrypt SECURITY hive.",
      src: "Microsoft reg.exe" },
    { id: "hive_files", label: "SECURITY + SYS", sub: "Hive files", x: 500, y: 180, r: 34, type: "artifact",
      desc: "Exported SECURITY and SYSTEM registry hive files.",
      src: "MITRE T1003.004" },
    { id: "mimi_offline", label: "Mimikatz", sub: "lsadump::secrets /security:", x: 650, y: 180, r: 36, type: "op",
      desc: "Offline: lsadump::secrets /security:security.hiv /system:system.hiv",
      src: "gentilkiwi/mimikatz" },

    // Row 3: Impacket offline
    { id: "secretsdump", label: "secretsdump", sub: "-security", x: 650, y: 280, r: 36, type: "op",
      desc: "Impacket secretsdump.py -security security.hiv -system system.hiv LOCAL",
      src: "fortra/impacket" },

    // Row 4: Impacket remote
    { id: "remote_dump", label: "secretsdump", sub: "admin@target", x: 200, y: 380, r: 36, type: "op",
      desc: "Impacket secretsdump.py admin@target — remote LSA Secrets via SMB + RemoteRegistry.",
      src: "fortra/impacket" },
    { id: "smb_445", label: "SMB :445", x: 340, y: 380, r: 28, type: "protocol",
      desc: "Remote extraction over SMB TCP/445 using RemoteRegistry and WinReg RPC.",
      src: "MS-SMB2; MS-RRP" },
    { id: "winreg_rpc", label: "WinReg RPC", sub: "OpenKey/QueryValue", x: 480, y: 380, r: 34, type: "api",
      desc: "MS-RRP: Remote Registry Protocol to read SECURITY hive values.",
      src: "Microsoft MS-RRP" },

    // ── Decryption ──
    { id: "boot_key", label: "Boot Key", sub: "from SYSTEM", x: 800, y: 130, r: 30, type: "api",
      desc: "Boot key extracted from SYSTEM hive (JD, Skew1, GBG, Data classes).",
      src: "Microsoft; secretsdump" },
    { id: "lsa_key", label: "LSA Key", sub: "Decrypt chain", x: 800, y: 230, r: 34, type: "api",
      desc: "Boot key → LSA key → NLKM key → Cached domain creds, and Boot key → LSA Secret encryption keys.",
      src: "Microsoft; mimikatz" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "reg.exe SECURITY", x: 340, y: 250, r: 32, type: "detect",
      desc: "Sysmon EID 1: reg.exe process with 'save' and 'SECURITY' in command line.",
      src: "Sysmon documentation" },
    { id: "ev_4656", label: "Event 4656", sub: "SECURITY key access", x: 500, y: 300, r: 30, type: "detect",
      desc: "Event 4656: Handle to SECURITY registry key from unexpected process.",
      src: "Microsoft Event 4656" },

    // ── Output ──
    { id: "svc_passwords", label: "Service Acct", sub: "Passwords", x: 960, y: 80, r: 34, type: "artifact",
      desc: "Plaintext passwords for services configured to run as domain accounts.",
      src: "MITRE T1003.004" },
    { id: "machine_acct", label: "Machine Account", sub: "Password", x: 960, y: 180, r: 34, type: "artifact",
      desc: "Computer account password ($MACHINE.ACC) — can be used for Silver Ticket or domain operations.",
      src: "MITRE T1003.004" },
    { id: "dpapi_backup", label: "DPAPI Backup", sub: "Key", x: 960, y: 280, r: 34, type: "artifact",
      desc: "DPAPI system backup key — can decrypt any DPAPI-protected data on the machine.",
      src: "MITRE T1003.004" },
    { id: "cached_logons", label: "Cached Logons", sub: "DCC2 hashes", x: 960, y: 370, r: 34, type: "artifact",
      desc: "Domain Cached Credentials (DCC2/mscachev2) — last N domain logons cached locally.",
      src: "MITRE T1003.005" },
  ],

  edges: [
    // Mimikatz direct
    { f: "admin", t: "mimi_lsa" },
    { f: "mimi_lsa", t: "lsaopen" },
    { f: "lsaopen", t: "lsaretrieve" },
    { f: "lsaretrieve", t: "lsa_key" },
    // Reg save offline
    { f: "admin", t: "reg_security" },
    { f: "admin", t: "reg_system" },
    { f: "reg_security", t: "hive_files" },
    { f: "reg_system", t: "hive_files" },
    { f: "hive_files", t: "mimi_offline" },
    { f: "hive_files", t: "secretsdump" },
    // Remote
    { f: "admin", t: "remote_dump" },
    { f: "remote_dump", t: "smb_445" },
    { f: "smb_445", t: "winreg_rpc" },
    { f: "winreg_rpc", t: "hive_files" },
    // Decryption
    { f: "hive_files", t: "boot_key" },
    { f: "boot_key", t: "lsa_key" },
    { f: "mimi_offline", t: "lsa_key" },
    { f: "secretsdump", t: "lsa_key" },
    // Detection
    { f: "reg_security", t: "sysmon_1" },
    { f: "mimi_lsa", t: "ev_4656" },
    { f: "winreg_rpc", t: "ev_4656" },
    // Output
    { f: "lsa_key", t: "svc_passwords" },
    { f: "lsa_key", t: "machine_acct" },
    { f: "lsa_key", t: "dpapi_backup" },
    { f: "lsa_key", t: "cached_logons" },
  ],
};

export default model;
