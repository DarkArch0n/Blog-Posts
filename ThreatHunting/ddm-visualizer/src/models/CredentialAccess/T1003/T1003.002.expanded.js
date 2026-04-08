// T1003.002 — SAM — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.002",
    name: "Security Account Manager",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 440,
    rows: [
      { label: "REG SAVE",   y: 80 },
      { label: "VSS COPY",   y: 180 },
      { label: "MIMIKATZ",   y: 280 },
      { label: "IMPACKET",   y: 380 },
    ],
  },

  nodes: [
    // ── Entry ──
    { id: "admin", label: "Local Admin", sub: "SYSTEM", x: 60, y: 180, r: 36, type: "entry",
      desc: "Local Administrator or SYSTEM required to read locked SAM and SYSTEM registry hives.",
      src: "MITRE ATT&CK T1003.002" },

    // Row 1: reg save path
    { id: "reg_save_sam", label: "reg save", sub: "HKLM\\SAM", x: 190, y: 80, r: 32, type: "op",
      desc: "reg save HKLM\\SAM sam.hiv — saves SAM hive to file. Built-in Windows binary.",
      src: "Microsoft reg.exe" },
    { id: "reg_save_sys", label: "reg save", sub: "HKLM\\SYSTEM", x: 330, y: 80, r: 32, type: "op",
      desc: "reg save HKLM\\SYSTEM system.hiv — saves SYSTEM hive (contains boot key for decryption).",
      src: "Microsoft reg.exe" },
    { id: "regopen_api", label: "RegOpenKeyEx", x: 190, y: 140, r: 30, type: "api",
      desc: "RegOpenKeyEx() opens SAM/SYSTEM registry keys with backup privilege.",
      src: "Microsoft Win32 API" },
    { id: "regsave_api", label: "RegSaveKey", x: 330, y: 140, r: 30, type: "api",
      desc: "RegSaveKey() writes hive to disk file.",
      src: "Microsoft Win32 API" },

    // Row 2: VSS path
    { id: "vssadmin", label: "vssadmin", sub: "create shadow", x: 190, y: 180, r: 34, type: "op",
      desc: "vssadmin create shadow /for=C: — creates Volume Shadow Copy to bypass file locks.",
      src: "Microsoft vssadmin" },
    { id: "vss_api", label: "IVssBackup", sub: "Components", x: 330, y: 180, r: 32, type: "api",
      desc: "VSS COM API IVssBackupComponents for shadow copy creation.",
      src: "Microsoft VSS API" },
    { id: "copy_hives", label: "copy SAM+SYS", sub: "from shadow", x: 480, y: 180, r: 34, type: "op",
      desc: "Copy SAM and SYSTEM from \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\",
      src: "MITRE T1003.002" },

    // Hive files
    { id: "hive_files", label: "SAM + SYSTEM", sub: "Hive files", x: 600, y: 130, r: 36, type: "artifact",
      desc: "SAM and SYSTEM registry hive files on disk. SAM contains user hashes, SYSTEM has boot key.",
      src: "MITRE T1003.002" },

    // Row 3: Mimikatz direct
    { id: "mimi_lsa", label: "Mimikatz", sub: "lsadump::sam", x: 190, y: 280, r: 34, type: "op",
      desc: "Mimikatz lsadump::sam — reads SAM directly from running registry (needs SYSTEM).",
      src: "gentilkiwi/mimikatz" },
    { id: "samsrv_api", label: "SamrQueryInfo", sub: "SamIConnect", x: 340, y: 280, r: 34, type: "api",
      desc: "Mimikatz uses SAM RPC APIs (SamIConnect, SamrQueryInformationUser) to read account hashes.",
      src: "MS-SAMR; gentilkiwi/mimikatz" },
    { id: "mimi_sys", label: "Mimikatz", sub: "lsadump::sam /system:", x: 190, y: 340, r: 32, type: "op",
      desc: "Offline: lsadump::sam /sam:sam.hiv /system:system.hiv — parses exported hive files.",
      src: "gentilkiwi/mimikatz" },

    // Row 4: Impacket secretsdump
    { id: "secretsdump", label: "secretsdump", sub: "-sam SAM", x: 190, y: 380, r: 34, type: "op",
      desc: "Impacket secretsdump.py -sam sam.hiv -system system.hiv LOCAL — offline extraction.",
      src: "fortra/impacket" },
    { id: "remote_dump", label: "secretsdump", sub: "-just-dc-user", x: 340, y: 380, r: 34, type: "op",
      desc: "Impacket secretsdump.py admin@target — remote SAM extraction via SMB + RemoteRegistry.",
      src: "fortra/impacket" },
    { id: "smb_445", label: "SMB :445", x: 480, y: 380, r: 28, type: "protocol",
      desc: "Remote secretsdump uses SMB over TCP/445 for RemoteRegistry + WinReg service.",
      src: "MS-SMB2; MS-RRP" },

    // ── Decryption ──
    { id: "boot_key", label: "Extract BootKey", sub: "from SYSTEM", x: 750, y: 130, r: 36, type: "api",
      desc: "Boot key (SysKey) extracted from SYSTEM hive — JD, Skew1, GBG, Data keys.",
      src: "Microsoft; secretsdump" },
    { id: "decrypt_sam", label: "Decrypt SAM", sub: "RC4/AES", x: 750, y: 280, r: 38, type: "api",
      desc: "SAM entries decrypted using boot key. Double-encryption: SysKey → per-account key → hash.",
      src: "Microsoft; mimikatz" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "reg.exe / vssadmin", x: 600, y: 60, r: 34, type: "detect",
      desc: "Sysmon EID 1: Process creation for reg.exe with 'save' and 'SAM'/'SYSTEM' arguments.",
      src: "Sysmon documentation" },
    { id: "ev_4656", label: "Event 4656", sub: "SAM Handle", x: 600, y: 320, r: 32, type: "detect",
      desc: "Event 4656: Handle requested to SAM registry key (\\REGISTRY\\MACHINE\\SAM).",
      src: "Microsoft Event 4656" },
    { id: "sysmon_11", label: "Sysmon 11", sub: "FileCreate .hiv", x: 750, y: 50, r: 30, type: "detect",
      desc: "Sysmon EID 11: File creation of .hiv/.save files from reg save output.",
      src: "Sysmon documentation" },

    // ── Output ──
    { id: "local_ntlm", label: "Local NTLM", sub: "Hashes", x: 920, y: 180, r: 36, type: "artifact",
      desc: "NT hashes for all local accounts: Administrator, Guest, any local accounts. LM:NT format.",
      src: "MITRE T1003.002" },
    { id: "pth", label: "Pass-the-Hash", sub: "T1550.002", x: 1060, y: 130, r: 34, type: "op",
      desc: "Extracted NTLM hashes used for pass-the-hash to other machines with same local admin password.",
      src: "MITRE T1550.002" },
    { id: "crack_hash", label: "hashcat", sub: "-m 1000", x: 1060, y: 240, r: 34, type: "blind",
      desc: "BLIND: Offline NTLM cracking. hashcat -m 1000. Zero logs.",
      src: "hashcat.net" },
  ],

  edges: [
    // reg save path
    { f: "admin", t: "reg_save_sam" },
    { f: "admin", t: "reg_save_sys" },
    { f: "reg_save_sam", t: "regopen_api" },
    { f: "reg_save_sys", t: "regsave_api" },
    { f: "regopen_api", t: "hive_files" },
    { f: "regsave_api", t: "hive_files" },
    // VSS path
    { f: "admin", t: "vssadmin" },
    { f: "vssadmin", t: "vss_api" },
    { f: "vss_api", t: "copy_hives" },
    { f: "copy_hives", t: "hive_files" },
    // Mimikatz direct
    { f: "admin", t: "mimi_lsa" },
    { f: "mimi_lsa", t: "samsrv_api" },
    { f: "samsrv_api", t: "decrypt_sam" },
    // Mimikatz offline
    { f: "hive_files", t: "mimi_sys" },
    { f: "mimi_sys", t: "boot_key" },
    // Impacket
    { f: "hive_files", t: "secretsdump" },
    { f: "secretsdump", t: "boot_key" },
    { f: "admin", t: "remote_dump" },
    { f: "remote_dump", t: "smb_445" },
    { f: "smb_445", t: "hive_files" },
    // Decryption
    { f: "hive_files", t: "boot_key" },
    { f: "boot_key", t: "decrypt_sam" },
    { f: "decrypt_sam", t: "local_ntlm" },
    // Detection
    { f: "reg_save_sam", t: "sysmon_1" },
    { f: "reg_save_sys", t: "sysmon_1" },
    { f: "vssadmin", t: "sysmon_1" },
    { f: "hive_files", t: "sysmon_11" },
    { f: "mimi_lsa", t: "ev_4656" },
    // Output
    { f: "local_ntlm", t: "pth" },
    { f: "local_ntlm", t: "crack_hash", blind: true },
  ],
};

export default model;
