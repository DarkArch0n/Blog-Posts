// T1003.005 — Cached Domain Credentials — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.005",
    name: "Cached Domain Credentials",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1350,
    svgHeight: 380,
    rows: [
      { label: "MIMIKATZ",  y: 80 },
      { label: "REG SAVE",  y: 180 },
      { label: "IMPACKET",  y: 280 },
    ],
  },

  nodes: [
    { id: "admin", label: "SYSTEM / Admin", x: 60, y: 150, r: 36, type: "entry",
      desc: "SYSTEM or local admin on target. Cached creds stored in SECURITY hive under NL$Control.",
      src: "MITRE ATT&CK T1003.005" },

    // Row 1: Mimikatz
    { id: "mimi_cache", label: "Mimikatz", sub: "lsadump::cache", x: 200, y: 80, r: 34, type: "op",
      desc: "Mimikatz lsadump::cache — reads cached domain logon entries from SECURITY hive.",
      src: "gentilkiwi/mimikatz" },
    { id: "nltest", label: "nltest", sub: "/dsgetdc:", x: 200, y: 140, r: 26, type: "op",
      desc: "nltest /dsgetdc:domain — verifies domain connectivity. Cached creds used when DC unavailable.",
      src: "Microsoft nltest" },
    { id: "lsa_api", label: "LsaOpenPolicy", sub: "+ RegQueryValueEx", x: 350, y: 80, r: 36, type: "api",
      desc: "Opens LSA + reads NL$1..NL$10 (cached logon entries) from SECURITY hive.",
      src: "Microsoft Win32 API" },

    // Row 2: Offline extraction
    { id: "reg_sec", label: "reg save", sub: "SECURITY + SYSTEM", x: 200, y: 180, r: 34, type: "op",
      desc: "Export SECURITY and SYSTEM hives for offline cached credential extraction.",
      src: "Microsoft reg.exe" },
    { id: "hives", label: "Hive Files", x: 350, y: 180, r: 30, type: "artifact",
      desc: "SECURITY hive (contains NL$ cached logon entries) + SYSTEM hive (boot key).",
      src: "MITRE T1003.005" },
    { id: "mimi_off", label: "Mimikatz", sub: "lsadump::cache /security:", x: 500, y: 140, r: 36, type: "op",
      desc: "Offline: lsadump::cache /security:security.hiv /system:system.hiv",
      src: "gentilkiwi/mimikatz" },

    // Row 3: Impacket
    { id: "secretsdump", label: "secretsdump", sub: "-security -cached", x: 500, y: 280, r: 36, type: "op",
      desc: "secretsdump.py -security security.hiv -system system.hiv LOCAL — extracts cached creds.",
      src: "fortra/impacket" },
    { id: "remote_sd", label: "secretsdump", sub: "admin@target", x: 200, y: 280, r: 34, type: "op",
      desc: "secretsdump.py admin@target — remote extraction via SMB + RemoteRegistry.",
      src: "fortra/impacket" },
    { id: "smb_445", label: "SMB :445", x: 350, y: 280, r: 28, type: "protocol",
      desc: "Remote extraction uses SMB/445 with RemoteRegistry service.",
      src: "MS-SMB2; MS-RRP" },

    // ── Decryption ──
    { id: "boot_key", label: "Boot Key", x: 650, y: 100, r: 28, type: "api",
      desc: "Boot key from SYSTEM hive → LSA key → NL$KM key for cached credential decryption.",
      src: "Microsoft; secretsdump" },
    { id: "nlkm", label: "NL$KM Key", sub: "Decrypt chain", x: 650, y: 200, r: 34, type: "api",
      desc: "NL$KM is the cached credential encryption key. Decrypted via boot key → LSA key chain.",
      src: "Microsoft; mimikatz" },
    { id: "dcc2_iter", label: "PBKDF2", sub: "10240 iterations", x: 780, y: 200, r: 32, type: "api",
      desc: "DCC2 (mscachev2) = PBKDF2-HMAC-SHA1 with 10240 iterations. Intentionally slow to crack.",
      src: "Microsoft; hashcat" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "mimikatz/reg.exe", x: 350, y: 340, r: 32, type: "detect",
      desc: "Sysmon EID 1: Process creation for reg.exe save SECURITY or mimikatz.",
      src: "Sysmon documentation" },
    { id: "ev_4656", label: "Event 4656", sub: "SECURITY key", x: 500, y: 340, r: 30, type: "detect",
      desc: "Event 4656: Handle request to SECURITY registry key.",
      src: "Microsoft Event 4656" },

    // ── Output ──
    { id: "dcc2_hashes", label: "DCC2 Hashes", sub: "mscachev2", x: 920, y: 140, r: 36, type: "artifact",
      desc: "Domain Cached Credentials v2: $DCC2$10240#username#hash format. Last 10 logons (default).",
      src: "MITRE T1003.005" },
    { id: "hashcat_dcc", label: "hashcat", sub: "-m 2100", x: 1060, y: 140, r: 36, type: "blind",
      desc: "BLIND: hashcat -m 2100 for DCC2 cracking. Very slow (~10k iterations). GPU required.",
      src: "hashcat.net" },
    { id: "plaintext", label: "Domain Password", x: 1200, y: 140, r: 34, type: "artifact",
      desc: "Cracked domain user password. These are users who previously logged into this machine.",
      src: "MITRE T1003.005" },
  ],

  edges: [
    // Mimikatz
    { f: "admin", t: "mimi_cache" },
    { f: "mimi_cache", t: "lsa_api" },
    { f: "lsa_api", t: "nlkm" },
    { f: "admin", t: "nltest" },
    // Reg save
    { f: "admin", t: "reg_sec" },
    { f: "reg_sec", t: "hives" },
    { f: "hives", t: "mimi_off" },
    { f: "hives", t: "secretsdump" },
    { f: "mimi_off", t: "boot_key" },
    // Impacket remote
    { f: "admin", t: "remote_sd" },
    { f: "remote_sd", t: "smb_445" },
    { f: "smb_445", t: "hives" },
    // Decryption
    { f: "hives", t: "boot_key" },
    { f: "boot_key", t: "nlkm" },
    { f: "secretsdump", t: "nlkm" },
    { f: "nlkm", t: "dcc2_iter" },
    { f: "dcc2_iter", t: "dcc2_hashes" },
    // Detection
    { f: "reg_sec", t: "sysmon_1" },
    { f: "mimi_cache", t: "ev_4656" },
    // Output
    { f: "dcc2_hashes", t: "hashcat_dcc", blind: true },
    { f: "hashcat_dcc", t: "plaintext", blind: true },
  ],
};

export default model;
