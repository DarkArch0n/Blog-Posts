// T1003.003 — NTDS — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.003",
    name: "NTDS",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 480,
    rows: [
      { label: "VSSADMIN",  y: 80 },
      { label: "NTDSUTIL", y: 180 },
      { label: "WMIC",     y: 280 },
      { label: "EXTRACT",  y: 400 },
    ],
  },

  nodes: [
    // ── Entry ──
    { id: "da_creds", label: "DA Credentials", sub: "On DC", x: 60, y: 180, r: 36, type: "entry",
      desc: "Domain Admin (or equivalent) access to a Domain Controller. Interactive or remote session.",
      src: "MITRE ATT&CK T1003.003" },

    // Row 1: vssadmin path
    { id: "vssadmin", label: "vssadmin", sub: "create shadow /for=C:", x: 200, y: 80, r: 34, type: "op",
      desc: "vssadmin create shadow /for=C: — creates Volume Shadow Copy to access locked NTDS.dit file.",
      src: "Microsoft vssadmin" },
    { id: "vss_api", label: "IVssBackup", sub: "Components", x: 350, y: 80, r: 30, type: "api",
      desc: "VSS COM API creates consistent snapshot of the volume including ntds.dit.",
      src: "Microsoft VSS API" },
    { id: "copy_ntds_1", label: "copy NTDS.dit", sub: "from shadow path", x: 510, y: 80, r: 36, type: "op",
      desc: "copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\",
      src: "MITRE T1003.003" },
    { id: "copy_sys_1", label: "copy SYSTEM", sub: "from shadow path", x: 510, y: 140, r: 30, type: "op",
      desc: "Also copy SYSTEM hive for boot key: \\Windows\\System32\\config\\SYSTEM",
      src: "MITRE T1003.003" },

    // Row 2: ntdsutil IFM path
    { id: "ntdsutil", label: "ntdsutil", sub: "ifm create full", x: 200, y: 180, r: 36, type: "op",
      desc: "ntdsutil 'ac i ntds' 'ifm' 'create full c:\\temp' — Install From Media creates NTDS.dit + SYSTEM.",
      src: "Microsoft ntdsutil" },
    { id: "esent_api", label: "ESENT API", sub: "JetAttachDatabase", x: 350, y: 180, r: 34, type: "api",
      desc: "ntdsutil uses ESE (JET) database API to copy NTDS.dit consistently.",
      src: "Microsoft ESENT documentation" },
    { id: "ifm_output", label: "IFM Output", sub: "ntds.dit + SYSTEM", x: 510, y: 200, r: 34, type: "artifact",
      desc: "IFM creates Active Directory/ and registry/ subdirectories with NTDS.dit and SYSTEM.",
      src: "Microsoft ntdsutil" },

    // Row 3: WMIC shadowcopy (legacy)
    { id: "wmic_vss", label: "wmic", sub: "shadowcopy create", x: 200, y: 280, r: 34, type: "op",
      desc: "wmic shadowcopy call create Volume='C:\\' — alternative shadow copy creation (deprecated tool).",
      src: "Microsoft WMIC (deprecated)" },
    { id: "wmi_api", label: "WMI", sub: "Win32_ShadowCopy", x: 350, y: 280, r: 32, type: "api",
      desc: "WMI class Win32_ShadowCopy Create() method for VSS shadow copy.",
      src: "Microsoft WMI" },

    // ── Collected files ──
    { id: "ntds_file", label: "ntds.dit", sub: "~500MB-10GB", x: 680, y: 180, r: 40, type: "artifact",
      desc: "AD database file containing all domain user accounts, hashes, and attributes. ESE/JET format.",
      src: "MITRE T1003.003" },
    { id: "system_hive", label: "SYSTEM Hive", x: 680, y: 280, r: 30, type: "artifact",
      desc: "Registry SYSTEM hive containing boot key needed to decrypt NTDS.dit.",
      src: "MITRE T1003.003" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "vssadmin/ntdsutil", x: 350, y: 340, r: 36, type: "detect",
      desc: "OPTIMAL: Sysmon EID 1 on DC: vssadmin.exe or ntdsutil.exe process creation. Check command line.",
      src: "Sysmon documentation" },
    { id: "ev_4688", label: "Event 4688", sub: "Process Create", x: 510, y: 340, r: 32, type: "detect",
      desc: "Event 4688 with command line auditing: ntdsutil, vssadmin, wmic arguments.",
      src: "Microsoft Event 4688" },
    { id: "ev_vss", label: "Event 8222", sub: "VSS Shadow Created", x: 350, y: 400, r: 30, type: "detect",
      desc: "VSS Event 8222: Shadow copy created. Correlate with DC context for suspicious activity.",
      src: "Microsoft VSS Events" },
    { id: "sysmon_11", label: "Sysmon 11", sub: "ntds.dit FileCreate", x: 680, y: 340, r: 34, type: "detect",
      desc: "Sysmon EID 11: ntds.dit file created outside normal NTDS path.",
      src: "Sysmon documentation" },

    // Row 4: Extraction
    { id: "secretsdump", label: "secretsdump.py", sub: "-ntds ntds.dit", x: 860, y: 380, r: 38, type: "op",
      desc: "Impacket secretsdump.py -ntds ntds.dit -system system.hiv LOCAL — offline hash extraction.",
      src: "fortra/impacket" },
    { id: "dsinternals", label: "DSInternals", sub: "Get-ADDBAccount", x: 860, y: 280, r: 36, type: "op",
      desc: "DSInternals PowerShell: Get-ADDBAccount -All -DBPath ntds.dit -BootKey <key>",
      src: "MichaelGrafnetter/DSInternals" },

    // ── Parse NTDS ──
    { id: "esent_parse", label: "ESENT Parse", sub: "JetOpenDatabase", x: 1020, y: 330, r: 34, type: "api",
      desc: "Open NTDS.dit as ESE database, read datatable for account records.",
      src: "Microsoft ESENT; secretsdump" },
    { id: "pek_decrypt", label: "PEK Decrypt", sub: "Boot key → PEK", x: 1020, y: 220, r: 34, type: "api",
      desc: "Password Encryption Key (PEK) decrypted using boot key from SYSTEM hive. Triple-DES or AES.",
      src: "Microsoft; DSInternals" },

    // ── Output ──
    { id: "all_hashes", label: "ALL Domain", sub: "NTLM Hashes", x: 1180, y: 240, r: 40, type: "artifact",
      desc: "NTLM hashes for EVERY domain account — users, computers, service accounts, krbtgt.",
      src: "MITRE T1003.003" },
    { id: "krbtgt_hash", label: "krbtgt Hash", sub: "→ Golden Ticket", x: 1340, y: 180, r: 34, type: "artifact",
      desc: "krbtgt account hash extracted. Enables Golden Ticket attacks (T1558.001).",
      src: "MITRE T1558.001" },
    { id: "mass_crack", label: "hashcat", sub: "-m 1000", x: 1340, y: 300, r: 34, type: "blind",
      desc: "BLIND: Offline cracking of all domain hashes. hashcat -m 1000. Zero logs.",
      src: "hashcat.net" },
  ],

  edges: [
    // vssadmin path
    { f: "da_creds", t: "vssadmin" },
    { f: "vssadmin", t: "vss_api" },
    { f: "vss_api", t: "copy_ntds_1" },
    { f: "vss_api", t: "copy_sys_1" },
    { f: "copy_ntds_1", t: "ntds_file" },
    { f: "copy_sys_1", t: "system_hive" },
    // ntdsutil path
    { f: "da_creds", t: "ntdsutil" },
    { f: "ntdsutil", t: "esent_api" },
    { f: "esent_api", t: "ifm_output" },
    { f: "ifm_output", t: "ntds_file" },
    { f: "ifm_output", t: "system_hive" },
    // WMIC path
    { f: "da_creds", t: "wmic_vss" },
    { f: "wmic_vss", t: "wmi_api" },
    { f: "wmi_api", t: "copy_ntds_1" },
    // Detection
    { f: "vssadmin", t: "sysmon_1" },
    { f: "ntdsutil", t: "sysmon_1" },
    { f: "wmic_vss", t: "ev_4688" },
    { f: "vss_api", t: "ev_vss" },
    { f: "ntds_file", t: "sysmon_11" },
    // Extraction
    { f: "ntds_file", t: "secretsdump" },
    { f: "system_hive", t: "secretsdump" },
    { f: "ntds_file", t: "dsinternals" },
    { f: "system_hive", t: "dsinternals" },
    // Parse
    { f: "secretsdump", t: "esent_parse" },
    { f: "dsinternals", t: "esent_parse" },
    { f: "system_hive", t: "pek_decrypt" },
    { f: "pek_decrypt", t: "esent_parse" },
    { f: "esent_parse", t: "all_hashes" },
    // Output
    { f: "all_hashes", t: "krbtgt_hash" },
    { f: "all_hashes", t: "mass_crack", blind: true },
  ],
};

export default model;
