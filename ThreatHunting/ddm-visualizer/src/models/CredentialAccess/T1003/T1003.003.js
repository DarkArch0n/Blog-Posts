// T1003.003 — NTDS — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.003",
    name: "NTDS",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 520,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "DUMP METHOD",  x: 270 },
      { label: "EXTRACTION",   x: 490 },
      { label: "DETECTION",    x: 700 },
      { label: "OUTCOME",      x: 910 },
    ],
    separators: [175, 380, 595, 805],
    annotations: [
      { text: "VSS + process creation monitoring", x: 700, y: 410, color: "#f57f17", fontWeight: "600" },
      { text: "Offline parsing — zero DC telemetry", x: 490, y: 460, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "da", label: "Domain Admin", sub: "on DC", x: 80, y: 250, r: 40, type: "source",
      tags: ["Domain Admin", "DC local admin", "Physical access"],
      telemetry: ["4624"],
      api: "Requires Domain Admin or local admin on a Domain Controller",
      artifact: "Event 4624 type 2/10 on DC · privileged logon session",
      desc: "Accessing NTDS.dit requires Domain Admin privileges or local admin on a Domain Controller. Physical access to a DC (or VM snapshot) also suffices for offline extraction without any logon events.",
      src: "MITRE ATT&CK T1003.003" },

    { id: "ntdsutil", label: "ntdsutil.exe", sub: "IFM", x: 270, y: 100, r: 36, type: "source",
      tags: ["ntdsutil", "activate instance ntds", "create full c:\\temp"],
      telemetry: ["4688", "Sysmon 1"],
      api: "ntdsutil.exe 'activate instance ntds' 'ifm' 'create full c:\\temp' quit quit",
      artifact: "Sysmon EID 1: ntdsutil.exe with IFM args · NTDS.dit + SYSTEM in output dir",
      desc: "ntdsutil.exe Install From Media (IFM) creates a copy of NTDS.dit and SYSTEM hive. Legitimate tool for creating replica DCs — LOTL technique. Detectable via process creation: ntdsutil.exe with 'ifm' and 'create full' arguments.",
      src: "Microsoft ntdsutil docs; MITRE T1003.003; Atomic Red Team" },

    { id: "vssadmin", label: "vssadmin", sub: "Shadow Copy", x: 270, y: 240, r: 36, type: "source",
      tags: ["vssadmin create shadow", "copy from shadow", "LOTL"],
      telemetry: ["4688", "Sysmon 1"],
      api: "vssadmin create shadow /for=C: → copy NTDS.dit + SYSTEM from shadow path",
      artifact: "Sysmon EID 1: vssadmin create shadow · VSS event logs · file copy",
      desc: "Creates a Volume Shadow Copy to access the locked NTDS.dit and SYSTEM files. Attacker copies from \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadow*\\Windows\\NTDS\\ntds.dit. Legitimate admin operation — detection requires context (time, user, purpose).",
      src: "MITRE T1003.003; Atomic Red Team" },

    { id: "wmic_shadow", label: "wmic", sub: "shadowcopy", x: 270, y: 370, r: 34, type: "source",
      tags: ["wmic shadowcopy call create", "Volume=C:\\", "Alternative to vssadmin"],
      telemetry: ["4688", "Sysmon 1"],
      api: "wmic shadowcopy call create Volume=C:\\ → copy NTDS.dit from shadow",
      artifact: "Sysmon EID 1: wmic shadowcopy call create · same shadow copy approach",
      desc: "Alternative to vssadmin using WMI command-line. Creates a Volume Shadow Copy via WMI provider. Some attackers prefer wmic over vssadmin for evasion. Detection is the same — process creation monitoring + VSS event logging.",
      src: "MITRE T1003.003" },

    { id: "disk_shadow", label: "diskshadow.exe", sub: "Script mode", x: 270, y: 480, r: 32, type: "source",
      tags: ["diskshadow /s script.txt", "LOTL", "Less monitored"],
      telemetry: ["4688", "Sysmon 1"],
      api: "diskshadow.exe /s script.txt — script creates shadow and exposes NTDS.dit",
      artifact: "Sysmon EID 1: diskshadow.exe · script file on disk · shadow copy created",
      desc: "diskshadow.exe is a Microsoft-signed binary that can create VSS copies via script mode. Less commonly monitored than vssadmin. Attacker creates a script file that adds/creates/exposes a shadow copy, then copies NTDS.dit from the exposed drive.",
      src: "Bohops — diskshadow.exe abuse; LOLBAS" },

    { id: "parse_ntds", label: "secretsdump", sub: "-ntds + -system", x: 490, y: 250, r: 38, type: "source",
      tags: ["secretsdump.py -ntds", "DSInternals", "Offline parsing"],
      telemetry: [],
      api: "secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL → all domain hashes",
      artifact: "Offline on attacker system — parses NTDS.dit → all domain account hashes",
      desc: "Impacket secretsdump.py parses the NTDS.dit database using the bootkey from SYSTEM hive. Extracts NTLM hashes for EVERY domain account including krbtgt, Domain Admins, and service accounts. DSInternals (PowerShell) also parses NTDS.dit. Parsing happens offline — zero DC telemetry.",
      src: "Impacket secretsdump; DSInternals — github.com/MichaelGrafnetter/DSInternals" },

    { id: "ev_detect", label: "VSS + Process", sub: "Multi-source", x: 700, y: 250, r: 50, type: "detect",
      tags: ["Sysmon 1", "4688", "VSS events", "ESENT 325/326"],
      telemetry: ["Sysmon 1", "4688"],
      api: "Process creation for ntdsutil/vssadmin/diskshadow + VSS event logs + ESENT logs",
      artifact: "OPTIMAL: Sysmon 1 for ntdsutil/vssadmin · VSS creation events · ESENT 325/326 on DC",
      desc: "OPTIMAL DETECTION NODE. Multiple telemetry sources: (1) Sysmon EID 1 / Event 4688: ntdsutil.exe with IFM args, vssadmin create shadow, wmic shadowcopy, diskshadow.exe. (2) VSS event logs: shadow copy creation on DC. (3) ESENT event 325/326: NTDS.dit database detach (indicates copy). (4) File access monitoring on NTDS.dit path. Defense in depth via layered detections.",
      src: "MITRE T1003.003; Sigma rules; Microsoft ESENT logging" },

    { id: "all_hashes", label: "All Domain", sub: "Hashes", x: 910, y: 170, r: 40, type: "source",
      tags: ["Every domain account", "krbtgt hash", "DA hashes", "Service accounts"],
      telemetry: [],
      api: "NTLM hashes for every account: krbtgt → Golden Ticket, DA → lateral, svc → Silver",
      artifact: "Complete hash dump · krbtgt for Golden Ticket · every user for mass compromise",
      desc: "NTDS.dit contains NTLM hashes for every domain account. krbtgt hash enables Golden Ticket (T1558.001). Domain Admin hashes enable Pass-the-Hash to any system. Service account hashes enable Silver Ticket (T1558.002). This is total domain compromise — every credential in the forest.",
      src: "MITRE T1003.003; adsecurity.org" },

    { id: "golden", label: "Golden Ticket", sub: "T1558.001", x: 910, y: 340, r: 36, type: "source",
      tags: ["krbtgt hash", "Forge TGT", "Persistent DA"],
      telemetry: [],
      api: "krbtgt NTLM hash from NTDS → Golden Ticket → persistent domain admin access",
      artifact: "krbtgt hash → Mimikatz/Impacket/Rubeus golden ticket → 10-year persistence",
      desc: "The krbtgt hash from NTDS.dit enables Golden Ticket attacks (T1558.001) — forging TGTs for any user with any group membership. Provides persistent domain admin access until krbtgt is rotated twice.",
      src: "MITRE T1558.001; adsecurity.org" },
  ],

  edges: [
    { f: "da", t: "ntdsutil" },
    { f: "da", t: "vssadmin" },
    { f: "da", t: "wmic_shadow" },
    { f: "da", t: "disk_shadow" },
    { f: "ntdsutil", t: "ev_detect" },
    { f: "vssadmin", t: "ev_detect" },
    { f: "wmic_shadow", t: "ev_detect" },
    { f: "disk_shadow", t: "ev_detect" },
    { f: "ntdsutil", t: "parse_ntds" },
    { f: "vssadmin", t: "parse_ntds" },
    { f: "wmic_shadow", t: "parse_ntds" },
    { f: "disk_shadow", t: "parse_ntds" },
    { f: "parse_ntds", t: "all_hashes" },
    { f: "all_hashes", t: "golden" },
  ],
};

export default model;
