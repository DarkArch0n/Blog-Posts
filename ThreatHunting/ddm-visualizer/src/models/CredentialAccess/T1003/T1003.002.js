// T1003.002 — Security Account Manager — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.002",
    name: "Security Account Manager",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1000,
    svgHeight: 500,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "DUMP METHOD",  x: 270 },
      { label: "EXTRACTION",   x: 490 },
      { label: "DETECTION",    x: 700 },
      { label: "OUTCOME",      x: 910 },
    ],
    separators: [175, 380, 595, 805],
    annotations: [
      { text: "Registry access + process creation", x: 700, y: 390, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "admin", label: "Local Admin", sub: "or SYSTEM", x: 80, y: 240, r: 40, type: "source",
      tags: ["Local admin", "SYSTEM", "Offline boot"],
      telemetry: [],
      api: "Requires local admin / SYSTEM, or physical access for offline extraction",
      artifact: "Admin session on target · or offline boot from USB/recovery",
      desc: "SAM database access requires local administrator, SYSTEM, or physical/offline access to the disk. Online methods use reg.exe or secretsdump. Offline methods extract SAM from a mounted disk or Volume Shadow Copy.",
      src: "MITRE ATT&CK T1003.002" },

    { id: "reg_save", label: "reg.exe save", sub: "HKLM\\SAM", x: 270, y: 100, r: 36, type: "source",
      tags: ["reg save HKLM\\SAM", "reg save HKLM\\SYSTEM", "LOTL"],
      telemetry: ["4688", "Sysmon 1"],
      api: "reg.exe save HKLM\\SAM sam.hiv · reg.exe save HKLM\\SYSTEM system.hiv",
      artifact: "Sysmon EID 1: reg.exe save HKLM\\SAM · Event 4688 · .hiv files on disk",
      desc: "Native reg.exe exports the SAM and SYSTEM registry hives to files. SAM contains the local account password hashes. SYSTEM contains the bootkey needed to decrypt them. Living-off-the-land — no external tools. Detectable via process creation monitoring for reg.exe save HKLM\\SAM.",
      src: "MITRE T1003.002; Atomic Red Team" },

    { id: "secretsdump", label: "secretsdump", sub: "-sam -system", x: 270, y: 230, r: 36, type: "source",
      tags: ["Impacket secretsdump.py", "-sam SAM -system SYSTEM", "Remote via SMB"],
      telemetry: ["4688"],
      api: "secretsdump.py -sam sam.hiv -system system.hiv LOCAL · or remote via -dc-ip",
      artifact: "Local parsing of exported hives · or remote SAM dump via SMB admin share",
      desc: "Impacket secretsdump.py parses exported SAM + SYSTEM hive files locally, or can dump SAM remotely via authenticated SMB access to admin shares (\\\\target\\C$). Remote extraction uses RemoteRegistry service or direct registry access.",
      src: "Impacket — github.com/fortra/impacket" },

    { id: "mimikatz_sam", label: "Mimikatz", sub: "lsadump::sam", x: 270, y: 360, r: 36, type: "source",
      tags: ["lsadump::sam", "SYSTEM hive", "In-memory or offline"],
      telemetry: ["Sysmon 1"],
      api: "lsadump::sam /system:system.hiv /sam:sam.hiv · or live: token::elevate → lsadump::sam",
      artifact: "Sysmon EID 1: mimikatz · live SAM access or offline hive parsing",
      desc: "Mimikatz lsadump::sam extracts local account hashes from the SAM database. Can parse exported hive files offline or access the live SAM database after elevating to SYSTEM via token::elevate.",
      src: "gentilkiwi/mimikatz; adsecurity.org" },

    { id: "vss_sam", label: "VSS Copy", sub: "Shadow Copy", x: 270, y: 470, r: 34, type: "source",
      tags: ["vssadmin", "Shadow copy SAM", "Offline copy"],
      telemetry: ["4688", "Sysmon 1"],
      api: "vssadmin create shadow /for=C: → copy SAM + SYSTEM from shadow",
      artifact: "VSS creation · copy from \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadow*",
      desc: "Volume Shadow Copy provides access to locked SAM and SYSTEM files. Attacker creates a VSS, then copies the files from the shadow copy path. Avoids direct registry access — uses file copy instead.",
      src: "MITRE T1003.002; Atomic Red Team" },

    { id: "parse", label: "Parse Hashes", sub: "Decrypt SAM", x: 490, y: 240, r: 38, type: "source",
      tags: ["Bootkey from SYSTEM", "DES/RC4 decrypt", "NTLM hashes out"],
      telemetry: [],
      api: "Extract bootkey from SYSTEM hive → decrypt SAM entries → NTLM hashes",
      artifact: "Bootkey + SAM → local account NTLM hashes (LM:NT format)",
      desc: "The SYSTEM hive contains the bootkey (syskey) needed to decrypt the SAM database entries. Tools extract the bootkey, then use it to decrypt each SAM entry via DES and RC4 to reveal the NTLM password hashes for all local accounts.",
      src: "Impacket secretsdump; creddump" },

    { id: "ev_detect", label: "Process + Reg", sub: "Sysmon 1 + 13", x: 700, y: 240, r: 50, type: "detect",
      tags: ["Sysmon 1", "Event 4688", "Sysmon 13", "Registry access"],
      telemetry: ["Sysmon 1", "4688", "Sysmon 13"],
      api: "Process creation monitoring + registry access auditing on SAM/SYSTEM hives",
      artifact: "OPTIMAL: Sysmon EID 1 for reg.exe save HKLM\\SAM · 4688 · Sysmon 13 registry access",
      desc: "OPTIMAL DETECTION NODE. Monitor for: (1) Sysmon EID 1 / Event 4688: reg.exe with save HKLM\\SAM or HKLM\\SYSTEM arguments. (2) Sysmon EID 13: Registry value access to SAM\\SAM hive keys. (3) Process creation of secretsdump.py, mimikatz with lsadump::sam. (4) VSS creation via vssadmin. Multiple telemetry sources provide defense in depth.",
      src: "MITRE T1003.002; Sysmon documentation; Sigma rules" },

    { id: "local_hashes", label: "Local Hashes", sub: "NTLM", x: 910, y: 170, r: 38, type: "source",
      tags: ["Local Administrator", "Built-in accounts", "NTLM hashes"],
      telemetry: [],
      api: "NTLM hashes for all local accounts — Administrator, Guest, custom locals",
      artifact: "Local admin NTLM hash → Pass-the-Hash to other systems with same password",
      desc: "SAM extraction reveals NTLM hashes for all local accounts. If the local Administrator password is reused across systems (common in environments without LAPS), the attacker can Pass-the-Hash to every system sharing that password. LAPS mitigates this by randomizing local admin passwords.",
      src: "MITRE T1003.002; Microsoft LAPS documentation" },

    { id: "pth", label: "Pass-the-Hash", sub: "Lateral Movement", x: 910, y: 330, r: 36, type: "source",
      tags: ["pth-winexe", "Impacket psexec", "Credential reuse"],
      telemetry: ["4624"],
      api: "NTLM hash used for Pass-the-Hash → lateral movement to systems with same password",
      artifact: "Event 4624 type 3 with NTLM auth · no password needed, hash suffices",
      desc: "Extracted local admin NTLM hash enables Pass-the-Hash attacks against any other system using the same local admin password. Impacket psexec.py, wmiexec.py, and smbexec.py all support hash-based authentication via -hashes flag.",
      src: "MITRE T1550.002; Impacket" },
  ],

  edges: [
    { f: "admin", t: "reg_save" },
    { f: "admin", t: "secretsdump" },
    { f: "admin", t: "mimikatz_sam" },
    { f: "admin", t: "vss_sam" },
    { f: "reg_save", t: "parse" },
    { f: "secretsdump", t: "parse" },
    { f: "mimikatz_sam", t: "parse" },
    { f: "vss_sam", t: "parse" },
    { f: "reg_save", t: "ev_detect" },
    { f: "secretsdump", t: "ev_detect" },
    { f: "mimikatz_sam", t: "ev_detect" },
    { f: "vss_sam", t: "ev_detect" },
    { f: "parse", t: "local_hashes" },
    { f: "local_hashes", t: "pth" },
  ],
};

export default model;
