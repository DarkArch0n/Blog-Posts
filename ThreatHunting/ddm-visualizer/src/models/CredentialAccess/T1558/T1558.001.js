// T1558.001 — Golden Ticket — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1558.001",
    name: "Golden Ticket",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  detectNodeId: "ev_anom",

  layout: {
    svgWidth: 1000,
    svgHeight: 520,
    columns: [
      { label: "HASH SOURCE",  x: 80  },
      { label: "FORGE TGT",    x: 260 },
      { label: "USE TGT",      x: 440 },
      { label: "DC RESPONSE",  x: 640 },
      { label: "OUTCOME",      x: 860 },
    ],
    separators: [170, 350, 540, 750],
    annotations: [
      { text: "Forging is fully offline — zero telemetry", x: 260, y: 485, color: "#c62828", fontStyle: "italic" },
      { text: "Anomaly: no prior 4768 for TGT", x: 640, y: 385, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    // Column 1 — Hash Source
    { id: "dcsync", label: "DCSync", sub: "T1003.006", x: 80, y: 120, r: 36, type: "source",
      tags: ["Mimikatz lsadump::dcsync", "Impacket secretsdump", "MS-DRSR"],
      telemetry: ["4662", "4624"],
      api: "DrsGetNCChanges() via MS-DRSR — replicates krbtgt hash from DC",
      artifact: "Event 4662: DS-Replication-Get-Changes-All · source != DC IP",
      desc: "DCSync uses the MS-DRSR replication protocol (DrsGetNCChanges) to request the krbtgt account's password hash from a Domain Controller. Mimikatz lsadump::dcsync /user:krbtgt and Impacket secretsdump.py both implement this. Detectable via Event 4662 when the requesting account is not a Domain Controller.",
      src: "adsecurity.org — Mimikatz DCSync; Impacket secretsdump.py; MITRE T1003.006" },

    { id: "ntds", label: "NTDS.dit", sub: "Extract", x: 80, y: 260, r: 36, type: "source",
      tags: ["ntdsutil", "vssadmin", "Volume Shadow Copy"],
      telemetry: ["4688", "Sysmon 1"],
      api: "vssadmin create shadow /for=C: → copy NTDS.dit + SYSTEM hive",
      artifact: "VSS creation event · ntdsutil.exe / vssadmin.exe process · NTDS.dit file access",
      desc: "Attacker creates a Volume Shadow Copy on the DC via vssadmin or ntdsutil, then copies NTDS.dit (the AD database) and SYSTEM registry hive. Offline extraction of krbtgt hash using Impacket secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL.",
      src: "MITRE T1003.003; adsecurity.org" },

    { id: "lsass_dc", label: "LSASS Dump", sub: "on DC", x: 80, y: 400, r: 36, type: "source",
      tags: ["Mimikatz", "procdump", "comsvcs.dll"],
      telemetry: ["Sysmon 10"],
      api: "MiniDumpWriteDump() or sekurlsa::logonpasswords on Domain Controller",
      artifact: "Sysmon EID 10: LSASS process access on DC · minidump file creation",
      desc: "Attacker with local admin on a DC dumps LSASS memory to extract the krbtgt hash. Tools include Mimikatz sekurlsa::logonpasswords, procdump -ma lsass.exe, and rundll32 comsvcs.dll MiniDump. The krbtgt hash is resident in DC LSASS memory.",
      src: "MITRE T1003.001; gentilkiwi/mimikatz" },

    // Column 2 — Forge TGT (BLIND — offline)
    { id: "mimi_golden", label: "Mimikatz", sub: "kerberos::golden", x: 260, y: 120, r: 36, type: "blind",
      tags: ["kerberos::golden", "/krbtgt:<hash>", "10-year default lifetime"],
      telemetry: [],
      api: "kerberos::golden /user:Administrator /domain:<d> /sid:<s> /krbtgt:<hash>",
      artifact: "⚠ Offline operation — zero DC telemetry during forging",
      desc: "BLIND SPOT: Mimikatz kerberos::golden forges a TGT offline using the krbtgt NTLM hash and domain SID. Default ticket lifetime is 10 years. Can specify any username, RID 500, and arbitrary group memberships including Domain Admins, Enterprise Admins, Schema Admins. Zero network traffic during forging.",
      src: "gentilkiwi/mimikatz; adsecurity.org — Golden Ticket Attack" },

    { id: "imp_ticket", label: "Impacket", sub: "ticketer.py", x: 260, y: 260, r: 36, type: "blind",
      tags: ["ticketer.py", "-nthash", ".ccache output"],
      telemetry: [],
      api: "ticketer.py -nthash <hash> -domain-sid <sid> -domain <d> Administrator",
      artifact: "⚠ Offline — .ccache file on attacker system · no network traffic",
      desc: "BLIND SPOT: Impacket ticketer.py forges a TGT entirely offline, outputting a .ccache file. Used with KRB5CCNAME environment variable for subsequent Impacket tools (psexec.py, wmiexec.py, smbexec.py). Zero host or DC artifacts during forging.",
      src: "Impacket — github.com/fortra/impacket" },

    { id: "rubeus_golden", label: "Rubeus", sub: "golden", x: 260, y: 400, r: 36, type: "blind",
      tags: ["Rubeus golden", "/rc4: or /aes256:", "/ptt auto-inject"],
      telemetry: [],
      api: "Rubeus.exe golden /rc4:<hash> /sid:<sid> /user:Administrator /ptt",
      artifact: "⚠ Offline forging — /ptt injects into current session LSASS",
      desc: "BLIND SPOT: Rubeus golden forges a TGT offline. Supports both RC4 (/rc4:) and AES256 (/aes256:) krbtgt keys. The /ptt flag automatically injects the forged ticket into the current logon session's LSASS Kerberos cache. AES256 forging evades detections that look for RC4-only TGTs.",
      src: "GhostPack/Rubeus — github.com/GhostPack/Rubeus" },

    // Column 3 — Use TGT
    { id: "ptt", label: "Pass-the-Ticket", sub: "Inject TGT", x: 440, y: 180, r: 36, type: "source",
      tags: ["kerberos::ptt", "Rubeus /ptt", "LSASS injection"],
      telemetry: ["Sysmon 10"],
      api: "LsaCallAuthenticationPackage(KerbSubmitTicketMessage) — inject TGT into LSASS",
      artifact: "Forged TGT in LSASS cache · Sysmon EID 10 on injecting host",
      desc: "Forged TGT is injected into the current Windows logon session via LsaCallAuthenticationPackage with KerbSubmitTicketMessage. Mimikatz kerberos::ptt and Rubeus /ptt both use this API. Subsequent Kerberos operations (TGS-REQ, service access) automatically use the forged identity.",
      src: "adsecurity.org Pass-the-Ticket; gentilkiwi/mimikatz" },

    { id: "direct_use", label: "Direct Use", sub: "Impacket -k", x: 440, y: 360, r: 36, type: "source",
      tags: ["psexec.py -k", "wmiexec.py -k", "KRB5CCNAME"],
      telemetry: [],
      api: "Impacket tools with -k -no-pass using KRB5CCNAME=<ticket>.ccache",
      artifact: "Remote service creation or WMI exec · Event 4624 type 3 on target",
      desc: "Impacket tools use the forged ticket directly via -k flag with KRB5CCNAME pointing to the .ccache file. psexec.py creates a Windows service, wmiexec.py uses WMI, smbexec.py uses SMB. No LSASS injection on the attacker host.",
      src: "Impacket — github.com/fortra/impacket" },

    // Column 4 — DC Response (DETECTION)
    { id: "ev_anom", label: "TGS-REQ", sub: "Event 4769", x: 640, y: 260, r: 50, type: "detect",
      tags: ["Event 4769", "No prior 4768", "TGT lifetime anomaly", "MDI alert"],
      telemetry: ["4769", "4768"],
      api: "KDC processes TGS-REQ containing forged TGT — encrypted with real krbtgt key",
      artifact: "OPTIMAL: Event 4769 with no prior 4768 · TGT lifetime > policy · SID mismatch",
      desc: "OPTIMAL DETECTION NODE. When the forged TGT is presented in a TGS-REQ, the DC decrypts it successfully (encrypted with real krbtgt key) and fires Event 4769. Key anomalies: (1) No preceding Event 4768 (AS-REQ) for this TGT — never legitimately issued. (2) TGT lifetime exceeds domain Kerberos policy (default golden ticket = 10 years vs. typical 10 hours). (3) Account SID/groups may not match current AD state. Microsoft Defender for Identity (MDI) detects Golden Ticket via these anomalies.",
      src: "MITRE ATT&CK T1558.001; Microsoft Defender for Identity — Golden Ticket detection; adsecurity.org" },

    // Column 5 — Outcome
    { id: "da_access", label: "Domain Admin", sub: "Access", x: 860, y: 180, r: 40, type: "source",
      tags: ["Any user identity", "Domain Admins", "Enterprise Admins"],
      telemetry: ["4624"],
      api: "Authenticated as forged identity — full DA privileges if DA group in PAC",
      artifact: "Event 4624 type 3 on target systems · full admin access to any domain resource",
      desc: "Attacker authenticates as any user with arbitrary group memberships. Typically spoofs Administrator (RID 500) with Domain Admins, Enterprise Admins, and Schema Admins. Full domain admin access to any system in the forest.",
      src: "MITRE T1558.001; adsecurity.org" },

    { id: "persist", label: "Persistence", sub: "10-year ticket", x: 860, y: 360, r: 36, type: "source",
      tags: ["10-year default", "krbtgt must rotate 2x", "Re-forge anytime"],
      telemetry: [],
      api: "Forged TGT valid until krbtgt password rotated TWICE — AD retains n-1 key",
      artifact: "⚠ Ticket valid for years · krbtgt double-rotation required to invalidate",
      desc: "Golden Ticket provides long-term persistent access. The forged TGT remains valid until the krbtgt password is changed TWICE (AD retains the previous krbtgt key). Default Mimikatz golden ticket lifetime is 10 years. Attacker can re-forge tickets at any time using the captured krbtgt hash.",
      src: "MITRE T1558.001; Microsoft — krbtgt account password reset guidance" },
  ],

  edges: [
    { f: "dcsync", t: "mimi_golden" },
    { f: "dcsync", t: "imp_ticket" },
    { f: "ntds", t: "mimi_golden" },
    { f: "ntds", t: "imp_ticket" },
    { f: "lsass_dc", t: "mimi_golden" },
    { f: "lsass_dc", t: "rubeus_golden" },
    { f: "mimi_golden", t: "ptt", blind: true },
    { f: "imp_ticket", t: "direct_use", blind: true },
    { f: "rubeus_golden", t: "ptt", blind: true },
    { f: "ptt", t: "ev_anom" },
    { f: "direct_use", t: "ev_anom" },
    { f: "ev_anom", t: "da_access" },
    { f: "ev_anom", t: "persist" },
  ],
};

export default model;
