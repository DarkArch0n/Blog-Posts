// T1003.006 — DCSync — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.006",
    name: "DCSync",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  detectNodeId: "ev_4662",

  layout: {
    svgWidth: 1000,
    svgHeight: 520,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "REPLICATION",  x: 280 },
      { label: "DC RESPONSE",  x: 500 },
      { label: "DETECTION",    x: 720 },
      { label: "OUTCOME",      x: 920 },
    ],
    separators: [180, 390, 610, 820],
    annotations: [
      { text: "Source != Domain Controller = malicious", x: 720, y: 430, color: "#f57f17", fontWeight: "600" },
      { text: "Legitimate DC replication uses the same protocol", x: 280, y: 470, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "repl_rights", label: "Replication", sub: "Rights Required", x: 80, y: 170, r: 40, type: "source",
      tags: ["Domain Admin", "DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All"],
      telemetry: [],
      api: "Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All ACL rights",
      artifact: "Account with replication ACLs — Domain Admins have this by default",
      desc: "DCSync requires the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights on the domain object. Domain Admins, Enterprise Admins, and the Domain Controllers group have these by default. Attackers may also grant these rights to a compromised account via ACL modification (T1222).",
      src: "MITRE ATT&CK T1003.006; adsecurity.org — DCSync" },

    { id: "network", label: "Network", sub: "to DC TCP/135,49152+", x: 80, y: 370, r: 36, type: "source",
      tags: ["RPC/TCP", "Port 135 + dynamic", "MS-DRSR protocol"],
      telemetry: [],
      api: "Network connectivity to DC on TCP/135 (RPC endpoint mapper) + dynamic port",
      artifact: "RPC connection from non-DC source to DC · MS-DRSR traffic",
      desc: "DCSync requires network connectivity from the attacker's machine to a Domain Controller over RPC (TCP/135 endpoint mapper + dynamic high port). No need to be on the DC itself — the attack works remotely from any domain-joined or authenticated system.",
      src: "Microsoft MS-DRSR protocol; MITRE T1003.006" },

    { id: "mimi_dcsync", label: "Mimikatz", sub: "lsadump::dcsync", x: 280, y: 120, r: 36, type: "source",
      tags: ["lsadump::dcsync", "/user:krbtgt", "/domain:<domain>"],
      telemetry: ["4662"],
      api: "lsadump::dcsync /user:krbtgt /domain:corp.local → DrsGetNCChanges()",
      artifact: "RPC call to DC · Event 4662 with replication GUIDs · source is non-DC",
      desc: "Mimikatz lsadump::dcsync calls DrsGetNCChanges() via the MS-DRSR protocol, requesting replication of a specific account's password data. Can target any account: krbtgt for Golden Ticket, Domain Admin for PtH, or all accounts with /all flag. Mimics legitimate DC-to-DC replication.",
      src: "gentilkiwi/mimikatz; adsecurity.org — Mimikatz DCSync" },

    { id: "imp_secrets", label: "Impacket", sub: "secretsdump.py", x: 280, y: 270, r: 36, type: "source",
      tags: ["secretsdump.py -dc-ip", "-just-dc", "DrsGetNCChanges"],
      telemetry: ["4662"],
      api: "secretsdump.py -dc-ip <DC> -just-dc domain/user:pass@dc → DrsGetNCChanges()",
      artifact: "RPC replication request · Event 4662 · all hashes if -just-dc used",
      desc: "Impacket secretsdump.py with -just-dc flag performs DCSync via DrsGetNCChanges(). Can dump a single account (-just-dc-user) or all accounts. Supports NTLM hash, Kerberos, or password authentication. Remote execution — no tools needed on the DC.",
      src: "Impacket — github.com/fortra/impacket; secretsdump.py" },

    { id: "dsinternals", label: "DSInternals", sub: "Get-ADReplAccount", x: 280, y: 420, r: 34, type: "source",
      tags: ["DSInternals PowerShell", "Get-ADReplAccount", ".NET MS-DRSR"],
      telemetry: ["4662"],
      api: "Get-ADReplAccount -SamAccountName krbtgt -Server dc01.corp.local",
      artifact: "PowerShell module · Event 4662 · same DrsGetNCChanges() underneath",
      desc: "DSInternals PowerShell module provides Get-ADReplAccount cmdlet that performs DCSync via the same DrsGetNCChanges() API. Built on .NET — may appear more legitimate in PowerShell-heavy environments. Same detection via Event 4662.",
      src: "DSInternals — github.com/MichaelGrafnetter/DSInternals" },

    { id: "dc_response", label: "DrsGetNCChanges", sub: "MS-DRSR", x: 500, y: 270, r: 42, type: "source",
      tags: ["MS-DRSR", "DrsGetNCChanges()", "Replication response"],
      telemetry: ["4662"],
      api: "DC processes DrsGetNCChanges() and returns password data including NTLM hash, Kerberos keys",
      artifact: "DC replicates account data → NTLM hash + supplemental credentials returned",
      desc: "The Domain Controller receives the DrsGetNCChanges() RPC call, validates the caller has replication rights, and returns the requested account's replicated attributes including unicodePwd (NTLM hash), supplementalCredentials (Kerberos keys), and password history. This is identical to legitimate DC replication.",
      src: "Microsoft MS-DRSR specification; [MS-DRSR] DrsGetNCChanges" },

    { id: "ev_4662", label: "Event 4662", sub: "Replication Audit", x: 720, y: 270, r: 50, type: "detect",
      tags: ["Event 4662", "1131f6aa-*", "1131f6ad-*", "Source != DC"],
      telemetry: ["4662"],
      api: "Event 4662: DS-Access with Replication GUIDs — filter source account != DC computer account",
      artifact: "OPTIMAL: Event 4662 with GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 + source != DC",
      desc: "OPTIMAL DETECTION NODE. Event 4662 fires on the DC when DS-Replication-Get-Changes or DS-Replication-Get-Changes-All ACLs are exercised. Key detection logic: filter Event 4662 where Properties contains GUIDs (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 for Get-Changes, 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 for Get-Changes-All) AND SubjectUserName is NOT a Domain Controller computer account. Legitimate replication ONLY occurs between DCs. Any other source is DCSync.",
      src: "MITRE T1003.006; adsecurity.org — DetectingDCSync; Sigma rules" },

    { id: "target_hash", label: "Target Hash", sub: "Any Account", x: 920, y: 170, r: 38, type: "source",
      tags: ["krbtgt hash", "DA hash", "Service acct hash", "Any user"],
      telemetry: [],
      api: "NTLM hash + Kerberos keys for the targeted account(s)",
      artifact: "Credential material for targeted account → Golden/Silver Ticket, PtH, PtT",
      desc: "DCSync returns the NTLM hash and Kerberos keys for any requested account. krbtgt → Golden Ticket (T1558.001). Service account → Silver Ticket (T1558.002) or Kerberoasting validation. Domain Admin → Pass-the-Hash. Can also dump all accounts with /all or -just-dc.",
      src: "MITRE T1003.006; adsecurity.org" },

    { id: "all_dump", label: "Full Domain", sub: "Dump", x: 920, y: 380, r: 36, type: "source",
      tags: ["/all flag", "-just-dc", "Every account hash"],
      telemetry: [],
      api: "lsadump::dcsync /all OR secretsdump -just-dc → every domain account hash",
      artifact: "Complete hash dump of entire domain · equivalent to NTDS.dit extraction",
      desc: "With /all (Mimikatz) or -just-dc (secretsdump), DCSync dumps every account hash in the domain. Equivalent to NTDS.dit extraction (T1003.003) but without needing access to the DC filesystem. Generates multiple Event 4662 entries — one per replicated account.",
      src: "MITRE T1003.006; adsecurity.org" },
  ],

  edges: [
    { f: "repl_rights", t: "mimi_dcsync" },
    { f: "repl_rights", t: "imp_secrets" },
    { f: "repl_rights", t: "dsinternals" },
    { f: "network", t: "mimi_dcsync" },
    { f: "network", t: "imp_secrets" },
    { f: "network", t: "dsinternals" },
    { f: "mimi_dcsync", t: "dc_response" },
    { f: "imp_secrets", t: "dc_response" },
    { f: "dsinternals", t: "dc_response" },
    { f: "dc_response", t: "ev_4662" },
    { f: "ev_4662", t: "target_hash" },
    { f: "ev_4662", t: "all_dump" },
  ],
};

export default model;
