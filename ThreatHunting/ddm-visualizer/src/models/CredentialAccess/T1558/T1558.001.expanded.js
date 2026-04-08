// T1558.001 — Golden Ticket — Expanded Technology Chain
// Tool -> API -> Protocol -> System -> Detection -> Artifact

const model = {
  metadata: {
    tcode: "T1558.001",
    name: "Golden Ticket",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1650,
    svgHeight: 580,
    rows: [
      { label: "DCSYNC",   y: 100 },
      { label: "NTDS.DIT", y: 200 },
      { label: "MIMIKATZ", y: 300 },
      { label: "IMPACKET", y: 400 },
      { label: "RUBEUS",   y: 500 },
    ],
    annotations: [
      { text: "Forging is fully offline - zero telemetry", x: 620, y: 560, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    // ── Prerequisites: Extract krbtgt hash ──
    { id: "da_creds", label: "DA Credentials", x: 60, y: 150, r: 36, type: "entry",
      desc: "Domain Admin or equivalent credentials required to extract the krbtgt hash. Obtained via prior compromise.",
      src: "MITRE ATT&CK T1558.001" },

    // Row 1: DCSync path
    { id: "mimi_dcsync", label: "Mimikatz", sub: "lsadump::dcsync", x: 170, y: 100, r: 32, type: "op",
      desc: "Mimikatz lsadump::dcsync /user:krbtgt — replicates krbtgt account hash from DC.",
      src: "gentilkiwi/mimikatz" },
    { id: "drsr_call", label: "DrsGetNCChanges", sub: "MS-DRSR", x: 300, y: 100, r: 36, type: "api",
      desc: "MS-DRSR DrsGetNCChanges() API call — Active Directory replication protocol.",
      src: "Microsoft MS-DRSR specification" },
    { id: "rpc_135", label: "RPC :135", sub: "MSRPC", x: 430, y: 100, r: 28, type: "protocol",
      desc: "DCSync uses MSRPC over TCP/135 + dynamic ports for AD replication.",
      src: "RFC 1831; MS-DRSR" },
    { id: "ev_4662", label: "Event 4662", sub: "DS-Replication", x: 560, y: 100, r: 34, type: "detect",
      desc: "Event 4662: DS-Replication-Get-Changes-All from non-DC source. Key detection for DCSync.",
      src: "Microsoft Security Event 4662" },

    // Row 2: NTDS.dit extraction path
    { id: "vssadmin", label: "vssadmin", sub: "create shadow", x: 170, y: 200, r: 30, type: "op",
      desc: "vssadmin create shadow /for=C: — creates Volume Shadow Copy to access locked NTDS.dit.",
      src: "Microsoft vssadmin" },
    { id: "ntdsutil", label: "ntdsutil", sub: "ifm create", x: 280, y: 200, r: 30, type: "op",
      desc: "ntdsutil 'ac i ntds' 'ifm' 'create full c:\\temp' — Install From Media creates NTDS.dit copy.",
      src: "Microsoft ntdsutil" },
    { id: "copy_ntds", label: "Copy NTDS.dit", sub: "+ SYSTEM hive", x: 420, y: 200, r: 34, type: "op",
      desc: "Copy NTDS.dit and SYSTEM registry hive from VSS shadow for offline extraction.",
      src: "MITRE T1003.003" },
    { id: "secretsdump", label: "secretsdump", sub: "-ntds", x: 560, y: 200, r: 34, type: "op",
      desc: "Impacket secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL — extracts krbtgt hash offline.",
      src: "fortra/impacket" },
    { id: "ev_vss", label: "Sysmon 1", sub: "vssadmin/ntdsutil", x: 420, y: 260, r: 28, type: "detect",
      desc: "Sysmon EID 1: Process creation for vssadmin.exe or ntdsutil.exe on DC.",
      src: "Sysmon documentation" },

    // ── Forging: BLIND SPOT — offline operations ──
    { id: "krbtgt_hash", label: "krbtgt Hash", sub: "NTLM + AES", x: 700, y: 150, r: 36, type: "artifact",
      desc: "Extracted krbtgt NTLM hash and AES256 key. Required for TGT forging.",
      src: "MITRE T1558.001" },

    // Row 3: Mimikatz golden path
    { id: "mimi_golden", label: "Mimikatz", sub: "kerberos::golden", x: 830, y: 300, r: 34, type: "blind",
      desc: "BLIND: kerberos::golden /user:Admin /domain:corp /sid:S-1-5-21-... /krbtgt:<hash> — forges TGT offline.",
      src: "gentilkiwi/mimikatz" },
    { id: "mimi_ptt", label: "kerberos::ptt", sub: "Inject TGT", x: 960, y: 300, r: 30, type: "op",
      desc: "kerberos::ptt ticket.kirbi — injects forged TGT into current LSASS Kerberos cache.",
      src: "gentilkiwi/mimikatz" },
    { id: "lsa_submit", label: "LsaCallAuth", sub: "SubmitTicket", x: 1090, y: 300, r: 34, type: "api",
      desc: "LsaCallAuthenticationPackage(KerbSubmitTicketMessage) — injects ticket into LSASS.",
      src: "Microsoft LSASS API" },

    // Row 4: Impacket ticketer path
    { id: "imp_ticket", label: "ticketer.py", sub: "-nthash", x: 830, y: 400, r: 34, type: "blind",
      desc: "BLIND: Impacket ticketer.py -nthash <hash> -domain-sid <sid> — forges TGT as .ccache file offline.",
      src: "fortra/impacket" },
    { id: "ccache", label: ".ccache File", x: 960, y: 400, r: 28, type: "artifact",
      desc: "Kerberos credential cache file. Used via KRB5CCNAME env var with Impacket -k tools.",
      src: "MIT Kerberos; Impacket" },
    { id: "psexec_k", label: "psexec.py -k", sub: "KRB5CCNAME", x: 1090, y: 400, r: 34, type: "op",
      desc: "Impacket psexec.py -k -no-pass — uses forged ticket for remote service execution.",
      src: "fortra/impacket" },

    // Row 5: Rubeus golden path
    { id: "rubeus_golden", label: "Rubeus", sub: "golden /ptt", x: 830, y: 500, r: 34, type: "blind",
      desc: "BLIND: Rubeus golden /rc4:<hash> /user:Admin /ptt — forges and injects TGT in one step.",
      src: "GhostPack/Rubeus" },

    // ── DC Processing & Detection ──
    { id: "tgs_req", label: "TGS-REQ", sub: "port 88", x: 1220, y: 380, r: 30, type: "protocol",
      desc: "Kerberos TGS-REQ containing forged TGT sent to DC on port 88.",
      src: "RFC 4120" },
    { id: "kdc", label: "KDC Service", sub: "krbtgt decrypt", x: 1340, y: 380, r: 36, type: "system",
      desc: "KDC decrypts forged TGT (encrypted with real krbtgt key) — it's cryptographically valid.",
      src: "Microsoft KDC; RFC 4120" },
    { id: "ev_4769", label: "Event 4769", sub: "No prior 4768", x: 1470, y: 380, r: 40, type: "detect",
      desc: "OPTIMAL: Event 4769 (TGS issued) with NO preceding 4768 (AS-REQ). TGT lifetime anomaly. MDI detects this.",
      src: "Microsoft Defender for Identity; MITRE T1558.001" },

    // ── Outcome ──
    { id: "da_access", label: "DA Access", sub: "Full domain", x: 1600, y: 320, r: 34, type: "artifact",
      desc: "Full Domain Admin access to any resource in the domain. Any user identity, any group membership.",
      src: "MITRE T1558.001" },
    { id: "persistence", label: "Persistence", sub: "10-year ticket", x: 1600, y: 440, r: 34, type: "artifact",
      desc: "TGT valid for 10 years (default). Survives password resets. Only invalidated by krbtgt double-rotation.",
      src: "MITRE T1558.001; Microsoft krbtgt reset" },
  ],

  edges: [
    // DCSync path
    { f: "da_creds", t: "mimi_dcsync" },
    { f: "mimi_dcsync", t: "drsr_call" },
    { f: "drsr_call", t: "rpc_135" },
    { f: "rpc_135", t: "ev_4662" },
    { f: "ev_4662", t: "krbtgt_hash" },

    // NTDS.dit path
    { f: "da_creds", t: "vssadmin" },
    { f: "da_creds", t: "ntdsutil" },
    { f: "vssadmin", t: "copy_ntds" },
    { f: "ntdsutil", t: "copy_ntds" },
    { f: "copy_ntds", t: "secretsdump" },
    { f: "copy_ntds", t: "ev_vss" },
    { f: "secretsdump", t: "krbtgt_hash" },

    // Forge paths (blind)
    { f: "krbtgt_hash", t: "mimi_golden", blind: true },
    { f: "krbtgt_hash", t: "imp_ticket", blind: true },
    { f: "krbtgt_hash", t: "rubeus_golden", blind: true },

    // Mimikatz golden -> inject
    { f: "mimi_golden", t: "mimi_ptt", blind: true },
    { f: "mimi_ptt", t: "lsa_submit" },
    { f: "lsa_submit", t: "tgs_req" },

    // Impacket golden -> use
    { f: "imp_ticket", t: "ccache", blind: true },
    { f: "ccache", t: "psexec_k" },
    { f: "psexec_k", t: "tgs_req" },

    // Rubeus golden -> inject
    { f: "rubeus_golden", t: "lsa_submit", blind: true },

    // DC processing
    { f: "tgs_req", t: "kdc" },
    { f: "kdc", t: "ev_4769" },
    { f: "ev_4769", t: "da_access" },
    { f: "ev_4769", t: "persistence" },
  ],
};

export default model;
