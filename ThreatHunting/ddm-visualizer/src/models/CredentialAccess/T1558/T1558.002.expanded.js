// T1558.002 — Silver Ticket — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1558.002",
    name: "Silver Ticket",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1600,
    svgHeight: 520,
    rows: [
      { label: "MIMIKATZ",  y: 100 },
      { label: "DCSYNC",    y: 200 },
      { label: "LSASS",     y: 300 },
      { label: "IMPACKET",  y: 400 },
      { label: "RUBEUS",    y: 480 },
    ],
    annotations: [
      { text: "Silver Ticket NEVER touches the KDC - no 4769 event", x: 1050, y: 500, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    // ── Hash Extraction ──
    { id: "target_svc", label: "Target Service", sub: "SPN account", x: 60, y: 200, r: 36, type: "entry",
      desc: "Identify target service (e.g., CIFS/server, MSSQLSvc/db, HTTP/webapp). Need that service account's NTLM hash or AES key.",
      src: "MITRE ATT&CK T1558.002" },

    // Row 1: Kerberoast to get hash
    { id: "kerberoast", label: "Kerberoast", sub: "T1558.003", x: 180, y: 100, r: 32, type: "op",
      desc: "Request TGS for target SPN, crack offline to get service account NTLM hash.",
      src: "MITRE T1558.003" },
    { id: "hashcat_13100", label: "hashcat", sub: "-m 13100", x: 310, y: 100, r: 30, type: "blind",
      desc: "BLIND: Offline GPU cracking of Kerberoasted TGS hash. Zero network traffic.",
      src: "hashcat.net" },

    // Row 2: DCSync for hash
    { id: "mimi_dcsync", label: "DCSync", sub: "lsadump::dcsync", x: 180, y: 200, r: 34, type: "op",
      desc: "DCSync the service account: Mimikatz lsadump::dcsync /user:svc_account",
      src: "gentilkiwi/mimikatz" },
    { id: "drsr_api", label: "DrsGetNCChanges", x: 310, y: 200, r: 34, type: "api",
      desc: "MS-DRSR replication of specific service account object from DC.",
      src: "Microsoft MS-DRSR" },
    { id: "ev_4662_dc", label: "Event 4662", x: 440, y: 200, r: 30, type: "detect",
      desc: "Event 4662: DS-Replication-Get-Changes on service account from non-DC source.",
      src: "Microsoft Event 4662" },

    // Row 3: LSASS dump for hash
    { id: "mimi_lsass", label: "Mimikatz", sub: "sekurlsa", x: 180, y: 300, r: 32, type: "op",
      desc: "Mimikatz sekurlsa::logonpasswords on host where service account is logged in.",
      src: "gentilkiwi/mimikatz" },
    { id: "minidump_api", label: "MiniDump", sub: "WriteDump()", x: 310, y: 300, r: 30, type: "api",
      desc: "MiniDumpWriteDump() on LSASS process to extract service credentials.",
      src: "Microsoft Debug API" },
    { id: "sysmon_10", label: "Sysmon 10", sub: "LSASS access", x: 440, y: 300, r: 30, type: "detect",
      desc: "Sysmon EID 10: Cross-process access to lsass.exe with credential read rights.",
      src: "Sysmon documentation" },

    // ── Service hash obtained ──
    { id: "svc_hash", label: "Service Hash", sub: "NTLM + AES", x: 560, y: 200, r: 36, type: "artifact",
      desc: "Service account NTLM hash and/or AES256 key obtained. Required for Silver Ticket.",
      src: "MITRE T1558.002" },

    // ── Forging: All paths are BLIND ──
    // Row 1: Mimikatz silver
    { id: "mimi_silver", label: "Mimikatz", sub: "kerberos::golden /service:", x: 700, y: 100, r: 34, type: "blind",
      desc: "BLIND: kerberos::golden /service:cifs /target:server /rc4:<hash> — forges TGS (silver ticket) offline.",
      src: "gentilkiwi/mimikatz" },

    // Row 4: Impacket ticketer
    { id: "imp_silver", label: "ticketer.py", sub: "-spn SPN", x: 700, y: 400, r: 34, type: "blind",
      desc: "BLIND: Impacket ticketer.py -nthash <hash> -domain-sid <sid> -spn cifs/server — forges TGS offline.",
      src: "fortra/impacket" },

    // Row 5: Rubeus silver
    { id: "rubeus_silver", label: "Rubeus", sub: "silver /service:", x: 700, y: 480, r: 34, type: "blind",
      desc: "BLIND: Rubeus silver /service:cifs/server /rc4:<hash> /ptt — forges and injects TGS.",
      src: "GhostPack/Rubeus" },

    // ── Injection ──
    { id: "ptt_inject", label: "kerberos::ptt", sub: "Inject TGS", x: 840, y: 200, r: 32, type: "op",
      desc: "Inject forged TGS into current logon session LSASS Kerberos cache.",
      src: "gentilkiwi/mimikatz; Rubeus" },
    { id: "lsa_call", label: "LsaCallAuth", sub: "SubmitTicket", x: 960, y: 200, r: 34, type: "api",
      desc: "LsaCallAuthenticationPackage(KerbSubmitTicketMessage) injects forged TGS into LSASS.",
      src: "Microsoft LSASS API" },

    // ── Direct service access (NO KDC contact) ──
    { id: "ap_req", label: "AP-REQ", sub: "Direct to service", x: 1100, y: 200, r: 34, type: "protocol",
      desc: "AP-REQ sent directly to target service. The KDC is NEVER contacted — no Event 4769.",
      src: "RFC 4120" },
    { id: "service_proc", label: "Service Process", sub: "Decrypt TGS", x: 1240, y: 200, r: 36, type: "system",
      desc: "Target service decrypts TGS with its own key — it's cryptographically valid. Grants access.",
      src: "RFC 4120; MS-KILE" },

    // ── Detection ──
    { id: "ev_4624", label: "Event 4624", sub: "Type 3 logon", x: 1380, y: 140, r: 34, type: "detect",
      desc: "Event 4624 type 3: Network logon on target host. Check for PAC anomalies, no 4768/4769.",
      src: "Microsoft Event 4624" },
    { id: "ev_4627", label: "Event 4627", sub: "Group membership", x: 1380, y: 260, r: 32, type: "detect",
      desc: "Event 4627: Groups in the token may not match actual AD group membership for the forged account.",
      src: "Microsoft Event 4627" },

    // ── Outcome ──
    { id: "svc_access", label: "Service Access", sub: "SMB/SQL/HTTP", x: 1530, y: 140, r: 34, type: "artifact",
      desc: "Access to specific service: file shares (CIFS), databases (MSSQL), web apps (HTTP), etc.",
      src: "MITRE T1558.002" },
    { id: "lateral", label: "Lateral Move", sub: "Single host", x: 1530, y: 280, r: 32, type: "artifact",
      desc: "Silver Ticket is scoped to one service on one host. Need separate ticket per service/host.",
      src: "MITRE T1558.002" },
  ],

  edges: [
    // Hash extraction paths
    { f: "target_svc", t: "kerberoast" },
    { f: "target_svc", t: "mimi_dcsync" },
    { f: "target_svc", t: "mimi_lsass" },
    { f: "kerberoast", t: "hashcat_13100" },
    { f: "hashcat_13100", t: "svc_hash", blind: true },
    { f: "mimi_dcsync", t: "drsr_api" },
    { f: "drsr_api", t: "ev_4662_dc" },
    { f: "ev_4662_dc", t: "svc_hash" },
    { f: "mimi_lsass", t: "minidump_api" },
    { f: "minidump_api", t: "sysmon_10" },
    { f: "sysmon_10", t: "svc_hash" },

    // Forging (blind)
    { f: "svc_hash", t: "mimi_silver", blind: true },
    { f: "svc_hash", t: "imp_silver", blind: true },
    { f: "svc_hash", t: "rubeus_silver", blind: true },

    // Injection
    { f: "mimi_silver", t: "ptt_inject", blind: true },
    { f: "imp_silver", t: "ptt_inject", blind: true },
    { f: "rubeus_silver", t: "ptt_inject", blind: true },
    { f: "ptt_inject", t: "lsa_call" },
    { f: "lsa_call", t: "ap_req" },

    // Service access (no KDC)
    { f: "ap_req", t: "service_proc" },
    { f: "service_proc", t: "ev_4624" },
    { f: "service_proc", t: "ev_4627" },
    { f: "ev_4624", t: "svc_access" },
    { f: "ev_4627", t: "lateral" },
  ],
};

export default model;
