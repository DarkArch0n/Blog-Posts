// T1558.003 — Kerberoasting — Expanded Technology Chain
// Adapted from the original T1558.003-DDM.html reference

const model = {
  metadata: {
    tcode: "T1558.003",
    name: "Kerberoasting",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.4",
  },

  layout: {
    svgWidth: 1650,
    svgHeight: 600,
    rows: [
      { label: "WINDOWS",  y: 100 },
      { label: "LINUX",    y: 200 },
      { label: "LOTL",     y: 300 },
      { label: "DELEG",    y: 400 },
      { label: "BLIND",    y: 520, color: "#c62828" },
    ],
  },

  nodes: [
    // Row 1: Rubeus / Windows path
    { id: "creds", label: "Domain Creds", x: 60, y: 100, r: 36, type: "entry",
      desc: "Any authenticated domain user. TGT already in LSASS from normal logon.",
      src: "MITRE ATT&CK T1558.003" },
    { id: "rubeus_enum", label: "Rubeus", sub: "kerberoast", x: 160, y: 100, r: 32, type: "op",
      desc: "Rubeus kerberoast command enumerates SPNs and requests TGS tickets.",
      src: "GhostPack/Rubeus" },
    { id: "dir_searcher", label: "DirectorySearcher", x: 280, y: 100, r: 34, type: "api",
      desc: "System.DirectoryServices.DirectorySearcher .NET class queries AD via LDAP.",
      src: "Microsoft .NET docs" },
    { id: "ldap_389", label: "LDAP :389", x: 400, y: 100, r: 30, type: "protocol",
      desc: "LDAP query to port 389 with filter (servicePrincipalName=*).",
      src: "RFC 4511" },
    { id: "krb_token", label: "KerberosRequestor", sub: "SecurityToken", x: 520, y: 100, r: 38, type: "api",
      desc: "System.IdentityModel.Tokens.KerberosRequestorSecurityToken requests TGS.",
      src: "Microsoft .NET docs" },
    { id: "acq_creds", label: "AcquireCreds", sub: "Handle()", x: 640, y: 100, r: 34, type: "api",
      desc: "Windows SSPI AcquireCredentialsHandle('Kerberos') for TGS-REQ.",
      src: "Microsoft SSPI docs" },
    { id: "tgs_req_1", label: "TGS-REQ", sub: "etype 0x17", x: 760, y: 100, r: 32, type: "protocol",
      desc: "Kerberos TGS-REQ on port 88 requesting RC4 (etype 23).",
      src: "RFC 4120" },

    // Row 2: Impacket / Linux path
    { id: "impacket", label: "Impacket", sub: "GetUserSPNs", x: 160, y: 200, r: 34, type: "op",
      desc: "Impacket GetUserSPNs.py remotely enumerates SPNs via LDAP.",
      src: "fortra/impacket" },
    { id: "ldap_bind", label: "LDAP Bind", x: 280, y: 200, r: 30, type: "api",
      desc: "Raw LDAP simple bind with plaintext creds or NT hash.",
      src: "Impacket ldap.py" },
    { id: "ldap_636", label: "LDAPS :636", x: 400, y: 200, r: 30, type: "protocol",
      desc: "LDAP over TLS on port 636 from non-Windows host.",
      src: "RFC 4511" },
    { id: "raw_tgs", label: "Raw TGS-REQ", sub: "kerberosv5.py", x: 520, y: 200, r: 36, type: "api",
      desc: "Impacket crafts raw TGS-REQ bypassing Windows Kerberos APIs.",
      src: "Impacket kerberosv5.py" },
    { id: "tgs_req_aes", label: "TGS-REQ", sub: "etype 0x12", x: 640, y: 200, r: 32, type: "protocol",
      desc: "TGS-REQ with AES256 (etype 18) — blends with normal traffic.",
      src: "TrustedSec Orpheus 2025" },

    // Row 3: setspn / LOTL path
    { id: "setspn", label: "setspn.exe", sub: "-Q */*", x: 160, y: 300, r: 34, type: "op",
      desc: "Native Windows binary enumerates SPNs. Living-off-the-land.",
      src: "Microsoft setspn.exe docs" },
    { id: "dsgetspn", label: "DsGetSpn()", x: 280, y: 300, r: 32, type: "api",
      desc: "Win32 DsGetSpn() API issues LDAP query for SPNs.",
      src: "Microsoft Win32 API docs" },
    { id: "sysmon_1", label: "Sysmon 1", sub: "Process Create", x: 400, y: 300, r: 30, type: "artifact",
      desc: "Sysmon Event ID 1: setspn.exe process creation with -Q */* args.",
      src: "Sysmon docs" },

    // Row 4: tgtdeleg path
    { id: "rubeus_deleg", label: "Rubeus", sub: "/tgtdeleg", x: 160, y: 400, r: 34, type: "op",
      desc: "Rubeus /tgtdeleg uses GSS-API fake delegation trick.",
      src: "GhostPack/Rubeus; kekeo" },
    { id: "gss_api", label: "GSS-API", x: 280, y: 400, r: 30, type: "api",
      desc: "Kerberos GSS-API for fake unconstrained delegation TGT.",
      src: "RFC 2743" },
    { id: "acq_creds_2", label: "AcquireCreds", sub: "Handle()", x: 400, y: 400, r: 34, type: "api",
      desc: "SSPI AcquireCredentialsHandle() to force RC4 TGS-REQ.",
      src: "Microsoft SSPI docs" },
    { id: "tgs_req_deleg", label: "TGS-REQ", sub: "S4U2Self", x: 520, y: 400, r: 32, type: "protocol",
      desc: "TGS-REQ with S4U2Self extension, etype 0x17. Patched WS2019+.",
      src: "SpecterOps 2019" },

    // ── DC Processing ──
    { id: "kdc", label: "KDC Service", x: 880, y: 200, r: 40, type: "system",
      desc: "Domain Controller Kerberos Distribution Center receives TGS-REQ.",
      src: "Microsoft KDC docs" },
    { id: "lookup_acct", label: "LookupAccount", sub: "Name()", x: 1000, y: 140, r: 34, type: "api",
      desc: "KDC looks up service account by SPN in Active Directory.",
      src: "Microsoft Win32 API" },
    { id: "encrypt_tkt", label: "EncryptTicket", sub: "(svc key)", x: 1000, y: 260, r: 36, type: "api",
      desc: "KDC encrypts TGS ticket with service account's password hash.",
      src: "RFC 4120; MS-KILE" },
    { id: "ev_4769", label: "Event 4769", sub: "TGS Issued", x: 1120, y: 200, r: 44, type: "detect",
      desc: "OPTIMAL: Security log fires for every TGS-REQ. Key fields: ServiceName, ClientAddress, TicketEncryptionType.",
      src: "MITRE DET0157; Microsoft Event 4769" },

    // ── Response & Extraction ──
    { id: "tgs_rep", label: "TGS-REP", sub: "port 88", x: 1240, y: 200, r: 34, type: "protocol",
      desc: "KRB_TGS_REP returns encrypted service ticket to client.",
      src: "RFC 4120" },
    { id: "lsa_submit", label: "LsaCallAuth", sub: "SubmitTicket", x: 1360, y: 140, r: 36, type: "api",
      desc: "LsaCallAuthenticationPackage(KerbSubmitTicketMessage) stores ticket in LSASS.",
      src: "Microsoft LSASS docs" },
    { id: "lsass", label: "LSASS", sub: "Ticket Cache", x: 1480, y: 140, r: 38, type: "system",
      desc: "TGS blob stored in LSASS Kerberos ticket cache in memory.",
      src: "Microsoft Kerberos SSP" },
    { id: "lsa_retrieve", label: "LsaCallAuth", sub: "RetrieveTicket", x: 1360, y: 260, r: 36, type: "api",
      desc: "LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage) extracts ticket blob.",
      src: "Microsoft LSASS docs" },
    { id: "mimikatz", label: "Mimikatz", sub: "sekurlsa::tickets", x: 1480, y: 260, r: 36, type: "op",
      desc: "Mimikatz reads TGS blob from LSASS memory. Requires local execution.",
      src: "gentilkiwi/mimikatz" },
    { id: "sysmon_10", label: "Sysmon 10", sub: "LSASS Access", x: 1600, y: 200, r: 34, type: "detect",
      desc: "Sysmon EID 10: Process access to lsass.exe with credential read.",
      src: "Sysmon docs" },

    // Direct output (no LSASS)
    { id: "direct_out", label: "Direct Output", sub: "$krb5tgs$", x: 1360, y: 360, r: 36, type: "op",
      desc: "Rubeus/Impacket output hash directly — no LSASS access needed. Bypasses Sysmon 10.",
      src: "HackTricks; Rubeus" },

    // Blind: passive capture
    { id: "pcap", label: "PCAP", sub: "Capture", x: 160, y: 520, r: 32, type: "blind",
      desc: "BLIND: Passive network capture of Kerberos traffic. No host artifacts.",
      src: "MITRE T1558.003" },
    { id: "extract_pcap", label: "extracttgs", sub: "frompcap.py", x: 400, y: 520, r: 36, type: "blind",
      desc: "BLIND: nidem/kerberoast parses TGS-REP enc-part from PCAP. Zero logs.",
      src: "nidem/kerberoast" },

    // Offline cracking
    { id: "hash_rc4", label: "$krb5tgs$23$", x: 1480, y: 360, r: 34, type: "artifact",
      desc: "RC4 TGS hash in hashcat format. Fast to crack on GPU.",
      src: "hashcat wiki" },
    { id: "hash_aes", label: "$krb5tgs$18$", x: 1480, y: 440, r: 34, type: "artifact",
      desc: "AES256 TGS hash. Slower to crack but still viable with weak passwords.",
      src: "hashcat wiki" },
    { id: "hashcat", label: "hashcat", sub: "-m 13100/19700", x: 1600, y: 400, r: 40, type: "blind",
      desc: "BLIND: Offline cracking. Zero DC events. Zero network traffic. Prevention only.",
      src: "hashcat.net" },
  ],

  edges: [
    // Row 1: Rubeus Windows path
    { f: "creds", t: "rubeus_enum" },
    { f: "rubeus_enum", t: "dir_searcher" },
    { f: "dir_searcher", t: "ldap_389" },
    { f: "rubeus_enum", t: "krb_token" },
    { f: "krb_token", t: "acq_creds" },
    { f: "acq_creds", t: "tgs_req_1" },
    { f: "tgs_req_1", t: "kdc" },
    // Row 2: Impacket
    { f: "creds", t: "impacket" },
    { f: "impacket", t: "ldap_bind" },
    { f: "ldap_bind", t: "ldap_636" },
    { f: "impacket", t: "raw_tgs" },
    { f: "raw_tgs", t: "tgs_req_aes" },
    { f: "tgs_req_aes", t: "kdc" },
    // Row 3: setspn
    { f: "creds", t: "setspn" },
    { f: "setspn", t: "dsgetspn" },
    { f: "dsgetspn", t: "ldap_389" },
    { f: "setspn", t: "sysmon_1" },
    // Row 4: tgtdeleg
    { f: "creds", t: "rubeus_deleg" },
    { f: "rubeus_deleg", t: "gss_api" },
    { f: "gss_api", t: "acq_creds_2" },
    { f: "acq_creds_2", t: "tgs_req_deleg" },
    { f: "tgs_req_deleg", t: "kdc" },
    // DC processing
    { f: "kdc", t: "lookup_acct" },
    { f: "lookup_acct", t: "encrypt_tkt" },
    { f: "encrypt_tkt", t: "ev_4769" },
    { f: "ev_4769", t: "tgs_rep" },
    // Response & storage
    { f: "tgs_rep", t: "lsa_submit" },
    { f: "lsa_submit", t: "lsass" },
    { f: "lsass", t: "lsa_retrieve" },
    { f: "lsa_retrieve", t: "mimikatz" },
    { f: "mimikatz", t: "sysmon_10" },
    // Direct output
    { f: "tgs_rep", t: "direct_out" },
    { f: "direct_out", t: "hash_rc4" },
    { f: "mimikatz", t: "hash_rc4" },
    // Passive/blind
    { f: "creds", t: "pcap", blind: true },
    { f: "pcap", t: "extract_pcap", blind: true },
    { f: "extract_pcap", t: "hash_aes", blind: true },
    // Cracking
    { f: "hash_rc4", t: "hashcat" },
    { f: "hash_aes", t: "hashcat", blind: true },
  ],
};

export default model;
