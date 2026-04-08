// T1558.003 — Kerberoasting — Detection Data Model
// Tactic: Credential Access
// Full data model: nodes, edges, layout, metadata

const model = {
  metadata: {
    tcode: "T1558.003",
    name: "Kerberoasting",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.5",
  },

  detectNodeId: "ev",

  layout: {
    svgWidth: 1000,
    svgHeight: 560,
    columns: [
      { label: "AUTH",        x: 70  },
      { label: "ENUM SPNs",   x: 220 },
      { label: "TGS REQUEST", x: 400 },
      { label: "DC RESPONSE", x: 580 },
      { label: "EXTRACTION",  x: 760 },
      { label: "CRACKING",    x: 920 },
    ],
    separators: [145, 310, 490, 670, 845],
    annotations: [
      { text: "Covers 4 procedures", x: 580, y: 320, color: "#f57f17", fontWeight: "600" },
      { text: "Passive path bypasses all detection", x: 400, y: 500, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    // Column 1 — Entry Point
    { id: "creds", label: "Authenticate", sub: "to Domain", x: 70, y: 280, r: 40, type: "source",
      tags: ["Any domain user", "No special privs", "TGT in LSASS"],
      telemetry: [],
      api: "Any authenticated domain user session",
      artifact: "Existing TGT in LSASS Kerberos cache",
      desc: "Any authenticated domain user session is sufficient. A valid TGT already exists in the LSASS Kerberos cache from normal logon. No privilege escalation needed before beginning the attack.",
      src: "MITRE ATT&CK T1558.003 — attack.mitre.org/techniques/T1558/003/" },

    // Column 2 — SPN Enumeration
    { id: "lw", label: "Query SPNs", sub: "LDAP (Windows)", x: 220, y: 100, r: 36, type: "source",
      tags: ["Rubeus", "PowerView", "DirectorySearcher", "LDAP :389"],
      telemetry: ["Sysmon 3", "4662"],
      api: "DirectorySearcher → filter: (servicePrincipalName=*)",
      artifact: "LDAP traffic port 389 · Event ID 1644 (if LDAP diag enabled)",
      desc: "Rubeus and PowerView use System.DirectoryServices.DirectorySearcher with LDAP filter (samAccountType=805306368)(servicePrincipalName=*) to find kerberoastable accounts. The filter itself is anomalous — legitimate admin tools rarely issue this wildcard SPN query.",
      src: "Atomic Red Team T1558.003; GhostPack/Rubeus — github.com/GhostPack/Rubeus; Microsoft DirectorySearcher docs" },

    { id: "ll", label: "Query SPNs", sub: "LDAP (Linux)", x: 220, y: 200, r: 36, type: "source",
      tags: ["Impacket GetUserSPNs.py", "NetExec", "LDAP :389/636"],
      telemetry: ["4662"],
      api: "Raw LDAP bind + search via Impacket / NetExec",
      artifact: "LDAP traffic port 389/636 from non-Windows host",
      desc: "Impacket issues a raw LDAP bind on port 389/636 followed by a search using the same SPN wildcard filter. Traffic originating from a Linux host to LDAP port 389 on a DC targeting servicePrincipalName=* is a strong anomaly in most environments.",
      src: "Impacket GetUserSPNs.py — github.com/fortra/impacket; HackTricks Kerberoast" },

    { id: "sp", label: "Enum SPNs", sub: "setspn.exe", x: 220, y: 300, r: 36, type: "source",
      tags: ["setspn.exe -T -Q */*", "LOTL", "DsGetSpn()"],
      telemetry: ["Sysmon 1"],
      api: "DsGetSpn() Win32 API → LDAP query",
      artifact: "Process creation: setspn.exe -Q */* · LDAP port 389",
      desc: "setspn.exe -T <domain> -Q */* calls DsGetSpn() which issues an LDAP query. Process creation of setspn.exe with -Q */* arguments is detectable via Sysmon EID 1 or EDR process telemetry. No elevated privileges required.",
      src: "Microsoft setspn.exe docs; Atomic Red Team T1558.003" },

    { id: "pn", label: "Sniff Traffic", sub: "Passive Capture", x: 220, y: 460, r: 36, type: "blind",
      tags: ["No query made", "PCAP only", "NDR only"],
      telemetry: [],
      api: "No API call — passive packet capture only",
      artifact: "⚠ No LDAP query · No Event ID 4769 · NDR only",
      desc: "BLIND SPOT: Attacker with network access captures KRB_TGS_REP packets passively using Wireshark or tcpdump. No LDAP query is issued. No TGS-REQ is made by the attacker. Event ID 4769 never fires. Only detectable via NDR/full packet capture.",
      src: "MITRE T1558.003; nidem/kerberoast extracttgsrepfrompcap.py — github.com/nidem/kerberoast; Netresec 2019" },

    // Column 3 — TGS Request Methods
    { id: "r4", label: "Request TGS", sub: "RC4 Downgrade", x: 400, y: 100, r: 36, type: "source",
      tags: ["etype 0x17", "RC4_HMAC_MD5", "KerberosRequestorSecurityToken"],
      telemetry: [],
      api: "KerberosRequestorSecurityToken() OR raw TGS-REQ etype 23",
      artifact: "KRB_TGS_REQ on port 88 · etype 0x17 in request",
      desc: "Most tools default to requesting etype 23 (RC4_HMAC_MD5). Via Windows .NET, KerberosRequestorSecurityToken() calls AcquireCredentialsHandle('Kerberos') then InitializeSecurityContext(). Via Rubeus, a raw KRB_TGS_REQ is crafted directly, bypassing Windows Kerberos APIs entirely — producing a different network fingerprint.",
      src: "TrustedSec Orpheus 2025; ired.team Kerberoasting; SpecterOps Kerberoasting Revisited 2019" },

    { id: "ae", label: "Request TGS", sub: "AES Stealth", x: 400, y: 200, r: 36, type: "source",
      tags: ["etype 0x12", "AES256", "Blends in"],
      telemetry: [],
      api: "Modified Impacket kerberosv5.py → raw TGS-REQ etype 18",
      artifact: "KRB_TGS_REQ port 88 · etype 0x12 · blends w/ normal",
      desc: "Modified Impacket kerberosv5.py forces etype 18 (AES256) in the TGS-REQ. The resulting Event ID 4769 shows TicketEncryptionType 0x12 rather than 0x17, bypassing RC4-based detection rules. Ticket blends with normal Kerberos traffic. Harder to crack offline.",
      src: "TrustedSec — Bypassing Kerberoast Detections with Orpheus, 2025 — trustedsec.com" },

    { id: "to", label: "Request TGS", sub: "Ticket Opts", x: 400, y: 300, r: 36, type: "source",
      tags: ["0x40810000", "Flag matching", "Renewable-ok"],
      telemetry: [],
      api: "Rubeus raw TGS-REQ with modified TicketOptions field",
      artifact: "KRB_TGS_REQ TicketOptions 0x40800000 vs normal 0x40810000",
      desc: "Rubeus crafts a raw TGS-REQ with TicketOptions field set to 0x40800000. Normal AD Kerberos traffic uses 0x40810000. The difference is the Renewable-ok flag. Attackers who set options to match normal traffic evade TicketOptions-based detection signatures.",
      src: "Intrinsec — Kerberos OPSEC Part 1, 2023 — intrinsec.com" },

    { id: "td", label: "Request TGS", sub: "tgtdeleg", x: 400, y: 400, r: 36, type: "source",
      tags: ["Rubeus /tgtdeleg", "S4U2Self", "Patched WS2019+"],
      telemetry: [],
      api: "GSS-API fake delegation → AcquireCredentialsHandle() → RC4 TGS-REQ",
      artifact: "KRB_TGS_REQ with S4U2Self · etype 0x17 · patched WS2019+",
      desc: "Rubeus /tgtdeleg uses the Kerberos GSS-API via AcquireCredentialsHandle() to request a fake unconstrained delegation TGT (kekeo trick). This TGT is then used to craft a raw TGS-REQ specifying only RC4, enabling RC4 ticket retrieval even for AES-configured accounts. Patched on Windows Server 2019+.",
      src: "SpecterOps — Kerberoasting Revisited, 2019 — specterops.io; gentilkiwi/kekeo" },

    // Column 4 — DC Issues TGS (OPTIMAL DETECTION)
    { id: "ev", label: "Issue TGS", sub: "Event 4769", x: 580, y: 250, r: 50, type: "detect",
      tags: ["Event 4769", "TGS-REP", "Exclude krbtgt", "Exclude *$"],
      telemetry: ["4769"],
      api: "KDC: LookupAccountName() → EncryptTicket(service acct key)",
      artifact: "OPTIMAL NODE: ServiceName, ClientAddress, TicketEncryptionType, TicketOptions",
      desc: "OPTIMAL DETECTION NODE. The DC fires Event ID 4769 for every KRB_TGS_REQ it receives. Key fields: ServiceName (look for user accounts not machine accounts), ClientAddress (source IP), TicketEncryptionType (0x17=RC4, 0x12=AES256), TicketOptions (0x40800000=Rubeus default). Filters: exclude krbtgt, exclude *$ accounts, success only (0x0). Covers all 4 active request procedures. Blind to passive PCAP path.",
      src: "MITRE ATT&CK DET0157 — attack.mitre.org/detectionstrategies/DET0157/; Microsoft Event 4769 docs" },

    // Column 5 — Extraction Methods
    { id: "me", label: "Extract Hash", sub: "Memory", x: 760, y: 180, r: 36, type: "source",
      tags: ["Mimikatz", "Rubeus dump", "LSASS access"],
      telemetry: ["Sysmon 10"],
      api: "LsaCallAuthenticationPackage() → KerbRetrieveEncodedTicketMessage",
      artifact: "Sysmon EID 10: LSASS access · sekurlsa::tickets in Mimikatz",
      desc: "Mimikatz sekurlsa::tickets and Rubeus dump both call LsaCallAuthenticationPackage() with KerbRetrieveEncodedTicketMessage to pull the raw ticket blob from LSASS. This LSASS memory access is detectable via Sysmon EID 10 (process access to lsass.exe) or EDR LSASS protection alerts.",
      src: "ired.team Kerberoasting; gentilkiwi/mimikatz — github.com/gentilkiwi/mimikatz; Sysmon EID 10" },

    { id: "do", label: "Extract Hash", sub: "File Output", x: 760, y: 300, r: 36, type: "source",
      tags: ["$krb5tgs$23$", "$krb5tgs$18$", "No LSASS"],
      telemetry: ["Sysmon 11"],
      api: "Rubeus/Impacket write $krb5tgs$ hash to stdout/file — no LSASS touch",
      artifact: "$krb5tgs$23$ (RC4) or $krb5tgs$18$ (AES256) · no Sysmon EID 10",
      desc: "Rubeus and Impacket write the $krb5tgs$ hash directly to stdout or file without touching LSASS at all. No Sysmon EID 10 fires. The hash is captured at the network/tool output layer. This path produces no LSASS-based artifacts and bypasses EDR LSASS protection entirely.",
      src: "HackTricks Kerberoast; GhostPack/Rubeus — github.com/GhostPack/Rubeus" },

    { id: "pe", label: "Extract Hash", sub: "From PCAP", x: 580, y: 460, r: 36, type: "blind",
      tags: ["extracttgsrepfrompcap.py", "nidem/kerberoast", "Zero logs"],
      telemetry: [],
      api: "extracttgsrepfrompcap.py parses KRB_TGS_REP enc-part from pcap",
      artifact: "⚠ No host artifacts · no logs · NDR/PCAP source only",
      desc: "BLIND SPOT: nidem/kerberoast extracttgsrepfrompcap.py parses the enc-part of KRB_TGS_REP packets directly from a PCAP file. No host execution on target. No LSASS access. No Windows events of any kind. Only detectable if full packet capture exists and is analyzed.",
      src: "nidem/kerberoast — github.com/nidem/kerberoast; Netresec PCAP blog 2019" },

    // Column 6 — Offline Cracking
    { id: "cr", label: "Crack Hash", sub: "Offline", x: 920, y: 280, r: 45, type: "blind",
      tags: ["hashcat 13100", "hashcat 19700", "No logs", "Prevention only"],
      telemetry: [],
      api: "hashcat -m 13100 (RC4) / -m 19700 (AES256) — no network comms",
      artifact: "⚠ Zero DC events · zero network traffic · prevention only",
      desc: "BLIND SPOT: Cracking is fully off-network on attacker hardware. hashcat -m 13100 for RC4 ($krb5tgs$23$) reaches billions of guesses/sec on modern GPUs. hashcat -m 19700 for AES256 ($krb5tgs$18$) is slower but viable against weak passwords. Zero DC events. Zero network traffic. Mitigation is preventive only: gMSA accounts, strong passwords (25+ chars), AES enforcement.",
      src: "HackTricks; ADSecurity Metcalf 2015 — adsecurity.org/?p=2293; Netwrix Kerberoasting" },
  ],

  edges: [
    // Auth to SPN enumeration
    { f: "creds", t: "lw" },
    { f: "creds", t: "ll" },
    { f: "creds", t: "sp" },
    { f: "creds", t: "pn", blind: true },

    // SPN enum to TGS request
    { f: "lw", t: "r4" },
    { f: "lw", t: "ae" },
    { f: "ll", t: "r4" },
    { f: "ll", t: "to" },
    { f: "sp", t: "r4" },
    { f: "sp", t: "td" },

    // TGS requests to DC detection
    { f: "r4", t: "ev" },
    { f: "ae", t: "ev" },
    { f: "to", t: "ev" },
    { f: "td", t: "ev" },

    // DC to extraction
    { f: "ev", t: "me" },
    { f: "ev", t: "do" },

    // Passive path (bypasses DC)
    { f: "pn", t: "pe", blind: true },

    // Extraction to cracking
    { f: "me", t: "cr" },
    { f: "do", t: "cr" },
    { f: "pe", t: "cr", blind: true },
  ],
};

export default model;
