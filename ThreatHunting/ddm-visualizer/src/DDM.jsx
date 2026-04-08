import { useState } from "react";

// LEFT-TO-RIGHT flow (VanVleet style)
// Green = attacker/source, Blue = target/DC, Red = blind spot, Yellow = optimal detection

const NODES = [
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
];

const EDGES = [
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
];

const COLORS = {
  source: { fill: "#e8f5e9", stroke: "#2e7d32", text: "#1b5e20" },
  target: { fill: "#e3f2fd", stroke: "#1565c0", text: "#0d47a1" },
  detect: { fill: "#fff8e1", stroke: "#f57f17", text: "#e65100" },
  blind:  { fill: "#ffebee", stroke: "#c62828", text: "#b71c1c" },
};

export default function DDM() {
  const [sel, setSel] = useState(null);
  const selNode = sel ? NODES.find(n => n.id === sel) : null;
  const isDetect = (id) => id === "ev";

  // Curved path from right edge of source to left edge of target
  const drawPath = (fn, tn) => {
    const x1 = fn.x + fn.r;
    const y1 = fn.y;
    const x2 = tn.x - tn.r;
    const y2 = tn.y;
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  };

  return (
    <div style={{ padding: "24px 32px", maxWidth: 1050, margin: "0 auto", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" }}>

      {/* Header */}
      <div style={{ marginBottom: 20, paddingBottom: 16, borderBottom: "2px solid #e0e0e0" }}>
        <div style={{ fontSize: 11, color: "#666", letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>
          Detection Data Model
        </div>
        <div style={{ fontSize: 24, fontWeight: 600, color: "#111" }}>
          T1558.003 — Kerberoasting
        </div>
        <div style={{ fontSize: 12, color: "#888", marginTop: 4 }}>
          Tactic: Credential Access · Platform: Windows Active Directory · MITRE ATT&CK v15
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 24, marginBottom: 20, fontSize: 12, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill={COLORS.source.fill} stroke={COLORS.source.stroke} strokeWidth="2"/></svg>
          <span>Attacker Operation</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="24" height="20"><circle cx="12" cy="10" r="8" fill={COLORS.detect.fill} stroke={COLORS.detect.stroke} strokeWidth="3"/></svg>
          <span style={{ fontWeight: 600 }}>Optimal Detection</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill={COLORS.blind.fill} stroke={COLORS.blind.stroke} strokeWidth="2" strokeDasharray="3,2"/></svg>
          <span>Blind Spot</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5" stroke="#c62828" strokeWidth="1.5" strokeDasharray="4,3"/></svg>
          <span style={{ color: "#999" }}>Blind Path</span>
        </div>
      </div>

      {/* SVG Graph */}
      <svg width="1000" height="560" style={{ display: "block", background: "#fafafa", border: "1px solid #e0e0e0", borderRadius: 4 }}>
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#666" />
          </marker>
          <marker id="arrow-blind" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#c62828" />
          </marker>
          <marker id="arrow-detect" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#f57f17" />
          </marker>
        </defs>

        {/* Column Labels */}
        <text x="70" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">AUTH</text>
        <text x="220" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">ENUM SPNs</text>
        <text x="400" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">TGS REQUEST</text>
        <text x="580" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">DC RESPONSE</text>
        <text x="760" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">EXTRACTION</text>
        <text x="920" y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">CRACKING</text>

        {/* Vertical separator lines */}
        <line x1="145" y1="45" x2="145" y2="520" stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>
        <line x1="310" y1="45" x2="310" y2="520" stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>
        <line x1="490" y1="45" x2="490" y2="520" stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>
        <line x1="670" y1="45" x2="670" y2="520" stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>
        <line x1="845" y1="45" x2="845" y2="520" stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>

        {/* Edges */}
        {EDGES.map((e, i) => {
          const fn = NODES.find(n => n.id === e.f);
          const tn = NODES.find(n => n.id === e.t);
          if (!fn || !tn) return null;

          const toDetect = tn.id === "ev";
          const isBlind = e.blind;

          return (
            <path
              key={i}
              d={drawPath(fn, tn)}
              stroke={isBlind ? "#c62828" : toDetect ? "#f57f17" : "#888"}
              strokeWidth={toDetect ? 2 : 1.5}
              strokeDasharray={isBlind ? "5,4" : "none"}
              fill="none"
              markerEnd={isBlind ? "url(#arrow-blind)" : toDetect ? "url(#arrow-detect)" : "url(#arrow)"}
            />
          );
        })}

        {/* Nodes */}
        {NODES.map(n => {
          const detect = isDetect(n.id);
          const colors = detect ? COLORS.detect : COLORS[n.type];
          const isSel = sel === n.id;
          const isBlindNode = n.type === "blind";

          return (
            <g key={n.id} onClick={() => setSel(sel === n.id ? null : n.id)} style={{ cursor: "pointer" }}>
              {/* Outer glow for selected */}
              {isSel && (
                <circle cx={n.x} cy={n.y} r={n.r + 6} fill="none" stroke="#333" strokeWidth="2" opacity="0.3" />
              )}

              {/* Main circle */}
              <circle
                cx={n.x}
                cy={n.y}
                r={n.r}
                fill={colors.fill}
                stroke={colors.stroke}
                strokeWidth={detect ? 4 : 2}
                strokeDasharray={isBlindNode ? "4,3" : "none"}
              />

              {/* Label */}
              <text
                x={n.x}
                y={n.y - 6}
                textAnchor="middle"
                fill={colors.text}
                fontSize={detect ? 12 : 10}
                fontWeight={detect ? "bold" : "500"}
              >
                {n.label}
              </text>

              {/* Subtitle */}
              <text
                x={n.x}
                y={n.y + 9}
                textAnchor="middle"
                fill={colors.text}
                fontSize={8}
                opacity={0.85}
              >
                {n.sub}
              </text>

              {/* Telemetry badge */}
              {n.telemetry && n.telemetry.length > 0 && (
                <g>
                  <rect
                    x={n.x - 20}
                    y={n.y + n.r + 4}
                    width={40}
                    height={14}
                    rx={3}
                    fill="#fff"
                    stroke="#9e9e9e"
                    strokeWidth="1"
                  />
                  <text
                    x={n.x}
                    y={n.y + n.r + 14}
                    textAnchor="middle"
                    fontSize="8"
                    fill="#616161"
                  >
                    {n.telemetry[0]}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Optimal detection highlight */}
        <text x="580" y="320" textAnchor="middle" fontSize="9" fill="#f57f17" fontWeight="600">
          Covers 4 procedures
        </text>

        {/* Blind path label */}
        <text x="400" y="500" textAnchor="middle" fontSize="9" fill="#c62828" fontStyle="italic">
          Passive path bypasses all detection
        </text>
      </svg>

      {/* Detail Panel */}
      {selNode && (
        <div style={{
          marginTop: 16,
          border: "1px solid #ddd",
          borderRadius: 6,
          padding: "16px 20px",
          background: "#fff",
          boxShadow: "0 2px 8px rgba(0,0,0,0.08)"
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{
                fontWeight: 600,
                fontSize: 15,
                marginBottom: 4,
                color: isDetect(selNode.id) ? COLORS.detect.stroke : COLORS[selNode.type].stroke
              }}>
                {selNode.label}: {selNode.sub}
              </div>

              {/* Tags */}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {selNode.tags.map((tag, i) => (
                  <span key={i} style={{
                    background: "#f5f5f5",
                    border: "1px solid #e0e0e0",
                    borderRadius: 4,
                    padding: "2px 8px",
                    fontSize: 11,
                    color: "#555"
                  }}>
                    {tag}
                  </span>
                ))}
              </div>

              <div style={{ fontSize: 10, color: "#777", fontStyle: "italic", marginBottom: 8 }}>
                <strong>API / Protocol:</strong> {selNode.api}
              </div>
              <div style={{ fontSize: 10, color: "#555", marginBottom: 8 }}>
                <strong>Observable Artifact:</strong> {selNode.artifact}
              </div>

              <div style={{ fontSize: 13, color: "#333", lineHeight: 1.7 }}>{selNode.desc}</div>

              {/* Telemetry */}
              {selNode.telemetry && selNode.telemetry.length > 0 && (
                <div style={{ marginTop: 12, padding: "8px 12px", background: "#e3f2fd", borderRadius: 4 }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: "#1565c0" }}>Telemetry: </span>
                  <span style={{ fontSize: 11, color: "#1976d2" }}>{selNode.telemetry.join(", ")}</span>
                </div>
              )}
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); setSel(null); }}
              style={{
                background: "none",
                border: "none",
                fontSize: 20,
                cursor: "pointer",
                color: "#aaa",
                marginLeft: 12,
                padding: "0 4px"
              }}
            >
              ×
            </button>
          </div>
          <div style={{
            marginTop: 12,
            paddingTop: 12,
            borderTop: "1px solid #eee",
            fontSize: 11,
            color: "#888"
          }}>
            <strong>Source:</strong> {selNode.src}
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{ marginTop: 12, fontSize: 11, color: "#bbb", textAlign: "center" }}>
        Click any node for details and sources · T1558.003 v1.5 · VanVleet DDM Style · MITRE ATT&CK Enterprise
      </div>
    </div>
  );
}
