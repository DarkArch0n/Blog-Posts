import { useState } from "react";

const NODES = [
  {
    id: "creds",
    label: "Valid Domain Credentials",
    api: "Any authenticated domain user session",
    artifact: "Existing TGT in LSASS Kerberos cache",
    x: 220, y: 20, w: 280, h: 58, type: "entry"
  },
  {
    id: "lw",
    label: "LDAP Query (Windows)",
    api: "DirectorySearcher → filter: (servicePrincipalName=*)",
    artifact: "LDAP traffic port 389 · Event ID 1644 (if LDAP diag enabled)",
    x: 10, y: 140, w: 200, h: 58, type: "op"
  },
  {
    id: "ll",
    label: "LDAP Query (Linux/Remote)",
    api: "Raw LDAP bind + search via Impacket / NetExec",
    artifact: "LDAP traffic port 389/636 from non-Windows host",
    x: 225, y: 140, w: 200, h: 58, type: "op"
  },
  {
    id: "sp",
    label: "setspn.exe",
    api: "DsGetSpn() Win32 API → LDAP query",
    artifact: "Process creation: setspn.exe -Q */* · LDAP port 389",
    x: 440, y: 140, w: 160, h: 58, type: "op"
  },
  {
    id: "pn",
    label: "Passive Network Capture",
    api: "No API call — passive packet capture only",
    artifact: "⚠ No LDAP query · No Event ID 4769 · NDR only",
    x: 615, y: 140, w: 175, h: 58, type: "blind"
  },
  {
    id: "r4",
    label: "TGS-REQ (RC4 Downgrade)",
    api: "KerberosRequestorSecurityToken() OR raw TGS-REQ etype 23",
    artifact: "KRB_TGS_REQ on port 88 · etype 0x17 in request",
    x: 10, y: 270, w: 200, h: 58, type: "op"
  },
  {
    id: "ae",
    label: "TGS-REQ (AES Stealth)",
    api: "Modified Impacket kerberosv5.py → raw TGS-REQ etype 18",
    artifact: "KRB_TGS_REQ port 88 · etype 0x12 · blends w/ normal",
    x: 225, y: 270, w: 200, h: 58, type: "op"
  },
  {
    id: "to",
    label: "Ticket Options Manipulation",
    api: "Rubeus raw TGS-REQ with modified TicketOptions field",
    artifact: "KRB_TGS_REQ TicketOptions 0x40800000 vs normal 0x40810000",
    x: 440, y: 270, w: 165, h: 58, type: "op"
  },
  {
    id: "td",
    label: "tgtdeleg RC4 Downgrade",
    api: "GSS-API fake delegation → AcquireCredentialsHandle() → RC4 TGS-REQ",
    artifact: "KRB_TGS_REQ with S4U2Self · etype 0x17 · patched WS2019+",
    x: 620, y: 270, w: 170, h: 58, type: "op"
  },
  {
    id: "dc",
    label: "DC Processes TGS-REQ",
    api: "KDC: LookupAccountName() → GetUserSPNs → EncryptTicket(service acct key)",
    artifact: "Event ID 4769 fired · ticket encrypted with svc acct NTLM hash",
    x: 195, y: 400, w: 420, h: 58, type: "system"
  },
  {
    id: "ev",
    label: "Windows Event ID 4769",
    api: "Security log on DC — KRB_TGS_REP issued",
    artifact: "OPTIMAL NODE: ServiceName, ClientAddress, TicketEncryptionType, TicketOptions",
    x: 195, y: 428, w: 420, h: 58, type: "detect"
  },
  {
    id: "st",
    label: "Ticket Stored in LSASS",
    api: "LsaCallAuthenticationPackage() → KerbSubmitTicketMessage",
    artifact: "TGS blob in LSASS Kerberos ticket cache — Sysmon Event ID 10",
    x: 195, y: 470, w: 420, h: 58, type: "system"
  },
  {
    id: "me",
    label: "In-Memory Extraction",
    api: "LsaCallAuthenticationPackage() → KerbRetrieveEncodedTicketMessage",
    artifact: "Sysmon EID 10: LSASS access · sekurlsa::tickets in Mimikatz",
    x: 50, y: 590, w: 200, h: 58, type: "op"
  },
  {
    id: "do",
    label: "Direct Tool Output",
    api: "Rubeus/Impacket write $krb5tgs$ hash to stdout/file — no LSASS touch",
    artifact: "$krb5tgs$23$ (RC4) or $krb5tgs$18$ (AES256) · no Sysmon EID 10",
    x: 270, y: 590, w: 200, h: 58, type: "op"
  },
  {
    id: "pe",
    label: "PCAP Hash Extraction",
    api: "extracttgsrepfrompcap.py parses KRB_TGS_REP enc-part from pcap",
    artifact: "⚠ No host artifacts · no logs · NDR/PCAP source only",
    x: 490, y: 590, w: 200, h: 58, type: "blind"
  },
  {
    id: "cr",
    label: "Offline Hash Cracking",
    api: "hashcat -m 13100 (RC4) / -m 19700 (AES256) — no network comms",
    artifact: "⚠ Zero DC events · zero network traffic · prevention only",
    x: 195, y: 710, w: 420, h: 58, type: "blind"
  },
];

const EDGES = [
  { f: "creds", t: "lw" }, { f: "creds", t: "ll" }, { f: "creds", t: "sp" }, { f: "creds", t: "pn", blind: true },
  { f: "lw", t: "r4" }, { f: "lw", t: "ae" },
  { f: "ll", t: "r4" }, { f: "ll", t: "to" },
  { f: "sp", t: "r4" }, { f: "sp", t: "td" },
  { f: "pn", t: "pe", blind: true },
  { f: "r4", t: "ev" }, { f: "ae", t: "ev" }, { f: "to", t: "ev" }, { f: "td", t: "ev" },
  { f: "ev", t: "st" },
  { f: "st", t: "me" }, { f: "st", t: "do" },
  { f: "me", t: "cr" }, { f: "do", t: "cr" }, { f: "pe", t: "cr", blind: true },
];

const DETAILS = {
  creds: { desc: "Any authenticated domain user session is sufficient. A valid TGT already exists in the LSASS Kerberos cache from normal logon. No privilege escalation needed before beginning the attack.", src: "MITRE ATT&CK T1558.003 — attack.mitre.org/techniques/T1558/003/" },
  lw: { desc: "Rubeus and PowerView use System.DirectoryServices.DirectorySearcher with LDAP filter (samAccountType=805306368)(servicePrincipalName=*) to find kerberoastable accounts. The filter itself is anomalous — legitimate admin tools rarely issue this wildcard SPN query.", src: "Atomic Red Team T1558.003; GhostPack/Rubeus — github.com/GhostPack/Rubeus; Microsoft DirectorySearcher docs" },
  ll: { desc: "Impacket issues a raw LDAP bind on port 389/636 followed by a search using the same SPN wildcard filter. Traffic originating from a Linux host to LDAP port 389 on a DC targeting servicePrincipalName=* is a strong anomaly in most environments.", src: "Impacket GetUserSPNs.py — github.com/fortra/impacket; HackTricks Kerberoast" },
  sp: { desc: "setspn.exe -T <domain> -Q */* calls DsGetSpn() which issues an LDAP query. Process creation of setspn.exe with -Q */* arguments is detectable via Sysmon EID 1 or EDR process telemetry. No elevated privileges required.", src: "Microsoft setspn.exe docs; Atomic Red Team T1558.003" },
  pn: { desc: "BLIND SPOT: Attacker with network access captures KRB_TGS_REP packets passively using Wireshark or tcpdump. No LDAP query is issued. No TGS-REQ is made by the attacker. Event ID 4769 never fires. Only detectable via NDR/full packet capture.", src: "MITRE T1558.003; nidem/kerberoast extracttgsrepfrompcap.py — github.com/nidem/kerberoast; Netresec 2019" },
  r4: { desc: "Most tools default to requesting etype 23 (RC4_HMAC_MD5). Via Windows .NET, KerberosRequestorSecurityToken() calls AcquireCredentialsHandle('Kerberos') then InitializeSecurityContext(). Via Rubeus, a raw KRB_TGS_REQ is crafted directly, bypassing Windows Kerberos APIs entirely — producing a different network fingerprint.", src: "TrustedSec Orpheus 2025; ired.team Kerberoasting; SpecterOps Kerberoasting Revisited 2019" },
  ae: { desc: "Modified Impacket kerberosv5.py forces etype 18 (AES256) in the TGS-REQ. The resulting Event ID 4769 shows TicketEncryptionType 0x12 rather than 0x17, bypassing RC4-based detection rules. Ticket blends with normal Kerberos traffic. Harder to crack offline.", src: "TrustedSec — Bypassing Kerberoast Detections with Orpheus, 2025 — trustedsec.com" },
  to: { desc: "Rubeus crafts a raw TGS-REQ with TicketOptions field set to 0x40800000. Normal AD Kerberos traffic uses 0x40810000. The difference is the Renewable-ok flag. Attackers who set options to match normal traffic evade TicketOptions-based detection signatures.", src: "Intrinsec — Kerberos OPSEC Part 1, 2023 — intrinsec.com" },
  td: { desc: "Rubeus /tgtdeleg uses the Kerberos GSS-API via AcquireCredentialsHandle() to request a fake unconstrained delegation TGT (kekeo trick). This TGT is then used to craft a raw TGS-REQ specifying only RC4, enabling RC4 ticket retrieval even for AES-configured accounts. Patched on Windows Server 2019+.", src: "SpecterOps — Kerberoasting Revisited, 2019 — specterops.io; gentilkiwi/kekeo" },
  dc: { desc: "The Domain Controller's KDC service receives the TGS-REQ, looks up the service account by SPN, and encrypts the ticket using the service account's password-derived key (NTLM hash for RC4, AES key for AES). This is the point where Event ID 4769 fires.", src: "Microsoft Kerberos KDC docs; RFC 4120" },
  ev: { desc: "OPTIMAL DETECTION NODE. The DC fires Event ID 4769 for every KRB_TGS_REQ it receives. Key fields: ServiceName (look for user accounts not machine accounts), ClientAddress (source IP), TicketEncryptionType (0x17=RC4, 0x12=AES256), TicketOptions (0x40800000=Rubeus default). Filters: exclude krbtgt, exclude *$ accounts, success only (0x0). Covers all 4 active request procedures. Blind to passive PCAP path.", src: "MITRE ATT&CK DET0157 — attack.mitre.org/detectionstrategies/DET0157/; Microsoft Event 4769 docs" },
  st: { desc: "After the KRB_TGS_REP is received, Windows calls LsaCallAuthenticationPackage() with KerbSubmitTicketMessage to store the ticket in the LSASS Kerberos ticket cache. The ticket blob is now resident in LSASS memory. Sysmon EID 10 (process access) may fire if extraction tools access LSASS at this point.", src: "Microsoft LSASS / Kerberos SSP docs; Sysmon EID 10" },
  me: { desc: "Mimikatz sekurlsa::tickets and Rubeus dump both call LsaCallAuthenticationPackage() with KerbRetrieveEncodedTicketMessage to pull the raw ticket blob from LSASS. This LSASS memory access is detectable via Sysmon EID 10 (process access to lsass.exe) or EDR LSASS protection alerts.", src: "ired.team Kerberoasting; gentilkiwi/mimikatz — github.com/gentilkiwi/mimikatz; Sysmon EID 10" },
  do: { desc: "Rubeus and Impacket write the $krb5tgs$ hash directly to stdout or file without touching LSASS at all. No Sysmon EID 10 fires. The hash is captured at the network/tool output layer. This path produces no LSASS-based artifacts and bypasses EDR LSASS protection entirely.", src: "HackTricks Kerberoast; GhostPack/Rubeus — github.com/GhostPack/Rubeus" },
  pe: { desc: "BLIND SPOT: nidem/kerberoast extracttgsrepfrompcap.py parses the enc-part of KRB_TGS_REP packets directly from a PCAP file. No host execution on target. No LSASS access. No Windows events of any kind. Only detectable if full packet capture exists and is analyzed.", src: "nidem/kerberoast — github.com/nidem/kerberoast; Netresec PCAP blog 2019" },
  cr: { desc: "BLIND SPOT: Cracking is fully off-network on attacker hardware. hashcat -m 13100 for RC4 ($krb5tgs$23$) reaches billions of guesses/sec on modern GPUs. hashcat -m 19700 for AES256 ($krb5tgs$18$) is slower but viable against weak passwords. Zero DC events. Zero network traffic. Mitigation is preventive only: gMSA accounts, strong passwords (25+ chars), AES enforcement.", src: "HackTricks; ADSecurity Metcalf 2015 — adsecurity.org/?p=2293; Netwrix Kerberoasting" },
};

const STYLE = {
  entry:  { bg: "#f9f9f9", border: "#333",   text: "#111", sub: "#555",   api: "#777"   },
  op:     { bg: "#ffffff", border: "#444",   text: "#111", sub: "#555",   api: "#777"   },
  detect: { bg: "#fffbe6", border: "#c8a000",text: "#111", sub: "#7a6000",api: "#c8a000"},
  system: { bg: "#f0f4ff", border: "#4466aa",text: "#223",  sub: "#446",   api: "#668"   },
  blind:  { bg: "#fafafa", border: "#ccc",   text: "#aaa", sub: "#bbb",   api: "#ccc"   },
};

export default function DDM() {
  const [sel, setSel] = useState(null);
  const byId = id => NODES.find(n => n.id === id);
  const cx = n => n.x + n.w / 2;
  const selNode = sel ? NODES.find(n => n.id === sel) : null;

  return (
    <div style={{ background: "#fff", minHeight: "100vh", fontFamily: "Arial, sans-serif", padding: "28px 32px" }}>
      <div style={{ maxWidth: 830, margin: "0 auto" }}>

        <div style={{ marginBottom: 16, paddingBottom: 12, borderBottom: "1px solid #ccc" }}>
          <div style={{ fontSize: 10, color: "#888", letterSpacing: 2, textTransform: "uppercase", marginBottom: 3 }}>Detection Data Model</div>
          <div style={{ fontSize: 20, fontWeight: "bold", color: "#111" }}>T1558.003 — Kerberoasting</div>
          <div style={{ fontSize: 11, color: "#999", marginTop: 2 }}>Tactic: Credential Access · Platform: Windows Active Directory · MITRE ATT&CK v15</div>
        </div>

        <div style={{ display: "flex", gap: 16, marginBottom: 14, fontSize: 10, color: "#555", flexWrap: "wrap", alignItems: "center" }}>
          {[
            { label: "Entry Point", bg: "#f9f9f9", border: "#333" },
            { label: "Attacker Procedure", bg: "#fff", border: "#444" },
            { label: "System Response", bg: "#f0f4ff", border: "#4466aa" },
            { label: "Optimal Detection Node", bg: "#fffbe6", border: "#c8a000" },
            { label: "Blind Spot", bg: "#fafafa", border: "#ccc" },
          ].map(({ label, bg, border }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <div style={{ width: 12, height: 12, borderRadius: 2, background: bg, border: `1.5px solid ${border}` }} />
              <span>{label}</span>
            </div>
          ))}
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <svg width="22" height="8"><line x1="0" y1="4" x2="22" y2="4" stroke="#ccc" strokeWidth="1.5" strokeDasharray="4,3" /></svg>
            <span style={{ color: "#bbb" }}>Blind Path</span>
          </div>
        </div>

        <div style={{ fontSize: 10, color: "#aaa", marginBottom: 10, fontStyle: "italic" }}>
          Each node shows: Operation · API Call / Protocol Message · Observable Artifact
        </div>

        <svg width="810" height="790" style={{ display: "block", border: "1px solid #e0e0e0", background: "#fff" }}>
          <defs>
            <marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3z" fill="#444" />
            </marker>
            <marker id="arr-b" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3z" fill="#ccc" />
            </marker>
          </defs>

          {/* Phase labels */}
          {[
            { label: "Phase 1 — SPN Enum",     y: 140, h: 80 },
            { label: "Phase 2 — TGS-REQ",      y: 270, h: 80 },
            { label: "Detection",               y: 390, h: 80, hi: true },
            { label: "System",                  y: 460, h: 80 },
            { label: "Phase 3 — Extraction",   y: 590, h: 80 },
            { label: "Phase 4 — Offline",      y: 710, h: 70 },
          ].map((p, i) => (
            <g key={i}>
              <line x1="18" y1={p.y} x2="18" y2={p.y + p.h} stroke={p.hi ? "#c8a000" : "#ddd"} strokeWidth="1.5" />
              <text x="14" y={p.y + p.h / 2} textAnchor="middle" fill={p.hi ? "#c8a000" : "#ccc"} fontSize="8" fontFamily="Arial"
                transform={`rotate(-90,14,${p.y + p.h / 2})`}>
                {p.label}
              </text>
            </g>
          ))}

          {/* Edges */}
          {EDGES.map((e, i) => {
            const fn = byId(e.f), tn = byId(e.t);
            if (!fn || !tn) return null;
            const x1 = cx(fn), y1 = fn.y + fn.h;
            const x2 = cx(tn), y2 = tn.y;
            const my = (y1 + y2) / 2;
            return (
              <path key={i}
                d={`M${x1},${y1} C${x1},${my} ${x2},${my} ${x2},${y2}`}
                stroke={e.blind ? "#ddd" : "#666"}
                strokeWidth="1"
                strokeDasharray={e.blind ? "5,4" : "none"}
                fill="none"
                markerEnd={e.blind ? "url(#arr-b)" : "url(#arr)"}
              />
            );
          })}

          {/* Nodes */}
          {NODES.map(n => {
            const s = STYLE[n.type];
            const isSel = sel === n.id;
            const isDetect = n.type === "detect";
            return (
              <g key={n.id} onClick={() => setSel(sel === n.id ? null : n.id)} style={{ cursor: "pointer" }}>
                <rect x={n.x} y={n.y} width={n.w} height={n.h} rx={2}
                  fill={isSel ? "#fff9e6" : s.bg}
                  stroke={isSel ? "#000" : s.border}
                  strokeWidth={isDetect ? 2 : 1}
                />
                {/* Operation label */}
                <text x={cx(n)} y={n.y + 14} textAnchor="middle"
                  fill={s.text} fontSize={isDetect ? 11 : 10} fontWeight={isDetect ? "bold" : "600"} fontFamily="Arial">
                  {n.label}
                </text>
                {/* API line */}
                <text x={cx(n)} y={n.y + 27} textAnchor="middle"
                  fill={s.api} fontSize={7.5} fontFamily="Arial" fontStyle="italic">
                  {n.api.length > 70 ? n.api.slice(0, 70) + "…" : n.api}
                </text>
                {/* Artifact line */}
                <text x={cx(n)} y={n.y + 40} textAnchor="middle"
                  fill={s.sub} fontSize={7.5} fontFamily="Arial">
                  {n.artifact.length > 72 ? n.artifact.slice(0, 72) + "…" : n.artifact}
                </text>
              </g>
            );
          })}
        </svg>

        {selNode && (
          <div style={{ marginTop: 14, border: `1px solid ${STYLE[selNode.type].border}`, padding: "14px 16px", background: "#fafafa", borderRadius: 2 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: "bold", fontSize: 13, marginBottom: 4 }}>{selNode.label}</div>
                <div style={{ fontSize: 10, color: "#777", fontStyle: "italic", marginBottom: 8 }}>
                  <strong>API / Protocol:</strong> {selNode.api}
                </div>
                <div style={{ fontSize: 10, color: "#555", marginBottom: 8 }}>
                  <strong>Observable Artifact:</strong> {selNode.artifact}
                </div>
                <div style={{ fontSize: 12, color: "#333", lineHeight: 1.7 }}>{DETAILS[selNode.id]?.desc}</div>
              </div>
              <button onClick={() => setSel(null)}
                style={{ background: "none", border: "none", fontSize: 18, cursor: "pointer", color: "#aaa", marginLeft: 12 }}>×</button>
            </div>
            <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid #eee", fontSize: 10, color: "#888" }}>
              <strong>Source:</strong> {DETAILS[selNode.id]?.src}
            </div>
          </div>
        )}

        <div style={{ marginTop: 8, fontSize: 10, color: "#ccc", textAlign: "center" }}>
          Click any node for full API detail, artifacts, and sources · T1558.003 v1.3 · MITRE ATT&CK Enterprise
        </div>
      </div>
    </div>
  );
}
