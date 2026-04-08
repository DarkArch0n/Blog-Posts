// T1557.002 — ARP Cache Poisoning — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1557.002",
    name: "ARP Cache Poisoning",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "POISONING",    x: 260 },
      { label: "MitM",         x: 450 },
      { label: "DETECTION",    x: 650 },
      { label: "OUTCOME",      x: 870 },
    ],
    separators: [170, 355, 550, 760],
    annotations: [
      { text: "Requires same L2 broadcast domain", x: 80, y: 400, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "lan", label: "LAN Access", sub: "Same subnet", x: 80, y: 220, r: 40, type: "source",
      tags: ["Same broadcast domain", "Layer 2 access", "Physical/VPN"],
      telemetry: [],
      api: "Attacker must be on the same Layer 2 broadcast domain as the victim(s)",
      artifact: "Network presence on target subnet",
      desc: "ARP cache poisoning requires Layer 2 adjacency — the attacker must be on the same broadcast domain (subnet/VLAN) as the target. This can be achieved via physical access, compromised host on the network, or VPN with split-tunnel misconfiguration.",
      src: "MITRE ATT&CK T1557.002" },

    { id: "arpspoof", label: "arpspoof", sub: "Gratuitous ARP", x: 260, y: 130, r: 36, type: "source",
      tags: ["arpspoof", "Ettercap", "Bettercap", "Gratuitous ARP"],
      telemetry: [],
      api: "arpspoof -i eth0 -t <victim> <gateway> · sends gratuitous ARP replies",
      artifact: "Gratuitous ARP packets · MAC-IP mapping changes · high ARP traffic volume",
      desc: "arpspoof, Ettercap, and Bettercap send gratuitous ARP replies to the victim, mapping the gateway's IP to the attacker's MAC address (and vice versa). All traffic between victim and gateway now flows through the attacker. Implements full duplex MitM.",
      src: "dsniff/arpspoof; Ettercap; Bettercap" },

    { id: "static_poison", label: "Static ARP", sub: "Entry injection", x: 260, y: 320, r: 34, type: "source",
      tags: ["arp -s", "Static entry", "Persistent poisoning"],
      telemetry: [],
      api: "Some malware modifies the victim's ARP table directly via arp -s on compromised host",
      artifact: "Modified ARP table entry · persistent MitM after reboot if in startup script",
      desc: "Instead of sending gratuitous ARPs, malware on a compromised host may directly modify the ARP table to statically map the gateway's IP to the attacker's MAC. More stealthy — no gratuitous ARP packet flood — but requires code execution on the victim.",
      src: "MITRE T1557.002" },

    { id: "intercept", label: "Traffic", sub: "Interception", x: 450, y: 220, r: 40, type: "source",
      tags: ["Packet capture", "Credential sniffing", "SSL strip", "IP forwarding"],
      telemetry: [],
      api: "ip_forward=1 · attacker forwards traffic while capturing — transparent MitM",
      artifact: "All victim traffic routed through attacker · credential sniffing · SSL stripping",
      desc: "With MitM active, all victim traffic flows through the attacker. IP forwarding ensures transparency. The attacker can: capture cleartext credentials (HTTP, FTP, Telnet), perform SSL stripping (downgrade HTTPS), inject content, or modify traffic in transit. Tools: mitmproxy, sslstrip, Wireshark.",
      src: "MITRE T1557.002; mitmproxy; sslstrip" },

    { id: "ev_detect", label: "ARP Monitoring", sub: "IDS/DAI", x: 650, y: 220, r: 50, type: "detect",
      tags: ["Dynamic ARP Inspection", "ARP anomaly", "Duplicate IP", "IDS alert"],
      telemetry: [],
      api: "Switch-level Dynamic ARP Inspection (DAI) + network IDS ARP anomaly signatures",
      artifact: "OPTIMAL: DAI violations on switch · IDS: gratuitous ARP flood · duplicate MAC-IP mappings",
      desc: "OPTIMAL DETECTION NODE. (1) Dynamic ARP Inspection (DAI) on managed switches validates ARP against DHCP snooping table — drops invalid ARP. (2) Network IDS: signatures for gratuitous ARP storms, ARP reply without request, MAC-IP mapping changes. (3) Host-based: arpwatch daemon logs ARP table changes. (4) Snort/Suricata: ARP spoofing detection rules. (5) PREVENTION: Static ARP entries for critical systems (gateway), 802.1X port security.",
      src: "MITRE T1557.002; Cisco DAI; arpwatch; Snort ARP rules" },

    { id: "creds", label: "Captured", sub: "Credentials", x: 870, y: 140, r: 36, type: "source",
      tags: ["HTTP Basic", "FTP creds", "NTLM relay", "Session cookies"],
      telemetry: [],
      api: "Cleartext credentials from unencrypted protocols + downgraded HTTPS",
      artifact: "Plaintext passwords, session tokens, API keys from intercepted traffic",
      desc: "Intercepted traffic yields credentials from unencrypted protocols (HTTP Basic Auth, FTP, LDAP without TLS, Telnet). SSL stripping may downgrade HTTPS connections. NTLM authentication in transit can be captured and cracked (Net-NTLMv2) or relayed.",
      src: "MITRE T1557.002" },

    { id: "modify", label: "Traffic", sub: "Modification", x: 870, y: 310, r: 36, type: "source",
      tags: ["Inject payloads", "Modify responses", "Redirect traffic"],
      telemetry: [],
      api: "Inject malicious content into HTTP responses, redirect DNS, modify downloads",
      artifact: "Modified HTTP responses · injected JavaScript · replaced binaries",
      desc: "Beyond credential capture, MitM position enables active traffic modification: inject malicious JavaScript into HTTP responses, replace downloaded executables with backdoored versions, redirect DNS queries, or inject browser exploitation frameworks (BeEF).",
      src: "MITRE T1557.002; BeEF Framework" },
  ],

  edges: [
    { f: "lan", t: "arpspoof" },
    { f: "lan", t: "static_poison" },
    { f: "arpspoof", t: "intercept" },
    { f: "static_poison", t: "intercept" },
    { f: "arpspoof", t: "ev_detect" },
    { f: "static_poison", t: "ev_detect" },
    { f: "intercept", t: "creds" },
    { f: "intercept", t: "modify" },
  ],
};

export default model;
