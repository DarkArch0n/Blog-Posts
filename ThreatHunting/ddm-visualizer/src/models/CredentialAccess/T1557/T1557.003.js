// T1557.003 — DHCP Spoofing — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1557.003",
    name: "DHCP Spoofing",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "PREREQUISITE",  x: 80  },
      { label: "ROGUE SERVER",  x: 260 },
      { label: "CLIENT CONFIG", x: 450 },
      { label: "DETECTION",     x: 650 },
      { label: "OUTCOME",       x: 870 },
    ],
    separators: [170, 355, 550, 760],
    annotations: [
      { text: "DHCP snooping on switches prevents this", x: 650, y: 390, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "lan", label: "LAN Access", sub: "Same broadcast", x: 80, y: 220, r: 40, type: "source",
      tags: ["Same broadcast domain", "Layer 2 access", "Race DHCP server"],
      telemetry: [],
      api: "Attacker on same broadcast domain — must respond faster than legitimate DHCP server",
      artifact: "Network presence on target subnet · rogue DHCP service",
      desc: "DHCP Spoofing requires Layer 2 adjacency. The attacker runs a rogue DHCP server that races the legitimate server to respond to DHCP Discover/Request packets. First response wins. Alternatively, attacker can DoS the legitimate DHCP server to guarantee rogue responses are accepted.",
      src: "MITRE ATT&CK T1557.003" },

    { id: "rogue_dhcp", label: "Rogue DHCP", sub: "Server", x: 260, y: 130, r: 38, type: "source",
      tags: ["Ettercap DHCP", "Yersinia", "dnsmasq rogue", "DHCPig + rogue"],
      telemetry: [],
      api: "Rogue DHCP server: assigns attacker as gateway and/or DNS server to victims",
      artifact: "DHCP OFFER/ACK with rogue gateway IP and/or DNS · unauthorized DHCP server",
      desc: "Tools: Ettercap DHCP spoofing plugin, Yersinia, rogue dnsmasq, or custom scripts. The rogue DHCP server provides the attacker's IP as default gateway (MitM all traffic) and/or as DNS server (redirect DNS queries). May also push rogue WPAD configuration.",
      src: "MITRE T1557.003; Ettercap; Yersinia" },

    { id: "dhcp_starve", label: "DHCP Starve", sub: "Exhaust pool", x: 260, y: 320, r: 34, type: "source",
      tags: ["DHCPig", "DHCP starvation", "Exhaust IP pool"],
      telemetry: [],
      api: "DHCPig / Gobbler exhausts legitimate DHCP pool → forces clients to accept rogue",
      artifact: "Mass DHCP requests from spoofed MACs · legitimate pool exhausted",
      desc: "DHCP starvation attack (DHCPig, Gobbler) sends thousands of DHCP requests with spoofed MAC addresses to exhaust the legitimate server's IP pool. New clients can only get addresses from the rogue DHCP server, guaranteeing the attacker controls their network configuration.",
      src: "DHCPig; MITRE T1557.003" },

    { id: "client_cfg", label: "Rogue Config", sub: "Gateway/DNS", x: 450, y: 220, r: 40, type: "source",
      tags: ["Rogue gateway", "Rogue DNS", "Rogue WPAD", "MitM position"],
      telemetry: [],
      api: "Victim configured with attacker's IP as gateway and/or DNS → all traffic routed through attacker",
      artifact: "Victim routing table points to attacker · DNS queries go to attacker",
      desc: "Victims accepting the rogue DHCP configuration use the attacker as: (1) Default gateway — all internet/intranet traffic routes through attacker (full MitM). (2) DNS server — attacker can respond with malicious IPs for any domain. (3) WPAD proxy — victim proxies all web traffic through attacker.",
      src: "MITRE T1557.003" },

    { id: "ev_detect", label: "DHCP Snooping", sub: "Switch Level", x: 650, y: 220, r: 50, type: "detect",
      tags: ["DHCP snooping", "Rogue server detection", "Port security", "802.1X"],
      telemetry: [],
      api: "DHCP snooping on managed switches: only trusted ports can send DHCP OFFER/ACK",
      artifact: "OPTIMAL: DHCP snooping violations · rogue DHCP server alerts · unauthorized OFFER/ACK",
      desc: "OPTIMAL DETECTION NODE. (1) DHCP Snooping: Switch-level feature that only allows DHCP server responses from trusted (uplink) ports — drops OFFER/ACK from untrusted ports. (2) Network monitoring: Alert on DHCP OFFER from unauthorized IPs. (3) 802.1X: Port-based authentication limits who can send DHCP responses. (4) Multiple DHCP servers offering different configurations indicates spoofing. (5) DHCP starvation detection: sudden pool exhaustion, mass MAC address changes.",
      src: "MITRE T1557.003; Cisco DHCP Snooping; IEEE 802.1X" },

    { id: "mitm_traffic", label: "MitM Traffic", sub: "Capture/Modify", x: 870, y: 140, r: 36, type: "source",
      tags: ["Credential capture", "DNS redirect", "Traffic modification"],
      telemetry: [],
      api: "Full traffic interception as gateway · DNS spoofing as DNS server",
      artifact: "Intercepted credentials · redirected DNS · modified HTTP responses",
      desc: "With gateway control, attacker captures all victim traffic including credentials from unencrypted protocols. With DNS control, attacker redirects victims to phishing pages or malicious downloads. Both positions enable credential harvesting and traffic manipulation.",
      src: "MITRE T1557.003" },

    { id: "persist_cfg", label: "Persistent", sub: "Config Change", x: 870, y: 310, r: 34, type: "source",
      tags: ["DHCP lease duration", "Survives server restart", "Network disruption"],
      telemetry: [],
      api: "Rogue configuration persists for DHCP lease duration (hours to days)",
      artifact: "Victims retain rogue config until DHCP lease expires and renews from legitimate server",
      desc: "DHCP configuration persists for the lease duration (typically 8-24 hours). Even after the rogue DHCP server is shut down, victims continue using the malicious gateway/DNS until their lease expires. Manual remediation may be required (ipconfig /release /renew).",
      src: "MITRE T1557.003" },
  ],

  edges: [
    { f: "lan", t: "rogue_dhcp" },
    { f: "lan", t: "dhcp_starve" },
    { f: "dhcp_starve", t: "rogue_dhcp" },
    { f: "rogue_dhcp", t: "client_cfg" },
    { f: "rogue_dhcp", t: "ev_detect" },
    { f: "dhcp_starve", t: "ev_detect" },
    { f: "client_cfg", t: "mitm_traffic" },
    { f: "client_cfg", t: "persist_cfg" },
  ],
};

export default model;
