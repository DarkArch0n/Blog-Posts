// T1557.003 — DHCP Spoofing — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1557.003",
    name: "DHCP Spoofing",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 400,
    rows: [
      { label: "ROGUE DHCP", y: 80 },
      { label: "MITM",       y: 200 },
      { label: "CAPTURE",    y: 320 },
    ],
  },

  nodes: [
    { id: "attacker", label: "Same Network", sub: "L2/L3 access", x: 60, y: 150, r: 36, type: "entry",
      desc: "Attacker on same broadcast domain. Races legitimate DHCP server to respond first.",
      src: "MITRE ATT&CK T1557.003" },

    // Row 1: Rogue DHCP
    { id: "rogue_dhcp", label: "Rogue DHCP", sub: "Server", x: 200, y: 80, r: 36, type: "op",
      desc: "Attacker runs rogue DHCP server that responds to DHCPDISCOVER before legitimate server.",
      src: "MITRE T1557.003; Ettercap" },
    { id: "dhcp_offer", label: "DHCPOFFER", sub: "UDP 67→68", x: 360, y: 80, r: 32, type: "protocol",
      desc: "Rogue DHCPOFFER with attacker-controlled gateway, DNS, and WPAD settings.",
      src: "RFC 2131" },
    { id: "dhcp_ack", label: "DHCPACK", sub: "Poisoned config", x: 520, y: 80, r: 34, type: "protocol",
      desc: "DHCPACK assigns: Gateway=attacker IP, DNS=attacker IP, WPAD=attacker URL.",
      src: "RFC 2131; RFC 2132" },
    { id: "victim_config", label: "Victim Config", sub: "Poisoned GW/DNS", x: 680, y: 80, r: 36, type: "system",
      desc: "Victim's network stack configured with attacker as default gateway and DNS server.",
      src: "RFC 2131" },

    // Row 2: MitM position
    { id: "dns_poison", label: "Rogue DNS", sub: "All queries", x: 680, y: 200, r: 36, type: "op",
      desc: "Attacker's DNS server resolves all queries to attacker IP or selectively poisons specific domains.",
      src: "MITRE T1557.003" },
    { id: "gw_forward", label: "Gateway Forward", sub: "ip_forward=1", x: 840, y: 140, r: 34, type: "system",
      desc: "Attacker forwards all traffic to real gateway. Victim maintains connectivity.",
      src: "Linux sysctl; iptables" },
    { id: "mitm_pos", label: "MitM Position", sub: "All traffic", x: 840, y: 240, r: 40, type: "op",
      desc: "Full MitM: all victim HTTP, SMB, LDAP, Kerberos traffic passes through attacker.",
      src: "MITRE T1557.003" },
    { id: "wpad_inject", label: "WPAD Inject", sub: "Option 252", x: 520, y: 200, r: 34, type: "op",
      desc: "DHCP Option 252 (WPAD) points victim's browser proxy to attacker → credential capture.",
      src: "WPAD; MS16-077" },

    // Row 3: Credential capture
    { id: "ntlm_capture", label: "NTLM Capture", sub: "SMB/HTTP auth", x: 840, y: 320, r: 36, type: "artifact",
      desc: "NTLMv2 hashes from SMB, HTTP, WPAD proxy authentication.",
      src: "MS-NLMP; Responder" },
    { id: "http_creds", label: "HTTP Creds", sub: "Form/Basic auth", x: 1000, y: 320, r: 32, type: "artifact",
      desc: "Cleartext HTTP credentials from poisoned DNS → fake login pages.",
      src: "MITRE T1557.003" },
    { id: "hashcat", label: "hashcat", sub: "-m 5600", x: 1000, y: 240, r: 34, type: "blind",
      desc: "BLIND: Offline NTLMv2 cracking from captured authentication.",
      src: "hashcat.net" },

    // ── Detection ──
    { id: "dhcp_snoop", label: "DHCP Snooping", sub: "Switch-level", x: 360, y: 200, r: 38, type: "detect",
      desc: "OPTIMAL: DHCP Snooping on switches blocks DHCP replies from untrusted ports. Best prevention.",
      src: "Cisco DHCP Snooping; IEEE 802.1" },
    { id: "ev_dhcp", label: "DHCP Event", sub: "Multiple offers", x: 360, y: 300, r: 34, type: "detect",
      desc: "Windows Event 50036/50037: DHCP client received multiple offers. Indicates rogue DHCP.",
      src: "Microsoft DHCP Events" },
    { id: "zeek_dhcp", label: "Zeek dhcp.log", sub: "Anomaly", x: 520, y: 320, r: 32, type: "detect",
      desc: "Zeek DHCP log analysis: detect unexpected DHCP server IPs on the network.",
      src: "Zeek; Corelight" },

    // ── Output ──
    { id: "creds", label: "Domain Creds", x: 1160, y: 280, r: 34, type: "artifact",
      desc: "Captured domain credentials (hashes or cleartext) from MitM position.",
      src: "MITRE T1557.003" },
  ],

  edges: [
    // DHCP poisoning
    { f: "attacker", t: "rogue_dhcp" },
    { f: "rogue_dhcp", t: "dhcp_offer" },
    { f: "dhcp_offer", t: "dhcp_ack" },
    { f: "dhcp_ack", t: "victim_config" },
    { f: "dhcp_ack", t: "wpad_inject" },
    // MitM setup
    { f: "victim_config", t: "dns_poison" },
    { f: "victim_config", t: "gw_forward" },
    { f: "gw_forward", t: "mitm_pos" },
    { f: "dns_poison", t: "mitm_pos" },
    { f: "wpad_inject", t: "mitm_pos" },
    // Capture
    { f: "mitm_pos", t: "ntlm_capture" },
    { f: "mitm_pos", t: "http_creds" },
    { f: "ntlm_capture", t: "hashcat", blind: true },
    { f: "hashcat", t: "creds", blind: true },
    { f: "http_creds", t: "creds" },
    // Detection
    { f: "rogue_dhcp", t: "dhcp_snoop" },
    { f: "dhcp_offer", t: "ev_dhcp" },
    { f: "dhcp_offer", t: "zeek_dhcp" },
  ],
};

export default model;
