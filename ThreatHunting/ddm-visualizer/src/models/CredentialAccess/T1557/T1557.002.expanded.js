// T1557.002 — ARP Cache Poisoning — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1557.002",
    name: "ARP Cache Poisoning",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 420,
    rows: [
      { label: "POISON",   y: 80 },
      { label: "INTERCEPT", y: 200 },
      { label: "CAPTURE",  y: 320 },
    ],
  },

  nodes: [
    { id: "attacker", label: "Same Subnet", sub: "L2 access", x: 60, y: 150, r: 36, type: "entry",
      desc: "Attacker must be on the same Layer 2 network segment as the victim. ARP is not routable.",
      src: "MITRE ATT&CK T1557.002" },

    // Row 1: ARP poisoning
    { id: "arpspoof", label: "arpspoof", sub: "/ ettercap", x: 200, y: 80, r: 34, type: "op",
      desc: "arpspoof -i eth0 -t victim gateway — sends gratuitous ARP replies to victim and gateway.",
      src: "dsniff; ettercap" },
    { id: "bettercap", label: "bettercap", sub: "arp.spoof on", x: 200, y: 150, r: 32, type: "op",
      desc: "bettercap: set arp.spoof.targets victim_ip; arp.spoof on — modern ARP poisoning tool.",
      src: "bettercap.org" },
    { id: "grat_arp", label: "Gratuitous ARP", sub: "Reply packets", x: 380, y: 80, r: 36, type: "protocol",
      desc: "Unsolicited ARP replies: 'Gateway MAC is <attacker MAC>' sent to victim's ARP cache.",
      src: "RFC 826; ARP" },
    { id: "arp_cache", label: "ARP Cache", sub: "Poisoned entry", x: 540, y: 80, r: 34, type: "system",
      desc: "Victim's ARP cache updated: gateway IP → attacker MAC. All traffic routed through attacker.",
      src: "RFC 826" },

    // Row 2: Interception
    { id: "ip_forward", label: "IP Forward", sub: "ip_forward=1", x: 540, y: 200, r: 34, type: "system",
      desc: "net.ipv4.ip_forward=1 — attacker forwards traffic to real gateway to remain transparent.",
      src: "Linux kernel; sysctl" },
    { id: "mitm_proxy", label: "MitM Position", sub: "All L2 traffic", x: 700, y: 200, r: 40, type: "op",
      desc: "Attacker now sees all victim traffic passing through: HTTP, SMB, FTP, DNS, etc.",
      src: "MITRE T1557.002" },
    { id: "sslstrip", label: "sslstrip", sub: "HTTPS downgrade", x: 860, y: 140, r: 32, type: "op",
      desc: "sslstrip downgrades HTTPS → HTTP for credential capture. Defeated by HSTS but still useful.",
      src: "Moxie Marlinspike; sslstrip" },

    // Row 3: Credential capture
    { id: "pcap", label: "tcpdump", sub: "Capture PCAP", x: 700, y: 320, r: 34, type: "op",
      desc: "tcpdump -i eth0 -w capture.pcap — full packet capture of MitM traffic.",
      src: "tcpdump.org" },
    { id: "ntlm_capture", label: "NTLM Capture", sub: "SMB/HTTP auth", x: 860, y: 280, r: 36, type: "artifact",
      desc: "NTLMv2 challenge-response hashes captured from SMB or HTTP NTLM authentication.",
      src: "MS-NLMP; Responder" },
    { id: "http_creds", label: "HTTP Creds", sub: "Basic/Form auth", x: 860, y: 370, r: 32, type: "artifact",
      desc: "HTTP Basic auth headers or form-posted credentials in cleartext.",
      src: "MITRE T1557.002" },
    { id: "hashcat_5600", label: "hashcat", sub: "-m 5600", x: 1020, y: 280, r: 34, type: "blind",
      desc: "BLIND: Offline NTLMv2 cracking from captured auth traffic.",
      src: "hashcat.net" },

    // ── Detection ──
    { id: "arp_anomaly", label: "ARP Anomaly", sub: "Duplicate MACs", x: 380, y: 200, r: 38, type: "detect",
      desc: "OPTIMAL: Detect duplicate IP-MAC bindings, gratuitous ARP floods. Switch DAI (Dynamic ARP Inspection).",
      src: "Cisco DAI; arpwatch" },
    { id: "arpwatch", label: "arpwatch", sub: "MAC changes", x: 380, y: 300, r: 32, type: "detect",
      desc: "arpwatch monitors ARP table changes and emails on flip-flops (MAC address changes for an IP).",
      src: "arpwatch; LBNL" },
    { id: "switch_dai", label: "Switch DAI", sub: "Dynamic ARP Inspection", x: 540, y: 320, r: 38, type: "system",
      desc: "Switch-level mitigation: DAI validates ARP packets against DHCP snooping binding table.",
      src: "Cisco DAI; IEEE 802.1" },

    // ── Output ──
    { id: "creds", label: "Captured Creds", x: 1160, y: 280, r: 34, type: "artifact",
      desc: "Domain credentials, session tokens, API keys captured from intercepted traffic.",
      src: "MITRE T1557.002" },
  ],

  edges: [
    // Poisoning
    { f: "attacker", t: "arpspoof" },
    { f: "attacker", t: "bettercap" },
    { f: "arpspoof", t: "grat_arp" },
    { f: "bettercap", t: "grat_arp" },
    { f: "grat_arp", t: "arp_cache" },
    // Interception
    { f: "arp_cache", t: "ip_forward" },
    { f: "ip_forward", t: "mitm_proxy" },
    { f: "mitm_proxy", t: "sslstrip" },
    // Capture
    { f: "mitm_proxy", t: "pcap" },
    { f: "pcap", t: "ntlm_capture" },
    { f: "sslstrip", t: "http_creds" },
    { f: "ntlm_capture", t: "hashcat_5600", blind: true },
    { f: "hashcat_5600", t: "creds", blind: true },
    { f: "http_creds", t: "creds" },
    // Detection
    { f: "grat_arp", t: "arp_anomaly" },
    { f: "grat_arp", t: "arpwatch" },
    { f: "arp_anomaly", t: "switch_dai" },
  ],
};

export default model;
