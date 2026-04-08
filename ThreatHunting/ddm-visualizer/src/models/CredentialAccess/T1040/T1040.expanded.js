// T1040 — Network Sniffing — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1040", name: "Network Sniffing", tactic: "Credential Access", platform: "Windows, Linux, macOS, Network", version: "v1.0" },
  layout: { svgWidth: 1400, svgHeight: 380, rows: [{ label: "PROMISCUOUS", y: 80 }, { label: "PCAP TOOLS", y: 180 }, { label: "PROTOCOL", y: 300 }] },
  nodes: [
    { id: "net_access", label: "Network Position", sub: "Span/tap/host NIC", x: 60, y: 180, r: 38, type: "entry", desc: "Attacker has access to network segment: compromised host, SPAN port, network tap, ARP spoof.", src: "MITRE ATT&CK T1040" },
    { id: "promisc", label: "Promiscuous Mode", sub: "NIC configuration", x: 240, y: 80, r: 34, type: "op", desc: "Set NIC to promiscuous mode to capture all traffic on shared segment.", src: "MITRE T1040" },
    { id: "raw_socket", label: "Raw Socket", sub: "AF_PACKET / Npcap", x: 440, y: 80, r: 32, type: "api", desc: "Linux: AF_PACKET raw socket. Windows: Npcap/WinPcap. Requires root/admin.", src: "Linux AF_PACKET; Npcap" },
    { id: "tcpdump", label: "tcpdump", sub: "-w capture.pcap", x: 240, y: 180, r: 34, type: "op", desc: "tcpdump -i eth0 -w /tmp/capture.pcap — command-line packet capture.", src: "tcpdump" },
    { id: "wireshark", label: "tshark/Wireshark", sub: "Protocol dissection", x: 440, y: 180, r: 34, type: "op", desc: "tshark -f 'port 21 or port 25 or port 110 or port 143' — filter for cleartext protocols.", src: "Wireshark" },
    { id: "responder", label: "Responder", sub: "LLMNR/NBT-NS", x: 440, y: 240, r: 34, type: "op", desc: "Responder captures NTLMv2 hashes via LLMNR/NBT-NS poisoning (see T1557.001).", src: "SpiderLabs/Responder" },
    { id: "ftp_creds", label: "FTP/Telnet", sub: "Plaintext capture", x: 640, y: 80, r: 32, type: "protocol", desc: "FTP (21), Telnet (23): credentials sent in plaintext. Trivial capture.", src: "RFC 959; RFC 854" },
    { id: "http_basic", label: "HTTP Basic Auth", sub: "Base64 creds", x: 640, y: 140, r: 32, type: "protocol", desc: "HTTP Basic Authentication: base64-encoded credentials in Authorization header.", src: "RFC 7617" },
    { id: "smtp_pop", label: "SMTP/POP3/IMAP", sub: "Email creds", x: 640, y: 200, r: 32, type: "protocol", desc: "Unencrypted email protocols: SMTP (25), POP3 (110), IMAP (143) — plaintext auth.", src: "RFC 5321; RFC 1939" },
    { id: "ntlm_hashes", label: "NTLMv2 Hashes", sub: "From Responder", x: 640, y: 260, r: 32, type: "artifact", desc: "NTLMv2 challenge-response hashes for offline cracking.", src: "Responder; hashcat" },
    { id: "sysmon_3", label: "Sysmon 3", sub: "Network connections", x: 840, y: 80, r: 36, type: "detect", desc: "Sysmon EID 3: network connections from capture tools (tcpdump, tshark).", src: "Sysmon documentation" },
    { id: "promisc_detect", label: "Promisc Detect", sub: "ip link / SIOCGIFFLAGS", x: 840, y: 180, r: 36, type: "detect", desc: "OPTIMAL: Detect promiscuous mode: ip link show (PROMISC flag), auditd for socket creation.", src: "Linux; auditd" },
    { id: "creds", label: "Network Credentials", sub: "Passwords/hashes", x: 1040, y: 180, r: 40, type: "artifact", desc: "Captured: plaintext passwords, NTLMv2 hashes, session tokens, API keys from unencrypted traffic.", src: "MITRE T1040" },
  ],
  edges: [
    { f: "net_access", t: "promisc" }, { f: "net_access", t: "tcpdump" },
    { f: "promisc", t: "raw_socket" }, { f: "raw_socket", t: "wireshark" },
    { f: "tcpdump", t: "wireshark" }, { f: "tcpdump", t: "responder" },
    { f: "wireshark", t: "ftp_creds" }, { f: "wireshark", t: "http_basic" }, { f: "wireshark", t: "smtp_pop" },
    { f: "responder", t: "ntlm_hashes" },
    { f: "ftp_creds", t: "creds" }, { f: "http_basic", t: "creds" }, { f: "smtp_pop", t: "creds" }, { f: "ntlm_hashes", t: "creds" },
    { f: "raw_socket", t: "sysmon_3" }, { f: "promisc", t: "promisc_detect" },
  ],
};
export default model;
