// T1040 — Network Sniffing — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1040",
    name: "Network Sniffing",
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
      { label: "SNIFF METHOD", x: 260 },
      { label: "DETECTION",    x: 470 },
      { label: "CAPTURED DATA", x: 700 },
      { label: "OUTCOME",      x: 900 },
    ],
    separators: [170, 365, 585, 800],
    annotations: [
      { text: "Promiscuous mode + cleartext protocols = data exposure", x: 470, y: 400, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "access", label: "Host Access", sub: "Admin/root", x: 80, y: 220, r: 40, type: "source",
      tags: ["Admin/root", "Promiscuous mode", "Mirror port", "Network tap"],
      telemetry: [],
      api: "Requires admin/root for promiscuous mode, or network tap/mirror port access",
      artifact: "Privileged access or physical network tap position",
      desc: "Network sniffing requires: (1) Admin/root privilege to set interfaces to promiscuous mode. (2) Physical access to install a network tap. (3) Switch access to configure port mirroring (SPAN). (4) On wireless networks, monitor mode on the wireless adapter.",
      src: "MITRE ATT&CK T1040" },

    { id: "tcpdump", label: "tcpdump", sub: "CLI capture", x: 260, y: 100, r: 34, type: "source",
      tags: ["tcpdump -i eth0", "pcap output", "BPF filters"],
      telemetry: ["Sysmon 1", "auditd"],
      api: "tcpdump -i eth0 -w capture.pcap · tcpdump port 80 or port 21",
      artifact: "Sysmon EID 1 / auditd: tcpdump process · promiscuous mode set · pcap file",
      desc: "Command-line packet capture tool available on all Linux/macOS systems. Captures raw packets to pcap files for offline analysis. BPF filters target specific protocols (HTTP, FTP, LDAP, SMTP). Can capture credentials from cleartext protocols in real-time.",
      src: "tcpdump; MITRE T1040" },

    { id: "wireshark", label: "Wireshark", sub: "GUI/tshark", x: 260, y: 230, r: 34, type: "source",
      tags: ["Wireshark", "tshark", "GUI capture", "Protocol dissectors"],
      telemetry: ["Sysmon 1"],
      api: "Wireshark GUI or tshark CLI · deep protocol analysis · credential extraction",
      artifact: "Sysmon EID 1: Wireshark/tshark · Npcap driver install · pcap files",
      desc: "Wireshark provides deep packet inspection with protocol dissectors that automatically identify and display credentials from HTTP Basic Auth, FTP, Telnet, LDAP, IMAP, POP3, and SMTP. tshark provides the same capability via CLI.",
      src: "Wireshark; MITRE T1040" },

    { id: "pktmon", label: "pktmon.exe", sub: "Windows native", x: 260, y: 360, r: 34, type: "source",
      tags: ["pktmon.exe", "Windows 10+", "LOTL", "Microsoft-signed"],
      telemetry: ["Sysmon 1"],
      api: "pktmon start -c --comp <component> · pktmon stop · native Windows packet monitor",
      artifact: "Sysmon EID 1: pktmon · .etl capture files · native Windows tool",
      desc: "Windows 10/Server 2019+ pktmon.exe is a native Microsoft-signed packet monitor. Living-off-the-land — no additional software needed. Captures to .etl format, convertible to pcap. Less commonly monitored than third-party sniffers.",
      src: "Microsoft pktmon; LOLBAS; MITRE T1040" },

    { id: "ev_detect", label: "Promisc Mode", sub: "Process + NIC", x: 470, y: 220, r: 50, type: "detect",
      tags: ["Promiscuous mode", "Sysmon 1", "Socket_RAW", "Npcap install"],
      telemetry: ["Sysmon 1", "auditd"],
      api: "Detect NIC promiscuous mode changes + sniffing tool process creation",
      artifact: "OPTIMAL: Sysmon 1 for tcpdump/wireshark/tshark/pktmon · promiscuous mode change · pcap files",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1 / Event 4688: creation of sniffing tools (tcpdump, wireshark, tshark, pktmon). (2) Linux: promiscuous mode changes via ip link set promisc on — auditd or kernel logging. (3) Npcap/WinPcap driver installation events. (4) File creation of .pcap/.etl files. (5) PREVENTION: Network segmentation, encryption (TLS everywhere), disable unused protocols.",
      src: "MITRE T1040; Sysmon; auditd; CIS benchmark" },

    { id: "cleartext", label: "Cleartext", sub: "Credentials", x: 700, y: 140, r: 36, type: "source",
      tags: ["HTTP Basic", "FTP", "Telnet", "LDAP", "SMTP"],
      telemetry: [],
      api: "Cleartext credentials from unencrypted protocols captured in network traffic",
      artifact: "Plaintext username:password pairs from HTTP Basic, FTP, Telnet, unencrypted LDAP",
      desc: "Cleartext protocols expose credentials directly in network captures: HTTP Basic Auth (base64 encoded — trivially decoded), FTP USER/PASS, Telnet sessions, unencrypted LDAP binds, SMTP AUTH, POP3/IMAP (without STARTTLS). These provide directly usable credentials.",
      src: "MITRE T1040" },

    { id: "ntlm_cap", label: "NTLM Hashes", sub: "Net-NTLMv2", x: 700, y: 310, r: 36, type: "source",
      tags: ["Net-NTLMv2", "SMB auth", "HTTP NTLM", "Crackable"],
      telemetry: [],
      api: "NTLM challenge-response captured from SMB or HTTP NTLM authentication",
      artifact: "Net-NTLMv2 hashes from intercepted SMB/HTTP NTLM auth → crackable offline",
      desc: "NTLM authentication captured in transit yields Net-NTLMv2 challenge-response hashes. Crackable offline (hashcat -m 5600) or relayable if the attacker is in MitM position. SMB, HTTP NTLM, and LDAP NTLM authentication are common sources.",
      src: "MITRE T1040; hashcat mode 5600" },
  ],

  edges: [
    { f: "access", t: "tcpdump" },
    { f: "access", t: "wireshark" },
    { f: "access", t: "pktmon" },
    { f: "tcpdump", t: "ev_detect" },
    { f: "wireshark", t: "ev_detect" },
    { f: "pktmon", t: "ev_detect" },
    { f: "ev_detect", t: "cleartext" },
    { f: "ev_detect", t: "ntlm_cap" },
  ],
};

export default model;
