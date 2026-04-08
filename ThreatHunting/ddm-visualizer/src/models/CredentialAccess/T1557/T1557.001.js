// T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1557.001",
    name: "LLMNR/NBT-NS Poisoning and SMB Relay",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 1020,
    svgHeight: 540,
    columns: [
      { label: "TRIGGER",     x: 70  },
      { label: "POISONING",   x: 240 },
      { label: "VICTIM RESP", x: 420 },
      { label: "DETECTION",   x: 620 },
      { label: "OUTCOME",     x: 850 },
    ],
    separators: [155, 330, 520, 735],
    annotations: [
      { text: "Disable LLMNR + NBT-NS via GPO to prevent entirely", x: 620, y: 460, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "name_query", label: "Name Query", sub: "Fails DNS", x: 70, y: 160, r: 38, type: "source",
      tags: ["DNS failure", "LLMNR fallback", "NBT-NS fallback", "Typo/misconfig"],
      telemetry: [],
      api: "Victim queries DNS for hostname → fails → falls back to LLMNR (UDP/5355) or NBT-NS (UDP/137)",
      artifact: "LLMNR multicast 224.0.0.252:5355 · NBT-NS broadcast on UDP/137",
      desc: "When a Windows hostname cannot be resolved via DNS, the system falls back to LLMNR (Link-Local Multicast Name Resolution) on UDP/5355 or NBT-NS (NetBIOS Name Service) on UDP/137. These broadcast/multicast protocols are inherently insecure — any host on the network segment can respond.",
      src: "MITRE ATT&CK T1557.001; RFC 4795 (LLMNR)" },

    { id: "smb_attempt", label: "SMB Connect", sub: "\\\\mistyped\\share", x: 70, y: 370, r: 36, type: "source",
      tags: ["UNC path", "Mapped drive", "File share access", "Mistyped hostname"],
      telemetry: [],
      api: "Victim attempts SMB connection (\\\\hostname\\share) to non-existent or mistyped host",
      artifact: "SMB connection attempt triggers name resolution → fallback to LLMNR/NBT-NS",
      desc: "Common triggers: typos in UNC paths, mapped drives to decommissioned servers, internal web pages referencing non-existent hosts, or WPAD (Web Proxy Auto-Discovery) requests. Each failed DNS resolution triggers the vulnerable fallback protocols.",
      src: "MITRE T1557.001" },

    { id: "responder", label: "Responder", sub: "LLMNR/NBT-NS", x: 240, y: 120, r: 38, type: "source",
      tags: ["Responder.py", "Inveigh", "LLMNR/NBT-NS poisoner"],
      telemetry: ["Sysmon 3"],
      api: "Responder.py -I eth0 -wrf · listens for LLMNR/NBT-NS queries and responds as the target",
      artifact: "Attacker process listening on UDP/5355 + UDP/137 · spoofed responses",
      desc: "Responder (Python) or Inveigh (PowerShell/.NET) listens for LLMNR and NBT-NS broadcast/multicast queries and responds with the attacker's IP, claiming to be the requested hostname. Victim then authenticates to the attacker's machine. Responder also serves rogue HTTP/SMB/WPAD services.",
      src: "SpiderLabs/Responder — github.com/SpiderLabs/Responder; Kevin Robertson/Inveigh" },

    { id: "relay", label: "ntlmrelayx", sub: "SMB Relay", x: 240, y: 320, r: 38, type: "source",
      tags: ["ntlmrelayx.py", "MultiRelay", "Relay to target"],
      telemetry: ["4624"],
      api: "ntlmrelayx.py -t smb://target -smb2support · relays captured NTLM auth to another host",
      artifact: "Event 4624 on relay target · authentication from unexpected source IP",
      desc: "Instead of capturing the hash for offline cracking, ntlmrelayx relays the victim's NTLM authentication directly to another target. If SMB signing is not required (default on workstations), the attacker authenticates as the victim on the relay target. Enables command execution, SAM dump, or LDAP attacks.",
      src: "Impacket ntlmrelayx; MITRE T1557.001" },

    { id: "mitm6", label: "mitm6", sub: "IPv6 WPAD", x: 240, y: 480, r: 34, type: "source",
      tags: ["mitm6", "IPv6 DNS", "WPAD poisoning", "DHCPv6"],
      telemetry: [],
      api: "mitm6 -d corp.local · replies to DHCPv6 requests, becomes DNS server, serves WPAD",
      artifact: "DHCPv6 responses · rogue DNS · WPAD proxy configuration",
      desc: "mitm6 exploits the IPv6 preference in Windows to become the victim's DNS server via DHCPv6. Responds to WPAD queries, forcing the victim to proxy through the attacker. Combined with ntlmrelayx for authentication relay. Works even on IPv4-only networks.",
      src: "fox-it/mitm6 — github.com/dirkjanm/mitm6; dirkjanm.io" },

    { id: "ntlm_auth", label: "NTLMv2 Auth", sub: "To Attacker", x: 420, y: 170, r: 38, type: "source",
      tags: ["NTLMv2 challenge-response", "Net-NTLMv2 hash", "Auto-auth"],
      telemetry: [],
      api: "Victim sends NTLMSSP_AUTH with NTLMv2 response to attacker's rogue service",
      artifact: "Net-NTLMv2 hash captured in Responder logs · hash format crackable offline",
      desc: "After the victim resolves the hostname to the attacker's IP, Windows automatically attempts NTLM authentication to the rogue SMB/HTTP service. The NTLMv2 challenge-response is captured. The Net-NTLMv2 hash can be cracked offline (hashcat -m 5600) or relayed in real-time.",
      src: "MITRE T1557.001; hashcat Net-NTLMv2 mode 5600" },

    { id: "ev_detect", label: "Network + Logs", sub: "Multi-source", x: 620, y: 260, r: 50, type: "detect",
      tags: ["LLMNR traffic", "4624 from unexpected IP", "Sysmon 3", "Honeypot auth"],
      telemetry: ["4624", "Sysmon 3"],
      api: "Network monitoring for LLMNR/NBT-NS responses + anomalous 4624 source IPs",
      artifact: "OPTIMAL: Anomalous 4624 source IP · LLMNR response from non-DNS host · honeypot triggers",
      desc: "OPTIMAL DETECTION NODE. (1) Network: Monitor for LLMNR responses (UDP/5355) from non-DNS servers — legitimate responses from workstations are suspicious. (2) Event 4624: Authentication from unexpected source IP (attacker's machine) to relay targets. (3) Honeypot/honeytoken: Deploy non-existent hostnames that trigger LLMNR — any response is malicious. (4) Sysmon 3: Unusual processes listening on UDP/5355 or 137. (5) PREVENTION: Disable LLMNR via GPO + disable NBT-NS in adapter settings.",
      src: "MITRE T1557.001; Sigma rules; Microsoft GPO LLMNR disable" },

    { id: "hash_crack", label: "Offline Crack", sub: "hashcat -m 5600", x: 850, y: 150, r: 36, type: "blind",
      tags: ["hashcat -m 5600", "Net-NTLMv2", "Offline cracking"],
      telemetry: [],
      api: "hashcat -m 5600 hashes.txt wordlist.txt — cracks Net-NTLMv2 challenge-response",
      artifact: "⚠ Offline operation — plaintext password if cracked",
      desc: "BLIND SPOT. Net-NTLMv2 hashes captured by Responder are cracked offline using hashcat mode 5600. Much slower than NTLM (mode 1000) due to HMAC-MD5 computation. Yields plaintext passwords for domain accounts. Strong passwords resist cracking.",
      src: "hashcat documentation; SpiderLabs/Responder" },

    { id: "relay_access", label: "Relay Access", sub: "As Victim", x: 850, y: 370, r: 38, type: "source",
      tags: ["Admin access on target", "SAM dump via relay", "LDAP delegation"],
      telemetry: ["4624"],
      api: "Authenticated session on relay target as the victim — command execution, SAM dump, LDAP",
      artifact: "Event 4624 on relay target · potential SAM dump · command execution",
      desc: "Successful relay provides authenticated access on the target as the victim. If the victim is a local admin on the relay target, attacker can execute commands, dump SAM, or modify AD objects via LDAP relay. SMB signing enforcement prevents SMB relay attacks.",
      src: "MITRE T1557.001; Impacket ntlmrelayx" },
  ],

  edges: [
    { f: "name_query", t: "responder" },
    { f: "smb_attempt", t: "responder" },
    { f: "name_query", t: "mitm6" },
    { f: "responder", t: "ntlm_auth" },
    { f: "mitm6", t: "relay" },
    { f: "ntlm_auth", t: "ev_detect" },
    { f: "ntlm_auth", t: "relay" },
    { f: "relay", t: "ev_detect" },
    { f: "ev_detect", t: "hash_crack" },
    { f: "ev_detect", t: "relay_access" },
  ],
};

export default model;
