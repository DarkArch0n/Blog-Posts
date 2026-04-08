// T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1557.001",
    name: "LLMNR/NBT-NS Poisoning and SMB Relay",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1600,
    svgHeight: 480,
    rows: [
      { label: "LLMNR",    y: 80 },
      { label: "NBT-NS",   y: 180 },
      { label: "MDNS",     y: 280 },
      { label: "RELAY",    y: 400 },
    ],
  },

  nodes: [
    { id: "victim_query", label: "Victim DNS Fail", sub: "Typo / stale", x: 60, y: 150, r: 38, type: "entry",
      desc: "Victim's DNS query fails (typo, stale mapping, missing record). OS falls back to LLMNR/NBT-NS multicast.",
      src: "MITRE ATT&CK T1557.001" },

    // Row 1: LLMNR poisoning
    { id: "llmnr_query", label: "LLMNR Query", sub: "UDP 5355 multicast", x: 200, y: 80, r: 34, type: "protocol",
      desc: "LLMNR multicast query on UDP/5355 (224.0.0.252). All hosts on subnet receive it.",
      src: "RFC 4795" },
    { id: "responder_llmnr", label: "Responder", sub: "LLMNR Poison", x: 360, y: 80, r: 36, type: "op",
      desc: "Responder answers LLMNR query: 'Yes, I am that hostname.' Sends attacker IP.",
      src: "lgandx/Responder" },
    { id: "llmnr_resp", label: "LLMNR Response", sub: "Attacker IP", x: 520, y: 80, r: 32, type: "protocol",
      desc: "Poisoned LLMNR response provides attacker's IP as the target hostname.",
      src: "RFC 4795; Responder" },

    // Row 2: NBT-NS poisoning
    { id: "nbtns_query", label: "NBT-NS Query", sub: "UDP 137 broadcast", x: 200, y: 180, r: 34, type: "protocol",
      desc: "NetBIOS Name Service broadcast on UDP/137. Older fallback protocol.",
      src: "RFC 1002" },
    { id: "responder_nbt", label: "Responder", sub: "NBT-NS Poison", x: 360, y: 180, r: 34, type: "op",
      desc: "Responder answers NBT-NS broadcast with attacker IP address.",
      src: "lgandx/Responder" },

    // Row 3: mDNS
    { id: "mdns_query", label: "mDNS Query", sub: "UDP 5353 multicast", x: 200, y: 280, r: 34, type: "protocol",
      desc: "Multicast DNS on UDP/5353 (224.0.0.251). Windows 10+ supports mDNS.",
      src: "RFC 6762" },
    { id: "responder_mdns", label: "Responder", sub: "mDNS Poison", x: 360, y: 280, r: 34, type: "op",
      desc: "Responder poisons mDNS queries in addition to LLMNR/NBT-NS.",
      src: "lgandx/Responder" },

    // ── Victim authenticates to attacker ──
    { id: "ntlm_auth", label: "NTLM Challenge", sub: "SMB/HTTP/WPAD", x: 680, y: 150, r: 40, type: "protocol",
      desc: "Victim connects to attacker (SMB/HTTP/WPAD). NTLM challenge-response occurs.",
      src: "MS-NLMP; RFC 4559" },
    { id: "ntlm_resp", label: "NTLMv2 Response", x: 820, y: 80, r: 36, type: "artifact",
      desc: "NTLMv2 hash (NetNTLMv2) captured: user::domain:challenge:NTProofStr:blob",
      src: "MS-NLMP; Responder" },

    // Capture path
    { id: "hashcat_5600", label: "hashcat", sub: "-m 5600", x: 960, y: 80, r: 36, type: "blind",
      desc: "BLIND: Offline NTLMv2 cracking. hashcat -m 5600. Zero network traffic.",
      src: "hashcat.net" },
    { id: "plaintext", label: "Plaintext Pwd", x: 1100, y: 80, r: 30, type: "artifact",
      desc: "Cracked domain password from NTLMv2 capture.",
      src: "MITRE T1557.001" },

    // Row 4: Relay path
    { id: "ntlmrelayx", label: "ntlmrelayx", sub: "impacket", x: 680, y: 400, r: 38, type: "op",
      desc: "impacket-ntlmrelayx relays captured NTLM auth to other targets instead of cracking.",
      src: "fortra/impacket" },
    { id: "smb_relay", label: "SMB Relay", sub: "TCP 445", x: 830, y: 350, r: 34, type: "protocol",
      desc: "Relay NTLMv2 auth to target SMB server. Requires SMB signing disabled on target.",
      src: "MS-SMB2; Impacket" },
    { id: "ldap_relay", label: "LDAP Relay", sub: "TCP 389/636", x: 830, y: 440, r: 34, type: "protocol",
      desc: "Relay to LDAP for AD modifications: add computer, modify ACLs, RBCD delegation.",
      src: "MS-ADTS; Impacket" },
    { id: "rbcd", label: "RBCD Attack", sub: "Delegate access", x: 980, y: 440, r: 34, type: "op",
      desc: "Resource-Based Constrained Delegation: modify msDS-AllowedToActOnBehalfOfOtherIdentity.",
      src: "SpecterOps; Impacket" },
    { id: "shell", label: "Remote Shell", sub: "SYSTEM", x: 980, y: 340, r: 34, type: "artifact",
      desc: "Interactive shell on target via relayed SMB auth + service creation/psexec.",
      src: "fortra/impacket" },

    // ── Detection ──
    { id: "ev_llmnr", label: "Zeek/IDS", sub: "LLMNR responses", x: 520, y: 200, r: 36, type: "detect",
      desc: "OPTIMAL: Monitor for LLMNR/NBT-NS responses from unexpected hosts. Zeek llmnr.log analysis.",
      src: "Zeek; Corelight" },
    { id: "ev_4624", label: "Event 4624", sub: "Type 3 anomaly", x: 1100, y: 340, r: 34, type: "detect",
      desc: "Event 4624 Type 3: Network logon from unexpected source IP (relay target sees attacker's relayed auth).",
      src: "Microsoft Event 4624" },
    { id: "honeytoken", label: "Honey Creds", sub: "Canary SPN", x: 520, y: 340, r: 32, type: "detect",
      desc: "Deploy honey credentials — fake shares/SPNs that trigger alerts when poisoned/accessed.",
      src: "Thinkst Canary; SpecterOps" },
  ],

  edges: [
    // LLMNR path
    { f: "victim_query", t: "llmnr_query" },
    { f: "llmnr_query", t: "responder_llmnr" },
    { f: "responder_llmnr", t: "llmnr_resp" },
    { f: "llmnr_resp", t: "ntlm_auth" },
    // NBT-NS path
    { f: "victim_query", t: "nbtns_query" },
    { f: "nbtns_query", t: "responder_nbt" },
    { f: "responder_nbt", t: "ntlm_auth" },
    // mDNS path
    { f: "victim_query", t: "mdns_query" },
    { f: "mdns_query", t: "responder_mdns" },
    { f: "responder_mdns", t: "ntlm_auth" },
    // Capture
    { f: "ntlm_auth", t: "ntlm_resp" },
    { f: "ntlm_resp", t: "hashcat_5600", blind: true },
    { f: "hashcat_5600", t: "plaintext", blind: true },
    // Relay
    { f: "ntlm_auth", t: "ntlmrelayx" },
    { f: "ntlmrelayx", t: "smb_relay" },
    { f: "ntlmrelayx", t: "ldap_relay" },
    { f: "smb_relay", t: "shell" },
    { f: "ldap_relay", t: "rbcd" },
    { f: "rbcd", t: "shell" },
    // Detection
    { f: "responder_llmnr", t: "ev_llmnr" },
    { f: "responder_nbt", t: "ev_llmnr" },
    { f: "shell", t: "ev_4624" },
    { f: "ntlm_auth", t: "honeytoken" },
  ],
};

export default model;
