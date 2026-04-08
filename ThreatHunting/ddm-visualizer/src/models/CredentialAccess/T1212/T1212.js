// T1212 — Exploitation for Credential Access — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1212",
    name: "Exploitation for Credential Access",
    tactic: "Credential Access",
    platform: "Windows, Linux",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "VULNERABILITY", x: 80  },
      { label: "EXPLOIT",      x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "EXTRACTION",   x: 690 },
      { label: "OUTCOME",      x: 890 },
    ],
    separators: [175, 375, 585, 790],
    annotations: [
      { text: "Patch management is primary prevention", x: 480, y: 410, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "zerologon", label: "Zerologon", sub: "CVE-2020-1472", x: 80, y: 100, r: 36, type: "source",
      tags: ["CVE-2020-1472", "Netlogon", "Computer acct password reset"],
      telemetry: ["5829"],
      api: "Netlogon RPC vulnerability — sets DC machine account password to empty via crypto flaw",
      artifact: "Event 5829: Netlogon vulnerable connection · DC machine account anomaly",
      desc: "Zerologon exploits a cryptographic flaw in the Netlogon RPC protocol (MS-NRPC). An unauthenticated attacker can set a DC's machine account password to empty by sending crafted Netlogon messages. Enables DCSync, Golden Ticket, or direct domain compromise. Patch: August 2020.",
      src: "CVE-2020-1472; Secura whitepaper; MITRE T1212" },

    { id: "printnightmare", label: "PrintNightmare", sub: "CVE-2021-34527", x: 80, y: 250, r: 34, type: "source",
      tags: ["CVE-2021-34527", "Print Spooler", "RCE as SYSTEM"],
      telemetry: ["Sysmon 1", "Sysmon 11"],
      api: "Print Spooler vulnerability — remote code execution as SYSTEM via malicious DLL",
      artifact: "Sysmon EID 1: spoolsv.exe child process · EID 11: DLL drop in spool directory",
      desc: "PrintNightmare allows authenticated users to execute code as SYSTEM via the Windows Print Spooler service. Loads an attacker-controlled DLL that can dump credentials (LSASS), add admin users, or deploy backdoors. Detectable via Sysmon monitoring of spoolsv.exe child processes.",
      src: "CVE-2021-34527; MITRE T1212" },

    { id: "petitpotam", label: "PetitPotam", sub: "CVE-2021-36942", x: 80, y: 400, r: 34, type: "source",
      tags: ["CVE-2021-36942", "EfsRpcOpenFileRaw", "Force DC auth"],
      telemetry: ["4624"],
      api: "EFSRPC API coerces DC to authenticate to attacker — relay to AD CS",
      artifact: "DC outbound NTLM to attacker IP · Event 4624 on AD CS from relay",
      desc: "PetitPotam abuses the Encrypting File System Remote Protocol (EFSRPC) to force a Domain Controller to authenticate to an attacker-controlled server. Combined with ntlmrelayx to AD Certificate Services (AD CS), enables certificate-based domain compromise. No authentication required.",
      src: "CVE-2021-36942; topotam/PetitPotam; MITRE T1212" },

    { id: "exploit_exec", label: "Exploit Code", sub: "Execute", x: 270, y: 250, r: 40, type: "source",
      tags: ["PoC exploit", "Metasploit module", "Impacket script"],
      telemetry: ["Sysmon 1", "Sysmon 3"],
      api: "Public PoC exploits, Metasploit modules, or Impacket scripts executing the vulnerability",
      artifact: "Sysmon EID 1 + 3: exploit process creation + network connection to target",
      desc: "Exploits are executed via public proof-of-concept code (GitHub), Metasploit framework modules, or custom scripts. Zerologon: zerologon_tester.py / Mimikatz lsadump::zerologon. PrintNightmare: CVE-2021-34527 PoC. PetitPotam: PetitPotam.py or Impacket.",
      src: "MITRE T1212; exploit-db; Metasploit" },

    { id: "ev_detect", label: "Vuln-Specific", sub: "Multi-source", x: 480, y: 250, r: 50, type: "detect",
      tags: ["CVE-specific signatures", "Patch status", "EDR", "IDS/IPS"],
      telemetry: ["5829", "Sysmon 1", "IDS"],
      api: "CVE-specific detection rules + patch management + EDR behavioral detection",
      artifact: "OPTIMAL: Event 5829 (Zerologon) · spoolsv.exe anomalies · outbound DC NTLM · IDS signatures",
      desc: "OPTIMAL DETECTION NODE. Each exploit has specific detection: (1) Zerologon: Event 5829 (vulnerable Netlogon connection), repeated Netlogon auth with ComputeNetlogonCredential failures. (2) PrintNightmare: Sysmon monitoring spoolsv.exe child processes, DLL loads from non-standard paths. (3) PetitPotam: DC making outbound NTLM to non-DC. (4) PREVENTION: Patch management is the primary defense. Disable unnecessary services (Print Spooler on DCs).",
      src: "MITRE T1212; Microsoft security advisories; Sigma rules" },

    { id: "creds_out", label: "Credentials", sub: "Obtained", x: 690, y: 160, r: 36, type: "source",
      tags: ["DC machine hash", "SYSTEM access", "Certificates"],
      telemetry: [],
      api: "Exploit yields credentials: DC machine account hash, SYSTEM shell, or AD CS certificates",
      artifact: "DC compromise credentials · machine account hash · admin certificates",
      desc: "Successful exploitation yields credential material: Zerologon provides the DC machine account hash (enables DCSync). PrintNightmare provides SYSTEM code execution (enables LSASS dump). PetitPotam via AD CS relay yields certificates that authenticate as any domain entity.",
      src: "MITRE T1212" },

    { id: "domain_comp", label: "Domain Compromise", sub: "Full control", x: 890, y: 250, r: 40, type: "source",
      tags: ["Domain Admin", "Golden Ticket", "DCSync", "Total compromise"],
      telemetry: [],
      api: "Credential exploitation → DCSync → full domain compromise",
      artifact: "Complete domain compromise from single vulnerability exploitation",
      desc: "All three example vulnerabilities lead to full domain compromise: Zerologon → DCSync via machine account. PrintNightmare → LSASS dump on DC → all credentials. PetitPotam → AD CS certificate → authenticate as Domain Admin. Single vulnerability = total domain compromise.",
      src: "MITRE T1212" },
  ],

  edges: [
    { f: "zerologon", t: "exploit_exec" },
    { f: "printnightmare", t: "exploit_exec" },
    { f: "petitpotam", t: "exploit_exec" },
    { f: "exploit_exec", t: "ev_detect" },
    { f: "ev_detect", t: "creds_out" },
    { f: "creds_out", t: "domain_comp" },
  ],
};

export default model;
