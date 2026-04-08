// T1003.004 — LSA Secrets — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.004",
    name: "LSA Secrets",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 480,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "DUMP METHOD",  x: 270 },
      { label: "DETECTION",    x: 490 },
      { label: "OUTCOME",      x: 740 },
    ],
    separators: [175, 380, 615],
    annotations: [
      { text: "Registry + process creation", x: 490, y: 400, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "admin", label: "Local Admin", sub: "or SYSTEM", x: 80, y: 230, r: 40, type: "source",
      tags: ["Local admin", "SYSTEM", "SeDebugPrivilege"],
      telemetry: [],
      api: "Requires SYSTEM or local admin with SeDebugPrivilege",
      artifact: "Privileged session on target host",
      desc: "LSA Secrets are stored in the SECURITY registry hive, which is only accessible by SYSTEM. Local admin can escalate to SYSTEM via psexec -s, token manipulation, or service creation.",
      src: "MITRE ATT&CK T1003.004" },

    { id: "mimi_lsa", label: "Mimikatz", sub: "lsadump::secrets", x: 270, y: 80, r: 36, type: "source",
      tags: ["lsadump::secrets", "token::elevate", "Live extraction"],
      telemetry: ["Sysmon 1"],
      api: "token::elevate → lsadump::secrets — reads LSA secrets from live registry",
      artifact: "Sysmon EID 1: mimikatz process · SECURITY hive access · token elevation",
      desc: "Mimikatz lsadump::secrets elevates to SYSTEM (token::elevate), then reads LSA secrets directly from the live SECURITY registry hive. Extracts service account passwords, machine account hash, DPAPI system master keys, and auto-logon credentials.",
      src: "gentilkiwi/mimikatz; adsecurity.org" },

    { id: "reg_security", label: "reg.exe save", sub: "HKLM\\SECURITY", x: 270, y: 220, r: 36, type: "source",
      tags: ["reg save HKLM\\SECURITY", "reg save HKLM\\SYSTEM", "LOTL"],
      telemetry: ["4688", "Sysmon 1"],
      api: "reg.exe save HKLM\\SECURITY security.hiv · reg.exe save HKLM\\SYSTEM system.hiv",
      artifact: "Sysmon EID 1: reg save HKLM\\SECURITY · exported hive files",
      desc: "Exports the SECURITY and SYSTEM registry hives to files using native reg.exe. The exported hives are parsed offline with secretsdump.py or Mimikatz. LOTL approach — no external tools needed for extraction.",
      src: "MITRE T1003.004; Atomic Red Team" },

    { id: "secretsdump_lsa", label: "secretsdump", sub: "LOCAL / remote", x: 270, y: 360, r: 36, type: "source",
      tags: ["secretsdump.py LOCAL", "Remote via SMB", "RemoteRegistry"],
      telemetry: ["4688"],
      api: "secretsdump.py -security security.hiv -system system.hiv LOCAL · or remote",
      artifact: "Offline hive parsing · or remote: SMB + RemoteRegistry service",
      desc: "Impacket secretsdump.py parses exported hives locally, or remotely extracts LSA Secrets via authenticated SMB access using the RemoteRegistry service. Remote mode connects to \\\\target, enables RemoteRegistry, and extracts secrets over the network.",
      src: "Impacket — github.com/fortra/impacket" },

    { id: "ev_detect", label: "Registry + Proc", sub: "Multi-source", x: 490, y: 230, r: 50, type: "detect",
      tags: ["Sysmon 1", "4688", "Sysmon 13", "4657"],
      telemetry: ["Sysmon 1", "4688", "4657"],
      api: "Process creation for reg.exe/mimikatz + registry access auditing on SECURITY hive",
      artifact: "OPTIMAL: Sysmon 1 for reg.exe save SECURITY · Event 4657 registry audit · Sysmon 13",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1 / Event 4688: reg.exe with 'save HKLM\\SECURITY' args, or mimikatz with lsadump::secrets. (2) Event 4657: Registry auditing on SECURITY hive key access (requires SACL configuration). (3) RemoteRegistry service start events for remote extraction. (4) EDR detections for credential dumping behavior.",
      src: "MITRE T1003.004; Sigma rules; Sysmon configuration guides" },

    { id: "svc_passwords", label: "Service Acct", sub: "Passwords", x: 740, y: 100, r: 38, type: "source",
      tags: ["Plaintext passwords", "Service accounts", "_SC_ prefix secrets"],
      telemetry: [],
      api: "LSA secret _SC_<ServiceName> → plaintext service account password",
      artifact: "Plaintext passwords for services running under domain accounts",
      desc: "LSA Secrets store service account passwords in plaintext (prefixed _SC_<ServiceName>). Any Windows service running under a domain account has its password stored here. These plaintext credentials enable direct authentication as the service account.",
      src: "adsecurity.org — LSA Secrets; Microsoft" },

    { id: "machine_hash", label: "Machine Acct", sub: "NTLM Hash", x: 740, y: 230, r: 36, type: "source",
      tags: ["$MACHINE.ACC", "Computer account", "Silver Ticket input"],
      telemetry: [],
      api: "LSA secret $MACHINE.ACC → computer account NTLM hash",
      artifact: "Computer account hash → Silver Ticket for services on this host",
      desc: "The $MACHINE.ACC LSA secret contains the computer account's NTLM hash. This can be used to forge Silver Tickets for services (CIFS, HOST, HTTP) running under the machine account. Also usable for S4U2Self attacks.",
      src: "adsecurity.org — LSA Secrets; MITRE T1558.002" },

    { id: "dpapi_keys", label: "DPAPI Keys", sub: "System Master", x: 740, y: 360, r: 36, type: "source",
      tags: ["DPAPI_SYSTEM", "Master key backup", "Credential Manager"],
      telemetry: [],
      api: "DPAPI_SYSTEM secret → system DPAPI master key → decrypt protected data",
      artifact: "DPAPI system key → decrypt Credential Manager, browser passwords, certificates",
      desc: "The DPAPI_SYSTEM LSA secret contains the system DPAPI master key used to decrypt machine-level protected data including Credential Manager stored credentials, scheduled task passwords, and system-level encrypted data. Enables further credential harvesting.",
      src: "gentilkiwi/mimikatz DPAPI; adsecurity.org" },
  ],

  edges: [
    { f: "admin", t: "mimi_lsa" },
    { f: "admin", t: "reg_security" },
    { f: "admin", t: "secretsdump_lsa" },
    { f: "mimi_lsa", t: "ev_detect" },
    { f: "reg_security", t: "ev_detect" },
    { f: "secretsdump_lsa", t: "ev_detect" },
    { f: "ev_detect", t: "svc_passwords" },
    { f: "ev_detect", t: "machine_hash" },
    { f: "ev_detect", t: "dpapi_keys" },
  ],
};

export default model;
