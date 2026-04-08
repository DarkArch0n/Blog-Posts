// T1555.004 — Windows Credential Manager — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.004",
    name: "Windows Credential Manager",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 440,
    columns: [
      { label: "PREREQUISITE", x: 80 },
      { label: "DUMP METHOD",  x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "user_ctx", label: "User Context", sub: "or SYSTEM", x: 80, y: 210, r: 40, type: "source",
      tags: ["User session", "SYSTEM", "DPAPI access"],
      telemetry: [],
      api: "User context for DPAPI decryption, or SYSTEM with DPAPI backup key",
      artifact: "Target user session on the compromised host",
      desc: "Windows Credential Manager stores credentials in the user's profile (%APPDATA%\\Microsoft\\Credentials\\). Protected by DPAPI using the user's master key. Extraction requires running as the target user or as SYSTEM with access to the DPAPI backup key.",
      src: "MITRE ATT&CK T1555.004" },

    { id: "mimi_vault", label: "Mimikatz", sub: "vault::cred", x: 270, y: 110, r: 36, type: "source",
      tags: ["vault::cred", "vault::list", "dpapi::cred"],
      telemetry: ["Sysmon 1"],
      api: "Mimikatz vault::cred · dpapi::cred /in:<credential_file> · dpapi::masterkey",
      artifact: "Sysmon EID 1: mimikatz · vault/dpapi module usage",
      desc: "Mimikatz vault::cred enumerates Credential Manager entries. dpapi::cred decrypts individual credential files from %APPDATA%\\Microsoft\\Credentials\\. Requires the DPAPI master key (obtained via sekurlsa::dpapi or dpapi::masterkey with the user's password/DPAPI backup key).",
      src: "gentilkiwi/mimikatz; MITRE T1555.004" },

    { id: "lazagne_cm", label: "LaZagne", sub: "Windows module", x: 270, y: 250, r: 34, type: "source",
      tags: ["LaZagne", "credman module", "Automated DPAPI"],
      telemetry: ["Sysmon 1"],
      api: "lazagne.exe windows — extracts Credential Manager stored creds automatically",
      artifact: "Sysmon EID 1: lazagne · Credential Manager file access",
      desc: "LaZagne's Windows module automates Credential Manager extraction. Handles DPAPI decryption transparently when running as the target user. Also extracts credentials from other Windows stores (Vault, WinSCP, RDP connections).",
      src: "AlessandroZ/LaZagne; MITRE T1555.004" },

    { id: "vaultcmd", label: "vaultcmd.exe", sub: "Native enum", x: 270, y: 380, r: 34, type: "source",
      tags: ["vaultcmd /listcreds", "Native tool", "Enumeration only"],
      telemetry: ["Sysmon 1"],
      api: "vaultcmd.exe /listcreds:\"Windows Credentials\" — native enumeration (not full dump)",
      artifact: "Sysmon EID 1: vaultcmd · credential enumeration events",
      desc: "Native Windows vaultcmd.exe can list stored credential entries (but not display passwords). Used for enumeration before targeted extraction with Mimikatz. rundll32.exe keymgr.dll,KRShowKeyMgr also opens Credential Manager GUI.",
      src: "Microsoft vaultcmd; MITRE T1555.004" },

    { id: "ev_detect", label: "DPAPI + Files", sub: "Access Monitor", x: 480, y: 210, r: 50, type: "detect",
      tags: ["Sysmon 1", "Credential file access", "DPAPI key usage", "vaultcmd enum"],
      telemetry: ["Sysmon 1"],
      api: "Monitor DPAPI usage from non-standard processes + Credential Manager file access",
      artifact: "OPTIMAL: Non-standard process accessing %APPDATA%\\Credentials\\ · DPAPI key access · vault enumeration",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1: mimikatz, lazagne, vaultcmd, or unknown processes. (2) File access: non-standard processes reading from %APPDATA%\\Microsoft\\Credentials\\ directory. (3) DPAPI: CryptUnprotectData from suspicious processes. (4) Registry: access to DPAPI master key locations. (5) PREVENTION: Windows Credential Guard (isolates DPAPI in virtualization-based security).",
      src: "MITRE T1555.004; Sysmon; Windows Credential Guard" },

    { id: "stored_creds", label: "Stored Creds", sub: "Plaintext", x: 730, y: 210, r: 40, type: "source",
      tags: ["RDP saved passwords", "SMB credentials", "Web credentials", "Scheduled task creds"],
      telemetry: [],
      api: "Plaintext credentials from Credential Manager: RDP, SMB, web, scheduled tasks",
      artifact: "RDP saved passwords → lateral movement · SMB share creds · web logins",
      desc: "Credential Manager stores: saved RDP connection passwords, mapped drive credentials, web credentials (IE/Edge legacy), and credentials for scheduled tasks/services. RDP saved passwords are particularly valuable for lateral movement. Users often save passwords for convenience.",
      src: "MITRE T1555.004" },
  ],

  edges: [
    { f: "user_ctx", t: "mimi_vault" },
    { f: "user_ctx", t: "lazagne_cm" },
    { f: "user_ctx", t: "vaultcmd" },
    { f: "mimi_vault", t: "ev_detect" },
    { f: "lazagne_cm", t: "ev_detect" },
    { f: "vaultcmd", t: "ev_detect" },
    { f: "ev_detect", t: "stored_creds" },
  ],
};

export default model;
