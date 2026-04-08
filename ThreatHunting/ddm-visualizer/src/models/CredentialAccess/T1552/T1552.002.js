// T1552.002 — Credentials in Registry — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.002",
    name: "Credentials in Registry",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "REGISTRY AREA",  x: 80 },
      { label: "QUERY METHOD",  x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "autologon", label: "AutoLogon", sub: "Winlogon", x: 80, y: 120, r: 36, type: "source",
      tags: ["DefaultPassword", "Winlogon", "AutoAdminLogon"],
      telemetry: ["Sysmon 13"],
      api: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon — DefaultPassword value",
      artifact: "Plaintext password stored in Winlogon\\DefaultPassword · AutoAdminLogon enabled",
      desc: "Windows AutoLogon stores credentials in the registry (DefaultUserName, DefaultPassword, DefaultDomainName under Winlogon key). The DefaultPassword is stored in plaintext. AutoLogon is used for kiosk machines, shared workstations, and sometimes carelessly configured servers.",
      src: "MITRE ATT&CK T1552.002; Microsoft KB324737" },

    { id: "app_creds", label: "App Creds", sub: "Software keys", x: 80, y: 280, r: 34, type: "source",
      tags: ["PuTTY saved sessions", "VNC password", "WinSCP", "App-specific"],
      telemetry: [],
      api: "Application-stored credentials: PuTTY (ProxyPassword), VNC (Password), WinSCP (passwords)",
      artifact: "Application credentials stored in HKCU\\Software\\ or HKLM\\Software\\",
      desc: "Many applications store credentials in the registry: PuTTY (proxy passwords, saved sessions), VNC (Password value — DES encrypted with known key), WinSCP (saved session passwords), SNMP community strings, SQL Server connection strings, and various enterprise software configurations.",
      src: "MITRE T1552.002" },

    { id: "reg_query", label: "Registry Query", sub: "reg query", x: 270, y: 200, r: 40, type: "source",
      tags: ["reg query", "Get-ItemProperty", "findstr password"],
      telemetry: ["Sysmon 1"],
      api: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v DefaultPassword",
      artifact: "Sysmon EID 1: reg.exe query to Winlogon or software credential keys",
      desc: "Attacker queries registry for credentials: reg query of Winlogon\\DefaultPassword, enumeration of software keys for known credential locations, or broad search (reg query HKLM /f password /t REG_SZ /s). PowerShell: Get-ItemProperty on credential-containing paths.",
      src: "MITRE T1552.002" },

    { id: "ev_detect", label: "Reg Access", sub: "Query monitor", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Sysmon 1 reg query", "Registry audit", "Winlogon access", "Credential key access"],
      telemetry: ["Sysmon 1", "Windows 4657"],
      api: "Sysmon 1: reg.exe queries to credential-containing keys + Windows SACL on sensitive keys",
      artifact: "OPTIMAL: Sysmon 1 reg query to Winlogon · Windows 4657 registry access audit · bulk registry enumeration",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1: reg.exe with arguments targeting Winlogon, VNC, PuTTY, WinSCP keys. (2) Windows 4657: registry SACL audit on DefaultPassword and other credential-containing values. (3) Behavioral: broad registry search for 'password' (reg query /f password /s). (4) PREVENTION: Remove AutoLogon credentials, use Credential Manager instead, LAPS for local admin passwords.",
      src: "MITRE T1552.002; Sysmon; Windows Security Auditing" },

    { id: "plaintext_creds", label: "Retrieved Creds", sub: "Plaintext/weak", x: 730, y: 200, r: 38, type: "source",
      tags: ["AutoLogon password", "VNC password", "Service credentials", "Plaintext"],
      telemetry: [],
      api: "Retrieved credentials: plaintext AutoLogon password, weakly encrypted app passwords",
      artifact: "Plaintext or easily decryptable credentials from registry",
      desc: "Yields credentials stored in registry: plaintext AutoLogon passwords, VNC passwords (trivially decryptable — fixed DES key), PuTTY proxy passwords, WinSCP session passwords, SNMP community strings, and various application service account credentials.",
      src: "MITRE T1552.002" },
  ],

  edges: [
    { f: "autologon", t: "reg_query" },
    { f: "app_creds", t: "reg_query" },
    { f: "reg_query", t: "ev_detect" },
    { f: "ev_detect", t: "plaintext_creds" },
  ],
};

export default model;
