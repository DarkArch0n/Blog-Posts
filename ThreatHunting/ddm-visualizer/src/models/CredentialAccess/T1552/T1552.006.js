// T1552.006 — Group Policy Preferences — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.006",
    name: "Group Policy Preferences",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "GPP SOURCE",   x: 80 },
      { label: "DECRYPT",      x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "sysvol", label: "SYSVOL", sub: "GPP XML files", x: 80, y: 130, r: 38, type: "source",
      tags: ["\\\\domain\\SYSVOL", "Groups.xml", "Scheduledtasks.xml", "cpassword"],
      telemetry: [],
      api: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{GUID}\\Machine\\Preferences\\ — GPP XML files",
      artifact: "GPP XML files containing cpassword attribute · readable by all domain users",
      desc: "Group Policy Preferences (GPP) allowed admins to set local admin passwords, map drives with credentials, create scheduled tasks with credentials, etc. The passwords were stored in XML files (Groups.xml, Scheduledtasks.xml, Services.xml, Datasources.xml) in SYSVOL as AES-256 encrypted 'cpassword' values. SYSVOL is readable by all authenticated domain users.",
      src: "MITRE ATT&CK T1552.006; Microsoft MS14-025" },

    { id: "gpp_key", label: "Known AES Key", sub: "MS published key", x: 80, y: 320, r: 34, type: "source",
      tags: ["AES-256 key published", "Microsoft MSDN", "Trivially decrypted"],
      telemetry: [],
      api: "Microsoft published the AES-256 key on MSDN — passwords are trivially decryptable",
      artifact: "AES key: 4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8...",
      desc: "Microsoft published the AES-256 key used to encrypt GPP passwords on MSDN documentation. Anyone with the cpassword value can decrypt it. Microsoft fixed this with MS14-025 (KB2962486) which prevents creating new GPP with passwords, but existing GPP password files are not automatically removed.",
      src: "Microsoft MS14-025; MSDN documentation" },

    { id: "gpp_decrypt", label: "gpp-decrypt", sub: "Tool decryption", x: 270, y: 200, r: 40, type: "source",
      tags: ["Get-GPPPassword", "gpp-decrypt", "PowerSploit", "CrackMapExec"],
      telemetry: ["Sysmon 1"],
      api: "Get-GPPPassword (PowerSploit) · gpp-decrypt · CrackMapExec --gpp-password",
      artifact: "Sysmon 1: PowerShell Get-GPPPassword · access to Groups.xml in SYSVOL",
      desc: "Automated tools to find and decrypt GPP passwords: Get-GPPPassword.ps1 (PowerSploit) searches SYSVOL and decrypts all cpassword values. gpp-decrypt (Kali) decrypts individual cpassword values. CrackMapExec has --gpp-password module. All produce plaintext passwords instantly.",
      src: "PowerSploit; CrackMapExec; MITRE T1552.006" },

    { id: "ev_detect", label: "SYSVOL Access", sub: "GPP file read", x: 480, y: 200, r: 50, type: "detect",
      tags: ["SYSVOL access audit", "Groups.xml read", "Get-GPPPassword", "Sysmon 1"],
      telemetry: ["Sysmon 1", "Windows 4663"],
      api: "Audit SYSVOL access for GPP XML files + detect Get-GPPPassword execution",
      artifact: "OPTIMAL: Sysmon 1 Get-GPPPassword · 4663 access to Groups.xml · SYSVOL\\..*Preferences.*\\.xml access",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1: Get-GPPPassword, gpp-decrypt, or CrackMapExec with --gpp-password. (2) Windows 4663: file access audit on SYSVOL Preferences XML files. (3) Network: SMB access to specific GPP file paths. (4) Remediation: DELETE old GPP password files from SYSVOL — they persist after MS14-025 patch. (5) PREVENTION: Remove all cpassword-containing XML files, use LAPS instead.",
      src: "MITRE T1552.006; MS14-025; Microsoft LAPS" },

    { id: "local_admin", label: "Local Admin", sub: "Domain-wide", x: 730, y: 200, r: 40, type: "source",
      tags: ["Local admin password", "Service account", "Scheduled task cred", "Domain-wide"],
      telemetry: [],
      api: "Decrypted GPP passwords: often local admin passwords set domain-wide",
      artifact: "Local admin passwords, service account credentials, scheduled task credentials",
      desc: "GPP commonly stored local admin passwords (set uniformly across all workstations/servers), service account credentials (for scheduled tasks, mapped drives), and data source credentials. A single GPP local admin password often works on every machine in the domain.",
      src: "MITRE T1552.006" },
  ],

  edges: [
    { f: "sysvol", t: "gpp_decrypt" },
    { f: "gpp_key", t: "gpp_decrypt" },
    { f: "gpp_decrypt", t: "ev_detect" },
    { f: "ev_detect", t: "local_admin" },
  ],
};

export default model;
