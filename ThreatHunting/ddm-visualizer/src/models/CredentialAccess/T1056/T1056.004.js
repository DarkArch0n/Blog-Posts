// T1056.004 — Credential API Hooking — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1056.004",
    name: "Credential API Hooking",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "HOOK TARGET",  x: 80 },
      { label: "HOOK METHOD",  x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "auth_api", label: "Auth APIs", sub: "LogonUser/SSPI", x: 80, y: 130, r: 36, type: "source",
      tags: ["LogonUserW", "LsaLogonUser", "SSPI", "CredUI"],
      telemetry: [],
      api: "Authentication APIs: LogonUserW(), LsaLogonUser(), AcquireCredentialsHandle()",
      artifact: "Windows authentication APIs that process plaintext credentials",
      desc: "Windows authentication APIs receive plaintext credentials before hashing. Key targets: LogonUserW/LogonUserA (local/domain logon), LsaLogonUser (LSA authentication), AcquireCredentialsHandle (SSPI/Negotiate), CredUIPromptForCredentials (credential UI). Hooking these captures passwords before they are processed.",
      src: "MITRE ATT&CK T1056.004" },

    { id: "crypto_api", label: "Crypto APIs", sub: "Encrypt/Hash", x: 80, y: 300, r: 34, type: "source",
      tags: ["CryptProtectData", "NtlmHash", "BCrypt*"],
      telemetry: [],
      api: "Cryptographic APIs: CryptProtectData(), NtlmHashPassword(), BCryptHashData()",
      artifact: "Crypto APIs that receive plaintext data before encryption/hashing",
      desc: "Cryptographic APIs receive plaintext data before hashing or encryption. Hooking these captures data at the point of protection. CryptProtectData (DPAPI) receives plaintext secrets. NtlmHashPassword receives the plaintext password before NTLM hash computation.",
      src: "MITRE T1056.004" },

    { id: "iat_hook", label: "IAT/EAT Hook", sub: "Import table", x: 270, y: 120, r: 36, type: "source",
      tags: ["IAT hooking", "EAT hooking", "DLL injection", "Inline patching"],
      telemetry: ["Sysmon 7"],
      api: "Overwrite IAT entries to redirect API calls → attacker function → original function",
      artifact: "Sysmon EID 7: suspicious DLL load · modified IAT entries · detour patches",
      desc: "Import Address Table (IAT) hooking overwrites function pointers in the target process's import table. When the process calls the hooked API, it executes the attacker's function first (capturing the plaintext input), then calls the original function. DLL injection is a prerequisite.",
      src: "MITRE T1056.004; detours" },

    { id: "ssp_hook", label: "SSP Install", sub: "Custom SSP", x: 270, y: 300, r: 36, type: "source",
      tags: ["AddSecurityPackage()", "mimilib.dll", "Custom SSP DLL"],
      telemetry: ["Sysmon 7", "Sysmon 13"],
      api: "AddSecurityPackage() installs custom SSP → SpAcceptCredentials receives plaintext passwords",
      artifact: "Sysmon EID 13: Security Packages registry · EID 7: SSP DLL loaded by LSASS",
      desc: "A malicious Security Support Provider (SSP) DLL loaded by LSASS receives plaintext credentials via SpAcceptCredentials() for every logon. mimilib.dll (Mimikatz SSP) logs all credentials to a file. Registered via AddSecurityPackage() API or HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages registry value.",
      src: "gentilkiwi/mimikatz mimilib; MITRE T1056.004; T1547.005" },

    { id: "ev_detect", label: "DLL + Hook", sub: "Integrity check", x: 480, y: 220, r: 50, type: "detect",
      tags: ["Sysmon 7", "IAT integrity", "SSP registration", "LSASS DLL loads"],
      telemetry: ["Sysmon 7", "Sysmon 13"],
      api: "Sysmon DLL load monitoring + IAT integrity checks + SSP registration monitoring",
      artifact: "OPTIMAL: Sysmon 7 DLL loads in LSASS · Sysmon 13 Security Packages change · IAT tampering · EDR hook detection",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 7: DLL loads in sensitive processes (lsass.exe) — unsigned or unusual DLLs. (2) Sysmon EID 13: Registry modification of Security Packages value. (3) EDR: IAT/EAT integrity validation — detect modified function pointers. (4) Process integrity checks: compare loaded DLLs against known-good baselines. (5) PREVENTION: Credential Guard (isolates LSASS in virtualization-based security), RunAsPPL.",
      src: "MITRE T1056.004; Sysmon; Windows Credential Guard" },

    { id: "plaintext_creds", label: "All Logon Creds", sub: "Captured", x: 730, y: 220, r: 40, type: "source",
      tags: ["Every authentication", "Plaintext passwords", "Including new passwords"],
      telemetry: [],
      api: "Every authentication through hooked API yields plaintext credential",
      artifact: "Continuous plaintext credential capture for all users who authenticate",
      desc: "API hooking captures plaintext credentials for every authentication event processed through the hooked API. An SSP hook in LSASS captures every interactive, network, and service logon. Provides a continuous stream of plaintext passwords, including when users change their passwords.",
      src: "MITRE T1056.004" },
  ],

  edges: [
    { f: "auth_api", t: "iat_hook" },
    { f: "auth_api", t: "ssp_hook" },
    { f: "crypto_api", t: "iat_hook" },
    { f: "iat_hook", t: "ev_detect" },
    { f: "ssp_hook", t: "ev_detect" },
    { f: "ev_detect", t: "plaintext_creds" },
  ],
};

export default model;
