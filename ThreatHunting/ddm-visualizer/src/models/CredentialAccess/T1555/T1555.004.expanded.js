// T1555.004 — Windows Credential Manager — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.004",
    name: "Windows Credential Manager",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 400,
    rows: [
      { label: "CMDKEY",   y: 80 },
      { label: "MIMIKATZ", y: 180 },
      { label: "DPAPI",    y: 300 },
    ],
  },

  nodes: [
    { id: "user_ctx", label: "User Context", x: 60, y: 150, r: 36, type: "entry",
      desc: "Running as the user whose credentials are stored. Credential Manager credentials are per-user DPAPI-encrypted.",
      src: "MITRE ATT&CK T1555.004" },

    // Row 1: cmdkey/vaultcmd enumeration
    { id: "cmdkey", label: "cmdkey /list", x: 200, y: 80, r: 34, type: "op",
      desc: "cmdkey /list — enumerates stored credentials (targets, usernames). Built-in Windows binary.",
      src: "Microsoft cmdkey" },
    { id: "vaultcmd", label: "vaultcmd", sub: "/listcreds", x: 350, y: 80, r: 32, type: "op",
      desc: "vaultcmd /listcreds:\"Windows Credentials\" — lists Windows Vault entries.",
      src: "Microsoft vaultcmd" },
    { id: "cred_enum_api", label: "CredEnumerate", sub: "Win32 API", x: 500, y: 80, r: 36, type: "api",
      desc: "CredEnumerate() / CredRead() Win32 APIs to enumerate and read credential entries.",
      src: "Microsoft Win32 Credential Management" },

    // Row 2: Mimikatz vault
    { id: "mimi_vault", label: "Mimikatz", sub: "vault::list", x: 200, y: 180, r: 34, type: "op",
      desc: "Mimikatz vault::list — lists and decrypts Windows Vault credentials.",
      src: "gentilkiwi/mimikatz" },
    { id: "mimi_cred", label: "Mimikatz", sub: "vault::cred", x: 350, y: 180, r: 34, type: "op",
      desc: "vault::cred decrypts credential blobs including generic and domain passwords.",
      src: "gentilkiwi/mimikatz" },
    { id: "sharpdpapi", label: "SharpDPAPI", sub: "credentials", x: 200, y: 240, r: 34, type: "op",
      desc: "SharpDPAPI credentials — decrypts Credential Manager DPAPI blobs programmatically.",
      src: "GhostPack/SharpDPAPI" },

    // Row 3: DPAPI decryption chain
    { id: "cred_files", label: "Credential Files", sub: "%APPDATA%\\Credentials", x: 500, y: 180, r: 36, type: "artifact",
      desc: "DPAPI-encrypted credential blobs at %APPDATA%\\Microsoft\\Credentials\\ (GUID filenames).",
      src: "Microsoft DPAPI" },
    { id: "dpapi_masterkey", label: "DPAPI Master Key", sub: "%APPDATA%\\Protect", x: 500, y: 300, r: 38, type: "artifact",
      desc: "User DPAPI master key at %APPDATA%\\Microsoft\\Protect\\{SID}\\{GUID}. Encrypted with user password.",
      src: "Microsoft DPAPI" },
    { id: "crypt_unprotect", label: "CryptUnprotectData", x: 680, y: 180, r: 40, type: "api",
      desc: "CryptUnprotectData() — Win32 API decrypts credential blob using DPAPI master key in user context.",
      src: "Microsoft DPAPI API" },
    { id: "rpc_dc", label: "MS-BKRP", sub: "DC Backup Key", x: 680, y: 300, r: 34, type: "protocol",
      desc: "DPAPI master key backup: domain-joined machines can decrypt via DC backup key (MS-BKRP RPC).",
      src: "Microsoft MS-BKRP" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "cmdkey/vaultcmd", x: 350, y: 340, r: 34, type: "detect",
      desc: "Sysmon EID 1: Process creation for cmdkey.exe or vaultcmd.exe.",
      src: "Sysmon documentation" },
    { id: "edr_dpapi", label: "EDR", sub: "DPAPI from unknown", x: 680, y: 370, r: 38, type: "detect",
      desc: "OPTIMAL: EDR detects CryptUnprotectData/DPAPI access on credential files by unknown processes.",
      src: "CrowdStrike; Microsoft Defender" },

    // ── Output ──
    { id: "rdp_creds", label: "RDP Credentials", x: 880, y: 100, r: 32, type: "artifact",
      desc: "Saved RDP server credentials (server:user:password).",
      src: "MITRE T1555.004" },
    { id: "web_creds", label: "Web Credentials", x: 880, y: 180, r: 32, type: "artifact",
      desc: "IE/Edge legacy saved web passwords, Windows Auth credentials.",
      src: "MITRE T1555.004" },
    { id: "generic_creds", label: "Generic Creds", sub: "SMB/mapped drives", x: 880, y: 260, r: 34, type: "artifact",
      desc: "Stored network credentials: mapped drives, SQL connections, other service passwords.",
      src: "MITRE T1555.004" },
  ],

  edges: [
    // cmdkey/vaultcmd
    { f: "user_ctx", t: "cmdkey" },
    { f: "user_ctx", t: "vaultcmd" },
    { f: "cmdkey", t: "cred_enum_api" },
    { f: "vaultcmd", t: "cred_enum_api" },
    { f: "cred_enum_api", t: "cred_files" },
    // Mimikatz
    { f: "user_ctx", t: "mimi_vault" },
    { f: "user_ctx", t: "mimi_cred" },
    { f: "user_ctx", t: "sharpdpapi" },
    { f: "mimi_vault", t: "cred_files" },
    { f: "mimi_cred", t: "cred_files" },
    { f: "sharpdpapi", t: "cred_files" },
    // DPAPI
    { f: "cred_files", t: "crypt_unprotect" },
    { f: "dpapi_masterkey", t: "crypt_unprotect" },
    { f: "dpapi_masterkey", t: "rpc_dc" },
    // Detection
    { f: "cmdkey", t: "sysmon_1" },
    { f: "vaultcmd", t: "sysmon_1" },
    { f: "crypt_unprotect", t: "edr_dpapi" },
    // Output
    { f: "crypt_unprotect", t: "rdp_creds" },
    { f: "crypt_unprotect", t: "web_creds" },
    { f: "crypt_unprotect", t: "generic_creds" },
  ],
};

export default model;
