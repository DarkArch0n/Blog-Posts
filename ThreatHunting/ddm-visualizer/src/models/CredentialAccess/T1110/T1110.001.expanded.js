// T1110.001 — Password Guessing — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1110.001",
    name: "Password Guessing",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS, Cloud",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 440,
    rows: [
      { label: "SMB",   y: 80 },
      { label: "RDP",   y: 180 },
      { label: "SSH",   y: 280 },
      { label: "WEB",   y: 380 },
    ],
  },

  nodes: [
    { id: "attacker", label: "Username List", sub: "+ Guesses", x: 60, y: 200, r: 38, type: "entry",
      desc: "Known or enumerated usernames paired with common password guesses (Season+Year, Company+123, etc.).",
      src: "MITRE ATT&CK T1110.001" },

    // Row 1: SMB/Kerberos
    { id: "crackmapexec", label: "CrackMapExec", sub: "smb --pass", x: 200, y: 80, r: 34, type: "op",
      desc: "CrackMapExec: cme smb target -u users.txt -p guesses.txt — SMB authentication brute force.",
      src: "byt3bl33d3r/CrackMapExec" },
    { id: "smb_auth", label: "SMB Auth", sub: "NTLMSSP", x: 360, y: 80, r: 30, type: "protocol",
      desc: "SMB authentication via NTLMSSP on TCP/445. Each guess = 1 SMB session setup.",
      src: "MS-SMB2; MS-NLMP" },
    { id: "ev_4625_smb", label: "Event 4625", sub: "Logon Failure", x: 520, y: 80, r: 36, type: "detect",
      desc: "OPTIMAL: Event 4625 (Failed Logon) on target. Failure Reason: Bad Password. Multiple per source.",
      src: "Microsoft Event 4625" },

    // Row 2: RDP
    { id: "hydra_rdp", label: "Hydra", sub: "-m rdp", x: 200, y: 180, r: 34, type: "op",
      desc: "Hydra: hydra -L users.txt -P passwords.txt rdp://target — Remote Desktop brute force.",
      src: "THC-Hydra" },
    { id: "rdp_credssp", label: "CredSSP", sub: "NLA + NTLM", x: 360, y: 180, r: 32, type: "protocol",
      desc: "RDP Network Level Authentication uses CredSSP (SPNEGO → NTLM/Kerberos) on TCP/3389.",
      src: "MS-CSSP; MS-RDPBCGR" },
    { id: "ev_4625_rdp", label: "Event 4625", sub: "Logon Type 10", x: 520, y: 180, r: 34, type: "detect",
      desc: "Event 4625 Logon Type 10 (RemoteInteractive): failed RDP logon attempts.",
      src: "Microsoft Event 4625" },

    // Row 3: SSH
    { id: "hydra_ssh", label: "Hydra", sub: "-m ssh", x: 200, y: 280, r: 34, type: "op",
      desc: "hydra -L users.txt -P passwords.txt ssh://target — SSH brute force.",
      src: "THC-Hydra" },
    { id: "medusa", label: "Medusa", sub: "-M ssh", x: 200, y: 340, r: 28, type: "op",
      desc: "Medusa -h target -U users.txt -P passwords.txt -M ssh — parallel SSH brute force.",
      src: "JoMo-Kun/Medusa" },
    { id: "ssh_auth", label: "SSH Auth", sub: "password method", x: 360, y: 280, r: 32, type: "protocol",
      desc: "SSH-USERAUTH password authentication on TCP/22.",
      src: "RFC 4252" },
    { id: "auth_log", label: "auth.log", sub: "Failed password", x: 520, y: 280, r: 36, type: "detect",
      desc: "Linux /var/log/auth.log: 'Failed password for <user> from <ip>'. PAM log entries.",
      src: "Linux syslog; PAM" },

    // Row 4: Web/LDAP
    { id: "burp", label: "Burp Intruder", sub: "/ ffuf", x: 200, y: 380, r: 34, type: "op",
      desc: "Burp Suite Intruder or ffuf for web-based login form brute force.",
      src: "PortSwigger; ffuf" },
    { id: "http_auth", label: "HTTP POST", sub: "Login form", x: 360, y: 380, r: 32, type: "protocol",
      desc: "HTTP/HTTPS POST to login endpoint with username/password pairs.",
      src: "RFC 7235; OWASP" },
    { id: "waf_log", label: "WAF / IDS", sub: "Rate anomaly", x: 520, y: 380, r: 34, type: "detect",
      desc: "Web Application Firewall or IDS detects rapid login attempts from single IP.",
      src: "ModSecurity; OWASP" },

    // ── Account Lockout ──
    { id: "lockout", label: "Account Lockout", sub: "After N fails", x: 700, y: 200, r: 38, type: "system",
      desc: "Account lockout policy: lock after N failed attempts (e.g., 5). DoS risk if weaponized.",
      src: "Microsoft AD; PAM faillock" },
    { id: "ev_4740", label: "Event 4740", sub: "Account Locked", x: 700, y: 100, r: 34, type: "detect",
      desc: "Event 4740: Account locked out. Correlate with 4625 events for source IP.",
      src: "Microsoft Event 4740" },

    // ── Success ──
    { id: "ev_4624", label: "Event 4624", sub: "Successful Logon", x: 700, y: 320, r: 36, type: "detect",
      desc: "Event 4624: Successful logon after series of failures = confirmed password guess.",
      src: "Microsoft Event 4624" },
    { id: "valid_creds", label: "Valid Credentials", x: 860, y: 200, r: 36, type: "artifact",
      desc: "Valid username:password pair obtained. Enables authenticated access.",
      src: "MITRE T1110.001" },
  ],

  edges: [
    // SMB path
    { f: "attacker", t: "crackmapexec" },
    { f: "crackmapexec", t: "smb_auth" },
    { f: "smb_auth", t: "ev_4625_smb" },
    // RDP path
    { f: "attacker", t: "hydra_rdp" },
    { f: "hydra_rdp", t: "rdp_credssp" },
    { f: "rdp_credssp", t: "ev_4625_rdp" },
    // SSH path
    { f: "attacker", t: "hydra_ssh" },
    { f: "attacker", t: "medusa" },
    { f: "hydra_ssh", t: "ssh_auth" },
    { f: "medusa", t: "ssh_auth" },
    { f: "ssh_auth", t: "auth_log" },
    // Web path
    { f: "attacker", t: "burp" },
    { f: "burp", t: "http_auth" },
    { f: "http_auth", t: "waf_log" },
    // Lockout
    { f: "ev_4625_smb", t: "lockout" },
    { f: "ev_4625_rdp", t: "lockout" },
    { f: "lockout", t: "ev_4740" },
    // Success
    { f: "ev_4625_smb", t: "ev_4624" },
    { f: "ev_4625_rdp", t: "ev_4624" },
    { f: "auth_log", t: "ev_4624" },
    { f: "ev_4624", t: "valid_creds" },
  ],
};

export default model;
