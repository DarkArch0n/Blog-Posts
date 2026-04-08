// T1110.003 — Password Spraying — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1110.003",
    name: "Password Spraying",
    tactic: "Credential Access",
    platform: "Windows, Linux, Cloud",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 480,
    rows: [
      { label: "SMB/KRB",  y: 80 },
      { label: "LDAP",     y: 180 },
      { label: "O365",     y: 280 },
      { label: "OWA/ADFS", y: 400 },
    ],
  },

  nodes: [
    { id: "attacker", label: "User List", sub: "+ 1 password", x: 60, y: 200, r: 38, type: "entry",
      desc: "Enumerated usernames + single common password tried against all users. Avoids lockout by limiting attempts per account.",
      src: "MITRE ATT&CK T1110.003" },

    // Row 1: SMB/Kerberos on-prem
    { id: "kerbrute", label: "kerbrute", sub: "passwordspray", x: 200, y: 80, r: 34, type: "op",
      desc: "kerbrute passwordspray — tests password via Kerberos AS-REQ pre-auth. No Windows event on failure.",
      src: "ropnop/kerbrute" },
    { id: "as_req", label: "AS-REQ", sub: "port 88", x: 360, y: 80, r: 30, type: "protocol",
      desc: "Kerberos AS-REQ with PA-ENC-TIMESTAMP. KDC_ERR_PREAUTH_FAILED if wrong password.",
      src: "RFC 4120" },
    { id: "cme_smb", label: "CrackMapExec", sub: "smb spray", x: 200, y: 140, r: 32, type: "op",
      desc: "cme smb dc -u users.txt -p 'Summer2024!' --continue-on-success",
      src: "byt3bl33d3r/CrackMapExec" },
    { id: "smb_ntlm", label: "SMB NTLM", sub: "TCP 445", x: 360, y: 140, r: 28, type: "protocol",
      desc: "SMB NTLMSSP authentication on TCP/445.",
      src: "MS-SMB2; MS-NLMP" },
    { id: "ev_4771", label: "Event 4771", sub: "Pre-auth Failed", x: 520, y: 80, r: 36, type: "detect",
      desc: "OPTIMAL: Event 4771 on DC: Kerberos Pre-Authentication Failed. Status 0x18 = bad password.",
      src: "Microsoft Event 4771" },

    // Row 2: LDAP
    { id: "ldap_spray", label: "Spray-AD", sub: "LDAP bind", x: 200, y: 180, r: 34, type: "op",
      desc: "LDAP simple bind spray: test credentials via LDAP TCP/389 or LDAPS TCP/636.",
      src: "Various; DomainPasswordSpray" },
    { id: "ldap_bind", label: "LDAP Bind", sub: "Simple/NTLM", x: 360, y: 180, r: 30, type: "protocol",
      desc: "LDAP simple bind or NTLM bind authentication attempt.",
      src: "RFC 4511; MS-ADTS" },
    { id: "ev_4625", label: "Event 4625", sub: "Failed Logon", x: 520, y: 180, r: 34, type: "detect",
      desc: "Event 4625 with Logon Type 3/8: many unique usernames, same source IP, few failures per user.",
      src: "Microsoft Event 4625" },

    // Row 3: O365/Azure AD
    { id: "msolspray", label: "MSOLSpray", sub: "Graph/Legacy", x: 200, y: 280, r: 34, type: "op",
      desc: "MSOLSpray: spray against Microsoft 365 login endpoints (Graph API, legacy auth).",
      src: "dafthack/MSOLSpray" },
    { id: "trevorspray", label: "TREVORspray", sub: "SOCKS rotation", x: 200, y: 340, r: 30, type: "op",
      desc: "TREVORspray: O365 spray with SOCKS proxy rotation to evade IP-based blocking.",
      src: "blacklanternsecurity/TREVORspray" },
    { id: "o365_auth", label: "HTTPS POST", sub: "login.microsoftonline.com", x: 400, y: 280, r: 40, type: "protocol",
      desc: "OAuth2/ROPC token request to https://login.microsoftonline.com/common/oauth2/token",
      src: "Microsoft Identity Platform" },
    { id: "aad_signin", label: "Azure Sign-in", sub: "Log", x: 580, y: 280, r: 38, type: "detect",
      desc: "OPTIMAL: Azure AD Sign-in Logs show failed attempts. Look for ResultType 50126 (bad password).",
      src: "Microsoft Entra Sign-in Logs" },
    { id: "smart_lockout", label: "Smart Lockout", sub: "Azure AD", x: 580, y: 360, r: 32, type: "system",
      desc: "Azure AD Smart Lockout: ML-based, distinguishes familiar vs unfamiliar locations.",
      src: "Microsoft Entra Smart Lockout" },

    // Row 4: OWA/ADFS
    { id: "ruler", label: "Ruler", sub: "OWA spray", x: 200, y: 400, r: 30, type: "op",
      desc: "Ruler brute: spray against OWA (Outlook Web App) or EWS endpoints.",
      src: "sensepost/ruler" },
    { id: "owa_auth", label: "OWA HTTPS", sub: "Forms/NTLM", x: 360, y: 400, r: 30, type: "protocol",
      desc: "OWA authentication via Forms-based or NTLM on HTTPS.",
      src: "Microsoft Exchange" },
    { id: "adfs_log", label: "ADFS Audit", sub: "Event 411", x: 520, y: 400, r: 34, type: "detect",
      desc: "ADFS Event 411: Token issued / 516: Failed authentication. ADFS is often spray target.",
      src: "Microsoft ADFS" },

    // ── Lockout avoidance ──
    { id: "lockout_policy", label: "Lockout Policy", sub: "Query via LDAP", x: 700, y: 130, r: 34, type: "op",
      desc: "Attackers query lockout policy first: net accounts /domain or LDAP ms-DS-Password-Settings.",
      src: "Microsoft; PowerView" },

    // ── Success ──
    { id: "ev_4624", label: "Event 4624", sub: "After spraying", x: 750, y: 250, r: 36, type: "detect",
      desc: "Successful logon after spray campaign. Correlate with 4625/4771 spike from same source.",
      src: "Microsoft Event 4624" },
    { id: "valid_creds", label: "Valid Credentials", x: 900, y: 250, r: 40, type: "artifact",
      desc: "One or more valid domain credentials. Often service accounts or users with common passwords.",
      src: "MITRE T1110.003" },
  ],

  edges: [
    // SMB/Kerberos
    { f: "attacker", t: "kerbrute" },
    { f: "attacker", t: "cme_smb" },
    { f: "kerbrute", t: "as_req" },
    { f: "cme_smb", t: "smb_ntlm" },
    { f: "as_req", t: "ev_4771" },
    { f: "smb_ntlm", t: "ev_4625" },
    // LDAP
    { f: "attacker", t: "ldap_spray" },
    { f: "ldap_spray", t: "ldap_bind" },
    { f: "ldap_bind", t: "ev_4625" },
    // O365
    { f: "attacker", t: "msolspray" },
    { f: "attacker", t: "trevorspray" },
    { f: "msolspray", t: "o365_auth" },
    { f: "trevorspray", t: "o365_auth" },
    { f: "o365_auth", t: "aad_signin" },
    { f: "o365_auth", t: "smart_lockout" },
    // OWA/ADFS
    { f: "attacker", t: "ruler" },
    { f: "ruler", t: "owa_auth" },
    { f: "owa_auth", t: "adfs_log" },
    // Lockout
    { f: "attacker", t: "lockout_policy" },
    // Success
    { f: "ev_4771", t: "ev_4624" },
    { f: "ev_4625", t: "ev_4624" },
    { f: "aad_signin", t: "ev_4624" },
    { f: "ev_4624", t: "valid_creds" },
  ],
};

export default model;
