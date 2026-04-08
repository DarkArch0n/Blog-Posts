// T1110.004 — Credential Stuffing — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1110.004",
    name: "Credential Stuffing",
    tactic: "Credential Access",
    platform: "Cloud, Web, Windows",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 380,
    rows: [
      { label: "BREACH DATA",  y: 80 },
      { label: "O365/CLOUD",   y: 180 },
      { label: "WEB APPS",     y: 280 },
    ],
  },

  nodes: [
    { id: "breach_db", label: "Breach Database", sub: "user:pass pairs", x: 60, y: 150, r: 40, type: "entry",
      desc: "Credentials from data breaches (Collection #1-5, BreachCompilation, etc.). Users reuse passwords across sites.",
      src: "MITRE ATT&CK T1110.004" },

    // Row 1: Breach data prep
    { id: "combo_list", label: "Combo Lists", sub: "email:password", x: 220, y: 80, r: 34, type: "op",
      desc: "Combine breach databases into email:password format. Filter by target domain (@corp.com).",
      src: "MITRE T1110.004" },
    { id: "dehash", label: "Deduplication", sub: "& credential wash", x: 380, y: 80, r: 32, type: "op",
      desc: "Deduplicate, filter for target org emails, remove known-invalid entries.",
      src: "MITRE T1110.004" },

    // Row 2: O365/Cloud
    { id: "msolspray", label: "MSOLSpray", sub: "Stuffing mode", x: 220, y: 180, r: 34, type: "op",
      desc: "MSOLSpray / CredMaster in credential-stuffing mode: unique password per user from breach data.",
      src: "dafthack/MSOLSpray" },
    { id: "o365_auth", label: "OAuth2 Token", sub: "login.microsoftonline.com", x: 400, y: 180, r: 38, type: "protocol",
      desc: "ROPC token request per user with their specific breached password.",
      src: "Microsoft Identity Platform" },
    { id: "aad_log", label: "Azure Sign-in", sub: "ResultType 50126/0", x: 580, y: 180, r: 38, type: "detect",
      desc: "OPTIMAL: Azure Sign-in Logs. 50126=bad password, 0=success. Look for IP/UserAgent patterns.",
      src: "Microsoft Entra Sign-in Logs" },

    // Row 3: Web apps
    { id: "sentry_mba", label: "SentryMBA", sub: "/ OpenBullet", x: 220, y: 280, r: 34, type: "op",
      desc: "Automated credential stuffing tools: SentryMBA, OpenBullet, Storm. Proxy rotation built-in.",
      src: "OWASP Credential Stuffing" },
    { id: "http_post", label: "HTTPS POST", sub: "Login endpoint", x: 400, y: 280, r: 34, type: "protocol",
      desc: "HTTP(S) login with unique user:pass per request. Proxy rotation evades IP blocking.",
      src: "OWASP" },
    { id: "waf_detect", label: "WAF / Bot Detect", sub: "Rate + fingerprint", x: 580, y: 280, r: 38, type: "detect",
      desc: "WAF/bot detection: device fingerprinting, CAPTCHA, behavioral analysis, Cloudflare Bot Mgmt.",
      src: "Cloudflare; AWS WAF; Shape" },

    // ── Evasion ──
    { id: "proxy_rotate", label: "Proxy Rotation", sub: "Residential IPs", x: 400, y: 350, r: 32, type: "op",
      desc: "Rotate through residential proxies/SOCKS to evade IP-based rate limiting.",
      src: "MITRE T1110.004" },

    // ── MFA ──
    { id: "mfa_check", label: "MFA Challenge", sub: "Blocks stuffing", x: 740, y: 180, r: 36, type: "system",
      desc: "MFA prevents credential stuffing even with valid passwords. Best mitigation.",
      src: "Microsoft; OWASP" },
    { id: "mfa_fatigue", label: "MFA Fatigue", sub: "T1621", x: 740, y: 280, r: 30, type: "op",
      desc: "If push-based MFA, attacker may attempt MFA fatigue (repeated push notifications).",
      src: "MITRE T1621" },

    // ── Output ──
    { id: "valid_creds", label: "Valid Credentials", x: 900, y: 140, r: 36, type: "artifact",
      desc: "Working username:password pairs confirmed against target. Password reuse = success.",
      src: "MITRE T1110.004" },
    { id: "mailbox", label: "Mailbox Access", sub: "OWA/IMAP", x: 900, y: 260, r: 32, type: "artifact",
      desc: "Email access via OWA/IMAP enables BEC, further credential harvesting, data exfiltration.",
      src: "MITRE T1114" },
  ],

  edges: [
    // Breach prep
    { f: "breach_db", t: "combo_list" },
    { f: "combo_list", t: "dehash" },
    // O365 path
    { f: "dehash", t: "msolspray" },
    { f: "msolspray", t: "o365_auth" },
    { f: "o365_auth", t: "aad_log" },
    { f: "o365_auth", t: "mfa_check" },
    // Web path
    { f: "dehash", t: "sentry_mba" },
    { f: "sentry_mba", t: "http_post" },
    { f: "sentry_mba", t: "proxy_rotate" },
    { f: "http_post", t: "waf_detect" },
    // MFA
    { f: "mfa_check", t: "mfa_fatigue" },
    { f: "mfa_check", t: "valid_creds" },
    // Output
    { f: "aad_log", t: "valid_creds" },
    { f: "waf_detect", t: "valid_creds" },
    { f: "valid_creds", t: "mailbox" },
  ],
};

export default model;
