// T1056.003 — Web Portal Capture — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1056.003",
    name: "Web Portal Capture",
    tactic: "Credential Access",
    platform: "Web",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1300,
    svgHeight: 340,
    rows: [
      { label: "INJECT",   y: 80 },
      { label: "CLONE",    y: 200 },
    ],
  },

  nodes: [
    { id: "web_access", label: "Web Server", sub: "Compromised", x: 60, y: 130, r: 38, type: "entry",
      desc: "Attacker has write access to web server or application. Can modify login pages.",
      src: "MITRE ATT&CK T1056.003" },

    // Row 1: Inject into existing portal
    { id: "js_inject", label: "JS Injection", sub: "Login page", x: 220, y: 80, r: 36, type: "op",
      desc: "Inject JavaScript into legitimate login page to exfiltrate credentials on form submit.",
      src: "MITRE T1056.003; Magecart" },
    { id: "dom_api", label: "DOM API", sub: "addEventListener", x: 400, y: 80, r: 34, type: "api",
      desc: "document.addEventListener('submit') or .querySelector('#password').value — capture form input.",
      src: "Web DOM API" },
    { id: "xhr_exfil", label: "XMLHttpRequest", sub: "Beacon to C2", x: 560, y: 80, r: 34, type: "api",
      desc: "Send captured credentials to attacker C2 via XHR/fetch/navigator.sendBeacon().",
      src: "Web API" },
    { id: "c2_server", label: "C2 Server", sub: "Receives creds", x: 720, y: 80, r: 32, type: "artifact",
      desc: "Attacker's collection server receives username:password pairs.",
      src: "MITRE T1056.003" },

    // Row 2: Clone portal
    { id: "evilginx", label: "evilginx2", sub: "Reverse proxy", x: 220, y: 200, r: 38, type: "op",
      desc: "evilginx2: reverse proxy that sits between victim and real login portal. Captures credentials + session tokens.",
      src: "kgretzky/evilginx2" },
    { id: "dns_phish", label: "DNS / Phishing", sub: "Redirect to proxy", x: 400, y: 200, r: 34, type: "protocol",
      desc: "Phishing link or DNS hijack redirects user to evilginx proxy (mimics real site).",
      src: "MITRE T1566" },
    { id: "tls_intercept", label: "TLS Termination", sub: "Let's Encrypt cert", x: 560, y: 200, r: 36, type: "protocol",
      desc: "evilginx terminates TLS with valid cert, proxies to real server. User sees valid HTTPS.",
      src: "kgretzky/evilginx2" },
    { id: "session_token", label: "Session Token", sub: "Cookie capture", x: 720, y: 200, r: 36, type: "artifact",
      desc: "Captures session token/cookies AFTER MFA — bypasses MFA completely.",
      src: "kgretzky/evilginx2; T1539" },

    // ── Detection ──
    { id: "csp", label: "CSP Headers", sub: "Content Security Policy", x: 400, y: 280, r: 36, type: "detect",
      desc: "Content Security Policy restricts JS sources and XHR destinations. Prevents injection exfil.",
      src: "W3C CSP; OWASP" },
    { id: "sri", label: "SRI", sub: "Subresource Integrity", x: 560, y: 280, r: 30, type: "system",
      desc: "Subresource Integrity hashes detect modified JavaScript files.",
      src: "W3C SRI" },
    { id: "waf", label: "WAF", sub: "JS modification detect", x: 720, y: 280, r: 34, type: "detect",
      desc: "OPTIMAL: WAF or FIM detects modifications to login page files. Alert on unauthorized changes.",
      src: "AWS WAF; ModSecurity" },

    // ── Output ──
    { id: "creds", label: "User Credentials", x: 900, y: 140, r: 36, type: "artifact",
      desc: "Plaintext usernames, passwords, and session tokens for all users who logged in.",
      src: "MITRE T1056.003" },
  ],

  edges: [
    // JS injection
    { f: "web_access", t: "js_inject" },
    { f: "js_inject", t: "dom_api" },
    { f: "dom_api", t: "xhr_exfil" },
    { f: "xhr_exfil", t: "c2_server" },
    // Clone/proxy
    { f: "web_access", t: "evilginx" },
    { f: "evilginx", t: "dns_phish" },
    { f: "dns_phish", t: "tls_intercept" },
    { f: "tls_intercept", t: "session_token" },
    // Detection
    { f: "js_inject", t: "csp" },
    { f: "js_inject", t: "sri" },
    { f: "js_inject", t: "waf" },
    // Output
    { f: "c2_server", t: "creds" },
    { f: "session_token", t: "creds" },
  ],
};

export default model;
