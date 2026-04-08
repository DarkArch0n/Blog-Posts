// T1056.003 — Web Portal Capture — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1056.003",
    name: "Web Portal Capture",
    tactic: "Credential Access",
    platform: "Windows, Linux",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "WEB SERVICE",  x: 80 },
      { label: "INJECTION",   x: 270 },
      { label: "DETECTION",   x: 480 },
      { label: "OUTCOME",     x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "owa", label: "OWA / Portal", sub: "Web login page", x: 80, y: 130, r: 36, type: "source",
      tags: ["OWA", "Exchange", "VPN portal", "Web login"],
      telemetry: [],
      api: "Outlook Web Access, VPN portals, or internal web apps with login forms",
      artifact: "Internet-facing web login portal compromised",
      desc: "Attacker compromises an internet-facing web login portal (OWA, Citrix, VPN, internal web apps). These portals handle credential input for authentication. The attacker modifies the login page to capture credentials as they pass through.",
      src: "MITRE ATT&CK T1056.003" },

    { id: "cms", label: "CMS / Web App", sub: "Login form", x: 80, y: 300, r: 34, type: "source",
      tags: ["WordPress", "Internal app", "SSO login page"],
      telemetry: [],
      api: "Compromised CMS or web application with authentication forms",
      artifact: "Web application login page modified to capture credentials",
      desc: "Any web application with a login form can be modified to capture credentials: WordPress admin panels, internal web applications, SSO login pages, or cloud portals. The modification captures credentials before or during the legitimate authentication process.",
      src: "MITRE T1056.003" },

    { id: "inject_js", label: "JS Injection", sub: "Form capture", x: 270, y: 130, r: 38, type: "source",
      tags: ["JavaScript hook", "XMLHttpRequest", "Form onsubmit handler", "Webshell"],
      telemetry: [],
      api: "Inject JavaScript: document.forms[0].onsubmit = function() { exfil(this.password.value); }",
      artifact: "Modified login page · injected JavaScript · exfiltration endpoint",
      desc: "Attacker injects JavaScript into the login page that captures form submissions. Methods: modify the onsubmit handler, add an event listener to the password field, or hook XMLHttpRequest/fetch. Credentials are exfiltrated to an attacker-controlled endpoint while normal auth continues transparently.",
      src: "MITRE T1056.003" },

    { id: "mod_backend", label: "Backend Mod", sub: "Server-side", x: 270, y: 300, r: 36, type: "source",
      tags: ["Modified auth handler", "Logging plaintext", "Webshell credential logger"],
      telemetry: [],
      api: "Modify server-side authentication handler to log plaintext credentials before hashing",
      artifact: "Modified auth code · credential log file · webshell-based capture",
      desc: "Server-side modification: attacker modifies the authentication handler to log plaintext credentials before they are hashed/validated. More stealthy than client-side JS injection. Can be embedded in a webshell. The credential log persists on the server for later retrieval.",
      src: "MITRE T1056.003" },

    { id: "ev_detect", label: "File Integrity", sub: "Web monitoring", x: 480, y: 220, r: 50, type: "detect",
      tags: ["File integrity monitoring", "Page hash change", "JS injection detection", "Web WAF"],
      telemetry: [],
      api: "FIM on web login pages + CSP headers + JavaScript integrity checking",
      artifact: "OPTIMAL: File integrity change on login page · new JS includes · outbound data to unknown endpoint",
      desc: "OPTIMAL DETECTION NODE. (1) File integrity monitoring (FIM): detect changes to login page files (HTML, JS, PHP, ASPX). (2) Content Security Policy (CSP): restrict JS execution to known sources. (3) Subresource Integrity (SRI): verify included script hashes. (4) Network monitoring: outbound data from web server to unknown endpoints. (5) Regular page hash comparison against known-good baseline.",
      src: "MITRE T1056.003; OWASP; File Integrity Monitoring" },

    { id: "creds_captured", label: "All User Creds", sub: "Who logs in", x: 730, y: 220, r: 40, type: "source",
      tags: ["All authenticating users", "Plaintext passwords", "Continuous harvest"],
      telemetry: [],
      api: "Every user who authenticates through the compromised portal has credentials captured",
      artifact: "Credentials for all users who log in · potentially hundreds of accounts · ongoing",
      desc: "Every user who authenticates through the compromised login portal has their credentials captured in plaintext. For a high-traffic portal (OWA, VPN), this can yield hundreds or thousands of unique credentials over time. Captures both passwords and any MFA codes entered on the page.",
      src: "MITRE T1056.003" },
  ],

  edges: [
    { f: "owa", t: "inject_js" },
    { f: "owa", t: "mod_backend" },
    { f: "cms", t: "inject_js" },
    { f: "cms", t: "mod_backend" },
    { f: "inject_js", t: "ev_detect" },
    { f: "mod_backend", t: "ev_detect" },
    { f: "ev_detect", t: "creds_captured" },
  ],
};

export default model;
