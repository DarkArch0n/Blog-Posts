// T1606.001 — Web Cookies — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1606.001",
    name: "Web Cookies",
    tactic: "Credential Access",
    platform: "Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "PREREQUISITE",  x: 80 },
      { label: "FORGE METHOD", x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "signing_key", label: "Signing Key", sub: "Secret stolen", x: 80, y: 200, r: 40, type: "source",
      tags: ["Cookie signing secret", "JWT secret", "Session key material"],
      telemetry: [],
      api: "Application's cookie signing key / JWT secret / session management key material",
      artifact: "Signing key extracted from app config, source code, environment, or memory",
      desc: "Forging web cookies requires the application's cookie signing key or JWT secret. Sources: application configuration files, environment variables, source code repositories, memory dump of the application process, or key management service compromise. With the key, the attacker can create any session cookie.",
      src: "MITRE ATT&CK T1606.001" },

    { id: "forge_cookie", label: "Forge Cookie", sub: "Arbitrary session", x: 270, y: 120, r: 38, type: "source",
      tags: ["HMAC forge", "JWT forgery", "Admin session", "Any user identity"],
      telemetry: [],
      api: "Forge HMAC-signed session cookie or JWT with arbitrary claims (user=admin, role=admin)",
      artifact: "Forged cookie/JWT with attacker-chosen identity and permissions",
      desc: "With the signing key, the attacker creates session cookies or JWTs with arbitrary claims: any username, admin role, extended expiration. The forged cookie is cryptographically valid — the application cannot distinguish it from a legitimately issued token.",
      src: "MITRE T1606.001" },

    { id: "golden_saml", label: "Golden Cookie", sub: "Like Golden Ticket", x: 270, y: 310, r: 36, type: "source",
      tags: ["Golden cookie", "Universal session", "Persistent access", "Any identity"],
      telemetry: [],
      api: "Forged cookie acts as 'golden ticket' for the web application — any identity, any permission",
      artifact: "Forged session valid until signing key is rotated · any identity accessible",
      desc: "A forged web cookie is the web application equivalent of a Golden Ticket — the attacker can impersonate any user with any permissions. Valid until the signing key is rotated. The attacker can forge cookies for any user at any time, providing persistent access to the application.",
      src: "MITRE T1606.001" },

    { id: "ev_detect", label: "Session Anomaly", sub: "Usage patterns", x: 480, y: 200, r: 50, type: "detect",
      tags: ["No login event", "Session without auth", "Impossible parameters", "Cookie age"],
      telemetry: [],
      api: "Detect sessions without corresponding authentication events + anomalous session parameters",
      artifact: "OPTIMAL: Session active with no login event · impossible session creation time · anomalous claims",
      desc: "OPTIMAL DETECTION NODE. (1) Session without authentication: active session cookie with no corresponding login event in application logs. (2) Session parameter anomalies: creation time in the past, unusual expiry, claims inconsistent with user's actual permissions. (3) Multiple simultaneous sessions for one user from different IPs. (4) PREVENTION: Rotate signing keys regularly, bind sessions to client attributes (IP, fingerprint), implement session revocation.",
      src: "MITRE T1606.001; OWASP Session Management" },

    { id: "access", label: "App Access", sub: "As any user", x: 730, y: 200, r: 40, type: "source",
      tags: ["Admin access", "Any user impersonation", "Data exfiltration"],
      telemetry: [],
      api: "Full application access as any user identity — bypasses all authentication",
      artifact: "Application access with forged identity · data access · admin operations",
      desc: "Forged session cookie provides full access to the web application as any user. The attacker can access admin panels, read/modify data, impersonate users, and exfiltrate information. No authentication is needed — the forged cookie IS the authenticated session.",
      src: "MITRE T1606.001" },
  ],

  edges: [
    { f: "signing_key", t: "forge_cookie" },
    { f: "signing_key", t: "golden_saml" },
    { f: "forge_cookie", t: "ev_detect" },
    { f: "golden_saml", t: "ev_detect" },
    { f: "ev_detect", t: "access" },
  ],
};

export default model;
