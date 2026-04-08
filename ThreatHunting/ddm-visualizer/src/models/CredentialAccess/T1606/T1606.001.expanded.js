// T1606.001 — Web Cookies — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1606.001", name: "Web Cookies", tactic: "Credential Access", platform: "Windows, Linux, macOS, SaaS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 340, rows: [{ label: "COOKIE FORGE", y: 80 }, { label: "GOLDEN SAML", y: 180 }, { label: "PASS COOKIE", y: 280 }] },
  nodes: [
    { id: "signing_key", label: "Signing Key", sub: "Token signing cert", x: 60, y: 130, r: 38, type: "entry", desc: "Access to web application signing key or token-signing certificate (e.g., AD FS cert).", src: "MITRE ATT&CK T1606.001" },
    { id: "forge_cookie", label: "Forge Cookie", sub: "Session token", x: 240, y: 80, r: 38, type: "op", desc: "Forge web application session cookies using stolen signing key or decrypted machine key.", src: "MITRE T1606.001" },
    { id: "aspnet_machkey", label: "ASP.NET MachineKey", sub: "web.config", x: 440, y: 80, r: 34, type: "api", desc: "ASP.NET: steal machineKey from web.config → forge Forms Authentication cookies.", src: "ASP.NET; MITRE T1606.001" },
    { id: "jwt_forge", label: "JWT Forge", sub: "HS256/RS256", x: 440, y: 140, r: 32, type: "op", desc: "Forge JWT tokens with stolen HMAC secret or RSA private key. Set any claims.", src: "JWT; MITRE T1606.001" },
    { id: "golden_saml", label: "Golden SAML", sub: "AD FS token-signing", x: 240, y: 180, r: 40, type: "op", desc: "Steal AD FS token-signing certificate → forge SAML assertions for any user to any relying party.", src: "CyberArk; SolarWinds/SUNBURST" },
    { id: "adfs_export", label: "AD FS DKM Key", sub: "from AD object", x: 440, y: 180, r: 34, type: "api", desc: "AD FS stores token-signing cert encrypted with DKM key in AD. DCSync or AD object read to extract.", src: "AD FS; AADInternals" },
    { id: "saml_token", label: "SAML Assertion", sub: "Any user, any RP", x: 640, y: 180, r: 36, type: "artifact", desc: "Forged SAML assertion: any user identity, any relying party (O365, AWS, etc.).", src: "SAML 2.0; CyberArk" },
    { id: "pass_cookie", label: "Pass-the-Cookie", sub: "Inject into browser", x: 240, y: 280, r: 36, type: "op", desc: "Inject forged session cookie into browser → bypass authentication entirely.", src: "MITRE T1606.001" },
    { id: "adfs_audit", label: "AD FS Audit", sub: "Event 510/1007", x: 640, y: 80, r: 36, type: "detect", desc: "AD FS Events 510/1007: token issuance. Compare against AD FS logs — forged tokens won't appear.", src: "Microsoft AD FS Audit" },
    { id: "sentinel", label: "Token Anomaly", sub: "IP/geo mismatch", x: 640, y: 280, r: 36, type: "detect", desc: "OPTIMAL: Detect token use from unexpected IP/geo. Token lifetime anomalies.", src: "Microsoft Sentinel; Azure AD" },
    { id: "full_access", label: "Full App Access", sub: "Any user identity", x: 860, y: 180, r: 40, type: "artifact", desc: "Persistent access to web applications as any user. No password needed, bypasses MFA.", src: "MITRE T1606.001" },
  ],
  edges: [
    { f: "signing_key", t: "forge_cookie" }, { f: "signing_key", t: "golden_saml" },
    { f: "forge_cookie", t: "aspnet_machkey" }, { f: "forge_cookie", t: "jwt_forge" },
    { f: "golden_saml", t: "adfs_export" }, { f: "adfs_export", t: "saml_token" },
    { f: "jwt_forge", t: "pass_cookie" }, { f: "aspnet_machkey", t: "pass_cookie" },
    { f: "saml_token", t: "pass_cookie" },
    { f: "pass_cookie", t: "full_access" }, { f: "saml_token", t: "full_access" },
    { f: "adfs_export", t: "adfs_audit" }, { f: "pass_cookie", t: "sentinel" },
  ],
};
export default model;
