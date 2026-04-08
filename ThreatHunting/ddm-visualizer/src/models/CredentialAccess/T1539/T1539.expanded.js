// T1539 — Steal Web Session Cookie — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access", platform: "Windows, Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 380, rows: [{ label: "BROWSER DB", y: 80 }, { label: "EVILGINX", y: 180 }, { label: "MALWARE", y: 300 }] },
  nodes: [
    { id: "endpoint", label: "Endpoint Access", sub: "Code execution", x: 60, y: 180, r: 38, type: "entry", desc: "Code execution on endpoint or real-time phishing proxy position.", src: "MITRE ATT&CK T1539" },
    { id: "chrome_db", label: "Chrome Cookies", sub: "Cookies SQLite DB", x: 240, y: 80, r: 36, type: "op", desc: "Read Chrome cookie DB: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies.", src: "MITRE T1539; Chrome" },
    { id: "dpapi_decrypt", label: "DPAPI Decrypt", sub: "CryptUnprotectData", x: 440, y: 80, r: 34, type: "api", desc: "Chrome encrypts cookies with DPAPI (Windows). Decrypt with user context or DPAPI masterkey.", src: "Microsoft DPAPI; Chrome" },
    { id: "app_bound", label: "App-Bound Encrypt", sub: "Chrome 127+", x: 440, y: 140, r: 30, type: "system", desc: "Chrome 127+: App-bound encryption ties cookies to Chrome process. Harder to steal.", src: "Chrome Security" },
    { id: "evilginx", label: "EvilGinx2", sub: "Proxy phishing", x: 240, y: 180, r: 38, type: "op", desc: "EvilGinx2: reverse proxy that captures session cookies post-authentication in real-time.", src: "EvilGinx2; kgretzky" },
    { id: "tls_proxy", label: "TLS Termination", sub: "HTTPS proxy", x: 440, y: 180, r: 32, type: "protocol", desc: "Real-time TLS termination and proxy of target site. User sees valid HTTPS.", src: "EvilGinx2" },
    { id: "session_cookie", label: "Session Cookie", sub: "Post-MFA", x: 640, y: 180, r: 38, type: "artifact", desc: "Captured session cookie: post-authentication, post-MFA. Bypasses all auth controls.", src: "MITRE T1539" },
    { id: "infostealer", label: "Infostealer", sub: "Raccoon/RedLine", x: 240, y: 300, r: 36, type: "op", desc: "Infostealer malware (Raccoon, RedLine, Vidar): automated cookie extraction from all browsers.", src: "Infostealers; MITRE T1539" },
    { id: "cookie_inject", label: "Cookie Import", sub: "EditThisCookie", x: 440, y: 300, r: 34, type: "op", desc: "Import stolen cookies into attacker's browser using EditThisCookie or browser DevTools.", src: "Browser DevTools" },
    { id: "token_binding", label: "Device-Bound", sub: "DBSC / Token Binding", x: 640, y: 300, r: 34, type: "system", desc: "FUTURE: Device-Bound Session Credentials bind cookies to device TPM. Prevents export.", src: "Chrome DBSC proposal" },
    { id: "sysmon_file", label: "Sysmon 11", sub: "Cookie DB access", x: 640, y: 80, r: 34, type: "detect", desc: "Sysmon EID 11: non-browser process accessing Cookie/Login Data files.", src: "Sysmon documentation" },
    { id: "sign_in_anomaly", label: "Sign-in Anomaly", sub: "New device/IP", x: 840, y: 180, r: 38, type: "detect", desc: "OPTIMAL: Cookie replay from new device/IP/user-agent → impossible travel, device mismatch.", src: "Azure AD; UEBA" },
    { id: "web_access", label: "Web App Access", sub: "Authenticated session", x: 1040, y: 180, r: 40, type: "artifact", desc: "Full authenticated web session: email, cloud console, SaaS apps. Bypasses MFA.", src: "MITRE T1539" },
  ],
  edges: [
    { f: "endpoint", t: "chrome_db" }, { f: "endpoint", t: "evilginx" }, { f: "endpoint", t: "infostealer" },
    { f: "chrome_db", t: "dpapi_decrypt" }, { f: "dpapi_decrypt", t: "app_bound" },
    { f: "evilginx", t: "tls_proxy" }, { f: "tls_proxy", t: "session_cookie" },
    { f: "dpapi_decrypt", t: "session_cookie" }, { f: "infostealer", t: "session_cookie" },
    { f: "session_cookie", t: "cookie_inject" }, { f: "cookie_inject", t: "web_access" },
    { f: "cookie_inject", t: "token_binding" },
    { f: "chrome_db", t: "sysmon_file" }, { f: "session_cookie", t: "sign_in_anomaly" },
  ],
};
export default model;
