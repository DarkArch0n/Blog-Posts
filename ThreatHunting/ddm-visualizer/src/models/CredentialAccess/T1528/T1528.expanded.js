// T1528 — Steal Application Access Token — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1528", name: "Steal Application Access Token", tactic: "Credential Access", platform: "SaaS, Azure AD, Google, AWS", version: "v1.0" },
  layout: { svgWidth: 1400, svgHeight: 380, rows: [{ label: "OAUTH CONSENT", y: 80 }, { label: "TOKEN THEFT", y: 180 }, { label: "CLOUD CLI", y: 300 }] },
  nodes: [
    { id: "user_session", label: "User Session", sub: "Authenticated", x: 60, y: 180, r: 38, type: "entry", desc: "Compromised user session, phishing link, or malicious app registration.", src: "MITRE ATT&CK T1528" },
    { id: "illicit_consent", label: "Illicit Consent", sub: "OAuth app grant", x: 240, y: 80, r: 38, type: "op", desc: "Register malicious OAuth app → phish user into granting consent → receive access token.", src: "MITRE T1528; Microsoft" },
    { id: "oauth_flow", label: "OAuth2 Auth Code", sub: "/authorize → /token", x: 440, y: 80, r: 34, type: "protocol", desc: "OAuth2 Authorization Code flow: user consent → auth code → exchange for access+refresh tokens.", src: "OAuth 2.0; RFC 6749" },
    { id: "refresh_token", label: "Refresh Token", sub: "Long-lived", x: 640, y: 80, r: 36, type: "artifact", desc: "OAuth refresh token: long-lived, persists through password resets. Enables ongoing access.", src: "RFC 6749" },
    { id: "token_file", label: "Token Files", sub: ".azure/ .aws/ .gcloud/", x: 240, y: 180, r: 36, type: "op", desc: "Steal cached tokens from CLI config: ~/.azure/accessTokens.json, ~/.aws/credentials, ~/.config/gcloud/.", src: "MITRE T1528" },
    { id: "browser_token", label: "Browser Token", sub: "localStorage/cookie", x: 440, y: 180, r: 34, type: "op", desc: "Extract OAuth tokens from browser localStorage, sessionStorage, or cookies.", src: "MITRE T1528" },
    { id: "graph_api", label: "Graph API", sub: "Mail, files, etc.", x: 640, y: 180, r: 34, type: "api", desc: "Use stolen token to call Microsoft Graph: read mail, files, Teams messages.", src: "Microsoft Graph API" },
    { id: "az_cli", label: "az cli / gcloud", sub: "Cached auth", x: 240, y: 300, r: 34, type: "op", desc: "Azure CLI caches tokens in plaintext JSON. gcloud stores in ~/.config/gcloud/credentials.db.", src: "Azure CLI; gcloud" },
    { id: "aws_env", label: "AWS Env Vars", sub: "AWS_SESSION_TOKEN", x: 440, y: 300, r: 34, type: "op", desc: "AWS session credentials in environment variables or ~/.aws/credentials file.", src: "AWS CLI" },
    { id: "consent_log", label: "Consent Audit", sub: "AAD audit log", x: 640, y: 300, r: 36, type: "detect", desc: "OPTIMAL: Azure AD audit log: OAuth consent grants. Alert on high-privilege scopes (Mail.Read, Files.ReadWrite).", src: "Azure AD Audit; Microsoft Sentinel" },
    { id: "token_anomaly", label: "Token Anomaly", sub: "IP/geo mismatch", x: 840, y: 80, r: 36, type: "detect", desc: "Token used from unexpected IP/geo. Multiple token uses from different locations simultaneously.", src: "UEBA; CAP" },
    { id: "api_access", label: "API Access", sub: "As user/app", x: 1040, y: 180, r: 42, type: "artifact", desc: "Full API access: mail, files, cloud resources. Persists through password changes.", src: "MITRE T1528" },
  ],
  edges: [
    { f: "user_session", t: "illicit_consent" }, { f: "user_session", t: "token_file" }, { f: "user_session", t: "az_cli" },
    { f: "illicit_consent", t: "oauth_flow" }, { f: "oauth_flow", t: "refresh_token" },
    { f: "token_file", t: "browser_token" }, { f: "browser_token", t: "graph_api" },
    { f: "az_cli", t: "aws_env" },
    { f: "refresh_token", t: "api_access" }, { f: "graph_api", t: "api_access" }, { f: "aws_env", t: "api_access" },
    { f: "illicit_consent", t: "consent_log" }, { f: "refresh_token", t: "token_anomaly" },
  ],
};
export default model;
