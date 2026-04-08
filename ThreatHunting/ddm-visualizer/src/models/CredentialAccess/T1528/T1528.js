// T1528 — Steal Application Access Token — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1528",
    name: "Steal Application Access Token",
    tactic: "Credential Access",
    platform: "Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "TOKEN SOURCE",  x: 80  },
      { label: "THEFT METHOD",  x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
    annotations: [
      { text: "Tokens bypass MFA — valid until revoked", x: 480, y: 410, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "oauth_consent", label: "OAuth Consent", sub: "Malicious app", x: 80, y: 100, r: 36, type: "source",
      tags: ["OAuth consent phishing", "Malicious app registration", "Illicit consent grant"],
      telemetry: ["Azure AD audit"],
      api: "Malicious OAuth app requests consent → user grants access → app receives tokens",
      artifact: "Azure AD: consent grant event · app registration · permissions requested",
      desc: "Attacker creates a malicious OAuth application (Azure AD app registration) that requests excessive permissions (Mail.Read, Files.ReadWrite). User is directed to consent URL and approves. The malicious app receives access and refresh tokens that bypass MFA and persist until revoked.",
      src: "MITRE ATT&CK T1528; Microsoft illicit consent grant; NOBELIUM campaign" },

    { id: "token_file", label: "Token from File", sub: "Config/cache", x: 80, y: 260, r: 34, type: "source",
      tags: [".azure/accessTokens.json", "AWS credentials", "gcloud config"],
      telemetry: ["Sysmon 11"],
      api: "Tokens stored in config files: ~/.azure/accessTokens.json, ~/.aws/credentials, ~/.config/gcloud",
      artifact: "File access to token cache files · cloud CLI credential stores",
      desc: "Cloud CLIs (az, aws, gcloud) cache access tokens and credentials in local files. An attacker with file system access can steal these tokens. Azure CLI: ~/.azure/accessTokens.json. AWS CLI: ~/.aws/credentials. Google Cloud: ~/.config/gcloud/credentials.db.",
      src: "MITRE T1528; Cloud CLI documentation" },

    { id: "token_env", label: "Token from Env", sub: "Environment var", x: 80, y: 400, r: 34, type: "source",
      tags: ["AZURE_ACCESS_TOKEN", "AWS_SESSION_TOKEN", "CI/CD secrets"],
      telemetry: [],
      api: "Tokens in environment variables or CI/CD pipeline secrets (GitHub Actions, Jenkins)",
      artifact: "Token exposed in environment · CI/CD logs · build artifacts",
      desc: "Access tokens may be exposed in environment variables, CI/CD pipeline configurations (GitHub Actions secrets, Jenkins credentials), or build logs. Container workloads often use service account tokens mounted at /var/run/secrets/kubernetes.io/serviceaccount/token.",
      src: "MITRE T1528" },

    { id: "intercept", label: "Token Intercept", sub: "MitM/redirect", x: 270, y: 130, r: 36, type: "source",
      tags: ["OAuth redirect hijack", "Authorization code intercept", "Proxy capture"],
      telemetry: [],
      api: "Intercept OAuth callback URL to steal authorization code → exchange for tokens",
      artifact: "Modified redirect_uri · authorization code captured · token exchange",
      desc: "Attacker modifies the OAuth redirect_uri to point to their server, intercepting the authorization code. Exchanges the code for access/refresh tokens. Also possible via MitM proxy capturing the OAuth callback or via open redirect vulnerabilities in the application.",
      src: "MITRE T1528; OAuth 2.0 security considerations RFC 6819" },

    { id: "token_steal", label: "Extract Token", sub: "From process/memory", x: 270, y: 310, r: 36, type: "source",
      tags: ["Process memory", "Browser storage", "Mobile app storage"],
      telemetry: [],
      api: "Extract tokens from browser localStorage/sessionStorage, process memory, or mobile app data",
      artifact: "Browser developer tools access · process memory read · mobile data extraction",
      desc: "Tokens stored in browser localStorage/sessionStorage, application memory, or mobile app data directories can be extracted by an attacker with local access. XSS vulnerabilities may allow JavaScript-based token theft from browser storage.",
      src: "MITRE T1528" },

    { id: "ev_detect", label: "Token Anomaly", sub: "Usage patterns", x: 480, y: 230, r: 50, type: "detect",
      tags: ["Unusual app consent", "Token from new IP", "Excessive permissions", "Refresh token abuse"],
      telemetry: ["Azure AD audit", "Azure AD sign-in"],
      api: "Monitor consent grants + token usage location/pattern + excessive permission requests",
      artifact: "OPTIMAL: New app consent with high-priv permissions · token use from anomalous IP · refresh token replay",
      desc: "OPTIMAL DETECTION NODE. (1) Consent monitoring: alert on new OAuth app consents, especially with high-privilege permissions (Mail.Read, Files.ReadWrite.All). (2) Token usage anomaly: access from unusual IP/geo compared to user's normal pattern. (3) Refresh token replay: same refresh token used from multiple IPs. (4) PREVENTION: Restrict user consent to verified publishers only (Azure AD). Admin consent workflow. Conditional Access token protection.",
      src: "MITRE T1528; Azure AD app consent policies; Microsoft CAE" },

    { id: "api_access", label: "API Access", sub: "As application", x: 730, y: 140, r: 38, type: "source",
      tags: ["Graph API", "AWS API", "GCP API", "Full scope access"],
      telemetry: [],
      api: "Use stolen token to call APIs: Microsoft Graph, AWS, GCP — within granted scopes",
      artifact: "API calls using stolen token · data access within granted permissions",
      desc: "Stolen access token enables API calls within the granted scopes. Microsoft Graph: read email, enumerate users, access files. AWS: describe/list/get/put operations per IAM policy. Token acts as the user (delegated) or application (app-only) until revoked.",
      src: "MITRE T1528" },

    { id: "persist_token", label: "Refresh Token", sub: "Long-lived access", x: 730, y: 340, r: 36, type: "source",
      tags: ["Refresh token", "90-day validity", "Re-issue access tokens", "Persistent access"],
      telemetry: [],
      api: "Refresh token generates new access tokens — persists for up to 90 days",
      artifact: "Refresh token used to silently acquire new access tokens · long-term access",
      desc: "OAuth refresh tokens persist for extended periods (Azure AD: up to 90 days). The attacker uses the stolen refresh token to silently acquire new access tokens without re-authenticating. Provides persistent access until the refresh token is explicitly revoked via Revoke-AzureADUserAllRefreshToken.",
      src: "MITRE T1528; Azure AD token lifetimes" },
  ],

  edges: [
    { f: "oauth_consent", t: "ev_detect" },
    { f: "token_file", t: "token_steal" },
    { f: "token_env", t: "token_steal" },
    { f: "oauth_consent", t: "intercept" },
    { f: "intercept", t: "ev_detect" },
    { f: "token_steal", t: "ev_detect" },
    { f: "ev_detect", t: "api_access" },
    { f: "ev_detect", t: "persist_token" },
    { f: "persist_token", t: "api_access" },
  ],
};

export default model;
