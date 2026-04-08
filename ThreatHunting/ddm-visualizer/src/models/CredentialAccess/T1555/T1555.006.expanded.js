// T1555.006 — Cloud Secrets Management Stores — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1555.006",
    name: "Cloud Secrets Management Stores",
    tactic: "Credential Access",
    platform: "AWS, Azure, GCP",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 400,
    rows: [
      { label: "AWS",   y: 80 },
      { label: "AZURE", y: 200 },
      { label: "GCP",   y: 320 },
    ],
  },

  nodes: [
    { id: "cloud_creds", label: "Cloud IAM", sub: "Compromised identity", x: 60, y: 180, r: 38, type: "entry",
      desc: "Compromised IAM role/service principal/service account with secrets read permissions.",
      src: "MITRE ATT&CK T1555.006" },

    // Row 1: AWS Secrets Manager / SSM
    { id: "aws_cli", label: "aws secretsmanager", sub: "get-secret-value", x: 220, y: 80, r: 38, type: "op",
      desc: "aws secretsmanager get-secret-value --secret-id <name> — retrieves secret value.",
      src: "AWS CLI; MITRE T1555.006" },
    { id: "ssm_param", label: "aws ssm", sub: "get-parameter --with-decrypt", x: 220, y: 140, r: 34, type: "op",
      desc: "aws ssm get-parameter --name /prod/db/password --with-decryption",
      src: "AWS Systems Manager Parameter Store" },
    { id: "aws_api", label: "AWS API", sub: "HTTPS sigv4", x: 420, y: 80, r: 32, type: "protocol",
      desc: "AWS API call with SigV4 authentication to secretsmanager/ssm endpoints.",
      src: "AWS SigV4; HTTPS" },
    { id: "cloudtrail", label: "CloudTrail", sub: "GetSecretValue", x: 600, y: 80, r: 40, type: "detect",
      desc: "OPTIMAL: CloudTrail logs GetSecretValue, GetParameter API calls. Alert on unusual principals/frequency.",
      src: "AWS CloudTrail" },

    // Row 2: Azure Key Vault
    { id: "az_kv", label: "az keyvault", sub: "secret show", x: 220, y: 200, r: 36, type: "op",
      desc: "az keyvault secret show --vault-name vault --name secret — retrieves Azure Key Vault secret.",
      src: "Azure CLI; MITRE T1555.006" },
    { id: "kv_list", label: "az keyvault", sub: "secret list", x: 220, y: 260, r: 30, type: "op",
      desc: "Enumerate all secrets: az keyvault secret list --vault-name vault",
      src: "Azure CLI" },
    { id: "azure_api", label: "Azure REST API", sub: "HTTPS OAuth2", x: 420, y: 200, r: 34, type: "protocol",
      desc: "REST API to vault.azure.net with OAuth2 bearer token.",
      src: "Microsoft Azure Key Vault REST API" },
    { id: "az_diag", label: "AzureDiagnostics", sub: "SecretGet", x: 600, y: 200, r: 40, type: "detect",
      desc: "OPTIMAL: Key Vault diagnostic logs: SecretGet, SecretList operations. Azure Monitor alerts.",
      src: "Azure Monitor; Key Vault Diagnostics" },
    { id: "az_rbac", label: "RBAC", sub: "Access policies", x: 600, y: 260, r: 30, type: "system",
      desc: "Key Vault RBAC or Access Policies control who can read secrets. Principle of least privilege.",
      src: "Azure Key Vault RBAC" },

    // Row 3: GCP Secret Manager
    { id: "gcloud_sm", label: "gcloud secrets", sub: "versions access", x: 220, y: 320, r: 36, type: "op",
      desc: "gcloud secrets versions access latest --secret=<name> — retrieves secret value.",
      src: "Google Cloud CLI; MITRE T1555.006" },
    { id: "gcp_api", label: "GCP REST API", sub: "HTTPS OAuth2", x: 420, y: 320, r: 34, type: "protocol",
      desc: "REST API to secretmanager.googleapis.com with service account credentials.",
      src: "Google Cloud Secret Manager API" },
    { id: "gcp_audit", label: "Cloud Audit Log", sub: "AccessSecretVersion", x: 600, y: 320, r: 40, type: "detect",
      desc: "OPTIMAL: GCP Audit Log: AccessSecretVersion events. Alert on unusual service accounts.",
      src: "Google Cloud Audit Logging" },

    // ── Output ──
    { id: "db_creds", label: "Database Creds", x: 800, y: 100, r: 32, type: "artifact",
      desc: "Database connection strings, passwords, API keys retrieved from secrets store.",
      src: "MITRE T1555.006" },
    { id: "api_keys", label: "API Keys", sub: "Service tokens", x: 800, y: 200, r: 32, type: "artifact",
      desc: "Third-party API keys, service tokens, webhook secrets.",
      src: "MITRE T1555.006" },
    { id: "tls_keys", label: "TLS Private Keys", x: 800, y: 300, r: 32, type: "artifact",
      desc: "TLS/SSL certificate private keys stored in secrets manager.",
      src: "MITRE T1555.006" },
  ],

  edges: [
    // AWS
    { f: "cloud_creds", t: "aws_cli" },
    { f: "cloud_creds", t: "ssm_param" },
    { f: "aws_cli", t: "aws_api" },
    { f: "ssm_param", t: "aws_api" },
    { f: "aws_api", t: "cloudtrail" },
    // Azure
    { f: "cloud_creds", t: "az_kv" },
    { f: "cloud_creds", t: "kv_list" },
    { f: "az_kv", t: "azure_api" },
    { f: "kv_list", t: "azure_api" },
    { f: "azure_api", t: "az_diag" },
    { f: "azure_api", t: "az_rbac" },
    // GCP
    { f: "cloud_creds", t: "gcloud_sm" },
    { f: "gcloud_sm", t: "gcp_api" },
    { f: "gcp_api", t: "gcp_audit" },
    // Output
    { f: "cloudtrail", t: "db_creds" },
    { f: "az_diag", t: "api_keys" },
    { f: "gcp_audit", t: "tls_keys" },
  ],
};

export default model;
