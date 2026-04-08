// T1555.006 — Cloud Secrets Management Stores — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1555.006",
    name: "Cloud Secrets Management Stores",
    tactic: "Credential Access",
    platform: "Cloud (AWS, Azure, GCP)",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 440,
    columns: [
      { label: "SECRET STORE", x: 80 },
      { label: "ACCESS METHOD", x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "aws_sm", label: "AWS Secrets Mgr", sub: "/ SSM Param", x: 80, y: 110, r: 34, type: "source",
      tags: ["AWS Secrets Manager", "SSM Parameter Store", "SecureString"],
      telemetry: ["CloudTrail"],
      api: "aws secretsmanager get-secret-value · aws ssm get-parameter --with-decryption",
      artifact: "CloudTrail: GetSecretValue / GetParameter API calls",
      desc: "AWS Secrets Manager and Systems Manager Parameter Store (SecureString) store application secrets, database credentials, and API keys. Encrypted with KMS. An attacker with IAM permissions (secretsmanager:GetSecretValue or ssm:GetParameter) can retrieve all secrets.",
      src: "MITRE T1555.006; AWS documentation" },

    { id: "azure_kv", label: "Azure Key Vault", sub: "Secrets/Keys", x: 80, y: 260, r: 34, type: "source",
      tags: ["Azure Key Vault", "Secrets", "Keys", "Certificates"],
      telemetry: ["Azure Activity"],
      api: "az keyvault secret show --vault-name <vault> --name <secret>",
      artifact: "Azure Activity Log: Microsoft.KeyVault/vaults/secrets/read",
      desc: "Azure Key Vault stores secrets, encryption keys, and certificates. Access controlled by RBAC and access policies. An attacker with Key Vault Reader/Contributor or explicit Get secret permissions can retrieve stored secrets via CLI, PowerShell, or REST API.",
      src: "MITRE T1555.006; Azure Key Vault documentation" },

    { id: "gcp_sm", label: "GCP Secret Mgr", sub: "Secrets", x: 80, y: 400, r: 34, type: "source",
      tags: ["GCP Secret Manager", "gcloud secrets", "IAM-controlled"],
      telemetry: ["Cloud Audit"],
      api: "gcloud secrets versions access latest --secret=<name>",
      artifact: "Cloud Audit Log: secretmanager.versions.access",
      desc: "GCP Secret Manager stores secrets with IAM-controlled access. roles/secretmanager.secretAccessor grants read access. An attacker with this role on a secret can retrieve its value via gcloud CLI or REST API.",
      src: "MITRE T1555.006; GCP Secret Manager documentation" },

    { id: "api_access", label: "API / CLI", sub: "Retrieve secrets", x: 270, y: 180, r: 38, type: "source",
      tags: ["CLI tool", "REST API", "SDK call", "Compromised credentials"],
      telemetry: ["CloudTrail", "Azure Activity"],
      api: "Attacker uses compromised cloud credentials to call secret retrieval APIs",
      artifact: "API calls from unusual IP/identity · bulk secret enumeration",
      desc: "Attacker with compromised cloud credentials (IAM keys, service principal, service account) calls the secrets management API. May enumerate all secrets first (list-secrets) then retrieve each one (get-secret-value). Bulk access to secrets from a single identity is highly suspicious.",
      src: "MITRE T1555.006" },

    { id: "metadata", label: "Instance Metadata", sub: "Credential chain", x: 270, y: 360, r: 34, type: "source",
      tags: ["IMDS", "Instance role", "169.254.169.254", "Assumed role"],
      telemetry: [],
      api: "curl http://169.254.169.254/latest/meta-data/iam/ → assume instance role → access secrets",
      artifact: "Secrets accessed using instance profile / managed identity credentials",
      desc: "On compromised cloud instances, the attacker can leverage Instance Metadata Service (IMDS) to assume the instance's IAM role. If the role has secrets access permissions, the attacker retrieves secrets without needing separate credentials. IMDSv2 (token-required) adds a layer but doesn't prevent this from compromised instances.",
      src: "AWS IMDS; Azure IMDS; MITRE T1555.006" },

    { id: "ev_detect", label: "Cloud Audit", sub: "Secret access logs", x: 480, y: 230, r: 50, type: "detect",
      tags: ["CloudTrail", "Azure Activity Log", "GCP Audit Log", "Anomalous access"],
      telemetry: ["CloudTrail", "Azure Activity", "GCP Audit"],
      api: "Cloud audit logs for secret access — alert on unusual identity, IP, volume, or timing",
      artifact: "OPTIMAL: CloudTrail GetSecretValue · Azure KeyVault audit · GCP SecretManager audit · anomalous access pattern",
      desc: "OPTIMAL DETECTION NODE. (1) AWS CloudTrail: GetSecretValue, ListSecrets events — alert on unusual caller identity, source IP, or access volume. (2) Azure Key Vault diagnostic logs: SecretGet operations from unexpected principals. (3) GCP Cloud Audit: secretmanager.versions.access. (4) Anomaly: identity accessing secrets it has never accessed before, bulk enumeration, access from unusual IP. (5) PREVENTION: Least-privilege IAM, VPC endpoints, IP-based access policies.",
      src: "MITRE T1555.006; AWS CloudTrail; Azure Diagnostic Logs; GCP Cloud Audit" },

    { id: "secrets_out", label: "App Secrets", sub: "Exposed", x: 730, y: 230, r: 40, type: "source",
      tags: ["Database credentials", "API keys", "Service account keys", "Encryption keys"],
      telemetry: [],
      api: "Retrieved secrets: DB passwords, API keys, service account credentials, encryption keys",
      artifact: "Database access → data exfiltration · API keys → lateral movement · encryption keys → data decryption",
      desc: "Cloud secrets stores typically contain: database connection strings/passwords, third-party API keys, service account credentials, encryption keys, TLS certificates, and application-specific secrets. Compromising these enables data access, lateral movement to connected services, and potential multi-cloud compromise.",
      src: "MITRE T1555.006" },
  ],

  edges: [
    { f: "aws_sm", t: "api_access" },
    { f: "azure_kv", t: "api_access" },
    { f: "gcp_sm", t: "api_access" },
    { f: "aws_sm", t: "metadata" },
    { f: "api_access", t: "ev_detect" },
    { f: "metadata", t: "ev_detect" },
    { f: "ev_detect", t: "secrets_out" },
  ],
};

export default model;
