// T1552.005 — Cloud Instance Metadata API — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.005",
    name: "Cloud Instance Metadata API",
    tactic: "Credential Access",
    platform: "Cloud (AWS, Azure, GCP)",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "METADATA API",  x: 80 },
      { label: "CREDENTIAL PATH",x: 270 },
      { label: "DETECTION",      x: 480 },
      { label: "OUTCOME",        x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "imds", label: "IMDS Endpoint", sub: "169.254.169.254", x: 80, y: 130, r: 40, type: "source",
      tags: ["169.254.169.254", "IMDS v1/v2", "Link-local", "Metadata API"],
      telemetry: [],
      api: "curl http://169.254.169.254/latest/meta-data/ — instance metadata service endpoint",
      artifact: "HTTP request to 169.254.169.254 from instance",
      desc: "Cloud instance metadata service (IMDS) at 169.254.169.254 provides instance information and temporary credentials. Available on AWS EC2, Azure VMs, and GCP Compute instances. Accessible from any process on the instance without authentication (IMDSv1) or with token (IMDSv2).",
      src: "MITRE ATT&CK T1552.005; AWS/Azure/GCP documentation" },

    { id: "ssrf", label: "SSRF Attack", sub: "Remote exploit", x: 80, y: 330, r: 34, type: "source",
      tags: ["SSRF to IMDS", "Server-side request forgery", "Capital One breach"],
      telemetry: [],
      api: "SSRF vulnerability in web app exploited to reach IMDS: http://169.254.169.254/...",
      artifact: "SSRF payload targeting 169.254.169.254 · web app making metadata requests",
      desc: "Server-Side Request Forgery (SSRF) allows external attackers to query IMDS through a vulnerable web application. The Capital One breach (2019) used SSRF to extract AWS IAM role credentials from the metadata service. IMDSv2 (token-required) mitigates SSRF-based access.",
      src: "Capital One breach analysis; MITRE T1552.005" },

    { id: "cred_path", label: "IAM Creds", sub: "Temporary tokens", x: 270, y: 200, r: 40, type: "source",
      tags: ["IAM role credentials", "STS token", "Managed identity", "OAuth token"],
      telemetry: [],
      api: "AWS: /iam/security-credentials/<role>; Azure: /metadata/identity/oauth2/token; GCP: /computeMetadata/v1/instance/service-accounts/default/token",
      artifact: "Temporary access key + secret key + session token retrieved from metadata",
      desc: "IMDS credential paths: AWS — /latest/meta-data/iam/security-credentials/<role-name> returns AccessKeyId, SecretAccessKey, Token; Azure — /metadata/identity/oauth2/token returns managed identity OAuth token; GCP — /computeMetadata/v1/instance/service-accounts/default/token returns access_token. Credentials are temporary but typically valid for hours.",
      src: "MITRE T1552.005; Cloud provider IMDS documentation" },

    { id: "ev_detect", label: "IMDS Monitor", sub: "Network + cloud", x: 480, y: 200, r: 50, type: "detect",
      tags: ["VPC flow logs", "IMDS hop limit", "CloudTrail", "IMDSv2 enforcement"],
      telemetry: ["CloudTrail", "VPC Flow Logs"],
      api: "Network monitoring for IMDS access + CloudTrail for credential usage from unexpected sources",
      artifact: "OPTIMAL: Unexpected IMDS requests · CloudTrail: IAM role creds used from external IP · IMDSv2 not enforced",
      desc: "OPTIMAL DETECTION NODE. (1) AWS: enforce IMDSv2 (requires token, blocks SSRF). Set metadata hop limit to 1 (blocks container escapes). (2) CloudTrail: IAM role credentials used from IP addresses outside the instance's VPC — indicates stolen credentials. (3) VPC flow logs: monitor traffic to 169.254.169.254. (4) Azure: restrict managed identity token scope, monitor identity usage. (5) PREVENTION: IMDSv2, minimal IAM role permissions, no IMDS for containers.",
      src: "MITRE T1552.005; AWS IMDS security; Azure managed identity best practices" },

    { id: "cloud_access", label: "Cloud Access", sub: "Role permissions", x: 730, y: 200, r: 40, type: "source",
      tags: ["S3 access", "EC2 control", "Azure resources", "GCP API"],
      telemetry: [],
      api: "Temporary cloud credentials provide access to whatever the instance role permits",
      artifact: "Cloud API access with instance role permissions: S3, EC2, database, secrets",
      desc: "Stolen IMDS credentials provide access to cloud resources permitted by the instance's IAM role/managed identity. Common permissions: S3 bucket access, EC2 management, database access, secrets manager, Lambda invocations. Over-permissioned roles dramatically increase impact.",
      src: "MITRE T1552.005" },
  ],

  edges: [
    { f: "imds", t: "cred_path" },
    { f: "ssrf", t: "cred_path" },
    { f: "cred_path", t: "ev_detect" },
    { f: "ev_detect", t: "cloud_access" },
  ],
};

export default model;
