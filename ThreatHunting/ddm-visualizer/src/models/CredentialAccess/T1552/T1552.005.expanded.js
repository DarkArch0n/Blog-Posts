// T1552.005 — Cloud Instance Metadata API — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.005", name: "Cloud Instance Metadata API", tactic: "Credential Access", platform: "AWS, Azure, GCP", version: "v1.0" },
  layout: { svgWidth: 1400, svgHeight: 340, rows: [{ label: "AWS IMDS", y: 80 }, { label: "AZURE IMDS", y: 180 }, { label: "GCP METADATA", y: 280 }] },
  nodes: [
    { id: "ssrf_or_exec", label: "SSRF / Code Exec", sub: "On cloud instance", x: 60, y: 170, r: 38, type: "entry", desc: "SSRF vulnerability or code execution on cloud compute instance to reach metadata endpoint.", src: "MITRE ATT&CK T1552.005" },
    { id: "aws_imds", label: "curl 169.254.169.254", sub: "/iam/security-credentials/", x: 240, y: 80, r: 40, type: "op", desc: "AWS IMDSv1: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role> — returns temp creds.", src: "AWS IMDS; MITRE T1552.005" },
    { id: "imdsv2_token", label: "IMDSv2 Token", sub: "PUT /token", x: 470, y: 80, r: 30, type: "protocol", desc: "IMDSv2 requires PUT with X-aws-ec2-metadata-token-ttl header first. Blocks some SSRF.", src: "AWS IMDSv2" },
    { id: "aws_creds", label: "AWS Temp Creds", sub: "AccessKey/Secret/Token", x: 650, y: 80, r: 38, type: "artifact", desc: "Temporary IAM role credentials: AccessKeyId, SecretAccessKey, Token. Valid for hours.", src: "AWS STS" },
    { id: "azure_imds", label: "curl 169.254.169.254", sub: "/metadata/identity/oauth2/token", x: 240, y: 180, r: 40, type: "op", desc: "Azure: curl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/'", src: "Azure IMDS" },
    { id: "azure_token", label: "Azure Token", sub: "Bearer JWT", x: 650, y: 180, r: 36, type: "artifact", desc: "Azure Managed Identity OAuth2 access token (JWT). Used to call ARM/Graph APIs.", src: "Azure Managed Identity" },
    { id: "gcp_metadata", label: "curl metadata.google", sub: "/computeMetadata/v1/", x: 240, y: 280, r: 40, type: "op", desc: "GCP: curl -H 'Metadata-Flavor:Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", src: "GCP Metadata; MITRE T1552.005" },
    { id: "gcp_token", label: "GCP Token", sub: "OAuth2 access_token", x: 650, y: 280, r: 36, type: "artifact", desc: "GCP service account OAuth2 access token for API access.", src: "Google Cloud" },
    { id: "cloudtrail", label: "CloudTrail", sub: "AssumeRole from instance", x: 850, y: 80, r: 36, type: "detect", desc: "OPTIMAL: CloudTrail: API calls from instance credentials outside expected patterns.", src: "AWS CloudTrail" },
    { id: "vpc_flow", label: "VPC Flow Logs", sub: "169.254.169.254 access", x: 470, y: 180, r: 32, type: "detect", desc: "Network logs showing metadata endpoint access from web application processes.", src: "AWS VPC Flow; Azure NSG" },
    { id: "imdsv2_enforce", label: "IMDSv2 Enforce", x: 470, y: 280, r: 30, type: "system", desc: "Best mitigation: enforce IMDSv2 (AWS), restrict metadata access (GCP/Azure).", src: "AWS; GCP; Azure" },
    { id: "cloud_access", label: "Cloud API Access", x: 1050, y: 180, r: 40, type: "artifact", desc: "Access to cloud APIs with instance role permissions: S3, EC2, IAM, etc.", src: "MITRE T1552.005" },
  ],
  edges: [
    { f: "ssrf_or_exec", t: "aws_imds" }, { f: "ssrf_or_exec", t: "azure_imds" }, { f: "ssrf_or_exec", t: "gcp_metadata" },
    { f: "aws_imds", t: "imdsv2_token" }, { f: "imdsv2_token", t: "aws_creds" },
    { f: "azure_imds", t: "azure_token" }, { f: "gcp_metadata", t: "gcp_token" },
    { f: "aws_creds", t: "cloudtrail" }, { f: "aws_creds", t: "cloud_access" },
    { f: "azure_token", t: "cloud_access" }, { f: "gcp_token", t: "cloud_access" },
    { f: "azure_imds", t: "vpc_flow" }, { f: "gcp_metadata", t: "imdsv2_enforce" },
  ],
};
export default model;
