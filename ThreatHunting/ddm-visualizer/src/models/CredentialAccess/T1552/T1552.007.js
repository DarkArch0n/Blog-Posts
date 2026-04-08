// T1552.007 — Container API — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.007",
    name: "Container API",
    tactic: "Credential Access",
    platform: "Containers",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "API SOURCE",   x: 80 },
      { label: "CREDENTIAL",   x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "k8s_api", label: "Kubernetes API", sub: "Service account", x: 80, y: 130, r: 38, type: "source",
      tags: ["K8s API server", "ServiceAccount token", "/var/run/secrets/kubernetes.io"],
      telemetry: ["K8s audit"],
      api: "ServiceAccount token at /var/run/secrets/kubernetes.io/serviceaccount/token",
      artifact: "ServiceAccount JWT token auto-mounted in pod · bearer token for K8s API",
      desc: "Every Kubernetes pod gets a ServiceAccount token auto-mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. This JWT token authenticates to the Kubernetes API server. If the ServiceAccount has excessive RBAC permissions, the token can be used to access secrets, create pods, or escalate privileges.",
      src: "MITRE ATT&CK T1552.007; Kubernetes security" },

    { id: "docker_api", label: "Docker API", sub: "Socket/TCP", x: 80, y: 330, r: 34, type: "source",
      tags: ["Docker socket", "/var/run/docker.sock", "Docker TCP API", "2375/2376"],
      telemetry: [],
      api: "Docker socket (/var/run/docker.sock) or TCP API (port 2375/2376) — container management",
      artifact: "Docker socket mounted in container · Docker API accessible",
      desc: "Docker daemon API accessible via Unix socket (/var/run/docker.sock — if mounted in container) or TCP (port 2375 unauthenticated, 2376 TLS). Provides full container management: inspect containers (env vars with secrets), create privileged containers (host escape), access networks and volumes.",
      src: "MITRE T1552.007" },

    { id: "secrets", label: "Container Secrets", sub: "Env vars / mounts", x: 270, y: 200, r: 42, type: "source",
      tags: ["K8s Secrets", "Env variables", "Docker secrets", "ConfigMaps"],
      telemetry: ["K8s audit"],
      api: "kubectl get secrets · docker inspect <container> (Env) · cat /run/secrets/<name>",
      artifact: "K8s Secrets (base64), Docker env vars, mounted secret files",
      desc: "Container secrets accessible via: Kubernetes Secrets (base64 encoded, not encrypted by default), environment variables in container spec (docker inspect reveals them), Docker secrets (/run/secrets/), ConfigMaps with sensitive data. From compromised pod: kubectl get secrets -o json reveals all namespace secrets if RBAC allows.",
      src: "MITRE T1552.007; Kubernetes documentation" },

    { id: "ev_detect", label: "API Audit", sub: "K8s + container", x: 480, y: 200, r: 50, type: "detect",
      tags: ["K8s audit logs", "Secret access logs", "Docker socket monitor", "RBAC"],
      telemetry: ["K8s audit"],
      api: "Kubernetes audit logs for secret access + Docker socket access monitoring",
      artifact: "OPTIMAL: K8s audit 'get secrets' from pod SA · docker.sock access · env var secrets · unusual API calls",
      desc: "OPTIMAL DETECTION NODE. (1) Kubernetes audit logs: ServiceAccount accessing secrets, configmaps, or other sensitive resources. (2) Pod RBAC: alert on ServiceAccounts with broad permissions (list secrets, create pods). (3) Docker socket: monitor for container processes accessing /var/run/docker.sock. (4) PREVENTION: Disable automountServiceAccountToken, use minimal RBAC, encrypt K8s secrets (KMS), never mount Docker socket in containers.",
      src: "MITRE T1552.007; Kubernetes RBAC; CIS Kubernetes Benchmark" },

    { id: "cred_access", label: "Cloud/App Creds", sub: "From secrets", x: 730, y: 200, r: 40, type: "source",
      tags: ["DB credentials", "Cloud API keys", "TLS certs", "Registry creds"],
      telemetry: [],
      api: "Recovered credentials: database passwords, cloud API keys, TLS certs, registry credentials",
      artifact: "Credentials from container secrets → database, cloud, registry access",
      desc: "Container secrets typically contain: database connection strings, cloud provider credentials (AWS_SECRET_ACCESS_KEY), TLS certificates, container registry credentials (docker login), API keys, and inter-service authentication tokens. Enables lateral movement to databases, cloud infrastructure, and other services.",
      src: "MITRE T1552.007" },
  ],

  edges: [
    { f: "k8s_api", t: "secrets" },
    { f: "docker_api", t: "secrets" },
    { f: "secrets", t: "ev_detect" },
    { f: "ev_detect", t: "cred_access" },
  ],
};

export default model;
