// T1552.007 — Container API — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.007", name: "Container API", tactic: "Credential Access", platform: "Kubernetes, Docker", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 340, rows: [{ label: "K8S SECRETS", y: 80 }, { label: "DOCKER", y: 180 }, { label: "ENV VARS", y: 280 }] },
  nodes: [
    { id: "container_access", label: "Container Access", sub: "Pod/container exec", x: 60, y: 160, r: 38, type: "entry", desc: "Code execution inside container or access to Kubernetes/Docker API.", src: "MITRE ATT&CK T1552.007" },
    { id: "k8s_secrets", label: "kubectl get secrets", x: 220, y: 80, r: 38, type: "op", desc: "kubectl get secrets -o yaml — reads Kubernetes Secrets (base64-encoded, not encrypted).", src: "Kubernetes; MITRE T1552.007" },
    { id: "k8s_api", label: "K8s API Server", sub: "/api/v1/secrets", x: 440, y: 80, r: 34, type: "api", desc: "Kubernetes API: GET /api/v1/namespaces/{ns}/secrets. ServiceAccount token from pod.", src: "Kubernetes API" },
    { id: "etcd_read", label: "etcd Direct", sub: "Port 2379", x: 440, y: 140, r: 30, type: "protocol", desc: "Direct etcd access (if exposed): etcdctl get /registry/secrets/ — all secrets unencrypted.", src: "etcd; Kubernetes" },
    { id: "docker_inspect", label: "docker inspect", sub: "Container env", x: 220, y: 180, r: 36, type: "op", desc: "docker inspect <container> — reveals environment variables including secrets.", src: "Docker; MITRE T1552.007" },
    { id: "docker_sock", label: "/var/run/docker.sock", x: 440, y: 180, r: 34, type: "api", desc: "Docker socket access from within container → escape + credential access.", src: "Docker" },
    { id: "env_vars", label: "/proc/1/environ", sub: "or env command", x: 220, y: 280, r: 36, type: "op", desc: "Read /proc/1/environ or env command to dump all environment variables in container.", src: "Linux proc; MITRE T1552.007" },
    { id: "sa_token", label: "ServiceAccount", sub: "Token (JWT)", x: 440, y: 280, r: 34, type: "artifact", desc: "Kubernetes ServiceAccount token at /var/run/secrets/kubernetes.io/serviceaccount/token.", src: "Kubernetes" },
    { id: "k8s_audit", label: "K8s Audit Log", sub: "Secret access", x: 640, y: 80, r: 40, type: "detect", desc: "OPTIMAL: Kubernetes audit log: verb=get/list resource=secrets. Alert on unexpected ServiceAccounts.", src: "Kubernetes Audit Logging" },
    { id: "falco", label: "Falco", sub: "Runtime monitoring", x: 640, y: 200, r: 36, type: "detect", desc: "Falco detects: reading SA tokens, env dumps, docker socket access from pods.", src: "Falco; Sysdig" },
    { id: "secrets_data", label: "Secrets Data", sub: "DB creds, API keys", x: 840, y: 160, r: 38, type: "artifact", desc: "Kubernetes Secrets: database passwords, TLS certs, API keys, Docker registry credentials.", src: "MITRE T1552.007" },
  ],
  edges: [
    { f: "container_access", t: "k8s_secrets" }, { f: "container_access", t: "docker_inspect" }, { f: "container_access", t: "env_vars" },
    { f: "k8s_secrets", t: "k8s_api" }, { f: "k8s_api", t: "etcd_read" },
    { f: "docker_inspect", t: "docker_sock" },
    { f: "env_vars", t: "sa_token" },
    { f: "k8s_api", t: "k8s_audit" }, { f: "docker_sock", t: "falco" }, { f: "env_vars", t: "falco" },
    { f: "k8s_api", t: "secrets_data" }, { f: "docker_sock", t: "secrets_data" }, { f: "sa_token", t: "secrets_data" },
  ],
};
export default model;
