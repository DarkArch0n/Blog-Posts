// T1552.004 — Private Keys — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1552.004",
    name: "Private Keys",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 460,
    columns: [
      { label: "KEY SOURCE",   x: 80 },
      { label: "SEARCH",       x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "ssh_keys", label: "SSH Keys", sub: "~/.ssh/", x: 80, y: 100, r: 36, type: "source",
      tags: ["id_rsa", "id_ed25519", "~/.ssh/", "authorized_keys"],
      telemetry: ["auditd"],
      api: "~/.ssh/id_rsa, ~/.ssh/id_ed25519 — SSH private keys for remote access",
      artifact: "SSH private key files in user home directories · authorized_keys for context",
      desc: "SSH private keys stored in ~/.ssh/ (Linux/macOS) or %USERPROFILE%\\.ssh\\ (Windows). Common filenames: id_rsa, id_ed25519, id_ecdsa. May be passwordless (no passphrase). The corresponding authorized_keys file shows which hosts accept the key.",
      src: "MITRE ATT&CK T1552.004" },

    { id: "tls_keys", label: "TLS/SSL Keys", sub: "Server certs", x: 80, y: 250, r: 34, type: "source",
      tags: [".pem", ".pfx", ".key", "PKCS#12", "Certificate store"],
      telemetry: [],
      api: "TLS/SSL private keys: .pem, .key, .pfx, .p12 files on web servers and in certificate stores",
      artifact: "Private key files for HTTPS certificates · code signing keys",
      desc: "TLS private keys for web servers (Apache ssl.key, Nginx privkey.pem), code signing certificates (.pfx/.p12), email signing certificates (S/MIME private keys), and API mTLS client certificates. Often found in /etc/ssl/private/, /etc/nginx/, Apache conf directories.",
      src: "MITRE T1552.004" },

    { id: "cloud_keys", label: "Cloud Keys", sub: "API/service keys", x: 80, y: 400, r: 34, type: "source",
      tags: ["AWS key pair .pem", "GCP service account JSON", "Azure SP cert"],
      telemetry: [],
      api: "Cloud private keys: AWS EC2 .pem key pairs, GCP service account JSON keys, Azure SP certs",
      artifact: "Cloud provider key files enabling infrastructure access",
      desc: "Cloud-specific private keys: AWS EC2 key pairs (.pem) for SSH, GCP service account JSON key files, Azure Service Principal certificate keys, Kubernetes TLS secrets, and cloud API signing keys.",
      src: "MITRE T1552.004" },

    { id: "key_search", label: "Key Search", sub: "Find/enumerate", x: 270, y: 240, r: 40, type: "source",
      tags: ["find *.pem", "dir /s *.pfx", "grep BEGIN PRIVATE", "certutil -store"],
      telemetry: ["Sysmon 1"],
      api: "find / -name '*.pem' -o -name '*.key' · dir /s *.pfx · grep -r 'BEGIN.*PRIVATE KEY'",
      artifact: "Sysmon 1: file search for key extensions · grep for PEM headers",
      desc: "Attacker searches for private key files: find/dir searching for .pem, .key, .pfx, .p12, .ppk extensions. Grep for PEM headers ('BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY'). Windows: certutil -store, Export-PfxCertificate. May also search source code repos and config management.",
      src: "MITRE T1552.004" },

    { id: "ev_detect", label: "Key Access", sub: "File monitoring", x: 480, y: 240, r: 50, type: "detect",
      tags: ["SSH dir access", "Key file read", "PEM search", "Cert export"],
      telemetry: ["Sysmon 1", "auditd"],
      api: "Monitor access to ~/.ssh/ directories + key file reads + cert export commands",
      artifact: "OPTIMAL: auditd watch on ~/.ssh/ · Sysmon 1 findstr/grep for private keys · certutil -exportPFX · non-owner key access",
      desc: "OPTIMAL DETECTION NODE. (1) auditd: -w /home/*/.ssh/ -p r -k ssh_key_access. (2) Sysmon EID 1: findstr/grep/find commands searching for key file extensions. (3) certutil -exportPFX or Export-PfxCertificate usage. (4) Non-owner access to SSH key directories. (5) PREVENTION: Passphrase-protect all private keys, use ssh-agent, use certificate-based auth, store keys in HSMs, implement SSH CA.",
      src: "MITRE T1552.004; auditd; Sysmon" },

    { id: "auth_access", label: "Key-based Auth", sub: "SSH/TLS/API", x: 730, y: 240, r: 40, type: "source",
      tags: ["SSH access", "TLS impersonation", "Code signing", "Cloud API"],
      telemetry: [],
      api: "Stolen keys provide: SSH access, HTTPS server impersonation, code signing, cloud API access",
      artifact: "Authentication via stolen private key · no password needed",
      desc: "Stolen private keys enable: passwordless SSH access to servers (no brute force or password needed), TLS server impersonation (MITM attacks), code signing with organization's certificate, cloud API access (AWS/GCP/Azure), and mTLS client authentication. Password changes don't invalidate key-based access.",
      src: "MITRE T1552.004" },
  ],

  edges: [
    { f: "ssh_keys", t: "key_search" },
    { f: "tls_keys", t: "key_search" },
    { f: "cloud_keys", t: "key_search" },
    { f: "key_search", t: "ev_detect" },
    { f: "ev_detect", t: "auth_access" },
  ],
};

export default model;
