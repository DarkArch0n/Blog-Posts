// T1552.004 — Private Keys — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.004", name: "Private Keys", tactic: "Credential Access", platform: "Windows, Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 340, rows: [{ label: "SSH KEYS", y: 80 }, { label: "TLS/CERTS", y: 180 }, { label: "PGP/GPG", y: 280 }] },
  nodes: [
    { id: "access", label: "File Access", x: 60, y: 150, r: 36, type: "entry", desc: "Read access to user home directories or certificate stores.", src: "MITRE ATT&CK T1552.004" },
    { id: "ssh_keys", label: "~/.ssh/id_*", sub: "Private keys", x: 220, y: 80, r: 36, type: "op", desc: "Read SSH private keys: id_rsa, id_ed25519, id_ecdsa from ~/.ssh/.", src: "MITRE T1552.004" },
    { id: "auth_keys", label: "authorized_keys", sub: "Target list", x: 420, y: 80, r: 32, type: "op", desc: "Read authorized_keys to identify SSH trust relationships and target hosts.", src: "OpenSSH" },
    { id: "ssh_config", label: "~/.ssh/config", sub: "Host mappings", x: 420, y: 140, r: 30, type: "op", desc: "SSH config reveals hostnames, ports, and which key is used for each host.", src: "OpenSSH" },
    { id: "tls_keys", label: "TLS Private Keys", sub: "/etc/ssl/private/", x: 220, y: 180, r: 34, type: "op", desc: "TLS certificate private keys: /etc/ssl/private/, /etc/pki/tls/, Windows cert store.", src: "MITRE T1552.004" },
    { id: "certutil", label: "certutil", sub: "-exportPFX", x: 420, y: 180, r: 32, type: "op", desc: "Windows: certutil -exportPFX to export certificates with private keys.", src: "Microsoft certutil" },
    { id: "dpapi_cert", label: "DPAPI Decrypt", sub: "Cert private key", x: 560, y: 180, r: 34, type: "api", desc: "Windows cert private keys DPAPI-encrypted. SharpDPAPI can extract.", src: "GhostPack/SharpDPAPI" },
    { id: "pgp_keys", label: "GPG Keyring", sub: "~/.gnupg/", x: 220, y: 280, r: 32, type: "op", desc: "GPG private keys in ~/.gnupg/ — decrypt messages, sign code.", src: "GnuPG" },
    { id: "sysmon_11", label: "Sysmon 11", sub: ".pem/.key access", x: 560, y: 80, r: 34, type: "detect", desc: "Sysmon EID 11: File access to .pem, .key, .pfx files by unexpected processes.", src: "Sysmon documentation" },
    { id: "auditd", label: "auditd", sub: "~/.ssh/ reads", x: 560, y: 280, r: 36, type: "detect", desc: "OPTIMAL: auditd -w /home/ -p r -k ssh_key_read for SSH key access monitoring.", src: "Linux auditd" },
    { id: "stolen_keys", label: "Private Keys", sub: "SSH/TLS/PGP", x: 760, y: 150, r: 38, type: "artifact", desc: "Stolen private keys enable: SSH access to servers, TLS impersonation, message decryption.", src: "MITRE T1552.004" },
  ],
  edges: [
    { f: "access", t: "ssh_keys" }, { f: "access", t: "tls_keys" }, { f: "access", t: "pgp_keys" },
    { f: "ssh_keys", t: "auth_keys" }, { f: "ssh_keys", t: "ssh_config" },
    { f: "tls_keys", t: "certutil" }, { f: "certutil", t: "dpapi_cert" },
    { f: "ssh_keys", t: "stolen_keys" }, { f: "auth_keys", t: "stolen_keys" },
    { f: "dpapi_cert", t: "stolen_keys" }, { f: "pgp_keys", t: "stolen_keys" },
    { f: "ssh_keys", t: "auditd" }, { f: "ssh_keys", t: "sysmon_11" },
  ],
};
export default model;
