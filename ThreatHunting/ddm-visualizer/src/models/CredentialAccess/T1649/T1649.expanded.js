// T1649 — Steal or Forge Authentication Certificates — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1649", name: "Steal or Forge Authentication Certificates", tactic: "Credential Access", platform: "Windows Active Directory", version: "v1.0" },
  layout: { svgWidth: 1500, svgHeight: 420, rows: [{ label: "ESC1-ESC3", y: 80 }, { label: "ESC4-ESC8", y: 190 }, { label: "CA THEFT", y: 310 }] },
  nodes: [
    { id: "adcs", label: "AD CS", sub: "Certificate Authority", x: 60, y: 190, r: 42, type: "entry", desc: "Active Directory Certificate Services deployment with misconfigured templates.", src: "MITRE ATT&CK T1649; SpecterOps Certified Pre-Owned" },
    { id: "esc1", label: "ESC1", sub: "SAN Misconfig", x: 240, y: 80, r: 36, type: "op", desc: "ESC1: Template allows SAN (Subject Alternative Name). Request cert as any user (e.g., DA).", src: "Certified Pre-Owned; Certipy" },
    { id: "esc2", label: "ESC2", sub: "Any Purpose EKU", x: 420, y: 60, r: 30, type: "op", desc: "ESC2: Template with Any Purpose or no EKU. Can be used for client authentication.", src: "Certified Pre-Owned" },
    { id: "esc3", label: "ESC3", sub: "Enrollment Agent", x: 420, y: 120, r: 30, type: "op", desc: "ESC3: Enrollment agent template. Enroll on behalf of other users.", src: "Certified Pre-Owned" },
    { id: "certipy", label: "Certipy", sub: "req -template", x: 640, y: 80, r: 36, type: "op", desc: "Certipy: certipy req -ca CA -template VulnTemplate -upn admin@domain.com", src: "Certipy; ly4k" },
    { id: "esc4", label: "ESC4", sub: "Template ACL write", x: 240, y: 190, r: 32, type: "op", desc: "ESC4: Write access to template object in AD → modify template to be vulnerable (ESC1 conditions).", src: "Certified Pre-Owned" },
    { id: "esc8", label: "ESC8", sub: "HTTP enrollment", x: 420, y: 190, r: 34, type: "op", desc: "ESC8: NTLM relay to AD CS HTTP enrollment endpoint. Coerce DC → relay → get DC cert.", src: "Certified Pre-Owned; PetitPotam" },
    { id: "pkinit_auth", label: "PKINIT Auth", sub: "Certificate → TGT", x: 840, y: 130, r: 40, type: "protocol", desc: "Use forged/stolen cert for PKINIT authentication → receive TGT as target user.", src: "RFC 4556; Rubeus" },
    { id: "ca_export", label: "CA Private Key", sub: "Export CA cert", x: 240, y: 310, r: 36, type: "op", desc: "Steal CA private key: export from CA server → forge any certificate (Golden Cert).", src: "SpecterOps; DPAPI" },
    { id: "golden_cert", label: "Golden Cert", sub: "Forge any cert", x: 440, y: 310, r: 38, type: "op", desc: "With CA private key: forge authentication certificates for any AD user. Persists until CA rotated.", src: "Certified Pre-Owned; ForgeCert" },
    { id: "ev_4886", label: "Event 4886/4887", sub: "Cert requested/issued", x: 640, y: 310, r: 36, type: "detect", desc: "Events 4886/4887: Certificate requested/issued. Alert on SAN != requester.", src: "Microsoft CA Audit" },
    { id: "certify_detect", label: "Template Audit", sub: "Vulnerable templates", x: 840, y: 310, r: 36, type: "detect", desc: "OPTIMAL: Audit AD CS templates with Certify/Certipy find. Alert on dangerous configurations.", src: "Certify; Certipy" },
    { id: "domain_persist", label: "Domain Persistence", sub: "Cert-based TGT", x: 1080, y: 190, r: 44, type: "artifact", desc: "Certificate-based Kerberos TGT: survives password resets. Golden Cert = indefinite persistence.", src: "MITRE T1649" },
  ],
  edges: [
    { f: "adcs", t: "esc1" }, { f: "adcs", t: "esc4" }, { f: "adcs", t: "ca_export" },
    { f: "esc1", t: "esc2" }, { f: "esc1", t: "esc3" }, { f: "esc1", t: "certipy" },
    { f: "esc4", t: "esc8" }, { f: "esc8", t: "pkinit_auth" },
    { f: "certipy", t: "pkinit_auth" },
    { f: "ca_export", t: "golden_cert" }, { f: "golden_cert", t: "pkinit_auth" },
    { f: "pkinit_auth", t: "domain_persist" },
    { f: "certipy", t: "ev_4886" }, { f: "esc1", t: "certify_detect" },
  ],
};
export default model;
