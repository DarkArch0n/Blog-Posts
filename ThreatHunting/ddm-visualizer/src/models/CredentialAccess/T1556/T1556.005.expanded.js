// T1556.005 — Reversible Encryption — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.005", name: "Reversible Encryption", tactic: "Credential Access", platform: "Windows Active Directory", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "GPO CHANGE", y: 80 }, { label: "EXTRACT", y: 200 }] },
  nodes: [
    { id: "da_access", label: "DA Access", x: 60, y: 130, r: 36, type: "entry", desc: "Domain Admin to modify Group Policy or user account attributes.", src: "MITRE ATT&CK T1556.005" },
    { id: "enable_rev", label: "Enable Policy", sub: "Reversible encryption", x: 220, y: 80, r: 38, type: "op", desc: "Enable 'Store password using reversible encryption' via GPO or per-user attribute.", src: "Microsoft AD; MITRE T1556.005" },
    { id: "gpo_set", label: "GPO Modify", sub: "Default Domain Policy", x: 420, y: 80, r: 34, type: "api", desc: "Group Policy: Computer Config → Policies → Windows Settings → Security → Password Policy.", src: "Microsoft Group Policy" },
    { id: "user_attr", label: "User Attribute", sub: "userAccountControl", x: 420, y: 140, r: 32, type: "api", desc: "Set ENCRYPTED_TEXT_PWD_ALLOWED (0x80) flag on target user's userAccountControl.", src: "Microsoft AD; LDAP" },
    { id: "pwd_change", label: "Password Change", sub: "Required", x: 600, y: 80, r: 30, type: "system", desc: "User must change password AFTER policy is enabled. Reversible hash stored on next change.", src: "Microsoft AD" },
    { id: "dcsync", label: "DCSync", sub: "T1003.006", x: 220, y: 200, r: 36, type: "op", desc: "DCSync to extract supplementalCredentials attribute containing reversible-encrypted password.", src: "MITRE T1003.006" },
    { id: "drsr_api", label: "DrsGetNCChanges", x: 420, y: 200, r: 34, type: "api", desc: "MS-DRSR replication retrieves supplementalCredentials blob with reversible-encrypted password.", src: "Microsoft MS-DRSR" },
    { id: "decrypt", label: "Decrypt", sub: "PEK + AES", x: 600, y: 200, r: 34, type: "api", desc: "Decrypt supplementalCredentials using PEK from NTDS.dit. Outputs plaintext password.", src: "DSInternals; secretsdump" },
    { id: "ev_4662", label: "Event 4662", sub: "GPO modification", x: 600, y: 270, r: 34, type: "detect", desc: "Event 4662: Object modification on Group Policy or user objects.", src: "Microsoft Event 4662" },
    { id: "gpo_audit", label: "GPO Audit", sub: "Advanced auditing", x: 420, y: 270, r: 36, type: "detect", desc: "OPTIMAL: Monitor GPO changes — password policy modifications are rare and high-impact.", src: "Microsoft Advanced Audit" },
    { id: "plaintext", label: "Plaintext Passwords", x: 780, y: 200, r: 38, type: "artifact", desc: "Plaintext domain user passwords recovered via reversible encryption.", src: "MITRE T1556.005" },
  ],
  edges: [
    { f: "da_access", t: "enable_rev" }, { f: "enable_rev", t: "gpo_set" }, { f: "enable_rev", t: "user_attr" },
    { f: "gpo_set", t: "pwd_change" }, { f: "user_attr", t: "pwd_change" },
    { f: "da_access", t: "dcsync" }, { f: "dcsync", t: "drsr_api" }, { f: "drsr_api", t: "decrypt" },
    { f: "decrypt", t: "plaintext" },
    { f: "gpo_set", t: "gpo_audit" }, { f: "user_attr", t: "ev_4662" },
  ],
};
export default model;
