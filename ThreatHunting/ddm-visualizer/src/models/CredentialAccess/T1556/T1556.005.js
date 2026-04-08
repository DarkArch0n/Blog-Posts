// T1556.005 — Reversible Encryption — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.005",
    name: "Reversible Encryption",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "ENABLE POLICY",  x: 80 },
      { label: "PASSWORD CHANGE",x: 270 },
      { label: "DETECTION",      x: 480 },
      { label: "OUTCOME",        x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "policy", label: "Enable Policy", sub: "Reversible encrypt", x: 80, y: 130, r: 38, type: "source",
      tags: ["GPO: Store passwords using reversible encryption", "AllowReversiblePasswordEncryption"],
      telemetry: ["Windows 4739"],
      api: "AD Group Policy: 'Store passwords using reversible encryption' → Enabled",
      artifact: "Windows 4739: Domain Policy was changed · GPO modification event",
      desc: "Attacker enables 'Store passwords using reversible encryption' via Group Policy. This setting causes Active Directory to store passwords in a reversible (essentially plaintext) form. When users change passwords, the new password is stored in a format that can be decrypted back to plaintext.",
      src: "MITRE ATT&CK T1556.005; Microsoft AD Security" },

    { id: "user_attr", label: "User Attribute", sub: "Per-account flag", x: 80, y: 320, r: 34, type: "source",
      tags: ["userAccountControl", "AllowReversiblePasswordEncryption", "Per-user"],
      telemetry: ["Windows 4738"],
      api: "Set AllowReversiblePasswordEncryption attribute on individual user accounts",
      artifact: "Windows 4738: user account changed · userAccountControl modification",
      desc: "Instead of domain-wide policy, attacker can enable reversible encryption on specific user accounts by modifying the AllowReversiblePasswordEncryption attribute (userAccountControl flag 0x80). More targeted and potentially less noticeable than domain-wide policy change.",
      src: "MITRE T1556.005" },

    { id: "next_change", label: "Next Pwd Change", sub: "Stored reversible", x: 270, y: 200, r: 40, type: "source",
      tags: ["Password rotation", "Force password change", "Stored encrypted"],
      telemetry: ["Windows 4723", "Windows 4724"],
      api: "On next password change, AD stores the new password in reversible encryption form",
      artifact: "Password stored in supplementalCredentials attribute in reversible form",
      desc: "The setting takes effect at next password change. Attacker can force password changes by setting pwdLastSet=0 (forcing password change at next logon). Reversibly encrypted passwords are stored in the supplementalCredentials attribute of the user object in AD database (ntds.dit).",
      src: "MITRE T1556.005" },

    { id: "ev_detect", label: "Policy Audit", sub: "GPO + attr monitor", x: 480, y: 200, r: 50, type: "detect",
      tags: ["GPO baseline", "4739 policy change", "4738 account change", "AD attribute monitor"],
      telemetry: ["Windows 4739", "Windows 4738"],
      api: "Monitor domain policy changes (4739) + user account attribute changes (4738) for reversible encryption enablement",
      artifact: "OPTIMAL: Windows 4739 domain policy change · 4738 per-user attribute change · GPO 'reversible encryption' enabled",
      desc: "OPTIMAL DETECTION NODE. (1) Windows 4739: domain policy change — alert on any policy change enabling reversible encryption. (2) Windows 4738: user account change — alert on AllowReversiblePasswordEncryption flag. (3) Regular GPO audit: compare domain security policy against baseline. (4) AD query: Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}. (5) PREVENTION: Enforce security baseline preventing reversible encryption.",
      src: "MITRE T1556.005; Microsoft Security Compliance Toolkit" },

    { id: "decrypt_pwd", label: "Decrypt Passwords", sub: "Plaintext from AD", x: 730, y: 200, r: 40, type: "source",
      tags: ["Extract from ntds.dit", "DCSync", "Plaintext passwords"],
      telemetry: [],
      api: "Extract and decrypt passwords from ntds.dit / DCSync — reversible encryption is trivially decrypted",
      artifact: "Plaintext domain passwords recovered from AD database",
      desc: "With domain admin access, attacker extracts the ntds.dit database (or uses DCSync) and decrypts the reversibly encrypted passwords. Unlike normal password hashes (which require cracking), reversibly encrypted passwords are trivially decrypted using the system key. Yields actual plaintext passwords.",
      src: "MITRE T1556.005" },
  ],

  edges: [
    { f: "policy", t: "next_change" },
    { f: "user_attr", t: "next_change" },
    { f: "next_change", t: "ev_detect" },
    { f: "ev_detect", t: "decrypt_pwd" },
  ],
};

export default model;
