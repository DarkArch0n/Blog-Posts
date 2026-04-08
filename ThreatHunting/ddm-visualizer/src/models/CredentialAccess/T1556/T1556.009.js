// T1556.009 — Conditional Access Policies — Detection Data Model
// Tactic: Credential Access / Defense Evasion

const model = {
  metadata: {
    tcode: "T1556.009",
    name: "Conditional Access Policies",
    tactic: "Credential Access",
    platform: "Cloud, SaaS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "ADMIN ACCESS",  x: 80 },
      { label: "POLICY CHANGE", x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "ca_admin", label: "Entra Admin", sub: "CA policy rights", x: 80, y: 200, r: 40, type: "source",
      tags: ["Global Admin", "Conditional Access Admin", "Security Admin"],
      telemetry: ["Azure AD audit"],
      api: "Global Admin, Conditional Access Admin, or Security Admin role in Azure AD / Entra ID",
      artifact: "Admin role assignment · privilege to modify Conditional Access policies",
      desc: "Modifying Conditional Access policies requires administrative roles in Azure AD / Entra ID: Global Admin, Conditional Access Admin, or Security Admin. Attacker achieves this via credential compromise, privilege escalation, or exploiting an over-privileged account.",
      src: "MITRE ATT&CK T1556.009; Microsoft Entra ID" },

    { id: "weaken_ca", label: "Weaken Policy", sub: "Exclude/disable", x: 270, y: 120, r: 38, type: "source",
      tags: ["Exclude user/group", "Disable MFA requirement", "Trust location"],
      telemetry: ["Azure AD audit"],
      api: "Modify CA policy: exclude attacker-controlled accounts, disable MFA for specific conditions, add trusted location",
      artifact: "Azure AD audit: Conditional Access policy modified · exclusion added · requirement removed",
      desc: "Weaken existing Conditional Access policies: exclude specific user accounts or groups from MFA requirements, add attacker-controlled IP ranges to trusted locations (bypassing location-based policies), or reduce authentication strength requirements for certain conditions.",
      src: "MITRE T1556.009" },

    { id: "disable_ca", label: "Disable Policy", sub: "Turn off entirely", x: 270, y: 300, r: 36, type: "source",
      tags: ["Disable CA policy", "Report-only mode", "Delete policy"],
      telemetry: ["Azure AD audit"],
      api: "Set Conditional Access policy to 'Off' or 'Report-only' mode, or delete the policy entirely",
      artifact: "Azure AD audit: CA policy disabled · policy set to report-only · policy deleted",
      desc: "More aggressive: disable Conditional Access policies entirely (set to 'Off' or 'Report-only' mode) or delete them. This removes authentication controls like MFA, device compliance, location restrictions, and risk-based policies for all users affected by the disabled policy.",
      src: "MITRE T1556.009" },

    { id: "ev_detect", label: "CA Policy Audit", sub: "Change monitoring", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Azure AD audit logs", "CA policy change", "Named location change", "Policy baseline"],
      telemetry: ["Azure AD audit"],
      api: "Monitor Azure AD audit logs for CA policy modifications + baseline comparison",
      artifact: "OPTIMAL: Azure AD audit: 'Update conditional access policy' · 'Delete conditional access policy' · exclusion change · trusted location added",
      desc: "OPTIMAL DETECTION NODE. (1) Azure AD audit logs: filter for 'Update conditional access policy', 'Delete conditional access policy' events. (2) Named locations: monitor for new trusted locations or modifications. (3) Policy baseline comparison: regularly export and diff CA policies against approved configurations. (4) Alerting: immediate alert on any CA policy modification outside of change windows. (5) PREVENTION: Privileged Identity Management (PIM) for CA admin roles, require approval for policy changes.",
      src: "MITRE T1556.009; Microsoft Entra ID audit" },

    { id: "bypass_controls", label: "Bypass Controls", sub: "No MFA/compliance", x: 730, y: 200, r: 42, type: "source",
      tags: ["MFA bypassed", "Device compliance bypassed", "Location restriction bypassed"],
      telemetry: [],
      api: "Authentication controls removed — attacker accesses cloud resources without MFA or compliance",
      artifact: "Access to cloud resources without MFA, device compliance, or location restrictions",
      desc: "With CA policies weakened or disabled, the attacker bypasses: MFA requirements, device compliance checks (Intune), location-based restrictions, session controls, and risk-based policies. This allows password-only authentication from any device, any location.",
      src: "MITRE T1556.009" },
  ],

  edges: [
    { f: "ca_admin", t: "weaken_ca" },
    { f: "ca_admin", t: "disable_ca" },
    { f: "weaken_ca", t: "ev_detect" },
    { f: "disable_ca", t: "ev_detect" },
    { f: "ev_detect", t: "bypass_controls" },
  ],
};

export default model;
