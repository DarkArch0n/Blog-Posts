// T1556.009 — Conditional Access Policies — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.009", name: "Conditional Access Policies", tactic: "Credential Access", platform: "Azure AD / Entra ID", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "MODIFY", y: 80 }, { label: "BYPASS", y: 200 }] },
  nodes: [
    { id: "ga_access", label: "Global Admin", sub: "or CA Admin", x: 60, y: 130, r: 36, type: "entry", desc: "Azure AD Global Admin or Conditional Access Administrator role.", src: "MITRE ATT&CK T1556.009" },
    { id: "modify_policy", label: "Modify CA Policy", sub: "Add exclusion", x: 220, y: 80, r: 38, type: "op", desc: "Modify Conditional Access policy to exclude attacker IPs, devices, or users from MFA/block rules.", src: "MITRE T1556.009" },
    { id: "graph_api", label: "Graph API", sub: "conditionalAccess", x: 420, y: 80, r: 34, type: "api", desc: "PATCH /identity/conditionalAccess/policies/{id} to modify conditions/grant controls.", src: "Microsoft Graph API" },
    { id: "add_location", label: "Trusted Location", sub: "Attacker IP range", x: 420, y: 140, r: 32, type: "op", desc: "Add attacker's IP range as 'trusted named location' → bypasses MFA for those IPs.", src: "Microsoft Entra" },
    { id: "disable_policy", label: "Disable Policy", sub: "State = disabled", x: 220, y: 200, r: 34, type: "op", desc: "Disable critical CA policies: set policy state to 'disabled' or 'enabledForReportingButNotEnforced'.", src: "MITRE T1556.009" },
    { id: "create_exempt", label: "Create Exemption", sub: "New weaker policy", x: 420, y: 200, r: 36, type: "op", desc: "Create new CA policy with broader exemptions that overrides existing restrictive policies.", src: "MITRE T1556.009" },
    { id: "az_audit", label: "Azure AD Audit", sub: "Policy changes", x: 620, y: 80, r: 42, type: "detect", desc: "OPTIMAL: Azure AD Audit Log: 'Update conditional access policy', 'Add named location'. High-priority alert.", src: "Microsoft Entra Audit" },
    { id: "az_signin", label: "Sign-in Log", sub: "CA not applied", x: 620, y: 200, r: 36, type: "detect", desc: "Azure Sign-in Log: conditionalAccessStatus='notApplied' for users who should have CA enforced.", src: "Microsoft Entra Sign-in" },
    { id: "bypass_access", label: "Unrestricted Access", x: 820, y: 130, r: 38, type: "artifact", desc: "Attacker authenticates without MFA, device compliance, or location restrictions.", src: "MITRE T1556.009" },
  ],
  edges: [
    { f: "ga_access", t: "modify_policy" }, { f: "modify_policy", t: "graph_api" },
    { f: "ga_access", t: "add_location" }, { f: "add_location", t: "graph_api" },
    { f: "ga_access", t: "disable_policy" }, { f: "ga_access", t: "create_exempt" },
    { f: "graph_api", t: "az_audit" }, { f: "disable_policy", t: "az_audit" },
    { f: "create_exempt", t: "az_signin" },
    { f: "graph_api", t: "bypass_access" }, { f: "disable_policy", t: "bypass_access" },
    { f: "create_exempt", t: "bypass_access" },
  ],
};
export default model;
