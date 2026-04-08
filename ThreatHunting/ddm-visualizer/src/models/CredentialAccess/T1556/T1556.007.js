// T1556.007 — Hybrid Identity — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.007",
    name: "Hybrid Identity",
    tactic: "Credential Access",
    platform: "Windows, Cloud",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 460,
    columns: [
      { label: "SYNC COMPONENT", x: 80 },
      { label: "MODIFICATION",   x: 270 },
      { label: "DETECTION",      x: 500 },
      { label: "OUTCOME",        x: 760 },
    ],
    separators: [175, 385, 630],
    annotations: [
      { text: "Azure AD Connect / Entra Connect is the bridge between on-prem and cloud", x: 270, y: 420, color: "#f57f17", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "aad_connect", label: "AAD Connect", sub: "Sync server", x: 80, y: 130, r: 40, type: "source",
      tags: ["Azure AD Connect", "Entra Connect", "Password Hash Sync", "Pass-through Auth"],
      telemetry: [],
      api: "Azure AD Connect server — syncs identities between on-premises AD and Azure AD",
      artifact: "Azure AD Connect server · PTA agent · PHS agent · Federation config",
      desc: "Azure AD Connect (Entra Connect) synchronizes identities between on-premises AD and Azure AD/Entra ID. Modes: Password Hash Sync (PHS), Pass-through Authentication (PTA), Federation (AD FS). Compromising this component allows the attacker to modify the authentication pipeline between on-prem and cloud.",
      src: "MITRE ATT&CK T1556.007; Microsoft Azure AD Connect" },

    { id: "pta_backdoor", label: "PTA Agent", sub: "Backdoor auth", x: 270, y: 110, r: 38, type: "source",
      tags: ["PTA agent backdoor", "Accept all passwords", "AADInternals"],
      telemetry: ["Azure AD sign-in"],
      api: "AADInternals Install-AADIntPTASpy — backdoor PTA agent accepts any password for any user",
      artifact: "Modified PTA agent DLL · all password validations return 'success'",
      desc: "Pass-through Authentication agent backdoor: AADInternals Install-AADIntPTASpy modifies the PTA agent to accept any password for any synchronized user. The agent sends 'authentication successful' to Azure AD regardless of the actual password. No on-premises events logged.",
      src: "Gerenios/AADInternals; MITRE T1556.007" },

    { id: "phs_extract", label: "PHS Extract", sub: "Dump AD hashes", x: 270, y: 280, r: 34, type: "source",
      tags: ["Dump Azure AD Connect creds", "DPAPI decrypt", "MSOL account"],
      telemetry: [],
      api: "Extract MSOL_ service account credentials from Azure AD Connect DB → DCSync with those creds",
      artifact: "MSOL_ service account credentials extracted · AD Replication rights abused",
      desc: "Extract the MSOL_ service account credentials stored in Azure AD Connect's local database (encrypted with DPAPI). This account has AD Replication rights (DCSync capability). Attacker uses these credentials to DCSync all domain password hashes.",
      src: "MITRE T1556.007; AADInternals; Dirk-jan Mollema research" },

    { id: "fed_mod", label: "Federation", sub: "Modify trust", x: 270, y: 430, r: 34, type: "source",
      tags: ["Add federated domain", "SAML trust", "Backdoor IdP"],
      telemetry: ["Azure AD audit"],
      api: "Add new federated domain or modify existing federation trust to accept attacker's IdP",
      artifact: "Azure AD audit: new federated domain added · federation settings changed",
      desc: "Modify Azure AD federation settings: add a new federated domain pointing to attacker-controlled IdP, or modify existing federation trust. The attacker's IdP issues SAML tokens that Azure AD trusts. Related to T1606.002 Golden SAML but at the federation configuration level.",
      src: "MITRE T1556.007; Secureworks Azure AD federation research" },

    { id: "ev_detect", label: "Sync Integrity", sub: "PTA + Fed audit", x: 500, y: 250, r: 50, type: "detect",
      tags: ["PTA agent integrity", "Federation audit", "Azure AD sign-in anomaly", "MSOL creds"],
      telemetry: ["Azure AD audit", "Azure AD sign-in"],
      api: "Monitor PTA agent DLL integrity + federation changes + Azure AD sign-in anomalies",
      artifact: "OPTIMAL: PTA agent binary hash change · new federated domain · auth from unexpected PTA agent · MSOL account usage",
      desc: "OPTIMAL DETECTION NODE. (1) PTA agent integrity: verify AzureADConnectAuthenticationAgentService DLL hashes against known-good. (2) Azure AD audit: new federated domain events, federation trust changes. (3) Sign-in logs: authentication from unexpected PTA agent servers. (4) MSOL_ account: monitor usage outside of sync operations. (5) PREVENTION: Secure AAD Connect server as Tier 0, use Cloud-only accounts for emergency access, monitor federation config changes.",
      src: "MITRE T1556.007; Microsoft security recommendations" },

    { id: "cloud_access", label: "Cloud Access", sub: "Any user", x: 760, y: 150, r: 38, type: "source",
      tags: ["Azure AD login as anyone", "O365 access", "Cloud admin"],
      telemetry: [],
      api: "Authenticate to Azure AD as any synchronized user — any password works",
      artifact: "Full cloud access as any identity · O365, Azure, all cloud services",
      desc: "Backdoored PTA agent or federation trust allows authentication as any cloud user with any password. Provides access to O365, Azure Portal, and all Azure AD-integrated applications. Can escalate to Global Admin by targeting admin accounts.",
      src: "MITRE T1556.007" },

    { id: "ad_hashes", label: "AD Hashes", sub: "All users", x: 760, y: 370, r: 36, type: "source",
      tags: ["DCSync via MSOL", "All NTLM hashes", "Full domain compromise"],
      telemetry: [],
      api: "MSOL_ account DCSync → extract all domain NTLM hashes and Kerberos keys",
      artifact: "Complete domain compromise via DCSync using MSOL_ service account",
      desc: "Extracted MSOL_ credentials enable DCSync: the attacker replicates all domain password hashes. Yields NTLM hashes, Kerberos keys, and reversibly encrypted passwords for every domain account. Full domain compromise from the Azure AD Connect server.",
      src: "MITRE T1556.007; Dirk-jan Mollema" },
  ],

  edges: [
    { f: "aad_connect", t: "pta_backdoor" },
    { f: "aad_connect", t: "phs_extract" },
    { f: "aad_connect", t: "fed_mod" },
    { f: "pta_backdoor", t: "ev_detect" },
    { f: "phs_extract", t: "ev_detect" },
    { f: "fed_mod", t: "ev_detect" },
    { f: "ev_detect", t: "cloud_access" },
    { f: "ev_detect", t: "ad_hashes" },
  ],
};

export default model;
