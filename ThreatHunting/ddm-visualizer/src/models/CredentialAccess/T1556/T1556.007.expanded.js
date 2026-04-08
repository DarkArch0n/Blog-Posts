// T1556.007 — Hybrid Identity — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.007", name: "Hybrid Identity", tactic: "Credential Access", platform: "Azure AD + On-Prem AD", version: "v1.0" },
  layout: { svgWidth: 1400, svgHeight: 340, rows: [{ label: "PTA AGENT", y: 80 }, { label: "AD CONNECT", y: 200 }] },
  nodes: [
    { id: "adconnect_host", label: "AD Connect Host", sub: "Compromised", x: 60, y: 130, r: 38, type: "entry", desc: "Compromise the Azure AD Connect server running PTA Agent or Password Hash Sync.", src: "MITRE ATT&CK T1556.007" },
    { id: "pta_backdoor", label: "PTA Backdoor", sub: "Intercept auth", x: 220, y: 80, r: 38, type: "op", desc: "Backdoor PTA Agent: intercept ValidateCredentials requests and always return 'success'.", src: "MITRE T1556.007; AADInternals" },
    { id: "pta_api", label: "PTA Agent API", sub: "Azure Service Bus", x: 420, y: 80, r: 36, type: "api", desc: "PTA Agent receives auth requests via Azure Service Bus. Modified agent accepts any password.", src: "Microsoft AD Connect PTA" },
    { id: "aad_login", label: "Azure AD Login", sub: "login.microsoftonline.com", x: 620, y: 80, r: 36, type: "protocol", desc: "Azure AD sends auth to PTA Agent → backdoored agent confirms → user logged in with any password.", src: "Microsoft Entra" },
    { id: "aad_extract", label: "AADInternals", sub: "Get-AADIntSyncCreds", x: 220, y: 200, r: 38, type: "op", desc: "AADInternals extracts Azure AD Connect sync credentials (MSOL_ service account).", src: "AADInternals; DrAzureAD" },
    { id: "dpapi_key", label: "DPAPI Decrypt", sub: "keyset_*.bin", x: 420, y: 200, r: 34, type: "api", desc: "AD Connect stores credentials DPAPI-encrypted. Extract with AADInternals on the server.", src: "AADInternals" },
    { id: "msol_creds", label: "MSOL_ Account", sub: "High-privilege", x: 620, y: 200, r: 36, type: "artifact", desc: "MSOL_ service account has DCSync rights by default — extract all AD hashes.", src: "AADInternals; MITRE T1556.007" },
    { id: "seamless_sso", label: "Seamless SSO", sub: "AZUREADSSOACC$", x: 420, y: 270, r: 34, type: "op", desc: "Extract AZUREADSSOACC$ computer account key → forge Kerberos tickets for Azure AD SSO.", src: "AADInternals" },
    { id: "aad_audit", label: "Azure AD Audit", sub: "PTA Agent changes", x: 800, y: 80, r: 38, type: "detect", desc: "OPTIMAL: Monitor PTA Agent registrations, AD Connect configuration changes in Azure AD Audit logs.", src: "Microsoft Entra Audit" },
    { id: "ev_adconnect", label: "Event Logs", sub: "AD Connect host", x: 800, y: 200, r: 34, type: "detect", desc: "Monitor AD Connect server for process modifications, DLL loads, credential access.", src: "Microsoft" },
    { id: "cloud_access", label: "Cloud/On-Prem", sub: "Full access", x: 1000, y: 130, r: 38, type: "artifact", desc: "Full access to both Azure AD cloud resources AND on-premises AD via extracted credentials.", src: "MITRE T1556.007" },
  ],
  edges: [
    { f: "adconnect_host", t: "pta_backdoor" }, { f: "pta_backdoor", t: "pta_api" },
    { f: "pta_api", t: "aad_login" },
    { f: "adconnect_host", t: "aad_extract" }, { f: "aad_extract", t: "dpapi_key" },
    { f: "dpapi_key", t: "msol_creds" }, { f: "dpapi_key", t: "seamless_sso" },
    { f: "aad_login", t: "aad_audit" }, { f: "aad_extract", t: "ev_adconnect" },
    { f: "aad_login", t: "cloud_access" }, { f: "msol_creds", t: "cloud_access" },
  ],
};
export default model;
