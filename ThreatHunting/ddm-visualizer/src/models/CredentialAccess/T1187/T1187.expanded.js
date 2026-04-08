// T1187 — Forced Authentication — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1187", name: "Forced Authentication", tactic: "Credential Access", platform: "Windows", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 380, rows: [{ label: "SMB COERCE", y: 80 }, { label: "WEBDAV", y: 180 }, { label: "URL FILES", y: 300 }] },
  nodes: [
    { id: "attacker_srv", label: "Attacker Server", sub: "SMB/HTTP listener", x: 60, y: 180, r: 38, type: "entry", desc: "Attacker hosts rogue SMB/HTTP server to capture NTLM authentication attempts.", src: "MITRE ATT&CK T1187" },
    { id: "petitpotam", label: "PetitPotam", sub: "EfsRpcOpenFileRaw", x: 240, y: 80, r: 36, type: "op", desc: "PetitPotam: abuse MS-EFSRPC to coerce DC to authenticate to attacker. EfsRpcOpenFileRaw.", src: "PetitPotam; MS-EFSRPC" },
    { id: "printerbug", label: "PrinterBug", sub: "SpoolService", x: 420, y: 80, r: 34, type: "op", desc: "Abuse Print Spooler RpcRemoteFindFirstPrinterChangeNotificationEx to coerce auth.", src: "SpoolSample; @tifkin_" },
    { id: "dfscoerce", label: "DFSCoerce", sub: "MS-DFSNM", x: 420, y: 140, r: 30, type: "op", desc: "Abuse MS-DFSNM NetrDfsRemoveStdRoot to coerce authentication from DFS servers.", src: "DFSCoerce" },
    { id: "webdav_unc", label: "WebDAV UNC", sub: "\\\\attacker@80\\share", x: 240, y: 180, r: 36, type: "op", desc: "WebDAV UNC path forces NTLM auth over HTTP. Works when WebClient service running.", src: "MITRE T1187; WebClient" },
    { id: "ntlm_auth", label: "NTLM Auth", sub: "Challenge-Response", x: 620, y: 130, r: 36, type: "protocol", desc: "Windows automatically sends NTLM credentials to \\\\UNC paths. Type 1/2/3 messages.", src: "MS-NLMP" },
    { id: "scf_file", label: ".scf / .url File", sub: "IconFile=\\\\attacker", x: 240, y: 300, r: 34, type: "op", desc: "Place .scf or .url file with UNC icon path on share. Explorer auto-resolves, sends creds.", src: "MITRE T1187" },
    { id: "lnk_file", label: ".lnk File", sub: "Icon UNC path", x: 420, y: 300, r: 34, type: "op", desc: ".lnk shortcut with icon pointing to \\\\attacker\\share. Auto-Auth when folder viewed.", src: "MITRE T1187" },
    { id: "ntlm_hash", label: "NTLMv2 Hash", sub: "For cracking/relay", x: 830, y: 130, r: 40, type: "artifact", desc: "Captured NTLMv2 challenge-response for offline cracking (hashcat -m 5600) or relay.", src: "hashcat; ntlmrelayx" },
    { id: "ev_4648", label: "Event 4648", sub: "Explicit logon", x: 620, y: 300, r: 36, type: "detect", desc: "Event 4648: Logon using explicit credentials to attacker IP.", src: "Microsoft Event 4648" },
    { id: "ntlm_audit", label: "NTLM Audit", sub: "Event 8001/8002", x: 620, y: 220, r: 34, type: "detect", desc: "OPTIMAL: NTLM Audit: Event 8001/8002 for outbound NTLM to non-standard destinations.", src: "Microsoft NTLM Audit" },
    { id: "smb_signing", label: "SMB Signing", sub: "Prevents relay", x: 830, y: 260, r: 34, type: "system", desc: "Enforce SMB signing + EPA to prevent relay. Doesn't prevent hash capture for cracking.", src: "Microsoft SMB Signing" },
  ],
  edges: [
    { f: "attacker_srv", t: "petitpotam" }, { f: "attacker_srv", t: "webdav_unc" }, { f: "attacker_srv", t: "scf_file" },
    { f: "petitpotam", t: "printerbug" }, { f: "petitpotam", t: "dfscoerce" },
    { f: "petitpotam", t: "ntlm_auth" }, { f: "webdav_unc", t: "ntlm_auth" },
    { f: "scf_file", t: "lnk_file" }, { f: "scf_file", t: "ntlm_auth" }, { f: "lnk_file", t: "ntlm_auth" },
    { f: "ntlm_auth", t: "ntlm_hash" },
    { f: "ntlm_auth", t: "ev_4648" }, { f: "ntlm_auth", t: "ntlm_audit" },
    { f: "ntlm_hash", t: "smb_signing" },
  ],
};
export default model;
