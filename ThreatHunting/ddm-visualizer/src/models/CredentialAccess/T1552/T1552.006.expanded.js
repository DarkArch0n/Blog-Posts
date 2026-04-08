// T1552.006 — Group Policy Preferences — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1552.006", name: "Group Policy Preferences", tactic: "Credential Access", platform: "Windows Active Directory", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "SYSVOL", y: 80 }, { label: "DECRYPT", y: 200 }] },
  nodes: [
    { id: "domain_user", label: "Domain User", x: 60, y: 130, r: 36, type: "entry", desc: "Any authenticated domain user can read SYSVOL. No special permissions needed.", src: "MITRE ATT&CK T1552.006" },
    { id: "gpp_find", label: "Browse SYSVOL", sub: "\\\\domain\\SYSVOL", x: 220, y: 80, r: 36, type: "op", desc: "Browse \\\\domain\\SYSVOL\\domain\\Policies\\ for Groups.xml, ScheduledTasks.xml, etc.", src: "MITRE T1552.006" },
    { id: "findstr_cpass", label: "findstr cpassword", x: 420, y: 80, r: 34, type: "op", desc: "findstr /S /I cpassword \\\\domain\\SYSVOL\\*.xml — find all GPP files with embedded passwords.", src: "MITRE T1552.006" },
    { id: "smb_read", label: "SMB Read", sub: "TCP 445", x: 420, y: 140, r: 28, type: "protocol", desc: "SYSVOL access via SMB on TCP/445. Standard domain file share.", src: "MS-SMB2" },
    { id: "gpp_decrypt", label: "gpp-decrypt", sub: "AES-256-CBC", x: 220, y: 200, r: 38, type: "op", desc: "Microsoft published the 32-byte AES key in MSDN (MS14-025). Any cpassword is trivially decryptable.", src: "MS14-025; gpp-decrypt" },
    { id: "aes_key", label: "Published AES Key", sub: "Microsoft MSDN", x: 420, y: 200, r: 36, type: "api", desc: "AES-256-CBC key published by Microsoft: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b", src: "MS14-025; MSDN" },
    { id: "gpp_auto", label: "Get-GPPPassword", sub: "PowerSploit", x: 220, y: 260, r: 32, type: "op", desc: "PowerSploit Get-GPPPassword automates GPP credential search and decryption.", src: "PowerSploit; CrackMapExec" },
    { id: "ev_5140", label: "Event 5140", sub: "SYSVOL access", x: 600, y: 80, r: 34, type: "detect", desc: "Event 5140: Network share access to SYSVOL. Filter for non-DC sources accessing policy files.", src: "Microsoft Event 5140" },
    { id: "sysmon_1", label: "Sysmon 1", sub: "Get-GPPPassword", x: 600, y: 200, r: 34, type: "detect", desc: "OPTIMAL: Sysmon EID 1: PowerShell/findstr with 'cpassword' or 'GPPPassword' arguments.", src: "Sysmon documentation" },
    { id: "local_admin_pwd", label: "Local Admin Pwd", sub: "Plaintext", x: 780, y: 130, r: 38, type: "artifact", desc: "Plaintext local administrator passwords set via GPP. Often same password across many machines.", src: "MITRE T1552.006; MS14-025" },
  ],
  edges: [
    { f: "domain_user", t: "gpp_find" }, { f: "gpp_find", t: "findstr_cpass" }, { f: "gpp_find", t: "smb_read" },
    { f: "domain_user", t: "gpp_auto" },
    { f: "findstr_cpass", t: "gpp_decrypt" }, { f: "gpp_auto", t: "gpp_decrypt" },
    { f: "gpp_decrypt", t: "aes_key" }, { f: "aes_key", t: "local_admin_pwd" },
    { f: "smb_read", t: "ev_5140" }, { f: "gpp_auto", t: "sysmon_1" },
  ],
};
export default model;
