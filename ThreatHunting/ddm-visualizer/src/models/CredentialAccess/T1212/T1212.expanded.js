// T1212 — Exploitation for Credential Access — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1212", name: "Exploitation for Credential Access", tactic: "Credential Access", platform: "Windows, Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 380, rows: [{ label: "ZEROLOGON", y: 80 }, { label: "PRINTNIGHTMARE", y: 180 }, { label: "OTHER CVEs", y: 300 }] },
  nodes: [
    { id: "vuln_system", label: "Vulnerable System", sub: "Unpatched", x: 60, y: 180, r: 38, type: "entry", desc: "Unpatched system vulnerable to credential-access exploit.", src: "MITRE ATT&CK T1212" },
    { id: "zerologon", label: "ZeroLogon", sub: "CVE-2020-1472", x: 240, y: 80, r: 38, type: "op", desc: "Netlogon AES-CFB8 IV bug: set DC machine password to empty with 256 attempts.", src: "CVE-2020-1472; Secura" },
    { id: "nrpc", label: "MS-NRPC", sub: "NetrServerPasswordSet2", x: 440, y: 80, r: 34, type: "protocol", desc: "DCE/RPC MS-NRPC: NetrServerAuthenticate3 + NetrServerPasswordSet2 with zero IV.", src: "MS-NRPC; CVE-2020-1472" },
    { id: "dc_hash", label: "DC Machine Hash", sub: "Reset to known", x: 640, y: 80, r: 36, type: "artifact", desc: "DC machine account password reset → attacker can DCSync all domain hashes.", src: "CVE-2020-1472; Mimikatz" },
    { id: "printnightmare", label: "PrintNightmare", sub: "CVE-2021-34527", x: 240, y: 180, r: 36, type: "op", desc: "Print Spooler RpcAddPrinterDriverEx: load arbitrary DLL as SYSTEM on remote host.", src: "CVE-2021-34527" },
    { id: "spooler_rpc", label: "MS-RPRN", sub: "AddPrinterDriverEx", x: 440, y: 180, r: 34, type: "protocol", desc: "DCE/RPC MS-RPRN: RpcAddPrinterDriverEx loads attacker DLL with SYSTEM privileges.", src: "MS-RPRN; CVE-2021-34527" },
    { id: "system_dll", label: "SYSTEM DLL", sub: "Code execution", x: 640, y: 180, r: 34, type: "artifact", desc: "DLL executes as SYSTEM → dump LSASS, extract credentials, create admin user.", src: "CVE-2021-34527" },
    { id: "samedit", label: "Baron SamEdit", sub: "CVE-2021-42278/87", x: 240, y: 300, r: 34, type: "op", desc: "CVE-2021-42278 + CVE-2021-42287: rename machine account to match DC → get TGT → S4U2self as admin.", src: "CVE-2021-42278; CVE-2021-42287" },
    { id: "pkinit", label: "PKINIT", sub: "CVE-2022-26923", x: 440, y: 300, r: 34, type: "op", desc: "Certifried: AD CS ESC8 / CVE-2022-26923 — machine account cert → DC impersonation.", src: "CVE-2022-26923; Certifried" },
    { id: "ev_4742", label: "Event 4742", sub: "Computer account change", x: 640, y: 300, r: 36, type: "detect", desc: "Event 4742: Computer account changed. Zerologon resets DC machine password.", src: "Microsoft Event 4742" },
    { id: "patch_status", label: "Patch Monitoring", sub: "Vuln scanning", x: 840, y: 80, r: 36, type: "detect", desc: "OPTIMAL: Continuous vulnerability scanning for known credential-access CVEs.", src: "Vulnerability Management" },
    { id: "sysmon_7", label: "Sysmon 7", sub: "DLL load in spoolsv", x: 840, y: 180, r: 34, type: "detect", desc: "Sysmon EID 7: unsigned DLL loaded by spoolsv.exe.", src: "Sysmon documentation" },
    { id: "domain_creds", label: "Domain Creds", sub: "Full compromise", x: 1040, y: 180, r: 42, type: "artifact", desc: "Full domain credential compromise: all user hashes, Kerberos keys, service account passwords.", src: "MITRE T1212" },
  ],
  edges: [
    { f: "vuln_system", t: "zerologon" }, { f: "vuln_system", t: "printnightmare" },
    { f: "vuln_system", t: "samedit" }, { f: "vuln_system", t: "pkinit" },
    { f: "zerologon", t: "nrpc" }, { f: "nrpc", t: "dc_hash" }, { f: "dc_hash", t: "domain_creds" },
    { f: "printnightmare", t: "spooler_rpc" }, { f: "spooler_rpc", t: "system_dll" }, { f: "system_dll", t: "domain_creds" },
    { f: "samedit", t: "domain_creds" }, { f: "pkinit", t: "domain_creds" },
    { f: "nrpc", t: "ev_4742" }, { f: "zerologon", t: "patch_status" },
    { f: "spooler_rpc", t: "sysmon_7" },
  ],
};
export default model;
