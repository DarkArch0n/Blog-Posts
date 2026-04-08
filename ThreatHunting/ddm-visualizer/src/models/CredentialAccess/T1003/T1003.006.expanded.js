// T1003.006 — DCSync — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1003.006",
    name: "DCSync",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 420,
    rows: [
      { label: "MIMIKATZ",  y: 100 },
      { label: "IMPACKET",  y: 220 },
      { label: "SHARPHOUND", y: 340 },
    ],
    annotations: [
      { text: "Requires DS-Replication-Get-Changes-All to replicate secret data", x: 200, y: 400, color: "#e65100", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "da_creds", label: "Replication", sub: "Privileges", x: 60, y: 180, r: 38, type: "entry",
      desc: "Domain Admin, Enterprise Admin, or any account with DS-Replication-Get-Changes + DS-Replication-Get-Changes-All.",
      src: "MITRE ATT&CK T1003.006" },

    // Row 1: Mimikatz lsadump::dcsync
    { id: "mimi_dcsync", label: "Mimikatz", sub: "lsadump::dcsync /user:", x: 200, y: 100, r: 36, type: "op",
      desc: "Mimikatz DCSync: replicate a single account. /user:krbtgt or /user:Administrator.",
      src: "gentilkiwi/mimikatz" },
    { id: "mimi_all", label: "Mimikatz", sub: "lsadump::dcsync /all", x: 200, y: 160, r: 30, type: "op",
      desc: "DCSync all accounts: /all /csv — replicate entire directory database.",
      src: "gentilkiwi/mimikatz" },
    { id: "drsr_bind", label: "DRSBind", sub: "MS-DRSR", x: 360, y: 100, r: 30, type: "api",
      desc: "IDL_DRSBind() establishes replication context with the DC.",
      src: "Microsoft MS-DRSR" },
    { id: "drsr_getnc", label: "DrsGetNCChanges", x: 500, y: 100, r: 38, type: "api",
      desc: "IDL_DRSGetNCChanges() — the core replication API. Requests AD object changes from DC.",
      src: "Microsoft MS-DRSR" },
    { id: "rpc_135", label: "RPC :135", sub: "+ dynamic port", x: 650, y: 100, r: 30, type: "protocol",
      desc: "MS-DRSR over MSRPC. Initial endpoint mapping on TCP/135, then dynamic high port.",
      src: "RFC 1831; MS-DRSR" },

    // Row 2: Impacket secretsdump
    { id: "imp_dcsync", label: "secretsdump.py", sub: "-just-dc", x: 200, y: 220, r: 36, type: "op",
      desc: "Impacket secretsdump.py -just-dc domain/admin@dc — DCSync from Linux.",
      src: "fortra/impacket" },
    { id: "imp_user", label: "secretsdump.py", sub: "-just-dc-user krbtgt", x: 200, y: 280, r: 34, type: "op",
      desc: "Target single account: -just-dc-user krbtgt for Golden Ticket material.",
      src: "fortra/impacket" },
    { id: "ntlm_auth", label: "NTLM Auth", sub: "or Kerberos -k", x: 360, y: 220, r: 32, type: "protocol",
      desc: "Authentication to DC via NTLM pass-the-hash or Kerberos (-k) before replication.",
      src: "Impacket; MS-NLMP" },
    { id: "drsr_getnc_2", label: "DrsGetNCChanges", x: 500, y: 220, r: 36, type: "api",
      desc: "Same MS-DRSR DrsGetNCChanges() API — protocol is identical from Impacket.",
      src: "Microsoft MS-DRSR" },

    // Row 3: BloodHound recon (find accounts with replication rights)
    { id: "bloodhound", label: "SharpHound", sub: "Recon", x: 200, y: 340, r: 30, type: "op",
      desc: "BloodHound identifies accounts with DCSync rights via ACL enumeration.",
      src: "BloodHoundAD/SharpHound" },
    { id: "dacl_enum", label: "DACL Enum", sub: "DS-Replication ACE", x: 360, y: 340, r: 34, type: "api",
      desc: "Enumerate DACLs on domain root for DS-Replication-Get-Changes-All (GUID 1131f6ad-...)",
      src: "Microsoft DACL; BloodHound" },

    // ── DC Processing ──
    { id: "dc_ntds", label: "DC NTDS Engine", sub: "Process replication", x: 800, y: 160, r: 44, type: "system",
      desc: "DC's NTDS engine processes DrsGetNCChanges. Returns requested AD objects with unicodePwd attribute.",
      src: "Microsoft AD; MS-DRSR" },

    // ── Detection ──
    { id: "ev_4662", label: "Event 4662", sub: "DS-Replication", x: 960, y: 80, r: 44, type: "detect",
      desc: "OPTIMAL: Event 4662 on DC. Property: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} = DS-Replication-Get-Changes-All. Source != DC machine account.",
      src: "Microsoft Event 4662; MITRE T1003.006" },
    { id: "ev_4624", label: "Event 4624", sub: "Logon from non-DC", x: 960, y: 180, r: 34, type: "detect",
      desc: "Event 4624 on DC: Network logon from workstation (non-DC) followed by replication events.",
      src: "Microsoft Event 4624" },
    { id: "mdi_dcsync", label: "MDI Alert", sub: "Suspicious replication", x: 960, y: 280, r: 38, type: "detect",
      desc: "Microsoft Defender for Identity detects DCSync from non-DC source IP addresses.",
      src: "Microsoft Defender for Identity" },

    // ── Network Detection ──
    { id: "zeek_drsr", label: "Zeek / IDS", sub: "MS-DRSR traffic", x: 800, y: 320, r: 34, type: "detect",
      desc: "Network IDS can detect MS-DRSR traffic from non-DC sources via RPC UUID monitoring.",
      src: "Zeek; Suricata; Corelight" },

    // ── Output ──
    { id: "ntlm_hashes", label: "NTLM Hashes", sub: "All accounts", x: 1140, y: 100, r: 36, type: "artifact",
      desc: "NTLM hashes for all replicated accounts. user:RID:LM:NT format.",
      src: "MITRE T1003.006" },
    { id: "krbtgt", label: "krbtgt Hash", sub: "→ T1558.001", x: 1140, y: 200, r: 34, type: "artifact",
      desc: "krbtgt hash enables Golden Ticket (T1558.001). Primary target for DCSync.",
      src: "MITRE T1558.001" },
    { id: "cleartext", label: "Cleartext", sub: "Reversible encryption", x: 1140, y: 300, r: 32, type: "artifact",
      desc: "Cleartext passwords for accounts with 'Store password using reversible encryption' enabled.",
      src: "MITRE T1003.006" },
    { id: "kerb_keys", label: "Kerberos Keys", sub: "AES256 + DES", x: 1300, y: 200, r: 32, type: "artifact",
      desc: "Kerberos AES256, AES128, DES keys for pass-the-key / overpass-the-hash.",
      src: "MITRE T1003.006" },
  ],

  edges: [
    // Mimikatz
    { f: "da_creds", t: "mimi_dcsync" },
    { f: "da_creds", t: "mimi_all" },
    { f: "mimi_dcsync", t: "drsr_bind" },
    { f: "mimi_all", t: "drsr_bind" },
    { f: "drsr_bind", t: "drsr_getnc" },
    { f: "drsr_getnc", t: "rpc_135" },
    { f: "rpc_135", t: "dc_ntds" },
    // Impacket
    { f: "da_creds", t: "imp_dcsync" },
    { f: "da_creds", t: "imp_user" },
    { f: "imp_dcsync", t: "ntlm_auth" },
    { f: "imp_user", t: "ntlm_auth" },
    { f: "ntlm_auth", t: "drsr_getnc_2" },
    { f: "drsr_getnc_2", t: "dc_ntds" },
    // Recon
    { f: "da_creds", t: "bloodhound" },
    { f: "bloodhound", t: "dacl_enum" },
    // Detection
    { f: "dc_ntds", t: "ev_4662" },
    { f: "dc_ntds", t: "ev_4624" },
    { f: "dc_ntds", t: "mdi_dcsync" },
    { f: "rpc_135", t: "zeek_drsr" },
    // Output
    { f: "dc_ntds", t: "ntlm_hashes" },
    { f: "dc_ntds", t: "krbtgt" },
    { f: "dc_ntds", t: "cleartext" },
    { f: "dc_ntds", t: "kerb_keys" },
  ],
};

export default model;
