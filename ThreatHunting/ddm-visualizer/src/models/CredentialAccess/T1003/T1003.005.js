// T1003.005 — Cached Domain Credentials — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1003.005",
    name: "Cached Domain Credentials",
    tactic: "Credential Access",
    platform: "Windows",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 480,
    columns: [
      { label: "PREREQUISITE", x: 80  },
      { label: "DUMP METHOD",  x: 270 },
      { label: "DETECTION",    x: 490 },
      { label: "CRACK",        x: 700 },
      { label: "OUTCOME",      x: 880 },
    ],
    separators: [175, 380, 595, 790],
    annotations: [
      { text: "DCC2 — extremely slow to crack", x: 700, y: 390, color: "#c62828", fontStyle: "italic" },
      { text: "Works offline — no DC needed", x: 270, y: 410, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "admin", label: "Local Admin", sub: "or SYSTEM", x: 80, y: 230, r: 40, type: "source",
      tags: ["Local admin", "SYSTEM", "No DC connectivity needed"],
      telemetry: [],
      api: "Requires SYSTEM or local admin — NO domain controller connectivity required",
      artifact: "Privileged local session · works fully offline",
      desc: "Cached domain credentials are stored locally in the SECURITY registry hive. Extraction requires SYSTEM privileges but does NOT require connectivity to a Domain Controller — ideal for disconnected/offline scenarios. Windows caches the last 10 domain logons by default (configurable via CachedLogonsCount).",
      src: "MITRE ATT&CK T1003.005; Microsoft CachedLogonsCount" },

    { id: "mimi_cache", label: "Mimikatz", sub: "lsadump::cache", x: 270, y: 100, r: 36, type: "source",
      tags: ["lsadump::cache", "token::elevate", "MSCACHEV2"],
      telemetry: ["Sysmon 1"],
      api: "token::elevate → lsadump::cache — reads cached logon hashes from SECURITY hive",
      artifact: "Sysmon EID 1: mimikatz · cached domain credential extraction",
      desc: "Mimikatz lsadump::cache reads cached domain logon credentials from the SECURITY registry hive. Outputs DCC2 (Domain Cached Credentials v2 / MSCACHEV2) hashes for the last N domain logons. These hashes are salted with the username.",
      src: "gentilkiwi/mimikatz; adsecurity.org" },

    { id: "secretsdump_cache", label: "secretsdump", sub: "CACHED", x: 270, y: 240, r: 36, type: "source",
      tags: ["secretsdump.py", "-security -system", "MSCACHE output"],
      telemetry: [],
      api: "secretsdump.py -security security.hiv -system system.hiv LOCAL → MSCACHE section",
      artifact: "Parsed from exported SECURITY + SYSTEM hives · MSCACHE entries",
      desc: "Impacket secretsdump.py extracts cached credentials from exported SECURITY + SYSTEM hive files. Outputs entries in the format domain\\user:$DCC2$iterations#username#hash. Also works remotely via SMB with admin credentials.",
      src: "Impacket — github.com/fortra/impacket" },

    { id: "cachedump", label: "cachedump", sub: "Standalone", x: 270, y: 370, r: 34, type: "source",
      tags: ["cachedump.exe", "Standalone tool", "No dependencies"],
      telemetry: ["Sysmon 1"],
      api: "cachedump.exe — standalone binary to extract cached domain credentials",
      artifact: "Sysmon EID 1: cachedump.exe process creation",
      desc: "Standalone tool specifically designed to extract cached domain logon credentials. Older but still functional. Easier to detect due to unique binary name. Modern attackers typically prefer Mimikatz or secretsdump.",
      src: "cachedump by arnezami; MITRE T1003.005" },

    { id: "ev_detect", label: "Registry + Proc", sub: "Multi-source", x: 490, y: 230, r: 50, type: "detect",
      tags: ["Sysmon 1", "4688", "4657", "SECURITY hive access"],
      telemetry: ["Sysmon 1", "4688", "4657"],
      api: "Process creation monitoring + registry access auditing on SECURITY\\Cache",
      artifact: "OPTIMAL: Sysmon 1 for mimikatz/cachedump · Event 4657 on SECURITY\\Cache key access",
      desc: "OPTIMAL DETECTION NODE. (1) Sysmon EID 1 / Event 4688: mimikatz with lsadump::cache, cachedump.exe, or reg.exe save HKLM\\SECURITY. (2) Event 4657: Audit SECURITY\\Cache registry key access (requires SACL). (3) Correlate: non-DC process accessing SECURITY hive Cache subkey. (4) EDR cached credential dumping detections.",
      src: "MITRE T1003.005; Sigma rules; CIS benchmark" },

    { id: "dcc2_crack", label: "hashcat", sub: "-m 2100", x: 700, y: 230, r: 40, type: "blind",
      tags: ["hashcat -m 2100", "PBKDF2", "10240 iterations", "Very slow"],
      telemetry: [],
      api: "hashcat -m 2100 dcc2_hashes.txt wordlist.txt — DCC2 = PBKDF2(NTLM, username, 10240)",
      artifact: "⚠ Offline cracking — zero target telemetry · DCC2 is ~1000x slower than NTLM",
      desc: "BLIND SPOT. DCC2 hashes use PBKDF2 with 10240 iterations of HMAC-SHA1 over the NTLM hash, salted with the lowercase username. This makes cracking approximately 1000x slower than raw NTLM hashes. hashcat mode 2100 handles DCC2. Weak passwords are still crackable but strong passwords may be infeasible.",
      src: "hashcat documentation; Microsoft MSCACHEV2 specification" },

    { id: "domain_creds", label: "Domain Creds", sub: "Plaintext", x: 880, y: 230, r: 38, type: "source",
      tags: ["Domain passwords", "DA potential", "Last 10 logons"],
      telemetry: [],
      api: "Cracked passwords for domain accounts that previously logged onto this machine",
      artifact: "Plaintext domain passwords → direct authentication · no PtH possible with DCC2",
      desc: "Successfully cracked DCC2 hashes yield plaintext passwords for domain accounts that previously authenticated to this workstation. Note: DCC2 hashes CANNOT be used for Pass-the-Hash — they must be cracked to plaintext first. The accounts recovered are whoever last logged into this specific machine (last 10 by default).",
      src: "MITRE T1003.005" },
  ],

  edges: [
    { f: "admin", t: "mimi_cache" },
    { f: "admin", t: "secretsdump_cache" },
    { f: "admin", t: "cachedump" },
    { f: "mimi_cache", t: "ev_detect" },
    { f: "secretsdump_cache", t: "ev_detect" },
    { f: "cachedump", t: "ev_detect" },
    { f: "ev_detect", t: "dcc2_crack" },
    { f: "dcc2_crack", t: "domain_creds", blind: true },
  ],
};

export default model;
