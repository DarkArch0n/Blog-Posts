// T1110.002 — Password Cracking — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1110.002",
    name: "Password Cracking",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "HASH SOURCE",  x: 80  },
      { label: "HASH TYPE",    x: 260 },
      { label: "DETECTION",    x: 440 },
      { label: "CRACK METHOD", x: 630 },
      { label: "OUTCOME",      x: 860 },
    ],
    separators: [170, 350, 535, 745],
    annotations: [
      { text: "⚠ Cracking is entirely offline — BLIND", x: 630, y: 420, color: "#c62828", fontStyle: "italic" },
      { text: "Detection window = hash acquisition phase only", x: 440, y: 400, color: "#f57f17", fontWeight: "600" },
    ],
  },

  nodes: [
    { id: "sam_dump", label: "SAM Dump", sub: "T1003.002", x: 80, y: 100, r: 34, type: "source",
      tags: ["SAM database", "reg save", "Local hashes"],
      telemetry: ["4688"],
      api: "SAM database extraction → local account NTLM hashes",
      artifact: "Process creation for reg.exe save · registry access",
      desc: "Local NTLM hashes extracted from SAM database (T1003.002). Quick to crack — raw NTLM with no salt. hashcat mode 1000.",
      src: "MITRE T1003.002" },

    { id: "ntds_dump", label: "NTDS.dit", sub: "T1003.003", x: 80, y: 230, r: 34, type: "source",
      tags: ["NTDS.dit", "Domain hashes", "All accounts"],
      telemetry: ["4688"],
      api: "NTDS.dit extraction → all domain account NTLM hashes",
      artifact: "ntdsutil/vssadmin process creation · VSS events",
      desc: "All domain account NTLM hashes extracted from NTDS.dit (T1003.003). Same raw NTLM format — hashcat mode 1000. Contains every account in the domain.",
      src: "MITRE T1003.003" },

    { id: "kerb_hash", label: "Kerberos Hash", sub: "T1558.003/.004", x: 80, y: 360, r: 34, type: "source",
      tags: ["Kerberoasting", "AS-REP Roasting", "TGS-REP/AS-REP"],
      telemetry: ["4769", "4768"],
      api: "Kerberoast (TGS-REP) or AS-REP Roast → Kerberos encrypted material",
      artifact: "Event 4769/4768 with RC4 encryption · service ticket requests",
      desc: "Kerberos service ticket or AS-REP encrypted material (T1558.003, T1558.004). hashcat modes 13100 (TGS-REP) and 18200 (AS-REP). Slower to crack than NTLM due to additional crypto rounds.",
      src: "MITRE T1558.003; T1558.004" },

    { id: "hash_type", label: "Hash Format", sub: "Algorithm ID", x: 260, y: 230, r: 38, type: "source",
      tags: ["NTLM ($NT$)", "NTLMv2 ($NTLMv2$)", "Kerberos 5", "SHA-512crypt"],
      telemetry: [],
      api: "Hash algorithm determines cracking speed: NTLM=fast, Kerberos=medium, bcrypt=slow",
      artifact: "Hash algorithm identification determines attack feasibility and tooling",
      desc: "Hash type determines cracking speed. NTLM (mode 1000): ~100 GH/s on GPU — extremely fast. Net-NTLMv2 (mode 5600): ~10 GH/s — medium. Kerberos 5 TGS-REP (mode 13100): ~1 GH/s. SHA-512crypt (mode 1800): ~1 MH/s — very slow. DCC2 (mode 2100): ~500 KH/s — extremely slow.",
      src: "hashcat benchmark data; NIST SP 800-63B" },

    { id: "ev_detect", label: "Hash Acquisition", sub: "Detect Source", x: 440, y: 230, r: 50, type: "detect",
      tags: ["Detect the dump", "Not the crack", "T1003 detection", "T1558 detection"],
      telemetry: ["4688", "4769", "Sysmon 10"],
      api: "Detection opportunity is during HASH ACQUISITION — not during cracking",
      artifact: "OPTIMAL: Detect hash acquisition (T1003/T1558 techniques) — cracking itself is invisible",
      desc: "OPTIMAL DETECTION NODE. Password cracking itself is ENTIRELY OFFLINE — zero telemetry. The detection window exists only during hash acquisition. Focus detection on the source technique: T1003 (Sysmon 10, 4688, 4662 for credential dumping) or T1558 (4769/4768 for Kerberoasting). Once hashes are exfiltrated, cracking is undetectable. Post-compromise: detect credential USE via anomalous 4624 logon patterns.",
      src: "MITRE T1110.002; defense-in-depth via source technique detection" },

    { id: "hashcat", label: "hashcat", sub: "GPU cracking", x: 630, y: 140, r: 36, type: "blind",
      tags: ["hashcat", "GPU acceleration", "Rules/masks", "100+ GH/s NTLM"],
      telemetry: [],
      api: "hashcat -m <mode> -a 0/3 hashes.txt wordlist/mask — GPU-accelerated cracking",
      artifact: "⚠ BLIND — runs on attacker's GPU(s) · zero target or network telemetry",
      desc: "BLIND SPOT. hashcat performs GPU-accelerated password cracking. Supports 350+ hash algorithms. Attack modes: dictionary (-a 0), combinator (-a 1), mask/brute-force (-a 3), rule-based. Multi-GPU support via -d. Modern GPUs achieve 100+ GH/s for NTLM. Entirely offline — undetectable.",
      src: "hashcat.net; GPU benchmark data" },

    { id: "john", label: "John the Ripper", sub: "CPU cracking", x: 630, y: 330, r: 36, type: "blind",
      tags: ["John the Ripper", "CPU mode", "Jumbo patch", "Auto-detect"],
      telemetry: [],
      api: "john --wordlist=rockyou.txt hashes.txt · auto-detects format · rule-based mutations",
      artifact: "⚠ BLIND — runs on attacker's CPU · zero target telemetry",
      desc: "BLIND SPOT. John the Ripper provides CPU-based cracking with auto-format detection. Jumbo patch adds extensive format support. Incremental mode tries all character combinations. Wordlist + rules provides efficient coverage. Slower than hashcat for GPU-friendly algorithms.",
      src: "openwall.com/john; JtR Jumbo" },

    { id: "plaintext", label: "Plaintext", sub: "Passwords", x: 860, y: 230, r: 40, type: "source",
      tags: ["Cracked passwords", "PtH not needed", "Direct authentication"],
      telemetry: [],
      api: "Recovered plaintext passwords for victim accounts",
      artifact: "Plaintext credentials → direct logon, lateral movement, privilege escalation",
      desc: "Cracked passwords enable direct authentication (no Pass-the-Hash needed). Plaintext passwords may also be reused across systems, cloud services, and personal accounts (credential stuffing). Stronger than hash-based access as it works through any authentication protocol.",
      src: "MITRE T1110.002" },
  ],

  edges: [
    { f: "sam_dump", t: "hash_type" },
    { f: "ntds_dump", t: "hash_type" },
    { f: "kerb_hash", t: "hash_type" },
    { f: "sam_dump", t: "ev_detect" },
    { f: "ntds_dump", t: "ev_detect" },
    { f: "kerb_hash", t: "ev_detect" },
    { f: "hash_type", t: "hashcat", blind: true },
    { f: "hash_type", t: "john", blind: true },
    { f: "hashcat", t: "plaintext", blind: true },
    { f: "john", t: "plaintext", blind: true },
  ],
};

export default model;
