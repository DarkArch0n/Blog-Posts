// T1110.002 — Password Cracking — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1110.002",
    name: "Password Cracking",
    tactic: "Credential Access",
    platform: "Offline (GPU/CPU)",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 440,
    rows: [
      { label: "NTLM",     y: 80 },
      { label: "KERBEROS",  y: 180 },
      { label: "DCC2",      y: 280 },
      { label: "LINUX",     y: 380 },
    ],
    annotations: [
      { text: "ALL cracking is offline — zero network telemetry, zero logs", x: 600, y: 430, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "hash_source", label: "Hash Collection", sub: "From other techniques", x: 60, y: 200, r: 38, type: "entry",
      desc: "Hashes obtained via T1003 (Credential Dumping), T1558 (Kerberoasting), T1557 (MitM), etc.",
      src: "MITRE ATT&CK T1110.002" },

    // Row 1: NTLM hashes
    { id: "ntlm_hash", label: "NT Hash", sub: "MD4(password)", x: 200, y: 80, r: 32, type: "artifact",
      desc: "NT hash from SAM, NTDS, LSASS dump. MD4 of UTF-16LE password. No salt.",
      src: "MITRE T1003" },
    { id: "hashcat_1000", label: "hashcat -m 1000", sub: "~100 GH/s on 4090", x: 380, y: 80, r: 40, type: "blind",
      desc: "BLIND: NTLM is extremely fast. RTX 4090 = ~100 GH/s. 8-char passwords fall in seconds.",
      src: "hashcat.net" },

    // Row 2: Kerberos hashes
    { id: "tgs_hash", label: "$krb5tgs$23$", sub: "RC4 Kerberoast", x: 200, y: 180, r: 34, type: "artifact",
      desc: "Kerberoasted TGS hash (RC4). hashcat mode 13100.",
      src: "MITRE T1558.003" },
    { id: "asrep_hash", label: "$krb5asrep$", sub: "AS-REP Roast", x: 200, y: 240, r: 30, type: "artifact",
      desc: "AS-REP roasted hash. hashcat mode 18200.",
      src: "MITRE T1558.004" },
    { id: "hashcat_13100", label: "hashcat -m 13100", sub: "~1.5 GH/s on 4090", x: 380, y: 180, r: 38, type: "blind",
      desc: "BLIND: RC4 TGS cracking. RTX 4090 = ~1.5 GH/s. Service accounts often have weak passwords.",
      src: "hashcat.net" },
    { id: "hashcat_19700", label: "hashcat -m 19700", sub: "AES TGS ~200 MH/s", x: 560, y: 180, r: 34, type: "blind",
      desc: "BLIND: AES256 TGS cracking (etype 18). Much slower but still viable for weak passwords.",
      src: "hashcat.net; TrustedSec" },

    // Row 3: DCC2
    { id: "dcc2_hash", label: "$DCC2$", sub: "mscachev2", x: 200, y: 280, r: 32, type: "artifact",
      desc: "Domain Cached Credentials v2. PBKDF2 with 10240 iterations.",
      src: "MITRE T1003.005" },
    { id: "hashcat_2100", label: "hashcat -m 2100", sub: "~1.2 MH/s on 4090", x: 380, y: 280, r: 38, type: "blind",
      desc: "BLIND: DCC2 is very slow (10240 iterations). RTX 4090 = ~1.2 MH/s. Only weak passwords fall.",
      src: "hashcat.net" },

    // Row 4: Linux hashes
    { id: "sha512_hash", label: "$6$ SHA-512crypt", x: 200, y: 380, r: 34, type: "artifact",
      desc: "Linux SHA-512crypt from /etc/shadow. 5000 rounds default.",
      src: "MITRE T1003.008" },
    { id: "hashcat_1800", label: "hashcat -m 1800", sub: "~1.5 MH/s on 4090", x: 380, y: 380, r: 38, type: "blind",
      desc: "BLIND: SHA-512crypt cracking. RTX 4090 = ~1.5 MH/s. Intentionally slow.",
      src: "hashcat.net" },

    // ── Attack modes ──
    { id: "wordlist", label: "Wordlist", sub: "rockyou / breach", x: 600, y: 80, r: 34, type: "op",
      desc: "Dictionary attack: rockyou.txt (14M), breach compilations, CrackStation (1.5B).",
      src: "hashcat; SecLists" },
    { id: "rules", label: "Rules Engine", sub: "best64 / dive", x: 740, y: 80, r: 34, type: "op",
      desc: "Rule-based mutations: capitalize, append digits, leet speak. best64.rule, dive.rule.",
      src: "hashcat rule engine" },
    { id: "mask", label: "Mask Attack", sub: "?u?l?l?l?d?d?d?d", x: 600, y: 300, r: 36, type: "op",
      desc: "Brute-force with pattern: ?u?l?l?l?d?d?d?d (Ulll1234). Covers common corporate patterns.",
      src: "hashcat" },
    { id: "combinator", label: "Combinator", sub: "word1+word2", x: 740, y: 300, r: 32, type: "op",
      desc: "Combine two wordlists: Season+Year (Summer2024), Company+Digits.",
      src: "hashcat" },

    // ── Output ──
    { id: "plaintext", label: "Plaintext Passwords", x: 940, y: 200, r: 40, type: "artifact",
      desc: "Recovered plaintext passwords. Can be used for authentication, further attacks, password analysis.",
      src: "MITRE T1110.002" },

    // ── No Detection ──
    { id: "no_detect", label: "NO DETECTION", sub: "Fully offline", x: 1100, y: 200, r: 44, type: "blind",
      desc: "BLIND: All cracking is offline on attacker hardware. Zero network traffic, zero DC events, zero logs.",
      src: "MITRE T1110.002" },
  ],

  edges: [
    // Hash sources
    { f: "hash_source", t: "ntlm_hash" },
    { f: "hash_source", t: "tgs_hash" },
    { f: "hash_source", t: "asrep_hash" },
    { f: "hash_source", t: "dcc2_hash" },
    { f: "hash_source", t: "sha512_hash" },
    // Cracking by type
    { f: "ntlm_hash", t: "hashcat_1000", blind: true },
    { f: "tgs_hash", t: "hashcat_13100", blind: true },
    { f: "tgs_hash", t: "hashcat_19700", blind: true },
    { f: "asrep_hash", t: "hashcat_13100", blind: true },
    { f: "dcc2_hash", t: "hashcat_2100", blind: true },
    { f: "sha512_hash", t: "hashcat_1800", blind: true },
    // Attack modes
    { f: "hashcat_1000", t: "wordlist", blind: true },
    { f: "hashcat_13100", t: "wordlist", blind: true },
    { f: "wordlist", t: "rules", blind: true },
    { f: "hashcat_1000", t: "mask", blind: true },
    { f: "hashcat_13100", t: "combinator", blind: true },
    // Output
    { f: "rules", t: "plaintext", blind: true },
    { f: "mask", t: "plaintext", blind: true },
    { f: "combinator", t: "plaintext", blind: true },
    { f: "plaintext", t: "no_detect", blind: true },
  ],
};

export default model;
