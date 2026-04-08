// T1558.004 — AS-REP Roasting — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1558.004",
    name: "AS-REP Roasting",
    tactic: "Credential Access",
    platform: "Windows Active Directory",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1500,
    svgHeight: 480,
    rows: [
      { label: "RUBEUS",   y: 100 },
      { label: "IMPACKET", y: 200 },
      { label: "HASHCAT",  y: 360, color: "#c62828" },
    ],
    annotations: [
      { text: "No password needed - pre-auth disabled accounts respond to anyone", x: 300, y: 440, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    // ── Entry ──
    { id: "attacker", label: "Any Network", sub: "Access", x: 60, y: 150, r: 36, type: "entry",
      desc: "No domain credentials required for AS-REP roasting — just network access to the DC on port 88.",
      src: "MITRE ATT&CK T1558.004" },

    // ── Enumeration ──
    { id: "enum_nopreauth", label: "Enum Users", sub: "DONT_REQ_PREAUTH", x: 180, y: 100, r: 34, type: "op",
      desc: "Enumerate accounts with 'Do not require Kerberos pre-authentication' (UAC 0x400000) set.",
      src: "MITRE T1558.004; PowerView" },
    { id: "ldap_query", label: "LDAP Query", sub: "UAC filter", x: 310, y: 100, r: 30, type: "api",
      desc: "LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=4194304) finds accounts with no pre-auth.",
      src: "Microsoft LDAP; PowerView Get-DomainUser" },

    // Row 1: Rubeus path
    { id: "rubeus_asrep", label: "Rubeus", sub: "asreproast", x: 440, y: 100, r: 34, type: "op",
      desc: "Rubeus asreproast /user:<user> — sends AS-REQ without pre-auth data.",
      src: "GhostPack/Rubeus" },
    { id: "asn1_asreq", label: "Build AS-REQ", sub: "No PA-DATA", x: 570, y: 100, r: 32, type: "api",
      desc: "Construct AS-REQ without PA-ENC-TIMESTAMP pre-authentication data.",
      src: "RFC 4120; Rubeus" },
    { id: "krb_88_1", label: "AS-REQ", sub: "port 88", x: 700, y: 100, r: 28, type: "protocol",
      desc: "KRB_AS_REQ sent to DC port 88 without pre-authentication.",
      src: "RFC 4120" },

    // Row 2: Impacket path
    { id: "imp_asrep", label: "GetNPUsers", sub: ".py", x: 440, y: 200, r: 34, type: "op",
      desc: "Impacket GetNPUsers.py — sends AS-REQ for accounts without pre-auth. Works remotely.",
      src: "fortra/impacket" },
    { id: "raw_asreq", label: "Raw AS-REQ", sub: "kerberosv5.py", x: 570, y: 200, r: 32, type: "api",
      desc: "Impacket constructs raw AS-REQ bypassing Windows APIs. Can specify etype preference.",
      src: "Impacket kerberosv5.py" },
    { id: "krb_88_2", label: "AS-REQ", sub: "port 88", x: 700, y: 200, r: 28, type: "protocol",
      desc: "KRB_AS_REQ from Linux/remote host to DC port 88.",
      src: "RFC 4120" },

    // ── DC Processing ──
    { id: "kdc", label: "KDC Service", x: 830, y: 150, r: 40, type: "system",
      desc: "KDC receives AS-REQ without pre-auth. Since pre-auth is not required for this account, it responds.",
      src: "Microsoft KDC; RFC 4120" },
    { id: "encrypt_asrep", label: "Encrypt AS-REP", sub: "(user key)", x: 960, y: 100, r: 34, type: "api",
      desc: "KDC encrypts part of AS-REP with user's password-derived key — this is the crackable material.",
      src: "RFC 4120; MS-KILE" },
    { id: "ev_4768", label: "Event 4768", sub: "TGT Issued", x: 960, y: 220, r: 40, type: "detect",
      desc: "OPTIMAL: Event 4768 with pre-auth type 0 (no pre-auth). Filter: PreAuthType=0, TicketEncryptionType.",
      src: "Microsoft Event 4768; MITRE T1558.004" },

    // ── Response ──
    { id: "as_rep", label: "AS-REP", sub: "port 88", x: 1100, y: 150, r: 30, type: "protocol",
      desc: "KRB_AS_REP returned — contains enc-part encrypted with user's password hash.",
      src: "RFC 4120" },

    // ── Hash extraction ──
    { id: "hash_extract", label: "Extract Hash", sub: "$krb5asrep$", x: 1230, y: 150, r: 36, type: "op",
      desc: "Rubeus/Impacket extract the enc-part into hashcat-ready format: $krb5asrep$23$user@domain",
      src: "hashcat; HackTricks" },

    // ── Offline cracking (BLIND) ──
    { id: "hash_asrep", label: "$krb5asrep$23$", x: 1230, y: 360, r: 36, type: "artifact",
      desc: "AS-REP hash in hashcat format. RC4 etype = fast GPU cracking.",
      src: "hashcat wiki" },
    { id: "hashcat", label: "hashcat", sub: "-m 18200", x: 1380, y: 360, r: 40, type: "blind",
      desc: "BLIND: Offline GPU cracking. hashcat -m 18200. Zero network traffic, zero logs.",
      src: "hashcat.net" },
    { id: "plaintext", label: "Plaintext Pwd", x: 1450, y: 200, r: 34, type: "artifact",
      desc: "User's plaintext password recovered from cracked AS-REP hash.",
      src: "MITRE T1558.004" },
  ],

  edges: [
    // Enumeration
    { f: "attacker", t: "enum_nopreauth" },
    { f: "enum_nopreauth", t: "ldap_query" },
    // Rubeus path
    { f: "ldap_query", t: "rubeus_asrep" },
    { f: "rubeus_asrep", t: "asn1_asreq" },
    { f: "asn1_asreq", t: "krb_88_1" },
    { f: "krb_88_1", t: "kdc" },
    // Impacket path
    { f: "attacker", t: "imp_asrep" },
    { f: "imp_asrep", t: "raw_asreq" },
    { f: "raw_asreq", t: "krb_88_2" },
    { f: "krb_88_2", t: "kdc" },
    // DC processing
    { f: "kdc", t: "encrypt_asrep" },
    { f: "kdc", t: "ev_4768" },
    { f: "encrypt_asrep", t: "as_rep" },
    { f: "ev_4768", t: "as_rep" },
    // Response
    { f: "as_rep", t: "hash_extract" },
    { f: "hash_extract", t: "hash_asrep" },
    // Cracking (blind)
    { f: "hash_asrep", t: "hashcat", blind: true },
    { f: "hashcat", t: "plaintext", blind: true },
  ],
};

export default model;
