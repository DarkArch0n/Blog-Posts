// T1556.004 — Network Device Authentication — Detection Data Model
// Tactic: Credential Access / Persistence

const model = {
  metadata: {
    tcode: "T1556.004",
    name: "Network Device Authentication",
    tactic: "Credential Access",
    platform: "Network",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "DEVICE ACCESS",  x: 80 },
      { label: "MODIFICATION",  x: 270 },
      { label: "DETECTION",     x: 480 },
      { label: "OUTCOME",       x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "device_admin", label: "Device Admin", sub: "Enable/root", x: 80, y: 200, r: 38, type: "source",
      tags: ["Router admin", "Switch admin", "Firewall admin", "SNMP RW"],
      telemetry: [],
      api: "Administrative access to network device (enable/config mode, SNMP RW, API)",
      artifact: "Admin session on network device via SSH/console/SNMP/API",
      desc: "Modifying network device authentication requires enable/config mode access on routers, switches, or firewalls. Access vectors: stolen credentials, default passwords, SNMP RW community strings, API tokens, or lateral movement from a management station.",
      src: "MITRE ATT&CK T1556.004" },

    { id: "mod_os", label: "Modify OS Image", sub: "Backdoor IOS", x: 270, y: 120, r: 38, type: "source",
      tags: ["Modified IOS", "Custom firmware", "SYNful Knock", "Implant"],
      telemetry: [],
      api: "Patch router OS image with backdoor authentication — accepts hidden password",
      artifact: "Modified firmware image · different hash than vendor image · hidden backdoor account",
      desc: "Attacker modifies the network device OS image (Cisco IOS, JunOS, etc.) to include a backdoor authentication mechanism. Example: SYNful Knock implant modified Cisco IOS to accept a backdoor password via crafted TCP packets. The modified image persists across reboots.",
      src: "MITRE T1556.004; Mandiant SYNful Knock analysis; Cisco PSIRT" },

    { id: "add_account", label: "Add Account", sub: "Hidden user", x: 270, y: 310, r: 34, type: "source",
      tags: ["Hidden admin user", "TACACS bypass", "Local account"],
      telemetry: [],
      api: "username backdoor privilege 15 secret <hash> · hidden from show commands",
      artifact: "New local admin account on device · may not appear in standard 'show' output",
      desc: "Simpler method: add a hidden local admin account to the device configuration, potentially configured to bypass TACACS+/RADIUS AAA so it authenticates locally even when centralized auth is configured. Some implants hide the account from standard 'show running-config' output.",
      src: "MITRE T1556.004" },

    { id: "ev_detect", label: "FW Integrity", sub: "Config audit", x: 480, y: 200, r: 50, type: "detect",
      tags: ["Firmware hash verify", "Config diff", "AAA logging", "Image integrity"],
      telemetry: [],
      api: "Verify firmware hash against vendor baseline + regular config audits + AAA logging",
      artifact: "OPTIMAL: Firmware hash mismatch · unexpected config changes · unknown user accounts · AAA bypass",
      desc: "OPTIMAL DETECTION NODE. (1) Firmware integrity: compare running image hash against known-good vendor hash. (2) Configuration audit: regular diff of running-config against approved baseline — detect new accounts, AAA changes. (3) AAA logging: monitor for local auth bypass when centralized auth is configured. (4) Secure boot: enable if supported. (5) PREVENTION: Signed firmware enforcement, configuration management, TACACS+ accounting.",
      src: "MITRE T1556.004; Cisco IOS integrity verification; CIS Benchmarks" },

    { id: "persistent", label: "Network Access", sub: "Persistent backdoor", x: 730, y: 200, r: 40, type: "source",
      tags: ["Persistent device access", "Network pivot", "Traffic interception"],
      telemetry: [],
      api: "Persistent admin access to network device — survives reboots if OS image is modified",
      artifact: "Backdoor access to routing/switching/firewall infrastructure",
      desc: "Provides persistent administrative access to network infrastructure. Enables: traffic interception, route modification, ACL manipulation, tunnel creation for lateral movement, and pivoting deeper into the network. Impact is severe — network devices control all traffic flow.",
      src: "MITRE T1556.004" },
  ],

  edges: [
    { f: "device_admin", t: "mod_os" },
    { f: "device_admin", t: "add_account" },
    { f: "mod_os", t: "ev_detect" },
    { f: "add_account", t: "ev_detect" },
    { f: "ev_detect", t: "persistent" },
  ],
};

export default model;
