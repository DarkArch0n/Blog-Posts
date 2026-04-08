// T1556.004 — Network Device Authentication — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1556.004", name: "Network Device Authentication", tactic: "Credential Access", platform: "Network Devices", version: "v1.0" },
  layout: { svgWidth: 1300, svgHeight: 300, rows: [{ label: "IOS PATCH", y: 80 }, { label: "FIRMWARE", y: 200 }] },
  nodes: [
    { id: "device_admin", label: "Device Admin", sub: "Enable access", x: 60, y: 130, r: 36, type: "entry", desc: "Administrative access to network device (router, switch, firewall). Enable/privilege 15.", src: "MITRE ATT&CK T1556.004" },
    { id: "ios_implant", label: "IOS Implant", sub: "SYNful Knock", x: 220, y: 80, r: 36, type: "op", desc: "Modified IOS image: SYNful Knock implant adds backdoor password to Cisco router OS.", src: "Mandiant/FireEye; MITRE T1556.004" },
    { id: "modify_auth", label: "Modify Auth", sub: "enable/local db", x: 400, y: 80, r: 34, type: "op", desc: "Add hidden local user or modify TACACS+/RADIUS config to accept attacker credentials.", src: "MITRE T1556.004" },
    { id: "cli_exec", label: "CLI Exec", sub: "conf t", x: 560, y: 80, r: 30, type: "protocol", desc: "Device CLI configuration: username backdoor privilege 15 secret <hash>", src: "Cisco IOS CLI" },
    { id: "firmware_mod", label: "Firmware Mod", sub: "Flash replacement", x: 220, y: 200, r: 36, type: "op", desc: "Replace device firmware/IOS image with modified version containing authentication backdoor.", src: "MITRE T1556.004" },
    { id: "tftp_upload", label: "TFTP/SCP", sub: "Image upload", x: 400, y: 200, r: 30, type: "protocol", desc: "Upload modified firmware image via TFTP/SCP to device flash.", src: "MITRE T1542.001" },
    { id: "config_diff", label: "Config Diff", sub: "RANCID/Oxidized", x: 560, y: 200, r: 38, type: "detect", desc: "OPTIMAL: Network config management (RANCID, Oxidized) detects configuration changes.", src: "RANCID; Oxidized" },
    { id: "snmp_baseline", label: "SNMP/Syslog", sub: "Auth changes", x: 560, y: 270, r: 34, type: "detect", desc: "Syslog messages for configuration changes, new user additions, firmware updates.", src: "Cisco syslog" },
    { id: "hash_verify", label: "Image Hash", sub: "Verify firmware", x: 400, y: 270, r: 30, type: "detect", desc: "Verify firmware hash against known-good: verify /md5 flash:ios.bin", src: "Cisco IOS" },
    { id: "backdoor", label: "Device Backdoor", x: 740, y: 130, r: 36, type: "artifact", desc: "Persistent backdoor access to network device. High-impact: controls network traffic.", src: "MITRE T1556.004" },
  ],
  edges: [
    { f: "device_admin", t: "ios_implant" }, { f: "device_admin", t: "modify_auth" },
    { f: "ios_implant", t: "cli_exec" }, { f: "modify_auth", t: "cli_exec" },
    { f: "device_admin", t: "firmware_mod" }, { f: "firmware_mod", t: "tftp_upload" },
    { f: "cli_exec", t: "config_diff" }, { f: "tftp_upload", t: "hash_verify" },
    { f: "cli_exec", t: "snmp_baseline" },
    { f: "cli_exec", t: "backdoor" }, { f: "tftp_upload", t: "backdoor" },
  ],
};
export default model;
