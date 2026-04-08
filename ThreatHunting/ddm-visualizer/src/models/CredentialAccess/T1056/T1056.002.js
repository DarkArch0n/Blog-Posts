// T1056.002 — GUI Input Capture — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1056.002",
    name: "GUI Input Capture",
    tactic: "Credential Access",
    platform: "Windows, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 920,
    svgHeight: 420,
    columns: [
      { label: "LURE METHOD",  x: 80 },
      { label: "FAKE PROMPT",  x: 270 },
      { label: "DETECTION",    x: 480 },
      { label: "OUTCOME",      x: 730 },
    ],
    separators: [175, 375, 605],
  },

  nodes: [
    { id: "fake_uac", label: "Fake UAC", sub: "Prompt clone", x: 80, y: 120, r: 36, type: "source",
      tags: ["Fake UAC prompt", "FakeLogonScreen", "CredUI clone"],
      telemetry: ["Sysmon 1"],
      api: "Custom application mimics Windows UAC or login prompts to harvest credentials",
      artifact: "Sysmon EID 1: FakeLogonScreen or custom prompt process · non-standard window class",
      desc: "Attacker deploys a fake UAC or login prompt that mimics the legitimate Windows credential dialog. User enters their password believing it's a real system prompt. Tools: FakeLogonScreen, SharpLocker. The fake prompt captures credentials and passes them to the attacker.",
      src: "MITRE ATT&CK T1056.002; Arvanaghi/FakeLogonScreen" },

    { id: "fake_osascript", label: "osascript", sub: "macOS dialog", x: 80, y: 260, r: 34, type: "source",
      tags: ["osascript", "display dialog", "AppleScript prompt", "macOS"],
      telemetry: ["es_log"],
      api: "osascript -e 'display dialog \"Enter password\" default answer \"\" with hidden answer'",
      artifact: "Process: osascript with 'display dialog' · credential prompt from non-system source",
      desc: "On macOS, osascript can display native-looking password dialogs via AppleScript. The dialog can mimic system authentication prompts. The entered password is captured by the script. Common in macOS malware and red team operations.",
      src: "MITRE T1056.002; macOS AppleScript" },

    { id: "web_phish", label: "Local Phish", sub: "Browser popup", x: 80, y: 400, r: 34, type: "source",
      tags: ["In-browser popup", "JavaScript prompt", "Browser-in-browser"],
      telemetry: [],
      api: "JavaScript-based fake login dialogs or 'browser-in-the-browser' phishing overlays",
      artifact: "Web-based credential prompt · rendered as part of compromised page",
      desc: "Attacker uses JavaScript to create convincing login popups or 'browser-in-the-browser' (BitB) overlays that look like legitimate OAuth/SSO login windows. The victim enters credentials into the attacker-controlled form. Particularly effective for OAuth/SSO flows where popups are expected.",
      src: "MITRE T1056.002; mrd0x/BITB" },

    { id: "prompt", label: "User Enters", sub: "Credentials", x: 270, y: 220, r: 40, type: "source",
      tags: ["User types password", "Credential harvested", "Social engineering"],
      telemetry: [],
      api: "User believes prompt is legitimate and enters their domain/local/cloud password",
      artifact: "Password entered into attacker-controlled input · captured in script/process memory",
      desc: "The user, believing the prompt is legitimate, enters their password. The credentials are captured by the attacker's code and either stored locally, exfiltrated via C2, or used immediately for authentication. No brute forcing needed — the user directly provides the credential.",
      src: "MITRE T1056.002" },

    { id: "ev_detect", label: "Process + UI", sub: "Anomaly detect", x: 480, y: 220, r: 50, type: "detect",
      tags: ["Non-system credential UI", "osascript dialog", "Window class mismatch", "EDR"],
      telemetry: ["Sysmon 1", "es_log"],
      api: "Detect non-system processes presenting credential UIs · osascript credential prompts",
      artifact: "OPTIMAL: Non-system process with CredUI window · osascript display dialog · EDR prompt detection",
      desc: "OPTIMAL DETECTION NODE. (1) Windows: Credential prompts from processes other than consent.exe (UAC), LogonUI.exe, or CredentialUIBroker.exe are suspicious. (2) Window class analysis: legitimate UAC has specific window class names. (3) macOS: osascript spawning 'display dialog' with password-related text. (4) EDR: behavioral detection for credential prompt mimicry. (5) User training: teach users to verify prompt legitimacy.",
      src: "MITRE T1056.002; Sysmon; EDR behavioral detection" },

    { id: "plaintext", label: "Plaintext Pwd", sub: "Captured", x: 730, y: 220, r: 40, type: "source",
      tags: ["Domain password", "Local password", "Cloud password", "Direct use"],
      telemetry: [],
      api: "Captured plaintext password from user input — ready for direct authentication",
      artifact: "Plaintext credential for victim account · usable for authentication",
      desc: "Yields the victim's actual plaintext password. Unlike hash-based attacks, plaintext passwords work through any authentication protocol (Kerberos, NTLM, cloud SSO, VPN). Can be used for lateral movement, privilege escalation, or persistent access.",
      src: "MITRE T1056.002" },
  ],

  edges: [
    { f: "fake_uac", t: "prompt" },
    { f: "fake_osascript", t: "prompt" },
    { f: "web_phish", t: "prompt" },
    { f: "prompt", t: "ev_detect" },
    { f: "ev_detect", t: "plaintext" },
  ],
};

export default model;
