// T1056.002 — GUI Input Capture — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1056.002",
    name: "GUI Input Capture",
    tactic: "Credential Access",
    platform: "Windows, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1300,
    svgHeight: 340,
    rows: [
      { label: "WIN DIALOG", y: 80 },
      { label: "MAC DIALOG", y: 200 },
    ],
  },

  nodes: [
    { id: "code_exec", label: "Code Execution", x: 60, y: 130, r: 36, type: "entry",
      desc: "Code execution in user context. Displays fake authentication dialog to trick user into entering credentials.",
      src: "MITRE ATT&CK T1056.002" },

    // Row 1: Windows fake dialog
    { id: "credui", label: "CredUIPrompt", sub: "ForCredentials", x: 210, y: 80, r: 38, type: "api",
      desc: "CredUIPromptForCredentials() — legitimate Windows API shows credential dialog. Misused by attackers.",
      src: "Microsoft Win32 CredUI API" },
    { id: "powershell", label: "PowerShell", sub: "Get-Credential", x: 210, y: 140, r: 32, type: "op",
      desc: "Get-Credential cmdlet displays PSCredential dialog. Phishing from PowerShell.",
      src: "Microsoft PowerShell" },
    { id: "custom_form", label: "Custom WinForm", sub: ".NET / C++", x: 380, y: 80, r: 34, type: "op",
      desc: "Custom Windows Forms or WPF dialog that mimics Windows Security or UAC prompt.",
      src: "MITRE T1056.002" },
    { id: "dialog_show", label: "Dialog Shown", sub: "User enters creds", x: 540, y: 80, r: 38, type: "system",
      desc: "Fake dialog displayed. User believes it's a legitimate Windows authentication prompt.",
      src: "MITRE T1056.002" },

    // Row 2: macOS fake dialog
    { id: "osascript", label: "osascript", sub: "dialog prompt", x: 210, y: 200, r: 36, type: "op",
      desc: "osascript -e 'display dialog \"Enter password\" default answer \"\" with hidden answer'",
      src: "Apple osascript; MITRE T1056.002" },
    { id: "applescript", label: "AppleScript", sub: "SystemUIServer", x: 380, y: 200, r: 34, type: "api",
      desc: "AppleScript dialog via SystemUIServer mimics macOS authentication prompt.",
      src: "Apple AppleScript" },
    { id: "swift_alert", label: "Swift/ObjC", sub: "NSAlert dialog", x: 380, y: 260, r: 30, type: "op",
      desc: "Custom Cocoa NSAlert or authorization plugin that displays credential dialog.",
      src: "Apple Cocoa" },
    { id: "mac_dialog", label: "Fake Prompt", sub: "macOS-styled", x: 540, y: 200, r: 36, type: "system",
      desc: "macOS-styled prompt: 'System Preferences wants to make changes' with password field.",
      src: "MITRE T1056.002" },

    // ── Credential capture ──
    { id: "cred_capture", label: "Credential Capture", x: 700, y: 140, r: 38, type: "op",
      desc: "User enters credentials into fake dialog. Plaintext username and password captured.",
      src: "MITRE T1056.002" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "osascript/powershell", x: 380, y: 310, r: 34, type: "detect",
      desc: "Sysmon EID 1: osascript or powershell with dialog/credential arguments.",
      src: "Sysmon documentation" },
    { id: "edr_credui", label: "EDR", sub: "CredUI from untrusted", x: 700, y: 260, r: 38, type: "detect",
      desc: "OPTIMAL: EDR detects CredUIPromptForCredentials() called by untrusted/unsigned processes.",
      src: "CrowdStrike; Defender" },
    { id: "es_mac", label: "Endpoint Security", sub: "ES_EVENT_TYPE", x: 700, y: 310, r: 32, type: "detect",
      desc: "macOS Endpoint Security: detect unexpected processes calling authorization APIs.",
      src: "Apple Endpoint Security" },

    // ── Output ──
    { id: "plaintext", label: "Plaintext Creds", x: 900, y: 140, r: 36, type: "artifact",
      desc: "Plaintext username and password entered by the tricked user.",
      src: "MITRE T1056.002" },
  ],

  edges: [
    // Windows
    { f: "code_exec", t: "credui" },
    { f: "code_exec", t: "powershell" },
    { f: "credui", t: "custom_form" },
    { f: "powershell", t: "dialog_show" },
    { f: "custom_form", t: "dialog_show" },
    { f: "dialog_show", t: "cred_capture" },
    // macOS
    { f: "code_exec", t: "osascript" },
    { f: "osascript", t: "applescript" },
    { f: "code_exec", t: "swift_alert" },
    { f: "applescript", t: "mac_dialog" },
    { f: "swift_alert", t: "mac_dialog" },
    { f: "mac_dialog", t: "cred_capture" },
    // Detection
    { f: "osascript", t: "sysmon_1" },
    { f: "powershell", t: "sysmon_1" },
    { f: "credui", t: "edr_credui" },
    { f: "applescript", t: "es_mac" },
    // Output
    { f: "cred_capture", t: "plaintext" },
  ],
};

export default model;
