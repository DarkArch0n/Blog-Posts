// T1056.001 — Keylogging — Detection Data Model
// Tactic: Credential Access

const model = {
  metadata: {
    tcode: "T1056.001",
    name: "Keylogging",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  detectNodeId: "ev_detect",

  layout: {
    svgWidth: 960,
    svgHeight: 480,
    columns: [
      { label: "HOOK METHOD",  x: 80  },
      { label: "CAPTURE",     x: 270 },
      { label: "DETECTION",   x: 480 },
      { label: "OUTCOME",     x: 730 },
    ],
    separators: [175, 375, 605],
    annotations: [
      { text: "SetWindowsHookEx is the most common API", x: 270, y: 420, color: "#c62828", fontStyle: "italic" },
    ],
  },

  nodes: [
    { id: "hookex", label: "SetWindowsHookEx", sub: "WH_KEYBOARD_LL", x: 80, y: 110, r: 36, type: "source",
      tags: ["SetWindowsHookEx", "WH_KEYBOARD_LL", "Low-level hook"],
      telemetry: ["Sysmon 1"],
      api: "SetWindowsHookEx(WH_KEYBOARD_LL, callback, hMod, 0) — global keyboard hook",
      artifact: "API call from suspicious process · DLL injection for hook callback",
      desc: "Most common Windows keylogging method. SetWindowsHookEx with WH_KEYBOARD_LL installs a low-level keyboard hook that receives all keystroke events system-wide. Requires a message pump. Detectable via API monitoring but widely used by both malware and legitimate software.",
      src: "MITRE ATT&CK T1056.001; Microsoft Win32 API" },

    { id: "getasync", label: "GetAsyncKeyState", sub: "Polling loop", x: 80, y: 260, r: 34, type: "source",
      tags: ["GetAsyncKeyState()", "Polling loop", "No hook needed"],
      telemetry: ["Sysmon 1"],
      api: "while(true) { for(vk=0; vk<256; vk++) { if(GetAsyncKeyState(vk) & 0x8000) log(vk); } }",
      artifact: "High CPU polling loop · GetAsyncKeyState calls in tight loop",
      desc: "Simpler method: poll GetAsyncKeyState() in a loop for each virtual key code. No hook installation needed. Higher CPU usage due to constant polling. Harder to detect via API hooking but easier to identify via behavioral analysis (tight polling loop pattern).",
      src: "MITRE T1056.001; Win32 GetAsyncKeyState" },

    { id: "linux_input", label: "/dev/input", sub: "Linux events", x: 80, y: 400, r: 34, type: "source",
      tags: ["/dev/input/event*", "evdev", "xinput", "Root required"],
      telemetry: ["auditd"],
      api: "cat /dev/input/event0 · python-evdev · xinput test",
      artifact: "Process reading /dev/input/event* · auditd file access event",
      desc: "On Linux, keyboard events are available via /dev/input/event* device files (requires root) or via X11 input extension (xinput test). Python-evdev library provides easy access. auditd can monitor access to input device files.",
      src: "MITRE T1056.001; Linux evdev documentation" },

    { id: "capture", label: "Keystroke Log", sub: "File/C2 exfil", x: 270, y: 200, r: 38, type: "source",
      tags: ["Log file", "C2 exfiltration", "Window title context", "Clipboard capture"],
      telemetry: ["Sysmon 11", "Sysmon 3"],
      api: "Keystrokes logged to file or exfiltrated via C2 — often with active window title as context",
      artifact: "Sysmon EID 11: log file creation · EID 3: C2 data exfiltration · hidden file",
      desc: "Captured keystrokes are typically logged with the active window title for context (e.g., 'login.microsoftonline.com — Chrome' → 'admin@corp.com<TAB>P@ssw0rd1!<ENTER>'). Exfiltrated to the attacker via C2 channel, email, or uploaded to file-sharing service. May also capture clipboard contents.",
      src: "MITRE T1056.001" },

    { id: "ev_detect", label: "API + EDR", sub: "Hook detection", x: 480, y: 230, r: 50, type: "detect",
      tags: ["SetWindowsHookEx monitor", "API hooking", "EDR behavioral", "Input device access"],
      telemetry: ["Sysmon 1", "EDR"],
      api: "EDR: SetWindowsHookEx(WH_KEYBOARD) calls · suspicious input device access · API patterns",
      artifact: "OPTIMAL: EDR detects SetWindowsHookEx + WH_KEYBOARD_LL · unusual input device access · keylogger signatures",
      desc: "OPTIMAL DETECTION NODE. (1) API monitoring: SetWindowsHookEx with WH_KEYBOARD_LL from non-standard process. (2) EDR behavioral: tight GetAsyncKeyState polling loops. (3) Linux: auditd monitoring /dev/input/event* access by non-input processes. (4) Sysmon EID 1: known keylogger process names/hashes. (5) File monitoring: suspicious log files with keystroke patterns. (6) PREVENTION: Credential Guard, virtual keyboards for sensitive input, hardware-backed credential entry.",
      src: "MITRE T1056.001; EDR documentation; Sysmon" },

    { id: "creds_cap", label: "Credentials", sub: "Captured", x: 730, y: 150, r: 36, type: "source",
      tags: ["Login passwords", "MFA codes", "SSH passphrases", "Email content"],
      telemetry: [],
      api: "All typed credentials: login passwords, MFA codes, SSH keys, sensitive data",
      artifact: "Plaintext passwords as typed · MFA codes · sensitive communication content",
      desc: "Keylogging captures ALL typed input including: login passwords, MFA codes (OTP), SSH key passphrases, email content, chat messages, and any other sensitive data entered via keyboard. Window title context helps the attacker identify which credentials belong to which service.",
      src: "MITRE T1056.001" },

    { id: "persist", label: "Persistent", sub: "Continuous capture", x: 730, y: 330, r: 34, type: "source",
      tags: ["Startup persistence", "Continuous monitoring", "Future credentials"],
      telemetry: [],
      api: "Keylogger persists via startup mechanism — captures all future credential entry",
      artifact: "Ongoing credential capture · new passwords captured on rotation",
      desc: "A persistent keylogger captures credentials continuously over time. When users change passwords, the new password is also captured. When users access new services, those credentials are captured too. Provides ongoing credential access as long as the keylogger remains active.",
      src: "MITRE T1056.001" },
  ],

  edges: [
    { f: "hookex", t: "capture" },
    { f: "getasync", t: "capture" },
    { f: "linux_input", t: "capture" },
    { f: "capture", t: "ev_detect" },
    { f: "ev_detect", t: "creds_cap" },
    { f: "ev_detect", t: "persist" },
  ],
};

export default model;
