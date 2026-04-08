// T1056.001 — Keylogging — Expanded Technology Chain

const model = {
  metadata: {
    tcode: "T1056.001",
    name: "Keylogging",
    tactic: "Credential Access",
    platform: "Windows, Linux, macOS",
    version: "v1.0",
  },

  layout: {
    svgWidth: 1400,
    svgHeight: 440,
    rows: [
      { label: "WIN HOOK",   y: 80 },
      { label: "RAW INPUT",  y: 180 },
      { label: "LINUX",      y: 280 },
      { label: "MACOS",      y: 380 },
    ],
  },

  nodes: [
    { id: "code_exec", label: "Code Execution", sub: "User/Admin context", x: 60, y: 200, r: 36, type: "entry",
      desc: "Code execution on target. Keylogger runs as user (captures that user) or admin (captures all).",
      src: "MITRE ATT&CK T1056.001" },

    // Row 1: Windows SetWindowsHookEx
    { id: "hook_keylog", label: "SetWindowsHookEx", sub: "WH_KEYBOARD_LL", x: 220, y: 80, r: 38, type: "api",
      desc: "SetWindowsHookEx(WH_KEYBOARD_LL) installs low-level keyboard hook. Captures all keystrokes system-wide.",
      src: "Microsoft Win32 API" },
    { id: "getmsg", label: "GetMessage", sub: "Message loop", x: 400, y: 80, r: 30, type: "api",
      desc: "GetMessage() / PeekMessage() message pump to receive keyboard hook callbacks.",
      src: "Microsoft Win32 API" },
    { id: "getkey_state", label: "GetAsyncKeyState", x: 220, y: 140, r: 32, type: "api",
      desc: "Alternative: Polling via GetAsyncKeyState() in a loop. No hook installation needed.",
      src: "Microsoft Win32 API" },

    // Row 2: Raw Input API
    { id: "rawinput", label: "RegisterRawInput", sub: "RIDEV_INPUTSINK", x: 220, y: 180, r: 36, type: "api",
      desc: "RegisterRawInputDevices with RIDEV_INPUTSINK flag — receives input even when not focused.",
      src: "Microsoft Win32 Raw Input API" },
    { id: "getrawinput", label: "GetRawInputData", x: 400, y: 180, r: 32, type: "api",
      desc: "GetRawInputData() retrieves keystroke data from raw input buffer.",
      src: "Microsoft Win32 API" },

    // Row 3: Linux
    { id: "xinput", label: "xinput", sub: "test-xi2", x: 220, y: 280, r: 34, type: "op",
      desc: "xinput test-xi2 — X11 input event monitoring. Captures all keyboard events on X display.",
      src: "X.org xinput" },
    { id: "xrecord", label: "XRecord", sub: "Extension API", x: 400, y: 280, r: 32, type: "api",
      desc: "X11 XRecord extension — programmatic keyboard event recording API.",
      src: "X11 XRecord extension" },
    { id: "evdev", label: "/dev/input", sub: "evN", x: 220, y: 340, r: 30, type: "op",
      desc: "Read /dev/input/eventX directly (requires root). Raw kernel input events.",
      src: "Linux input subsystem" },
    { id: "read_evdev", label: "read()", sub: "input_event struct", x: 400, y: 340, r: 32, type: "api",
      desc: "read() on /dev/input/eventN returns struct input_event with keycode and state.",
      src: "Linux evdev" },

    // Row 4: macOS
    { id: "cg_event", label: "CGEventTap", sub: "kCGHIDEventTap", x: 220, y: 380, r: 36, type: "api",
      desc: "CGEventTapCreate(kCGHIDEventTap) — Core Graphics event tap for keyboard monitoring.",
      src: "Apple Core Graphics; Quartz Event Taps" },
    { id: "iokit", label: "IOKit HID", sub: "Manager", x: 400, y: 380, r: 32, type: "api",
      desc: "IOKit HID Manager registers for keyboard device input callbacks.",
      src: "Apple IOKit HID" },
    { id: "tcc_input", label: "TCC", sub: "Input Monitoring", x: 560, y: 380, r: 30, type: "system",
      desc: "macOS TCC requires Input Monitoring permission for event taps (Catalina+).",
      src: "Apple TCC" },

    // ── Log file / exfil ──
    { id: "log_file", label: "Keystroke Log", sub: "Local file", x: 580, y: 180, r: 36, type: "artifact",
      desc: "Keystrokes logged to local file with timestamps, window titles, and key data.",
      src: "MITRE T1056.001" },
    { id: "exfil", label: "Exfiltration", sub: "C2 / email / HTTP", x: 740, y: 180, r: 34, type: "op",
      desc: "Keystroke logs exfiltrated via C2 channel, email, HTTP POST to attacker server.",
      src: "MITRE T1041" },

    // ── Detection ──
    { id: "sysmon_1", label: "Sysmon 1", sub: "Known keyloggers", x: 580, y: 80, r: 34, type: "detect",
      desc: "Sysmon EID 1: Process creation matching known keylogger signatures.",
      src: "Sysmon documentation" },
    { id: "edr_hook", label: "EDR", sub: "SetWindowsHookEx", x: 580, y: 300, r: 40, type: "detect",
      desc: "OPTIMAL: EDR detects SetWindowsHookEx WH_KEYBOARD_LL from untrusted processes.",
      src: "CrowdStrike; Microsoft Defender" },
    { id: "sysmon_11", label: "Sysmon 11", sub: "Log file creation", x: 740, y: 80, r: 30, type: "detect",
      desc: "Sysmon EID 11: Suspicious file creation patterns (rapid append, keystroke log filenames).",
      src: "Sysmon documentation" },

    // ── Output ──
    { id: "passwords", label: "Typed Passwords", x: 900, y: 140, r: 34, type: "artifact",
      desc: "Passwords typed into login forms, applications, sudo prompts, RDP sessions.",
      src: "MITRE T1056.001" },
    { id: "messages", label: "Messages", sub: "Email/Chat", x: 900, y: 230, r: 30, type: "artifact",
      desc: "Email content, chat messages, code, documents — everything typed.",
      src: "MITRE T1056.001" },
  ],

  edges: [
    // Windows hooks
    { f: "code_exec", t: "hook_keylog" },
    { f: "hook_keylog", t: "getmsg" },
    { f: "code_exec", t: "getkey_state" },
    { f: "getmsg", t: "log_file" },
    { f: "getkey_state", t: "log_file" },
    // Raw input
    { f: "code_exec", t: "rawinput" },
    { f: "rawinput", t: "getrawinput" },
    { f: "getrawinput", t: "log_file" },
    // Linux
    { f: "code_exec", t: "xinput" },
    { f: "xinput", t: "xrecord" },
    { f: "code_exec", t: "evdev" },
    { f: "evdev", t: "read_evdev" },
    { f: "xrecord", t: "log_file" },
    { f: "read_evdev", t: "log_file" },
    // macOS
    { f: "code_exec", t: "cg_event" },
    { f: "code_exec", t: "iokit" },
    { f: "cg_event", t: "tcc_input" },
    { f: "iokit", t: "tcc_input" },
    { f: "tcc_input", t: "log_file" },
    // Exfil
    { f: "log_file", t: "exfil" },
    // Detection
    { f: "hook_keylog", t: "edr_hook" },
    { f: "code_exec", t: "sysmon_1" },
    { f: "log_file", t: "sysmon_11" },
    // Output
    { f: "exfil", t: "passwords" },
    { f: "exfil", t: "messages" },
  ],
};

export default model;
