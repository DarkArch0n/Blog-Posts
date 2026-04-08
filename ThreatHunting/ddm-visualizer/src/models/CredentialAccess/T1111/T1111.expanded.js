// T1111 — Multi-Factor Authentication Interception — Expanded Technology Chain

const model = {
  metadata: { tcode: "T1111", name: "Multi-Factor Authentication Interception", tactic: "Credential Access", platform: "Windows, Linux, macOS", version: "v1.0" },
  layout: { svgWidth: 1350, svgHeight: 380, rows: [{ label: "SMARTCARD", y: 80 }, { label: "OTP INTERCEPT", y: 180 }, { label: "PUSH FATIGUE", y: 300 }] },
  nodes: [
    { id: "mfa_flow", label: "MFA Auth Flow", sub: "User authenticating", x: 60, y: 180, r: 38, type: "entry", desc: "User performing MFA authentication. Adversary intercepts the MFA factor.", src: "MITRE ATT&CK T1111" },
    { id: "smartcard_api", label: "Smart Card API", sub: "SCardTransmit", x: 240, y: 80, r: 36, type: "op", desc: "Hook SCardTransmit API to intercept smart card PIN and APDUs during authentication.", src: "MITRE T1111; Windows WinSCard" },
    { id: "keylog_pin", label: "Keylog PIN", sub: "Smart card PIN", x: 440, y: 80, r: 32, type: "op", desc: "Keylogger captures smart card PIN entered at prompt. Combined with card = full MFA bypass.", src: "MITRE T1111" },
    { id: "scard_relay", label: "Card Relay", sub: "Remote APDU", x: 440, y: 140, r: 30, type: "protocol", desc: "Relay smart card APDUs over network to use victim's card remotely.", src: "Smart card relay attacks" },
    { id: "otp_phish", label: "OTP Phishing", sub: "Real-time relay", x: 240, y: 180, r: 36, type: "op", desc: "Real-time phishing proxy (EvilGinx2, Modlishka): captures OTP token as user enters it.", src: "EvilGinx2; MITRE T1111" },
    { id: "otp_keylog", label: "OTP Keylogging", sub: "6-digit capture", x: 440, y: 180, r: 34, type: "op", desc: "Keylogger captures TOTP/HOTP codes typed into authentication forms.", src: "MITRE T1111" },
    { id: "ss7_intercept", label: "SS7 Intercept", sub: "SMS interception", x: 440, y: 240, r: 34, type: "protocol", desc: "SS7 network attacks to intercept SMS-based MFA codes. Requires telecom access.", src: "SS7; NIST SP 800-63B" },
    { id: "push_fatigue", label: "Push Fatigue", sub: "Repeated push", x: 240, y: 300, r: 36, type: "op", desc: "Repeatedly trigger push notifications until user approves out of fatigue (MFA bombing).", src: "Lapsus$; MITRE T1621" },
    { id: "duo_log", label: "Duo Auth Log", sub: "Push denials", x: 640, y: 300, r: 36, type: "detect", desc: "OPTIMAL: Multiple push denials followed by approval. Anomalous auth frequency.", src: "Duo Security; Okta" },
    { id: "impossible_travel", label: "Impossible Travel", sub: "Geo anomaly", x: 640, y: 180, r: 36, type: "detect", desc: "Authentication from impossible geographic locations relative to user's normal pattern.", src: "Azure AD; UEBA" },
    { id: "evilginx_detect", label: "Phishing Domain", sub: "Certificate/domain", x: 640, y: 80, r: 34, type: "detect", desc: "Detect real-time phishing proxy domains via certificate transparency, typosquatting.", src: "CT Logs; DNS monitoring" },
    { id: "session_token", label: "Session Token", sub: "MFA-authenticated", x: 860, y: 180, r: 40, type: "artifact", desc: "Post-MFA session token captured. Enables access without repeating MFA.", src: "MITRE T1111" },
  ],
  edges: [
    { f: "mfa_flow", t: "smartcard_api" }, { f: "mfa_flow", t: "otp_phish" }, { f: "mfa_flow", t: "push_fatigue" },
    { f: "smartcard_api", t: "keylog_pin" }, { f: "smartcard_api", t: "scard_relay" },
    { f: "otp_phish", t: "otp_keylog" }, { f: "otp_phish", t: "ss7_intercept" },
    { f: "keylog_pin", t: "session_token" }, { f: "otp_keylog", t: "session_token" }, { f: "ss7_intercept", t: "session_token" },
    { f: "push_fatigue", t: "session_token" },
    { f: "push_fatigue", t: "duo_log" }, { f: "otp_phish", t: "impossible_travel" }, { f: "otp_phish", t: "evilginx_detect" },
  ],
};
export default model;
