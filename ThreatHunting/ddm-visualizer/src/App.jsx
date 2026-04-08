import { useState } from "react";
import DDMLayout from "./shared/DDMLayout.jsx";

// ─── Registry ─────────────────────────────────────────────────────
// Import each DDM data module and register it here.
// When a technique spans multiple tactics, import the same module
// into each tactic entry.
// ──────────────────────────────────────────────────────────────────

import T1558_001 from "./models/CredentialAccess/T1558/T1558.001.js";
import T1558_002 from "./models/CredentialAccess/T1558/T1558.002.js";
import T1558_003 from "./models/CredentialAccess/T1558/T1558.003.js";
import T1558_004 from "./models/CredentialAccess/T1558/T1558.004.js";

import T1003_001 from "./models/CredentialAccess/T1003/T1003.001.js";
import T1003_002 from "./models/CredentialAccess/T1003/T1003.002.js";
import T1003_003 from "./models/CredentialAccess/T1003/T1003.003.js";
import T1003_004 from "./models/CredentialAccess/T1003/T1003.004.js";
import T1003_005 from "./models/CredentialAccess/T1003/T1003.005.js";
import T1003_006 from "./models/CredentialAccess/T1003/T1003.006.js";
import T1003_007 from "./models/CredentialAccess/T1003/T1003.007.js";
import T1003_008 from "./models/CredentialAccess/T1003/T1003.008.js";

import T1557_001 from "./models/CredentialAccess/T1557/T1557.001.js";
import T1557_002 from "./models/CredentialAccess/T1557/T1557.002.js";
import T1557_003 from "./models/CredentialAccess/T1557/T1557.003.js";

import T1110_001 from "./models/CredentialAccess/T1110/T1110.001.js";
import T1110_002 from "./models/CredentialAccess/T1110/T1110.002.js";
import T1110_003 from "./models/CredentialAccess/T1110/T1110.003.js";
import T1110_004 from "./models/CredentialAccess/T1110/T1110.004.js";

import T1040 from "./models/CredentialAccess/T1040/T1040.js";
import T1111 from "./models/CredentialAccess/T1111/T1111.js";
import T1187 from "./models/CredentialAccess/T1187/T1187.js";
import T1212 from "./models/CredentialAccess/T1212/T1212.js";
import T1528 from "./models/CredentialAccess/T1528/T1528.js";
import T1539 from "./models/CredentialAccess/T1539/T1539.js";
import T1621 from "./models/CredentialAccess/T1621/T1621.js";
import T1649 from "./models/CredentialAccess/T1649/T1649.js";

import T1555_001 from "./models/CredentialAccess/T1555/T1555.001.js";
import T1555_002 from "./models/CredentialAccess/T1555/T1555.002.js";
import T1555_003 from "./models/CredentialAccess/T1555/T1555.003.js";
import T1555_004 from "./models/CredentialAccess/T1555/T1555.004.js";
import T1555_005 from "./models/CredentialAccess/T1555/T1555.005.js";
import T1555_006 from "./models/CredentialAccess/T1555/T1555.006.js";

import T1056_001 from "./models/CredentialAccess/T1056/T1056.001.js";
import T1056_002 from "./models/CredentialAccess/T1056/T1056.002.js";
import T1056_003 from "./models/CredentialAccess/T1056/T1056.003.js";
import T1056_004 from "./models/CredentialAccess/T1056/T1056.004.js";

import T1556_001 from "./models/CredentialAccess/T1556/T1556.001.js";
import T1556_002 from "./models/CredentialAccess/T1556/T1556.002.js";
import T1556_003 from "./models/CredentialAccess/T1556/T1556.003.js";
import T1556_004 from "./models/CredentialAccess/T1556/T1556.004.js";
import T1556_005 from "./models/CredentialAccess/T1556/T1556.005.js";
import T1556_006 from "./models/CredentialAccess/T1556/T1556.006.js";
import T1556_007 from "./models/CredentialAccess/T1556/T1556.007.js";
import T1556_008 from "./models/CredentialAccess/T1556/T1556.008.js";
import T1556_009 from "./models/CredentialAccess/T1556/T1556.009.js";

import T1552_001 from "./models/CredentialAccess/T1552/T1552.001.js";
import T1552_002 from "./models/CredentialAccess/T1552/T1552.002.js";
import T1552_003 from "./models/CredentialAccess/T1552/T1552.003.js";
import T1552_004 from "./models/CredentialAccess/T1552/T1552.004.js";
import T1552_005 from "./models/CredentialAccess/T1552/T1552.005.js";
import T1552_006 from "./models/CredentialAccess/T1552/T1552.006.js";
import T1552_007 from "./models/CredentialAccess/T1552/T1552.007.js";
import T1552_008 from "./models/CredentialAccess/T1552/T1552.008.js";

import T1606_001 from "./models/CredentialAccess/T1606/T1606.001.js";
import T1606_002 from "./models/CredentialAccess/T1606/T1606.002.js";

const REGISTRY = [
  // ── T1558 — Steal or Forge Kerberos Tickets ──
  { tactic: "Credential Access", technique: "T1558", sub: "T1558.001", name: "Golden Ticket",     model: T1558_001 },
  { tactic: "Credential Access", technique: "T1558", sub: "T1558.002", name: "Silver Ticket",     model: T1558_002 },
  { tactic: "Credential Access", technique: "T1558", sub: "T1558.003", name: "Kerberoasting",     model: T1558_003 },
  { tactic: "Credential Access", technique: "T1558", sub: "T1558.004", name: "AS-REP Roasting",   model: T1558_004 },

  // ── T1003 — OS Credential Dumping ──
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.001", name: "LSASS Memory",                model: T1003_001 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.002", name: "Security Account Manager",    model: T1003_002 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.003", name: "NTDS",                        model: T1003_003 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.004", name: "LSA Secrets",                 model: T1003_004 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.005", name: "Cached Domain Credentials",   model: T1003_005 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.006", name: "DCSync",                      model: T1003_006 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.007", name: "Proc Filesystem",             model: T1003_007 },
  { tactic: "Credential Access", technique: "T1003", sub: "T1003.008", name: "/etc/passwd and /etc/shadow", model: T1003_008 },

  // ── T1557 — Adversary-in-the-Middle ──
  { tactic: "Credential Access", technique: "T1557", sub: "T1557.001", name: "LLMNR/NBT-NS Poisoning and SMB Relay", model: T1557_001 },
  { tactic: "Credential Access", technique: "T1557", sub: "T1557.002", name: "ARP Cache Poisoning",                model: T1557_002 },
  { tactic: "Credential Access", technique: "T1557", sub: "T1557.003", name: "DHCP Spoofing",                      model: T1557_003 },

  // ── T1110 — Brute Force ──
  { tactic: "Credential Access", technique: "T1110", sub: "T1110.001", name: "Password Guessing",     model: T1110_001 },
  { tactic: "Credential Access", technique: "T1110", sub: "T1110.002", name: "Password Cracking",     model: T1110_002 },
  { tactic: "Credential Access", technique: "T1110", sub: "T1110.003", name: "Password Spraying",     model: T1110_003 },
  { tactic: "Credential Access", technique: "T1110", sub: "T1110.004", name: "Credential Stuffing",   model: T1110_004 },

  // ── Standalone Credential Access techniques ──
  { tactic: "Credential Access", technique: "T1040", name: "Network Sniffing",                              model: T1040 },
  { tactic: "Credential Access", technique: "T1111", name: "Multi-Factor Authentication Interception",       model: T1111 },
  { tactic: "Credential Access", technique: "T1187", name: "Forced Authentication",                          model: T1187 },
  { tactic: "Credential Access", technique: "T1212", name: "Exploitation for Credential Access",             model: T1212 },
  { tactic: "Credential Access", technique: "T1528", name: "Steal Application Access Token",                 model: T1528 },
  { tactic: "Credential Access", technique: "T1539", name: "Steal Web Session Cookie",                       model: T1539 },
  { tactic: "Credential Access", technique: "T1621", name: "Multi-Factor Authentication Request Generation", model: T1621 },
  { tactic: "Credential Access", technique: "T1649", name: "Steal or Forge Authentication Certificates",     model: T1649 },

  // ── T1555 — Credentials from Password Stores ──
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.001", name: "Keychain",                         model: T1555_001 },
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.002", name: "Securityd Memory",                 model: T1555_002 },
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.003", name: "Credentials from Web Browsers",    model: T1555_003 },
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.004", name: "Windows Credential Manager",       model: T1555_004 },
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.005", name: "Password Managers",                model: T1555_005 },
  { tactic: "Credential Access", technique: "T1555", sub: "T1555.006", name: "Cloud Secrets Management Stores",  model: T1555_006 },

  // ── T1056 — Input Capture ──
  { tactic: "Credential Access", technique: "T1056", sub: "T1056.001", name: "Keylogging",                model: T1056_001 },
  { tactic: "Credential Access", technique: "T1056", sub: "T1056.002", name: "GUI Input Capture",         model: T1056_002 },
  { tactic: "Credential Access", technique: "T1056", sub: "T1056.003", name: "Web Portal Capture",       model: T1056_003 },
  { tactic: "Credential Access", technique: "T1056", sub: "T1056.004", name: "Credential API Hooking",   model: T1056_004 },

  // ── T1556 — Modify Authentication Process ──
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.001", name: "Domain Controller Authentication", model: T1556_001 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.002", name: "Password Filter DLL",              model: T1556_002 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.003", name: "Pluggable Authentication Modules", model: T1556_003 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.004", name: "Network Device Authentication",    model: T1556_004 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.005", name: "Reversible Encryption",            model: T1556_005 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.006", name: "Multi-Factor Authentication",      model: T1556_006 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.007", name: "Hybrid Identity",                  model: T1556_007 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.008", name: "Network Provider DLL",             model: T1556_008 },
  { tactic: "Credential Access", technique: "T1556", sub: "T1556.009", name: "Conditional Access Policies",      model: T1556_009 },

  // ── T1552 — Unsecured Credentials ──
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.001", name: "Credentials In Files",            model: T1552_001 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.002", name: "Credentials in Registry",         model: T1552_002 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.003", name: "Bash History",                    model: T1552_003 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.004", name: "Private Keys",                    model: T1552_004 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.005", name: "Cloud Instance Metadata API",     model: T1552_005 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.006", name: "Group Policy Preferences",        model: T1552_006 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.007", name: "Container API",                   model: T1552_007 },
  { tactic: "Credential Access", technique: "T1552", sub: "T1552.008", name: "Chat Messages",                   model: T1552_008 },

  // ── T1606 — Forge Web Credentials ──
  { tactic: "Credential Access", technique: "T1606", sub: "T1606.001", name: "Web Cookies",   model: T1606_001 },
  { tactic: "Credential Access", technique: "T1606", sub: "T1606.002", name: "SAML Tokens",   model: T1606_002 },
];

// Group registry by tactic → technique → subtechniques
function buildTree(entries) {
  const tree = {};
  for (const e of entries) {
    if (!tree[e.tactic]) tree[e.tactic] = {};
    if (!tree[e.tactic][e.technique]) tree[e.tactic][e.technique] = [];
    tree[e.tactic][e.technique].push(e);
  }
  return tree;
}

export default function App() {
  const [activeModel, setActiveModel] = useState(null);
  const tree = buildTree(REGISTRY);

  if (activeModel) {
    return (
      <div>
        <div style={{
          padding: "8px 32px",
          borderBottom: "1px solid #e0e0e0",
          background: "#fafafa",
          fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
        }}>
          <button
            onClick={() => setActiveModel(null)}
            style={{
              background: "none", border: "none", cursor: "pointer",
              fontSize: 13, color: "#1565c0", padding: "4px 0"
            }}
          >
            ← Back to Index
          </button>
        </div>
        <DDMLayout model={activeModel} />
      </div>
    );
  }

  return (
    <div style={{
      padding: "40px 48px",
      maxWidth: 800,
      margin: "0 auto",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
    }}>
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontSize: 11, color: "#666", letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>
          Detection Data Models
        </div>
        <div style={{ fontSize: 28, fontWeight: 600, color: "#111", marginBottom: 6 }}>
          DDM Visualizer
        </div>
        <div style={{ fontSize: 13, color: "#888" }}>
          Interactive detection data models organized by MITRE ATT&CK tactic, technique, and sub-technique.
        </div>
      </div>

      {Object.entries(tree).map(([tactic, techniques]) => (
        <div key={tactic} style={{ marginBottom: 28 }}>
          <div style={{
            fontSize: 16, fontWeight: 600, color: "#2e7d32",
            borderBottom: "2px solid #e8f5e9", paddingBottom: 6, marginBottom: 12
          }}>
            {tactic}
          </div>

          {Object.entries(techniques).map(([techId, subs]) => (
            <div key={techId} style={{ marginLeft: 16, marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "#444", marginBottom: 6 }}>
                {techId}
              </div>

              {subs.map(entry => (
                <button
                  key={entry.sub || entry.technique}
                  onClick={() => setActiveModel(entry.model)}
                  style={{
                    display: "block",
                    width: "100%",
                    textAlign: "left",
                    background: "#fff",
                    border: "1px solid #e0e0e0",
                    borderRadius: 4,
                    padding: "10px 16px",
                    marginBottom: 6,
                    marginLeft: 16,
                    cursor: "pointer",
                    transition: "border-color 0.15s, box-shadow 0.15s",
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = "#1565c0"; e.currentTarget.style.boxShadow = "0 1px 4px rgba(0,0,0,0.08)"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = "#e0e0e0"; e.currentTarget.style.boxShadow = "none"; }}
                >
                  <span style={{ fontWeight: 500, color: "#111" }}>
                    {entry.sub || entry.technique}
                  </span>
                  <span style={{ color: "#888", marginLeft: 10 }}>
                    {entry.name}
                  </span>
                  <span style={{ float: "right", color: "#bbb", fontSize: 12 }}>
                    {entry.model.metadata.version}
                  </span>
                </button>
              ))}
            </div>
          ))}
        </div>
      ))}

      {REGISTRY.length === 0 && (
        <div style={{ color: "#999", fontStyle: "italic", marginTop: 40, textAlign: "center" }}>
          No DDM models registered yet. Add entries to the REGISTRY in App.jsx.
        </div>
      )}

      <div style={{ marginTop: 40, fontSize: 11, color: "#ccc", textAlign: "center" }}>
        DDM Visualizer · VanVleet Style · MITRE ATT&CK Enterprise
      </div>
    </div>
  );
}
