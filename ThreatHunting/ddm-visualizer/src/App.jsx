import { useState } from "react";
import DDMLayout from "./shared/DDMLayout.jsx";

// ─── Registry ─────────────────────────────────────────────────────
// Import each DDM data module and register it here.
// When a technique spans multiple tactics, import the same module
// into each tactic entry.
// ──────────────────────────────────────────────────────────────────

import T1558_003 from "./models/CredentialAccess/T1558/T1558.003.js";

const REGISTRY = [
  // { tactic, technique, subtechnique?, model }
  { tactic: "Credential Access", technique: "T1558", sub: "T1558.003", name: "Kerberoasting", model: T1558_003 },
  // ── Add future DDMs here ──
  // { tactic: "Credential Access", technique: "T1003", sub: "T1003.001", name: "LSASS Memory", model: T1003_001 },
  // { tactic: "Lateral Movement", technique: "T1021", sub: "T1021.002", name: "SMB/Admin Shares", model: T1021_002 },
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
