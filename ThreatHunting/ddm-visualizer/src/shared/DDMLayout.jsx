import { useState } from "react";
import { COLORS } from "./colors.js";

/**
 * Shared DDM visualization layout (VanVleet style).
 *
 * Props:
 *   model — object with shape:
 *     metadata:     { tcode, name, tactic, platform, version }
 *     nodes:        [{ id, label, sub, x, y, r, type, tags, telemetry, api, artifact, desc, src }]
 *     edges:        [{ f, t, blind? }]
 *     detectNodeId: string — id of the optimal detection node
 *     layout: {
 *       svgWidth, svgHeight,
 *       columns:    [{ label, x }],
 *       separators: [x, x, ...],
 *       annotations:[{ text, x, y, color, fontWeight?, fontStyle? }]
 *     }
 */
export default function DDMLayout({ model }) {
  const { metadata, nodes, edges, detectNodeId, layout } = model;
  const [sel, setSel] = useState(null);
  const selNode = sel ? nodes.find(n => n.id === sel) : null;
  const isDetect = (id) => id === detectNodeId;

  // Curved path from right edge of source to left edge of target (left-to-right flow)
  const drawPath = (fn, tn) => {
    const x1 = fn.x + fn.r;
    const y1 = fn.y;
    const x2 = tn.x - tn.r;
    const y2 = tn.y;
    const mx = (x1 + x2) / 2;
    return `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
  };

  return (
    <div style={{ padding: "24px 32px", maxWidth: layout.svgWidth + 60, margin: "0 auto", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" }}>

      {/* Header */}
      <div style={{ marginBottom: 20, paddingBottom: 16, borderBottom: "2px solid #e0e0e0" }}>
        <div style={{ fontSize: 11, color: "#666", letterSpacing: 2, textTransform: "uppercase", marginBottom: 4 }}>
          Detection Data Model
        </div>
        <div style={{ fontSize: 24, fontWeight: 600, color: "#111" }}>
          {metadata.tcode} — {metadata.name}
        </div>
        <div style={{ fontSize: 12, color: "#888", marginTop: 4 }}>
          Tactic: {metadata.tactic} · Platform: {metadata.platform} · MITRE ATT&CK {metadata.version}
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 24, marginBottom: 20, fontSize: 12, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill={COLORS.source.fill} stroke={COLORS.source.stroke} strokeWidth="2"/></svg>
          <span>Attacker Operation</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="24" height="20"><circle cx="12" cy="10" r="8" fill={COLORS.detect.fill} stroke={COLORS.detect.stroke} strokeWidth="3"/></svg>
          <span style={{ fontWeight: 600 }}>Optimal Detection</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill={COLORS.blind.fill} stroke={COLORS.blind.stroke} strokeWidth="2" strokeDasharray="3,2"/></svg>
          <span>Blind Spot</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5" stroke="#c62828" strokeWidth="1.5" strokeDasharray="4,3"/></svg>
          <span style={{ color: "#999" }}>Blind Path</span>
        </div>
      </div>

      {/* SVG Graph */}
      <svg width={layout.svgWidth} height={layout.svgHeight} style={{ display: "block", background: "#fafafa", border: "1px solid #e0e0e0", borderRadius: 4 }}>
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#666" />
          </marker>
          <marker id="arrow-blind" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#c62828" />
          </marker>
          <marker id="arrow-detect" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3z" fill="#f57f17" />
          </marker>
        </defs>

        {/* Column Labels */}
        {layout.columns.map((col, i) => (
          <text key={i} x={col.x} y="30" textAnchor="middle" fontSize="10" fill="#999" fontWeight="500">
            {col.label}
          </text>
        ))}

        {/* Vertical separator lines */}
        {layout.separators.map((x, i) => (
          <line key={i} x1={x} y1="45" x2={x} y2={layout.svgHeight - 40} stroke="#eee" strokeWidth="1" strokeDasharray="4,4"/>
        ))}

        {/* Edges */}
        {edges.map((e, i) => {
          const fn = nodes.find(n => n.id === e.f);
          const tn = nodes.find(n => n.id === e.t);
          if (!fn || !tn) return null;

          const toDetect = tn.id === detectNodeId;
          const isBlind = e.blind;

          return (
            <path
              key={i}
              d={drawPath(fn, tn)}
              stroke={isBlind ? "#c62828" : toDetect ? "#f57f17" : "#888"}
              strokeWidth={toDetect ? 2 : 1.5}
              strokeDasharray={isBlind ? "5,4" : "none"}
              fill="none"
              markerEnd={isBlind ? "url(#arrow-blind)" : toDetect ? "url(#arrow-detect)" : "url(#arrow)"}
            />
          );
        })}

        {/* Nodes */}
        {nodes.map(n => {
          const detect = isDetect(n.id);
          const colors = detect ? COLORS.detect : COLORS[n.type];
          const isSel = sel === n.id;
          const isBlindNode = n.type === "blind";

          return (
            <g key={n.id} onClick={() => setSel(sel === n.id ? null : n.id)} style={{ cursor: "pointer" }}>
              {isSel && (
                <circle cx={n.x} cy={n.y} r={n.r + 6} fill="none" stroke="#333" strokeWidth="2" opacity="0.3" />
              )}
              <circle
                cx={n.x} cy={n.y} r={n.r}
                fill={colors.fill} stroke={colors.stroke}
                strokeWidth={detect ? 4 : 2}
                strokeDasharray={isBlindNode ? "4,3" : "none"}
              />
              <text x={n.x} y={n.y - 6} textAnchor="middle"
                fill={colors.text} fontSize={detect ? 12 : 10} fontWeight={detect ? "bold" : "500"}>
                {n.label}
              </text>
              <text x={n.x} y={n.y + 9} textAnchor="middle"
                fill={colors.text} fontSize={8} opacity={0.85}>
                {n.sub}
              </text>
              {n.telemetry && n.telemetry.length > 0 && (
                <g>
                  <rect x={n.x - 20} y={n.y + n.r + 4} width={40} height={14} rx={3}
                    fill="#fff" stroke="#9e9e9e" strokeWidth="1" />
                  <text x={n.x} y={n.y + n.r + 14} textAnchor="middle" fontSize="8" fill="#616161">
                    {n.telemetry[0]}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Annotations */}
        {layout.annotations.map((a, i) => (
          <text key={i} x={a.x} y={a.y} textAnchor="middle" fontSize="9"
            fill={a.color} fontWeight={a.fontWeight || "normal"} fontStyle={a.fontStyle || "normal"}>
            {a.text}
          </text>
        ))}
      </svg>

      {/* Detail Panel */}
      {selNode && (
        <div style={{
          marginTop: 16, border: "1px solid #ddd", borderRadius: 6,
          padding: "16px 20px", background: "#fff",
          boxShadow: "0 2px 8px rgba(0,0,0,0.08)"
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{
                fontWeight: 600, fontSize: 15, marginBottom: 4,
                color: isDetect(selNode.id) ? COLORS.detect.stroke : COLORS[selNode.type].stroke
              }}>
                {selNode.label}: {selNode.sub}
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {selNode.tags.map((tag, i) => (
                  <span key={i} style={{
                    background: "#f5f5f5", border: "1px solid #e0e0e0", borderRadius: 4,
                    padding: "2px 8px", fontSize: 11, color: "#555"
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
              <div style={{ fontSize: 10, color: "#777", fontStyle: "italic", marginBottom: 8 }}>
                <strong>API / Protocol:</strong> {selNode.api}
              </div>
              <div style={{ fontSize: 10, color: "#555", marginBottom: 8 }}>
                <strong>Observable Artifact:</strong> {selNode.artifact}
              </div>
              <div style={{ fontSize: 13, color: "#333", lineHeight: 1.7 }}>{selNode.desc}</div>
              {selNode.telemetry && selNode.telemetry.length > 0 && (
                <div style={{ marginTop: 12, padding: "8px 12px", background: "#e3f2fd", borderRadius: 4 }}>
                  <span style={{ fontSize: 11, fontWeight: 600, color: "#1565c0" }}>Telemetry: </span>
                  <span style={{ fontSize: 11, color: "#1976d2" }}>{selNode.telemetry.join(", ")}</span>
                </div>
              )}
            </div>
            <button onClick={(e) => { e.stopPropagation(); setSel(null); }}
              style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer", color: "#aaa", marginLeft: 12, padding: "0 4px" }}>
              ×
            </button>
          </div>
          <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #eee", fontSize: 11, color: "#888" }}>
            <strong>Source:</strong> {selNode.src}
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{ marginTop: 12, fontSize: 11, color: "#bbb", textAlign: "center" }}>
        Click any node for details and sources · {metadata.tcode} {metadata.version} · VanVleet DDM Style · MITRE ATT&CK Enterprise
      </div>
    </div>
  );
}
