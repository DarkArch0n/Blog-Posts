# build-html.ps1
# Reads all DDM model .js files and generates a standalone HTML visualizer
# Usage: .\scripts\build-html.ps1
# Output: dist\ddm-credential-access.html  (open directly in browser)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$modelsDir = Join-Path $root "src\models\CredentialAccess"
$distDir   = Join-Path $root "dist"
$outFile   = Join-Path $distDir "ddm-credential-access.html"

if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

# ── Collect every model .js file (skip index.js) ────────────────
$jsFiles = Get-ChildItem -Path $modelsDir -Recurse -Filter "*.js" |
           Where-Object { $_.Name -ne "index.js" } |
           Sort-Object FullName

Write-Host "Found $($jsFiles.Count) model files"

# ── Transform each file into a MODELS[tcode] assignment ─────────
$modelBlocks = ""
foreach ($f in $jsFiles) {
    $raw   = Get-Content $f.FullName -Raw
    $tcode = $f.BaseName   # e.g. "T1558.001" or "T1040"

    # Strip: const model = → MODELS["T1558.001"] =
    #        export default model; → (nothing)
    $block = $raw -replace 'const model = ', "MODELS[`"$tcode`"] = " `
                  -replace 'export default model;', ''

    $modelBlocks += "`n// --- $tcode ---`n$block`n"
}

# ── HTML template with vanilla JS renderer ──────────────────────
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DDM Visualizer &mdash; Credential Access</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fff; color: #111; }

  /* ── nav sidebar ── */
  #sidebar {
    position: fixed; top: 0; left: 0; bottom: 0; width: 320px;
    background: #fafafa; border-right: 1px solid #e0e0e0;
    overflow-y: auto; padding: 24px 20px;
  }
  #sidebar h2 { font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: #666; margin-bottom: 4px; }
  #sidebar h1 { font-size: 20px; font-weight: 600; color: #111; margin-bottom: 16px; }
  .tech-group { margin-bottom: 14px; }
  .tech-group-label { font-size: 12px; font-weight: 600; color: #444; margin-bottom: 4px; padding-left: 4px; }
  .nav-btn {
    display: block; width: 100%; text-align: left; background: #fff;
    border: 1px solid #e0e0e0; border-radius: 4px; padding: 7px 12px;
    margin-bottom: 4px; cursor: pointer; font-size: 12px; transition: border-color .15s;
  }
  .nav-btn:hover { border-color: #1565c0; }
  .nav-btn.active { border-color: #2e7d32; background: #e8f5e9; }
  .nav-btn .tcode { font-weight: 500; color: #111; }
  .nav-btn .tname { color: #888; margin-left: 8px; }

  /* ── main area ── */
  #main { margin-left: 320px; padding: 28px 36px 60px; }

  /* ── header ── */
  #vis-header { margin-bottom: 20px; padding-bottom: 16px; border-bottom: 2px solid #e0e0e0; }
  #vis-header .label { font-size: 11px; color: #666; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 4px; }
  #vis-header .title { font-size: 24px; font-weight: 600; }
  #vis-header .meta  { font-size: 12px; color: #888; margin-top: 4px; }

  /* ── legend ── */
  #legend { display: flex; gap: 20px; margin-bottom: 20px; font-size: 12px; flex-wrap: wrap; align-items: center; }
  #legend .item { display: flex; align-items: center; gap: 6px; }

  /* ── svg area ── */
  #svg-wrap svg { display: block; background: #fafafa; border: 1px solid #e0e0e0; border-radius: 4px; }

  /* ── detail panel ── */
  #detail {
    margin-top: 16px; border: 1px solid #ddd; border-radius: 6px;
    padding: 16px 20px; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,.08);
    display: none;
  }
  #detail .node-title { font-weight: 600; font-size: 15px; margin-bottom: 4px; }
  #detail .tags { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
  #detail .tag {
    background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px;
    padding: 2px 8px; font-size: 11px; color: #555;
  }
  #detail .field { font-size: 10px; color: #777; font-style: italic; margin-bottom: 8px; }
  #detail .field strong { font-style: normal; }
  #detail .artifact { font-size: 10px; color: #555; margin-bottom: 8px; }
  #detail .artifact strong { font-style: normal; }
  #detail .desc { font-size: 13px; color: #333; line-height: 1.7; }
  #detail .telemetry { margin-top: 12px; padding: 8px 12px; background: #e3f2fd; border-radius: 4px; }
  #detail .telemetry span.lbl { font-size: 11px; font-weight: 600; color: #1565c0; }
  #detail .telemetry span.val { font-size: 11px; color: #1976d2; }
  #detail .source { margin-top: 12px; padding-top: 12px; border-top: 1px solid #eee; font-size: 11px; color: #888; }
  #detail .close-btn {
    float: right; background: none; border: none; font-size: 20px;
    cursor: pointer; color: #aaa; padding: 0 4px;
  }

  #footer { margin-top: 12px; font-size: 11px; color: #bbb; text-align: center; }

  /* placeholder when nothing selected */
  #placeholder { color: #bbb; text-align: center; margin-top: 120px; font-size: 14px; }
</style>
</head>
<body>

<!-- Sidebar Navigation -->
<div id="sidebar">
  <h2>Detection Data Models</h2>
  <h1>Credential Access</h1>
  <div id="nav"></div>
</div>

<!-- Main Visualization Area -->
<div id="main">
  <div id="placeholder">Select a technique from the sidebar to view its DDM visualization.</div>
  <div id="vis-header" style="display:none">
    <div class="label">Detection Data Model</div>
    <div class="title" id="hdr-title"></div>
    <div class="meta" id="hdr-meta"></div>
  </div>
  <div id="legend" style="display:none">
    <div class="item">
      <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill="#e8f5e9" stroke="#2e7d32" stroke-width="2"/></svg>
      <span>Attacker Operation</span>
    </div>
    <div class="item">
      <svg width="24" height="20"><circle cx="12" cy="10" r="8" fill="#fff8e1" stroke="#f57f17" stroke-width="3"/></svg>
      <span style="font-weight:600">Optimal Detection</span>
    </div>
    <div class="item">
      <svg width="20" height="20"><circle cx="10" cy="10" r="8" fill="#ffebee" stroke="#c62828" stroke-width="2" stroke-dasharray="3,2"/></svg>
      <span>Blind Spot</span>
    </div>
    <div class="item">
      <svg width="30" height="10"><line x1="0" y1="5" x2="30" y2="5" stroke="#c62828" stroke-width="1.5" stroke-dasharray="4,3"/></svg>
      <span style="color:#999">Blind Path</span>
    </div>
  </div>
  <div id="svg-wrap"></div>
  <div id="detail"></div>
  <div id="footer" style="display:none">Click any node for details and sources &middot; VanVleet DDM Style &middot; MITRE ATT&amp;CK Enterprise</div>
</div>

<script>
// ════════════════════════════════════════════════════════════════
// COLOR PALETTE
// ════════════════════════════════════════════════════════════════
const COLORS = {
  source: { fill: "#e8f5e9", stroke: "#2e7d32", text: "#1b5e20" },
  target: { fill: "#e3f2fd", stroke: "#1565c0", text: "#0d47a1" },
  detect: { fill: "#fff8e1", stroke: "#f57f17", text: "#e65100" },
  blind:  { fill: "#ffebee", stroke: "#c62828", text: "#b71c1c" },
};

// ════════════════════════════════════════════════════════════════
// MODEL REGISTRY  (populated by build-html.ps1)
// ════════════════════════════════════════════════════════════════
const MODELS = {};

$modelBlocks

// ════════════════════════════════════════════════════════════════
// TECHNIQUE META — for navigation grouping
// ════════════════════════════════════════════════════════════════
const TECHNIQUE_FAMILIES = {
  "T1558": "Steal or Forge Kerberos Tickets",
  "T1003": "OS Credential Dumping",
  "T1557": "Adversary-in-the-Middle",
  "T1110": "Brute Force",
  "T1555": "Credentials from Password Stores",
  "T1056": "Input Capture",
  "T1556": "Modify Authentication Process",
  "T1552": "Unsecured Credentials",
  "T1606": "Forge Web Credentials",
};

// ════════════════════════════════════════════════════════════════
// BUILD SIDEBAR NAVIGATION
// ════════════════════════════════════════════════════════════════
(function buildNav() {
  const nav = document.getElementById("nav");
  const keys = Object.keys(MODELS).sort();

  // Group by technique family (first 5 chars, e.g. "T1558")
  const groups = {};
  for (const k of keys) {
    const family = k.includes(".") ? k.split(".")[0] : k;
    if (!groups[family]) groups[family] = [];
    groups[family].push(k);
  }

  // Render groups
  for (const [family, tcodes] of Object.entries(groups)) {
    const div = document.createElement("div");
    div.className = "tech-group";

    const label = document.createElement("div");
    label.className = "tech-group-label";
    label.textContent = family + (TECHNIQUE_FAMILIES[family] ? " \u2014 " + TECHNIQUE_FAMILIES[family] : "");
    div.appendChild(label);

    for (const tcode of tcodes) {
      const btn = document.createElement("button");
      btn.className = "nav-btn";
      btn.dataset.tcode = tcode;
      btn.innerHTML = '<span class="tcode">' + tcode + '</span><span class="tname">' + MODELS[tcode].metadata.name + '</span>';
      btn.addEventListener("click", () => selectModel(tcode));
      div.appendChild(btn);
    }
    nav.appendChild(div);
  }
})();

// ════════════════════════════════════════════════════════════════
// RENDER MODEL
// ════════════════════════════════════════════════════════════════
let currentTcode = null;
let selectedNodeId = null;

function selectModel(tcode) {
  currentTcode = tcode;
  selectedNodeId = null;

  // highlight nav button
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const active = document.querySelector('.nav-btn[data-tcode="' + tcode + '"]');
  if (active) active.classList.add("active");

  const m = MODELS[tcode];
  document.getElementById("placeholder").style.display = "none";
  document.getElementById("vis-header").style.display = "";
  document.getElementById("legend").style.display = "";
  document.getElementById("footer").style.display = "";
  document.getElementById("detail").style.display = "none";
  document.getElementById("hdr-title").textContent = m.metadata.tcode + " \u2014 " + m.metadata.name;
  document.getElementById("hdr-meta").textContent =
    "Tactic: " + m.metadata.tactic + " \u00b7 Platform: " + m.metadata.platform + " \u00b7 MITRE ATT&CK " + m.metadata.version;

  renderSVG(m);
}

function renderSVG(m) {
  const wrap = document.getElementById("svg-wrap");
  wrap.innerHTML = "";

  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", m.layout.svgWidth);
  svg.setAttribute("height", m.layout.svgHeight);

  // ── defs: arrow markers ──
  const defs = document.createElementNS(ns, "defs");
  const markers = [
    { id: "arrow",        fill: "#666"    },
    { id: "arrow-blind",  fill: "#c62828" },
    { id: "arrow-detect", fill: "#f57f17" },
  ];
  markers.forEach(({ id, fill }) => {
    const marker = document.createElementNS(ns, "marker");
    marker.setAttribute("id", id);
    marker.setAttribute("markerWidth", "8");
    marker.setAttribute("markerHeight", "8");
    marker.setAttribute("refX", "7");
    marker.setAttribute("refY", "3");
    marker.setAttribute("orient", "auto");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M0,0 L0,6 L8,3z");
    p.setAttribute("fill", fill);
    marker.appendChild(p);
    defs.appendChild(marker);
  });
  svg.appendChild(defs);

  // ── column headers ──
  (m.layout.columns || []).forEach(col => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", col.x);
    t.setAttribute("y", "30");
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("font-size", "10");
    t.setAttribute("fill", "#999");
    t.setAttribute("font-weight", "500");
    t.textContent = col.label;
    svg.appendChild(t);
  });

  // ── vertical separators ──
  (m.layout.separators || []).forEach(x => {
    const l = document.createElementNS(ns, "line");
    l.setAttribute("x1", x); l.setAttribute("y1", "45");
    l.setAttribute("x2", x); l.setAttribute("y2", m.layout.svgHeight - 40);
    l.setAttribute("stroke", "#eee"); l.setAttribute("stroke-width", "1");
    l.setAttribute("stroke-dasharray", "4,4");
    svg.appendChild(l);
  });

  // ── edges ──
  m.edges.forEach(e => {
    const fn = m.nodes.find(n => n.id === e.f);
    const tn = m.nodes.find(n => n.id === e.t);
    if (!fn || !tn) return;
    const toDetect = tn.id === m.detectNodeId;
    const isBlind = !!e.blind;
    const x1 = fn.x + fn.r, y1 = fn.y;
    const x2 = tn.x - tn.r, y2 = tn.y;
    const mx = (x1 + x2) / 2;
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2);
    p.setAttribute("stroke", isBlind ? "#c62828" : toDetect ? "#f57f17" : "#888");
    p.setAttribute("stroke-width", toDetect ? "2" : "1.5");
    if (isBlind) p.setAttribute("stroke-dasharray", "5,4");
    p.setAttribute("fill", "none");
    p.setAttribute("marker-end", isBlind ? "url(#arrow-blind)" : toDetect ? "url(#arrow-detect)" : "url(#arrow)");
    svg.appendChild(p);
  });

  // ── nodes ──
  m.nodes.forEach(n => {
    const detect = n.id === m.detectNodeId;
    const colors = detect ? COLORS.detect : (COLORS[n.type] || COLORS.source);
    const isBlindNode = n.type === "blind";
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";
    g.addEventListener("click", () => showDetail(m, n.id));

    // selection ring (will be shown/hidden via data attribute)
    const ring = document.createElementNS(ns, "circle");
    ring.setAttribute("cx", n.x); ring.setAttribute("cy", n.y);
    ring.setAttribute("r", n.r + 6);
    ring.setAttribute("fill", "none");
    ring.setAttribute("stroke", "#333");
    ring.setAttribute("stroke-width", "2");
    ring.setAttribute("opacity", "0.3");
    ring.setAttribute("visibility", selectedNodeId === n.id ? "visible" : "hidden");
    ring.classList.add("sel-ring");
    ring.dataset.nid = n.id;
    g.appendChild(ring);

    // main circle
    const c = document.createElementNS(ns, "circle");
    c.setAttribute("cx", n.x); c.setAttribute("cy", n.y);
    c.setAttribute("r", n.r);
    c.setAttribute("fill", colors.fill);
    c.setAttribute("stroke", colors.stroke);
    c.setAttribute("stroke-width", detect ? "4" : "2");
    if (isBlindNode) c.setAttribute("stroke-dasharray", "4,3");
    g.appendChild(c);

    // label
    const t1 = document.createElementNS(ns, "text");
    t1.setAttribute("x", n.x); t1.setAttribute("y", n.y - 6);
    t1.setAttribute("text-anchor", "middle");
    t1.setAttribute("fill", colors.text);
    t1.setAttribute("font-size", detect ? "12" : "10");
    t1.setAttribute("font-weight", detect ? "bold" : "500");
    t1.textContent = n.label;
    g.appendChild(t1);

    // sub-label
    const t2 = document.createElementNS(ns, "text");
    t2.setAttribute("x", n.x); t2.setAttribute("y", n.y + 9);
    t2.setAttribute("text-anchor", "middle");
    t2.setAttribute("fill", colors.text);
    t2.setAttribute("font-size", "8");
    t2.setAttribute("opacity", "0.85");
    t2.textContent = n.sub;
    g.appendChild(t2);

    // telemetry badge
    if (n.telemetry && n.telemetry.length) {
      const bw = 40;
      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("x", n.x - bw / 2);
      rect.setAttribute("y", n.y + n.r + 4);
      rect.setAttribute("width", bw);
      rect.setAttribute("height", 14);
      rect.setAttribute("rx", 3);
      rect.setAttribute("fill", "#fff");
      rect.setAttribute("stroke", "#9e9e9e");
      rect.setAttribute("stroke-width", "1");
      g.appendChild(rect);

      const tb = document.createElementNS(ns, "text");
      tb.setAttribute("x", n.x);
      tb.setAttribute("y", n.y + n.r + 14);
      tb.setAttribute("text-anchor", "middle");
      tb.setAttribute("font-size", "8");
      tb.setAttribute("fill", "#616161");
      tb.textContent = n.telemetry[0];
      g.appendChild(tb);
    }

    svg.appendChild(g);
  });

  // ── annotations ──
  (m.layout.annotations || []).forEach(a => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", a.x); t.setAttribute("y", a.y);
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("font-size", "9");
    t.setAttribute("fill", a.color);
    if (a.fontWeight) t.setAttribute("font-weight", a.fontWeight);
    if (a.fontStyle)  t.setAttribute("font-style", a.fontStyle);
    t.textContent = a.text;
    svg.appendChild(t);
  });

  wrap.appendChild(svg);
}

// ════════════════════════════════════════════════════════════════
// DETAIL PANEL
// ════════════════════════════════════════════════════════════════
function showDetail(m, nodeId) {
  if (selectedNodeId === nodeId) { hideDetail(); return; }
  selectedNodeId = nodeId;
  const n = m.nodes.find(nd => nd.id === nodeId);
  if (!n) return;

  // update selection rings
  document.querySelectorAll(".sel-ring").forEach(r => {
    r.setAttribute("visibility", r.dataset.nid === nodeId ? "visible" : "hidden");
  });

  const detect = n.id === m.detectNodeId;
  const colors = detect ? COLORS.detect : (COLORS[n.type] || COLORS.source);
  const panel = document.getElementById("detail");
  panel.style.display = "block";
  panel.innerHTML = "";

  // close button
  const closeBtn = document.createElement("button");
  closeBtn.className = "close-btn";
  closeBtn.textContent = "\u00d7";
  closeBtn.addEventListener("click", (e) => { e.stopPropagation(); hideDetail(); });
  panel.appendChild(closeBtn);

  // title
  const title = document.createElement("div");
  title.className = "node-title";
  title.style.color = colors.stroke;
  title.textContent = n.label + ": " + n.sub;
  panel.appendChild(title);

  // tags
  if (n.tags && n.tags.length) {
    const tags = document.createElement("div");
    tags.className = "tags";
    n.tags.forEach(t => {
      const span = document.createElement("span");
      span.className = "tag";
      span.textContent = t;
      tags.appendChild(span);
    });
    panel.appendChild(tags);
  }

  // API
  if (n.api) {
    const d = document.createElement("div");
    d.className = "field";
    d.innerHTML = "<strong>API / Protocol:</strong> " + escHtml(n.api);
    panel.appendChild(d);
  }

  // Artifact
  if (n.artifact) {
    const d = document.createElement("div");
    d.className = "artifact";
    d.innerHTML = "<strong>Observable Artifact:</strong> " + escHtml(n.artifact);
    panel.appendChild(d);
  }

  // Description
  if (n.desc) {
    const d = document.createElement("div");
    d.className = "desc";
    d.textContent = n.desc;
    panel.appendChild(d);
  }

  // Telemetry
  if (n.telemetry && n.telemetry.length) {
    const d = document.createElement("div");
    d.className = "telemetry";
    d.innerHTML = '<span class="lbl">Telemetry: </span><span class="val">' + escHtml(n.telemetry.join(", ")) + '</span>';
    panel.appendChild(d);
  }

  // Source
  if (n.src) {
    const d = document.createElement("div");
    d.className = "source";
    d.innerHTML = "<strong>Source:</strong> " + escHtml(n.src);
    panel.appendChild(d);
  }
}

function hideDetail() {
  selectedNodeId = null;
  document.getElementById("detail").style.display = "none";
  document.querySelectorAll(".sel-ring").forEach(r => r.setAttribute("visibility", "hidden"));
}

function escHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
</script>
</body>
</html>
"@

# ── Write the output file ───────────────────────────────────────
[System.IO.File]::WriteAllText($outFile, $html, [System.Text.Encoding]::UTF8)
$size = (Get-Item $outFile).Length
Write-Host "Generated: $outFile ($([math]::Round($size / 1024)) KB) with $($jsFiles.Count) DDM models"
