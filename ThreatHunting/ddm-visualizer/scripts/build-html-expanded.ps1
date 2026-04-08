# build-html-expanded.ps1
# Reads all *.expanded.js DDM model files and generates a standalone HTML visualizer
# using the Expanded/Technology-Chain style (Tool -> API -> Protocol -> System -> Detection)
# Usage: .\scripts\build-html-expanded.ps1
# Output: dist\ddm-credential-access-expanded.html

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$modelsDir = Join-Path $root "src\models\CredentialAccess"
$distDir   = Join-Path $root "dist"
$outFile   = Join-Path $distDir "ddm-credential-access-expanded.html"

if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }

# -- Collect every .expanded.js file --
$jsFiles = Get-ChildItem -Path $modelsDir -Recurse -Filter "*.expanded.js" |
           Sort-Object FullName

Write-Host "Found $($jsFiles.Count) expanded model files"

# -- Transform each file into a MODELS[tcode] assignment --
$modelBlocks = ""
foreach ($f in $jsFiles) {
    $raw   = Get-Content $f.FullName -Raw
    # basename is e.g. "T1558.003.expanded" -> extract tcode
    $tcode = $f.BaseName -replace '\.expanded$', ''

    $block = $raw -replace 'const model = ', "MODELS[`"$tcode`"] = " `
                  -replace 'export default model;', ''

    $modelBlocks += "`n// --- $tcode ---`n$block`n"
}

# -- HTML template with expanded-style renderer --
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DDM Visualizer &mdash; Credential Access (Expanded Technology Chain)</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fff; color: #111; }

  #sidebar {
    position: fixed; top: 0; left: 0; bottom: 0; width: 320px;
    background: #fafafa; border-right: 1px solid #e0e0e0;
    overflow-y: auto; padding: 24px 20px;
  }
  #sidebar h2 { font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: #666; margin-bottom: 4px; }
  #sidebar h1 { font-size: 18px; font-weight: 600; color: #111; margin-bottom: 4px; }
  #sidebar .sub { font-size: 11px; color: #999; margin-bottom: 16px; }
  .tech-group { margin-bottom: 14px; }
  .tech-group-label { font-size: 12px; font-weight: 600; color: #444; margin-bottom: 4px; padding-left: 4px; }
  .nav-btn {
    display: block; width: 100%; text-align: left; background: #fff;
    border: 1px solid #e0e0e0; border-radius: 4px; padding: 7px 12px;
    margin-bottom: 4px; cursor: pointer; font-size: 12px; transition: border-color .15s;
  }
  .nav-btn:hover { border-color: #7b1fa2; }
  .nav-btn.active { border-color: #7b1fa2; background: #f3e5f5; }
  .nav-btn .tcode { font-weight: 500; color: #111; }
  .nav-btn .tname { color: #888; margin-left: 8px; }

  #main { margin-left: 320px; padding: 28px 36px 60px; overflow-x: auto; }

  #vis-header { margin-bottom: 16px; padding-bottom: 14px; border-bottom: 2px solid #e0e0e0; }
  #vis-header .label { font-size: 11px; color: "#666"; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 4px; }
  #vis-header .title { font-size: 24px; font-weight: 600; }
  #vis-header .meta  { font-size: 12px; color: #888; margin-top: 4px; }

  #legend { display: flex; gap: 16px; margin-bottom: 16px; font-size: 11px; flex-wrap: wrap; align-items: center; }
  #legend .item { display: flex; align-items: center; gap: 5px; }

  #svg-wrap { overflow-x: auto; }
  #svg-wrap svg { display: block; background: #fafafa; border: 1px solid #e0e0e0; border-radius: 4px; }

  #detail {
    margin-top: 16px; border: 2px solid #ddd; border-radius: 6px;
    padding: 16px 20px; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,.08);
    display: none;
  }
  #detail .node-title { font-weight: 600; font-size: 14px; margin-bottom: 6px; }
  #detail .node-type { font-size: 10px; color: #999; text-transform: uppercase; margin-left: 10px; }
  #detail .desc { font-size: 12px; color: #333; line-height: 1.6; }
  #detail .source { margin-top: 10px; padding-top: 8px; border-top: 1px solid #eee; font-size: 10px; color: #888; }
  #detail .close-btn {
    float: right; background: none; border: none; font-size: 20px;
    cursor: pointer; color: #aaa; padding: 0 4px;
  }

  #footer { margin-top: 12px; font-size: 11px; color: #bbb; text-align: center; }
  #placeholder { color: #bbb; text-align: center; margin-top: 120px; font-size: 14px; }
</style>
</head>
<body>

<div id="sidebar">
  <h2>Detection Data Models</h2>
  <h1>Credential Access</h1>
  <div class="sub">Expanded Technology Chain View</div>
  <div id="nav"></div>
</div>

<div id="main">
  <div id="placeholder">Select a technique from the sidebar to view the expanded technology chain.</div>
  <div id="vis-header" style="display:none">
    <div class="label">Detection Data Model &mdash; Expanded View</div>
    <div class="title" id="hdr-title"></div>
    <div class="meta" id="hdr-meta"></div>
  </div>
  <div id="legend" style="display:none">
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#f5f5f5" stroke="#333" stroke-width="2"/></svg><span>Entry Point</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#e8f5e9" stroke="#2e7d32" stroke-width="2"/></svg><span>Attacker Op</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#f3e5f5" stroke="#7b1fa2" stroke-width="2"/></svg><span>API Call</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#fff3e0" stroke="#e65100" stroke-width="2"/></svg><span>Protocol</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#e3f2fd" stroke="#1565c0" stroke-width="2"/></svg><span>System Process</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#fff8e1" stroke="#f57f17" stroke-width="3"/></svg><span style="font-weight:600">Detection Point</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#eceff1" stroke="#607d8b" stroke-width="2"/></svg><span>Artifact</span></div>
    <div class="item"><svg width="18" height="18"><circle cx="9" cy="9" r="7" fill="#ffebee" stroke="#c62828" stroke-width="2" stroke-dasharray="3,2"/></svg><span>Blind Spot</span></div>
  </div>
  <div id="svg-wrap"></div>
  <div id="detail"></div>
  <div id="footer" style="display:none">Click any node for details &middot; Expanded Technology Chain &middot; MITRE ATT&amp;CK Enterprise</div>
</div>

<script>
const COLORS = {
  entry:    { fill: "#f5f5f5", stroke: "#333",    text: "#111"   },
  op:       { fill: "#e8f5e9", stroke: "#2e7d32", text: "#1b5e20" },
  api:      { fill: "#f3e5f5", stroke: "#7b1fa2", text: "#4a148c" },
  protocol: { fill: "#fff3e0", stroke: "#e65100", text: "#bf360c" },
  system:   { fill: "#e3f2fd", stroke: "#1565c0", text: "#0d47a1" },
  detect:   { fill: "#fff8e1", stroke: "#f57f17", text: "#e65100" },
  artifact: { fill: "#eceff1", stroke: "#607d8b", text: "#37474f" },
  blind:    { fill: "#ffebee", stroke: "#c62828", text: "#b71c1c" },
};

const MODELS = {};

$modelBlocks

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

// -- Build sidebar nav --
(function buildNav() {
  const nav = document.getElementById("nav");
  const keys = Object.keys(MODELS).sort();
  const groups = {};
  for (const k of keys) {
    const family = k.includes(".") ? k.split(".")[0] : k;
    if (!groups[family]) groups[family] = [];
    groups[family].push(k);
  }
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

// -- Render --
let currentTcode = null;
let selectedNodeId = null;

function selectModel(tcode) {
  currentTcode = tcode;
  selectedNodeId = null;
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
    "Tactic: " + m.metadata.tactic + " \u00b7 Platform: " + m.metadata.platform +
    " \u00b7 Operations \u2192 APIs \u2192 Protocols \u2192 Systems \u2192 Detection";
  renderSVG(m);
}

function renderSVG(m) {
  const wrap = document.getElementById("svg-wrap");
  wrap.innerHTML = "";
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", m.layout.svgWidth);
  svg.setAttribute("height", m.layout.svgHeight);

  // defs
  const defs = document.createElementNS(ns, "defs");
  [{ id: "arrow", fill: "#888" }, { id: "arrow-blind", fill: "#c62828" }].forEach(({ id, fill }) => {
    const marker = document.createElementNS(ns, "marker");
    marker.setAttribute("id", id); marker.setAttribute("markerWidth", "6");
    marker.setAttribute("markerHeight", "6"); marker.setAttribute("refX", "5");
    marker.setAttribute("refY", "3"); marker.setAttribute("orient", "auto");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M0,0 L0,6 L6,3z"); p.setAttribute("fill", fill);
    marker.appendChild(p); defs.appendChild(marker);
  });
  svg.appendChild(defs);

  // row labels
  (m.layout.rows || []).forEach(row => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", "10"); t.setAttribute("y", row.y);
    t.setAttribute("font-size", "9"); t.setAttribute("fill", row.color || "#999");
    t.setAttribute("font-weight", "500"); t.textContent = row.label;
    svg.appendChild(t);
  });

  // edges
  m.edges.forEach(e => {
    const fn = m.nodes.find(n => n.id === e.f);
    const tn = m.nodes.find(n => n.id === e.t);
    if (!fn || !tn) return;
    const isBlind = !!e.blind;
    const x1 = fn.x + fn.r, y1 = fn.y;
    const x2 = tn.x - tn.r, y2 = tn.y;
    const mx = (x1 + x2) / 2;
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2);
    p.setAttribute("stroke", isBlind ? "#c62828" : "#aaa");
    p.setAttribute("stroke-width", "1.2");
    if (isBlind) p.setAttribute("stroke-dasharray", "4,3");
    p.setAttribute("fill", "none");
    p.setAttribute("marker-end", isBlind ? "url(#arrow-blind)" : "url(#arrow)");
    svg.appendChild(p);
  });

  // nodes
  m.nodes.forEach(n => {
    const isDetect = n.type === "detect";
    const isBlindN = n.type === "blind";
    const colors = COLORS[n.type] || COLORS.op;
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";
    g.addEventListener("click", () => showDetail(m, n.id));

    // selection ring
    const ring = document.createElementNS(ns, "circle");
    ring.setAttribute("cx", n.x); ring.setAttribute("cy", n.y);
    ring.setAttribute("r", n.r + 5); ring.setAttribute("fill", "none");
    ring.setAttribute("stroke", "#333"); ring.setAttribute("stroke-width", "2");
    ring.setAttribute("opacity", "0.4");
    ring.setAttribute("visibility", "hidden");
    ring.classList.add("sel-ring"); ring.dataset.nid = n.id;
    g.appendChild(ring);

    const c = document.createElementNS(ns, "circle");
    c.setAttribute("cx", n.x); c.setAttribute("cy", n.y); c.setAttribute("r", n.r);
    c.setAttribute("fill", colors.fill); c.setAttribute("stroke", colors.stroke);
    c.setAttribute("stroke-width", isDetect ? "3" : "1.5");
    if (isBlindN) c.setAttribute("stroke-dasharray", "3,2");
    g.appendChild(c);

    const t1 = document.createElementNS(ns, "text");
    t1.setAttribute("x", n.x); t1.setAttribute("y", n.sub ? n.y - 3 : n.y + 3);
    t1.setAttribute("text-anchor", "middle"); t1.setAttribute("fill", colors.text);
    t1.setAttribute("font-size", isDetect ? "10" : "8");
    t1.setAttribute("font-weight", isDetect ? "bold" : "500");
    t1.textContent = n.label;
    g.appendChild(t1);

    if (n.sub) {
      const t2 = document.createElementNS(ns, "text");
      t2.setAttribute("x", n.x); t2.setAttribute("y", n.y + 9);
      t2.setAttribute("text-anchor", "middle"); t2.setAttribute("fill", colors.text);
      t2.setAttribute("font-size", "7"); t2.setAttribute("opacity", "0.7");
      t2.textContent = n.sub;
      g.appendChild(t2);
    }
    svg.appendChild(g);
  });

  // annotations
  (m.layout.annotations || []).forEach(a => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", a.x); t.setAttribute("y", a.y);
    t.setAttribute("text-anchor", "middle"); t.setAttribute("font-size", "9");
    t.setAttribute("fill", a.color || "#999");
    if (a.fontWeight) t.setAttribute("font-weight", a.fontWeight);
    if (a.fontStyle) t.setAttribute("font-style", a.fontStyle);
    t.textContent = a.text;
    svg.appendChild(t);
  });

  wrap.appendChild(svg);
}

function showDetail(m, nodeId) {
  if (selectedNodeId === nodeId) { hideDetail(); return; }
  selectedNodeId = nodeId;
  const n = m.nodes.find(nd => nd.id === nodeId);
  if (!n) return;
  document.querySelectorAll(".sel-ring").forEach(r => {
    r.setAttribute("visibility", r.dataset.nid === nodeId ? "visible" : "hidden");
  });
  const colors = COLORS[n.type] || COLORS.op;
  const panel = document.getElementById("detail");
  panel.style.display = "block";
  panel.style.borderColor = colors.stroke;
  panel.innerHTML = "";

  const closeBtn = document.createElement("button");
  closeBtn.className = "close-btn"; closeBtn.textContent = "\u00d7";
  closeBtn.addEventListener("click", (e) => { e.stopPropagation(); hideDetail(); });
  panel.appendChild(closeBtn);

  const title = document.createElement("div");
  title.className = "node-title";
  title.style.color = colors.text;
  title.innerHTML = escHtml(n.label + (n.sub ? " \u2014 " + n.sub : "")) +
    '<span class="node-type">' + escHtml(n.type) + '</span>';
  panel.appendChild(title);

  if (n.desc) {
    const d = document.createElement("div");
    d.className = "desc"; d.textContent = n.desc;
    panel.appendChild(d);
  }
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

function escHtml(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($outFile, $html, [System.Text.Encoding]::UTF8)
$size = (Get-Item $outFile).Length
Write-Host "Generated: $outFile ($([math]::Round($size / 1024)) KB) with $($jsFiles.Count) expanded DDM models"
