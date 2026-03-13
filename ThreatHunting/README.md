# Huntability Framework — Project README

## Project Overview

This project aims to quantify a theory called **Huntability** — a scoring system that adds weight and priority to TTPs (Tactics, Techniques, and Procedures) within the MITRE ATT&CK Enterprise Matrix based on **signal-to-noise ratios**.

The core question this framework answers:

> *"Given perfect visibility, which MITRE ATT&CK sub-techniques produce the cleanest, most reliable hunting signal — and why?"*

This is not a visibility exercise. Telemetry availability is assumed to be complete. The framework measures the **intrinsic huntability** of a technique based on the nature of the behavior itself.

---

## Key References

- **Primary methodology guide:** [VanVleet — Technique Analysis and Modeling](https://medium.com/@vanvleet/technique-analysis-and-modeling-ffef1f0a595a)
- **Detection Data Model (DDM) concept:** [VanVleet — Improving Threat Identification with Detection Data Models](https://medium.com/@vanvleet/improving-threat-identification-with-detection-data-models-1cad2f8ce051)
- **ATT&CK Matrix:** [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)

---

## Core Assumptions

1. **Visibility is assumed** — All logs and telemetry sources are available. This is not a detection engineering gap analysis. Visibility is a separate layer handled elsewhere.
2. **Scored at the sub-technique level** — Each ATT&CK sub-technique (TCode) is scored individually.
3. **Environment-agnostic** — Scores should be reusable across any SOC or hunt team regardless of their stack.
4. **Empirically grounded** — Scores are derived from lab emulation against a realistic user noise baseline, not opinion.

---

## Methodology

The Huntability Framework follows a four-phase process per sub-technique:

### Phase 1 — Build a Detection Data Model (DDM)
Model every known procedural implementation path for the sub-technique. Based on the VanVleet DDM approach — visually decomposing *how* the technique executes across all known variants.

- Map all known tools, APIs, protocols, and execution paths
- Cite every procedure to a primary source (tool repo, Microsoft docs, threat intel report, etc.)
- Document known blind spots

### Phase 2 — Identify the Optimal Detection Node
Within the DDM, find the node shared by the most procedure paths. This is the **Primary Detection Point** — where a single detection covers the broadest set of implementations.

### Phase 3 — Lab Emulation with Noise Baseline
Execute the procedures in a controlled lab environment that includes **realistic user activity emulation**. Measure the malicious signal against the noise floor of normal operations — not in a vacuum.

### Phase 4 — Score Signal Fidelity
Compare malicious signal against the baseline noise at the optimal detection node. This produces an empirical, defensible Huntability Score.

---

## Scoring Model

### Huntability Score Formula (Draft)

```
Huntability Score = Z-Score × Procedural Coverage %
```

- **Z-Score** = (Malicious Event Rate − Baseline Mean) / Baseline Standard Deviation
  - Measures how many standard deviations the malicious behavior stands out from normal activity
  - High Z-score = technique stands out sharply = highly huntable
  - Low Z-score = blends into normal activity = poor signal fidelity

- **Procedural Coverage %** = Percentage of known procedures detectable at the optimal detection node
  - Accounts for how broadly a single detection point covers the technique's attack surface

### Why Z-Score over Simple Ratio
A simple ratio (malicious events / total events) does not account for variance or sample size. Two techniques could share the same ratio with very different statistical confidence. The Z-score normalizes against the mean and standard deviation of the noise baseline, producing a more defensible and comparable score.

### Scoring Dimensions (Supporting)
These qualitative dimensions inform and contextualize the quantitative score:

| Dimension | Description |
|---|---|
| Signal Fidelity | How distinctly malicious does the behavior look vs. legitimate activity? |
| Procedure Distinctness | How many meaningfully different implementation paths exist? |
| Evasion Resistance | How easily can an attacker modify their approach without losing effectiveness? |
| Adversary Use Frequency | How commonly observed across real-world threat actor activity? |
| Behavioral Uniqueness | Does this technique leave artifacts inherently rare in normal operations? |
| Detection Complexity | Even with perfect data, how hard is it to write a reliable low-FP detection? |

---

## Output Artifacts Per Sub-Technique

For each sub-technique the framework produces:

1. **Detection Data Model (DDM)** — Visual node graph of all procedural paths
2. **Optimal Detection Node Analysis** — Which node covers the most procedures and why
3. **Blind Spot Documentation** — Known gaps at the optimal node and mitigation paths
4. **Source Citations** — Every procedural claim cited to a primary source
5. **Huntability Score** — Empirical Z-score × procedural coverage composite
6. **Technique Research Report (TRR)** — Full written document capturing all of the above

---

## Visual Format — Detection Data Model (DDM)

DDMs are rendered as node-graph flowcharts. Each node represents an operation or procedure. Edges represent execution flow. Built as interactive React (JSX) components.

### Node Types
| Type | Description | Visual |
|---|---|---|
| Entry Point | Starting condition for the technique | Green border |
| Procedure / Operation | A distinct implementation path | Blue border |
| Optimal Detection Node | The node covering the most procedures | Yellow fill, bold border |
| Blind Spot | Path or node with no reliable telemetry | Red/faded border, dashed edge |

### Tech Stack for Visuals
- React (JSX) with inline styles only
- SVG for node graph rendering
- No Tailwind CSS — inline styles only to avoid CSS conflicts
- `index.css` should contain only a reset, no Tailwind directives

---

## Pilot Sub-Technique — T1558.003: Kerberoasting

### Overview
- **Tactic:** Credential Access
- **Platform:** Windows Active Directory
- **MITRE Version:** v15, Last Modified October 2025

### DDM Summary

**Phase 1 — SPN Enumeration (4 procedures)**
1. LDAP Query via Windows tool (Rubeus / PowerView / PowerShell IdentityModel)
2. LDAP Query via Linux/Remote tool (Impacket GetUserSPNs.py / NetExec)
3. Native binary enumeration (setspn.exe)
4. ⚠ Passive Network Capture — *BLIND SPOT: no LDAP query issued, no 4769 fires*

**Phase 2 — TGS-REQ (4 procedures)**
1. RC4 Downgrade Request (etype 0x17) — default for most tools
2. AES Stealth Request (etype 0x12) — modified Impacket, blends with normal traffic
3. Ticket Options Manipulation — modify flags to match normal AD traffic patterns
4. tgtdeleg RC4 Downgrade — Rubeus /tgtdeleg, patched on Windows Server 2019+

**Optimal Detection Node — Windows Event ID 4769**
- Covers all 4 active tool-based TGS request procedures
- Key filters: exclude krbtgt, exclude machine accounts (*$), success only (failure code 0x0)
- Also monitor: encryption type 0x17 (RC4 downgrade), anomalous ticket option flags

**Phase 3 — Extraction (3 procedures)**
1. In-memory extraction (Mimikatz / Rubeus from LSASS cache)
2. Direct tool output ($krb5tgs$23$ RC4 / $krb5tgs$18$ AES256 to file)
3. ⚠ PCAP Hash Extraction — *BLIND SPOT: nidem/kerberoast pcap parser, passive*

**Phase 4 — Offline Cracking**
- ⚠ BLIND SPOT: Entirely off-network. Zero DC events. Zero logs.
- RC4: hashcat mode 13100
- AES256: hashcat mode 19700

### Known Blind Spots

| Blind Spot | Reason | Mitigation Path |
|---|---|---|
| Passive PCAP collection | No TGS-REQ made, no 4769 fires | NDR / enforce encrypted Kerberos traffic |
| Offline cracking phase | Happens entirely off-network | Prevention only — strong passwords, gMSA |
| AES + normal ticket options | No RC4 indicator, no anomalous flags | Behavioral baseline of per-account TGS volume |

### Sources — T1558.003
- MITRE ATT&CK T1558.003 — https://attack.mitre.org/techniques/T1558/003/
- MITRE ATT&CK DET0157 — https://attack.mitre.org/detectionstrategies/DET0157/
- SpecterOps — Kerberoasting Revisited, 2019 — https://specterops.io/blog/2019/02/20/kerberoasting-revisited/
- TrustedSec — Bypassing Kerberoast Detections with Orpheus, 2025 — https://trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus
- Intrinsec — Kerberos OPSEC Part 1, 2023 — https://www.intrinsec.com/en/kerberos_opsec_part_1_kerberoasting/
- ADSecurity — Cracking Kerberos TGS Tickets, Metcalf 2015 — https://adsecurity.org/?p=2293
- HackTricks Kerberoast — https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast
- Atomic Red Team T1558.003 — https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md
- nidem/kerberoast — https://github.com/nidem/kerberoast
- Netresec — Extracting Kerberos Credentials from PCAP, 2019 — https://www.netresec.com/?page=Blog&month=2019-11&post=Extracting-Kerberos-Credentials-from-PCAP

---

## Blog / Publishing Plan

The project will be documented publicly as a blog series covering:
1. The Huntability theory and framework
2. Deep dives per sub-technique (DDM + scoring + lab results)

**Recommended platform:** Hashnode (short term) → Custom Astro site (long term) so that interactive DDM visuals can be embedded natively in posts rather than as screenshots.

---

## Project Status

| Item | Status |
|---|---|
| Framework defined | ✅ Complete |
| Scoring model (draft) | ✅ Complete |
| Pilot DDM — T1558.003 | ✅ Research complete, visual in progress |
| Lab emulation methodology | 🔲 Not started |
| TRR template | 🔲 Not started |
| Second sub-technique | 🔲 Not started |
| Blog setup | 🔲 Not started |

---

## Notes for Copilot

- All DDM visuals are React JSX components using SVG for the node graph and **inline styles only**
- Do not use Tailwind CSS — remove any Tailwind directives from index.css and replace with a simple CSS reset
- Node types: `entry`, `op`, `detect`, `blind`
- Edges support a `blind: true` flag which renders as a dashed line with a faded arrow
- Each node has an `id`, `label`, `sub` (subtitle), `x`, `y`, `w`, `h`, and `type`
- Clicking a node opens a detail panel below the SVG showing description and source citations
- The optimal detection node (`type: "detect"`) should be visually distinct — bold border, highlighted fill
