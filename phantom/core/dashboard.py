"""
Interactive web dashboard generator for PHANTOM scan results.
Big, clear stats. Easy to understand at a glance. Presentation-grade.
"""

from __future__ import annotations

import json
import html as html_mod
from datetime import datetime
from phantom.core.models import ScanResult, Severity


def generate_dashboard(result: ScanResult, path: str) -> None:
    findings_json = json.dumps([
        {
            "title": f.title,
            "category": f.category.value,
            "severity": f.severity.value,
            "description": f.description,
            "evidence": f.evidence,
            "module": f.module,
            "chainable": f.chainable,
            "chain_tags": f.chain_tags,
            "remediation": f.remediation,
            "has_differential": f.differential is not None,
            "differential": {
                "probe": f.differential.probe_description,
                "layers": [
                    {"name": l.layer_name, "interpretation": l.interpretation, "status": l.status_code}
                    for l in f.differential.layers
                ],
                "exploitable": f.differential.exploitable,
            } if f.differential else None,
        }
        for f in sorted(result.findings, key=lambda x: x.severity.score, reverse=True)
    ])

    chains_json = json.dumps([
        {
            "name": c.name,
            "severity": c.severity.value,
            "description": c.description,
            "impact": c.impact,
            "steps": c.steps,
            "finding_count": len(c.findings),
        }
        for c in result.chains
    ])

    fp = result.fingerprint
    fingerprint_json = json.dumps({
        "web_server": fp.web_server if fp else None,
        "framework": fp.framework if fp else None,
        "waf": fp.waf if fp else None,
        "reverse_proxy": fp.reverse_proxy if fp else None,
        "cdn": fp.cdn if fp else None,
        "language": fp.language if fp else None,
        "layer_count": fp.layer_count if fp else 0,
        "layers": [{"label": k, "value": v} for k, v in fp.summary_lines()] if fp else [],
    })

    sev_counts = {s.value: 0 for s in Severity}
    for f in result.findings:
        sev_counts[f.severity.value] += 1

    cat_counts: dict[str, int] = {}
    for f in result.findings:
        cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1

    scan_time = datetime.fromtimestamp(result.start_time).strftime("%Y-%m-%d %H:%M:%S")

    page = _TEMPLATE
    replacements = {
        "{{TARGET}}": html_mod.escape(result.target),
        "{{SCAN_TIME}}": scan_time,
        "{{DURATION}}": f"{result.duration:.1f}",
        "{{REQUESTS}}": str(result.requests_sent),
        "{{TOTAL_FINDINGS}}": str(len(result.findings)),
        "{{CRITICAL_COUNT}}": str(sev_counts.get("critical", 0)),
        "{{HIGH_COUNT}}": str(sev_counts.get("high", 0)),
        "{{MEDIUM_COUNT}}": str(sev_counts.get("medium", 0)),
        "{{LOW_COUNT}}": str(sev_counts.get("low", 0)),
        "{{INFO_COUNT}}": str(sev_counts.get("info", 0)),
        "{{CHAIN_COUNT}}": str(len(result.chains)),
        "{{FINDINGS_JSON}}": findings_json,
        "{{CHAINS_JSON}}": chains_json,
        "{{FINGERPRINT_JSON}}": fingerprint_json,
        "{{CATEGORY_LABELS}}": json.dumps(list(cat_counts.keys())),
        "{{CATEGORY_VALUES}}": json.dumps(list(cat_counts.values())),
    }
    for k, v in replacements.items():
        page = page.replace(k, v)

    with open(path, "w") as fh:
        fh.write(page)


_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHANTOM Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#05060f;--surface:#0b0d1a;--surface2:#10132a;--surface3:#161a35;
  --border:#1c2048;--fg:#e8eaf6;--dim:#7881a8;
  --accent:#00e5ff;--accent2:#7c4dff;--glow-accent:rgba(0,229,255,.25);
  --crit:#ff1744;--high:#ff5252;--med:#ffab00;--low:#00e676;--info:#448aff;
  --font:'Inter','Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono','Fira Code',monospace;
}
body{background:var(--bg);color:var(--fg);font-family:var(--font);line-height:1.5}

/* Grid BG */
.grid-bg{position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:
    linear-gradient(rgba(0,229,255,.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,.025) 1px,transparent 1px);
  background-size:50px 50px}

.wrap{position:relative;z-index:1;max-width:1320px;margin:0 auto;padding:2rem 1.5rem}

/* ───── HEADER ───── */
.hdr{text-align:center;padding:2.5rem 0 .5rem}
.hdr h1{font-size:3.2rem;font-weight:900;letter-spacing:.18em;
  background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  filter:drop-shadow(0 0 40px var(--glow-accent))}
.hdr .sub{color:var(--dim);font-size:.82rem;letter-spacing:.25em;text-transform:uppercase;margin-top:.2rem}
.target-bar{margin:1.5rem auto .3rem;display:inline-flex;align-items:center;gap:.75rem;
  padding:.5rem 2rem;border:1px solid var(--accent);border-radius:100px;
  background:rgba(0,229,255,.04);font-family:var(--mono);font-size:.95rem;color:var(--accent)}
.target-bar .dot{width:8px;height:8px;border-radius:50%;background:var(--low);
  box-shadow:0 0 8px var(--low);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.meta-line{color:var(--dim);font-size:.78rem;margin-top:.6rem}

/* ───── BIG HERO STATS ───── */
.hero{display:grid;grid-template-columns:repeat(4,1fr);gap:1.25rem;margin:2.5rem 0}
.hero-card{background:linear-gradient(135deg,var(--surface) 0%,var(--surface2) 100%);
  border:1px solid var(--border);border-radius:16px;padding:2rem 1.5rem;text-align:center;
  position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s}
.hero-card:hover{transform:translateY(-4px);box-shadow:0 12px 40px rgba(0,0,0,.4)}
.hero-card .num{font-size:3.8rem;font-weight:900;font-family:var(--mono);line-height:1}
.hero-card .label{color:var(--dim);font-size:.82rem;text-transform:uppercase;letter-spacing:.15em;margin-top:.5rem}
.hero-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:4px}
.hero-card.total .num{color:var(--accent)}
.hero-card.total::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.hero-card.critical .num{color:var(--crit)}
.hero-card.critical::after{background:var(--crit)}
.hero-card.high .num{color:var(--high)}
.hero-card.high::after{background:var(--high)}
.hero-card.chains .num{color:var(--accent2)}
.hero-card.chains::after{background:var(--accent2)}

/* ───── SECONDARY STATS ───── */
.sec-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2.5rem}
.sec-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:1rem 1.25rem;display:flex;align-items:center;gap:1rem}
.sec-card .icon{width:44px;height:44px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;font-size:1.3rem;font-weight:800;flex-shrink:0}
.sec-card .icon.req{background:rgba(0,229,255,.1);color:var(--accent)}
.sec-card .icon.dur{background:rgba(124,77,255,.1);color:var(--accent2)}
.sec-card .icon.med{background:rgba(255,171,0,.1);color:var(--med)}
.sec-card .icon.low{background:rgba(0,230,118,.1);color:var(--low)}
.sec-card .val{font-size:1.4rem;font-weight:800;font-family:var(--mono)}
.sec-card .lbl{color:var(--dim);font-size:.72rem;text-transform:uppercase;letter-spacing:.1em}

/* ───── SEVERITY BAR ───── */
.sev-bar-wrap{margin-bottom:2.5rem}
.sev-bar-title{color:var(--dim);font-size:.75rem;text-transform:uppercase;letter-spacing:.15em;margin-bottom:.6rem}
.sev-bar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--surface2)}
.sev-bar span{transition:width .8s ease}
.sev-legend{display:flex;gap:1.5rem;margin-top:.6rem;flex-wrap:wrap}
.sev-legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:.3rem;vertical-align:middle}
.sev-legend small{color:var(--dim);font-size:.78rem}

/* ───── PANELS ───── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:14px;
  padding:1.5rem;margin-bottom:1.5rem}
.panel-hd{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.12em;
  color:var(--accent);margin-bottom:1.25rem;display:flex;align-items:center;gap:.5rem}
.panel-hd::before{content:'';width:4px;height:16px;background:var(--accent);border-radius:2px}

/* ───── CHARTS ───── */
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem}
.chart-box{height:300px;position:relative}

/* ───── LAYERS VISUAL ───── */
.layers{display:flex;flex-direction:column;gap:.6rem}
.layer-row{display:flex;align-items:center;gap:1rem;padding:.7rem 1rem;
  background:var(--surface2);border:1px solid var(--border);border-radius:10px;
  transition:border-color .2s}
.layer-row:hover{border-color:var(--accent)}
.layer-dot{width:10px;height:10px;border-radius:50%;background:var(--accent);
  box-shadow:0 0 8px var(--accent);flex-shrink:0}
.layer-name{color:var(--dim);min-width:110px;font-size:.82rem}
.layer-val{font-weight:700;font-size:.9rem;flex:1}
.layer-bar{height:6px;border-radius:3px;background:var(--surface);overflow:hidden;width:100px;flex-shrink:0}
.layer-bar-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2))}

/* ───── CHAINS ───── */
.chain{background:var(--surface2);border-left:4px solid var(--crit);border-radius:0 12px 12px 0;
  padding:1.25rem 1.5rem;margin-bottom:1rem;position:relative}
.chain-hd{display:flex;align-items:center;gap:.75rem;margin-bottom:.6rem;flex-wrap:wrap}
.chain-name{font-weight:800;font-size:1rem}
.badge{padding:.2rem .7rem;border-radius:5px;font-size:.7rem;font-weight:800;text-transform:uppercase}
.badge-crit{background:var(--crit);color:#fff}
.badge-high{background:var(--high);color:#fff}
.badge-med{background:var(--med);color:#000}
.badge-low{background:var(--low);color:#000}
.badge-info{background:var(--info);color:#fff}
.chain ol{padding-left:1.5rem;margin:.4rem 0}
.chain li{color:var(--dim);font-size:.85rem;margin:.2rem 0}
.chain li::marker{color:var(--accent)}
.chain-impact{font-size:.82rem;color:var(--crit);border-top:1px solid var(--border);
  padding-top:.6rem;margin-top:.6rem;font-style:italic}

/* ───── FINDINGS ───── */
.finding{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  margin-bottom:.75rem;overflow:hidden;transition:border-color .2s}
.finding:hover{border-color:var(--accent)}
.finding-hd{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;cursor:pointer}
.finding-hd:hover{background:rgba(0,229,255,.02)}
.sev-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.sev-dot.critical{background:var(--crit);box-shadow:0 0 10px var(--crit)}
.sev-dot.high{background:var(--high);box-shadow:0 0 8px var(--high)}
.sev-dot.medium{background:var(--med);box-shadow:0 0 6px var(--med)}
.sev-dot.low{background:var(--low)}
.sev-dot.info{background:var(--info)}
.finding-title{font-weight:700;font-size:.92rem;flex:1}
.finding-arrow{color:var(--dim);transition:transform .2s;flex-shrink:0;font-size:.8rem}
.finding.open .finding-arrow{transform:rotate(90deg)}
.finding-body{display:none;padding:0 1.25rem 1.25rem;border-top:1px solid var(--border)}
.finding.open .finding-body{display:block}
.finding-desc{color:var(--dim);font-size:.85rem;margin-top:.75rem;line-height:1.6}
.evidence{background:var(--bg);border:1px solid var(--border);border-radius:8px;
  padding:.75rem 1rem;font-family:var(--mono);font-size:.82rem;margin-top:.75rem;
  overflow-x:auto;white-space:pre-wrap;color:var(--accent);line-height:1.6}
.diff-table{width:100%;border-collapse:collapse;margin-top:.75rem;font-size:.82rem}
.diff-table th{text-align:left;color:var(--accent);padding:.5rem .7rem;border-bottom:2px solid var(--border);font-weight:700}
.diff-table td{padding:.5rem .7rem;border-bottom:1px solid rgba(255,255,255,.04)}
.diff-ok{color:var(--low);font-weight:700}
.diff-bad{color:var(--crit);font-weight:700}
.diff-exploit{color:var(--crit);font-weight:800;margin-top:.6rem;font-size:.85rem}
.finding-tags{display:flex;gap:.4rem;margin-top:.75rem;flex-wrap:wrap}
.tag{font-size:.7rem;padding:.15rem .55rem;border-radius:20px;
  background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.15);color:var(--accent)}
.finding-fix{font-size:.82rem;color:var(--low);margin-top:.6rem;font-style:italic}

/* ───── SECTION TITLES ───── */
.sec-title{font-size:1.2rem;font-weight:800;margin:2.5rem 0 1.25rem;
  padding-bottom:.6rem;border-bottom:2px solid var(--border);
  display:flex;align-items:center;gap:.75rem;letter-spacing:.03em}
.sec-title .ic{font-size:1.3rem}

/* ───── FOOTER ───── */
.footer{text-align:center;color:var(--dim);font-size:.75rem;padding:3rem 0 2rem;
  border-top:1px solid var(--border);margin-top:3rem}

/* ───── RESPONSIVE ───── */
@media(max-width:900px){.hero,.sec-stats{grid-template-columns:repeat(2,1fr)}.chart-row{grid-template-columns:1fr}}
@media(max-width:600px){.hero{grid-template-columns:1fr}.hero-card .num{font-size:2.5rem}.wrap{padding:1rem}}
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="wrap">

<!-- HEADER -->
<div class="hdr">
  <h1>PHANTOM</h1>
  <div class="sub">Inter-Layer Semantic Gap Exploitation Framework</div>
  <div class="target-bar"><span class="dot"></span> {{TARGET}}</div>
  <div class="meta-line">Scanned {{SCAN_TIME}}</div>
</div>

<!-- HERO STATS -->
<div class="hero">
  <div class="hero-card total">
    <div class="num" data-count="{{TOTAL_FINDINGS}}">0</div>
    <div class="label">Total Findings</div>
  </div>
  <div class="hero-card critical">
    <div class="num" data-count="{{CRITICAL_COUNT}}">0</div>
    <div class="label">Critical</div>
  </div>
  <div class="hero-card high">
    <div class="num" data-count="{{HIGH_COUNT}}">0</div>
    <div class="label">High Severity</div>
  </div>
  <div class="hero-card chains">
    <div class="num" data-count="{{CHAIN_COUNT}}">0</div>
    <div class="label">Attack Chains</div>
  </div>
</div>

<!-- SECONDARY STATS -->
<div class="sec-stats">
  <div class="sec-card"><div class="icon req">TX</div><div><div class="val">{{REQUESTS}}</div><div class="lbl">Requests Sent</div></div></div>
  <div class="sec-card"><div class="icon dur">T</div><div><div class="val">{{DURATION}}s</div><div class="lbl">Scan Duration</div></div></div>
  <div class="sec-card"><div class="icon med">{{MEDIUM_COUNT}}</div><div><div class="val">Medium</div><div class="lbl">Severity Findings</div></div></div>
  <div class="sec-card"><div class="icon low">{{LOW_COUNT}}</div><div><div class="val">Low / Info</div><div class="lbl">Severity Findings</div></div></div>
</div>

<!-- SEVERITY BAR -->
<div class="sev-bar-wrap">
  <div class="sev-bar-title">Severity Distribution</div>
  <div class="sev-bar" id="sevBar"></div>
  <div class="sev-legend" id="sevLegend"></div>
</div>

<!-- CHARTS -->
<div class="chart-row">
  <div class="panel">
    <div class="panel-hd">Findings by Severity</div>
    <div class="chart-box"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-hd">Findings by Category</div>
    <div class="chart-box"><canvas id="catChart"></canvas></div>
  </div>
</div>

<!-- FINGERPRINT -->
<div class="panel">
  <div class="panel-hd">Stack Fingerprint — Parsing Layers</div>
  <div class="layers" id="layerStack"></div>
</div>

<!-- CHAINS -->
<div id="chainsSection"></div>

<!-- FINDINGS -->
<div class="sec-title"><span class="ic">&#9670;</span> All Findings</div>
<div id="findingsBox"></div>

<div class="footer">PHANTOM v1.0.0 &mdash; Protocol Hallucination &amp; Anomaly Network Testing Oracle Machine</div>
</div>

<script>
const findings={{FINDINGS_JSON}};
const chains={{CHAINS_JSON}};
const fp={{FINGERPRINT_JSON}};
const catLabels={{CATEGORY_LABELS}};
const catValues={{CATEGORY_VALUES}};
const sevData={critical:{{CRITICAL_COUNT}},high:{{HIGH_COUNT}},medium:{{MEDIUM_COUNT}},low:{{LOW_COUNT}},info:{{INFO_COUNT}}};
const total={{TOTAL_FINDINGS}};

/* Animated counters */
document.querySelectorAll('[data-count]').forEach(el=>{
  const t=+el.dataset.count;let c=0;
  const s=Math.max(1,Math.ceil(t/25));
  const iv=setInterval(()=>{c+=s;if(c>=t){c=t;clearInterval(iv)}el.textContent=c},40);
});

/* Severity bar */
(function(){
  const bar=document.getElementById('sevBar');
  const leg=document.getElementById('sevLegend');
  const items=[
    {k:'critical',n:'Critical',c:'#ff1744',v:sevData.critical},
    {k:'high',n:'High',c:'#ff5252',v:sevData.high},
    {k:'medium',n:'Medium',c:'#ffab00',v:sevData.medium},
    {k:'low',n:'Low',c:'#00e676',v:sevData.low},
    {k:'info',n:'Info',c:'#448aff',v:sevData.info}
  ];
  const t=Math.max(total,1);
  items.forEach(i=>{
    if(!i.v) return;
    const s=document.createElement('span');
    s.style.cssText=`width:${(i.v/t*100).toFixed(1)}%;background:${i.c}`;
    bar.appendChild(s);
    leg.innerHTML+=`<small><i style="background:${i.c}"></i>${i.n}: ${i.v}</small>`;
  });
})();

/* Charts */
Chart.defaults.color='#7881a8';Chart.defaults.borderColor='rgba(255,255,255,.04)';
new Chart(document.getElementById('sevChart'),{
  type:'doughnut',
  data:{labels:['Critical','High','Medium','Low','Info'],
    datasets:[{data:[sevData.critical,sevData.high,sevData.medium,sevData.low,sevData.info],
      backgroundColor:['#ff1744','#ff5252','#ffab00','#00e676','#448aff'],
      borderColor:'#0b0d1a',borderWidth:4,hoverOffset:10}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'68%',
    plugins:{legend:{position:'bottom',labels:{padding:16,font:{size:12},usePointStyle:true,pointStyleWidth:10}}}}
});

new Chart(document.getElementById('catChart'),{
  type:'bar',
  data:{labels:catLabels,
    datasets:[{data:catValues,
      backgroundColor:catLabels.map((_,i)=>['#00e5ff','#7c4dff','#ff1744','#ffab00','#00e676','#ff5252','#448aff','#e040fb','#18ffff','#b388ff'][i%10]),
      borderRadius:8,borderSkipped:false,maxBarThickness:44}]},
  options:{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{legend:{display:false}},
    scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{font:{size:11}}},
            y:{grid:{display:false},ticks:{font:{size:12}}}}}
});

/* Layers */
(function(){
  const el=document.getElementById('layerStack');
  if(!fp.layers.length){el.innerHTML='<div style="color:var(--dim);font-size:.85rem">Minimal stack — fewer differential surfaces.</div>';return}
  fp.layers.forEach((l,i)=>{
    const pct=Math.round((fp.layers.length-i)/5*100);
    el.innerHTML+=`<div class="layer-row"><div class="layer-dot"></div>
      <div class="layer-name">${esc(l.label)}</div><div class="layer-val">${esc(l.value)}</div>
      <div class="layer-bar"><div class="layer-bar-fill" style="width:${pct}%"></div></div></div>`;
  });
  const risk=['Minimal','Low','Moderate','High','Very High','Critical'][fp.layer_count]||'Unknown';
  const clr=fp.layer_count<3?'var(--low)':fp.layer_count<4?'var(--med)':'var(--crit)';
  el.innerHTML+=`<div style="margin-top:.75rem;font-size:.82rem;color:var(--dim)">
    <strong style="color:${clr}">${fp.layer_count} layers</strong> detected &mdash; Differential risk: <strong style="color:${clr}">${risk}</strong></div>`;
})();

/* Chains */
(function(){
  const el=document.getElementById('chainsSection');if(!chains.length) return;
  let h='<div class="sec-title"><span class="ic">&#9939;</span> Attack Chains &mdash; Exploitable Combinations</div>';
  chains.forEach(c=>{
    const bc={critical:'badge-crit',high:'badge-high',medium:'badge-med',low:'badge-low'}[c.severity]||'badge-info';
    h+=`<div class="chain"><div class="chain-hd"><span class="chain-name">${esc(c.name)}</span>
      <span class="badge ${bc}">${c.severity.toUpperCase()}</span></div>
      <ol>${c.steps.map(s=>'<li>'+esc(s)+'</li>').join('')}</ol>
      <div class="chain-impact">Impact: ${esc(c.impact)}</div></div>`;
  });
  el.innerHTML=h;
})();

/* Findings */
(function(){
  const el=document.getElementById('findingsBox');
  findings.forEach((f,i)=>{
    const bc={critical:'badge-crit',high:'badge-high',medium:'badge-med',low:'badge-low'}[f.severity]||'badge-info';
    let body='<div class="finding-desc">'+esc(f.description)+'</div>';
    if(f.evidence) body+='<div class="evidence">'+esc(f.evidence)+'</div>';
    if(f.has_differential&&f.differential){
      body+='<table class="diff-table"><tr><th>Layer</th><th>Interpretation</th><th>Status</th></tr>';
      f.differential.layers.forEach(l=>{
        const cls=l.status&&l.status<400?'diff-ok':'diff-bad';
        body+=`<tr><td>${esc(l.name)}</td><td>${esc(l.interpretation)}</td><td class="${cls}">${l.status||'—'}</td></tr>`;
      });
      body+='</table>';
      if(f.differential.exploitable) body+='<div class="diff-exploit">&#9889; Exploitable mismatch detected</div>';
    }
    if(f.remediation) body+='<div class="finding-fix">&#128161; '+esc(f.remediation)+'</div>';
    if(f.chain_tags.length) body+='<div class="finding-tags">'+f.chain_tags.map(t=>'<span class="tag">#'+esc(t)+'</span>').join('')+'</div>';

    el.innerHTML+=`<div class="finding" onclick="this.classList.toggle('open')">
      <div class="finding-hd"><div class="sev-dot ${f.severity}"></div>
        <div class="finding-title">#${i+1} ${esc(f.title)}</div>
        <span class="badge ${bc}">${f.severity.toUpperCase()}</span>
        <span class="finding-arrow">&#9656;</span></div>
      <div class="finding-body">${body}</div></div>`;
  });
})();

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script>
</body>
</html>'''
