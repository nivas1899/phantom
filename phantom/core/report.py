"""
Report generation — JSON export and HTML report.
"""

from __future__ import annotations

import json
import html
from datetime import datetime
from phantom.core.models import ScanResult, Severity


def export_json(result: ScanResult, path: str) -> None:
    data = {
        "tool": "PHANTOM",
        "version": "1.0.0",
        "target": result.target,
        "scan_time": datetime.fromtimestamp(result.start_time).isoformat(),
        "duration_seconds": round(result.duration, 2),
        "requests_sent": result.requests_sent,
        "summary": {
            "total_findings": len(result.findings),
            "critical": result.critical_count,
            "high": result.high_count,
            "chains": len(result.chains),
        },
        "fingerprint": _serialize_fingerprint(result),
        "findings": [_serialize_finding(f) for f in result.findings],
        "chains": [_serialize_chain(c) for c in result.chains],
        "errors": result.errors,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def export_html(result: ScanResult, path: str) -> None:
    findings_html = ""
    for i, f in enumerate(
        sorted(result.findings, key=lambda x: x.severity.score, reverse=True), 1
    ):
        sev_class = f.severity.value
        findings_html += f"""
        <div class="finding {sev_class}">
            <div class="finding-header">
                <span class="badge {sev_class}">{f.severity.value.upper()}</span>
                <span class="finding-title">#{i} {html.escape(f.title)}</span>
                <span class="finding-cat">{html.escape(f.category.value)}</span>
            </div>
            <p>{html.escape(f.description)}</p>
            <pre class="evidence">{html.escape(f.evidence)}</pre>
            {"<p class='chain-tags'>Chainable: " + ", ".join(f.chain_tags) + "</p>" if f.chainable else ""}
        </div>"""

    chains_html = ""
    for i, c in enumerate(result.chains, 1):
        steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in c.steps)
        chains_html += f"""
        <div class="chain">
            <h3>Chain #{i}: {html.escape(c.name)}</h3>
            <span class="badge {c.severity.value}">{c.severity.value.upper()}</span>
            <p>{html.escape(c.description)}</p>
            <ol>{steps_html}</ol>
            <p class="impact"><strong>Impact:</strong> {html.escape(c.impact)}</p>
        </div>"""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHANTOM Report — {html.escape(result.target)}</title>
<style>
:root{{--bg:#0a0a0f;--fg:#e0e0e0;--accent:#00d4ff;--crit:#ff1744;--high:#ff5252;
--med:#ffc107;--low:#4caf50;--info:#2196f3;--card:#12121a;--border:#222}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--fg);font-family:'Segoe UI',system-ui,sans-serif;
padding:2rem;max-width:960px;margin:0 auto}}
h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.5rem}}
h2{{color:var(--accent);margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
h3{{color:var(--fg);margin-bottom:.5rem}}
.meta{{color:#888;margin-bottom:2rem}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:1.5rem 0}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}}
.stat-val{{font-size:1.5rem;font-weight:700;color:var(--accent)}}
.stat-label{{color:#888;font-size:.85rem}}
.finding{{background:var(--card);border:1px solid var(--border);border-radius:8px;
padding:1.25rem;margin-bottom:1rem}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;flex-wrap:wrap}}
.finding-title{{font-weight:600;font-size:1rem}}
.finding-cat{{color:#888;font-size:.85rem;margin-left:auto}}
.badge{{padding:.15rem .6rem;border-radius:4px;font-size:.75rem;font-weight:700;text-transform:uppercase}}
.badge.critical{{background:var(--crit);color:#fff}}
.badge.high{{background:var(--high);color:#fff}}
.badge.medium{{background:var(--med);color:#000}}
.badge.low{{background:var(--low);color:#fff}}
.badge.info{{background:var(--info);color:#fff}}
.evidence{{background:#0d0d14;border:1px solid var(--border);border-radius:4px;
padding:.75rem;font-family:monospace;font-size:.85rem;overflow-x:auto;margin-top:.75rem}}
.chain{{background:var(--card);border:2px solid var(--crit);border-radius:8px;
padding:1.25rem;margin-bottom:1rem}}
.chain ol{{padding-left:1.5rem;margin:.75rem 0}}
.chain li{{margin:.25rem 0}}
.impact{{color:var(--crit);font-weight:500;margin-top:.5rem}}
.chain-tags{{color:#888;font-size:.85rem;font-style:italic}}
</style>
</head>
<body>
<h1>PHANTOM</h1>
<p class="meta">Inter-Layer Semantic Gap Exploitation Framework</p>
<p><strong>Target:</strong> {html.escape(result.target)}<br>
<strong>Scan Time:</strong> {datetime.fromtimestamp(result.start_time).strftime("%Y-%m-%d %H:%M:%S")}<br>
<strong>Duration:</strong> {result.duration:.1f}s &middot; {result.requests_sent} requests</p>
<div class="summary">
<div class="stat"><div class="stat-val">{len(result.findings)}</div><div class="stat-label">Findings</div></div>
<div class="stat"><div class="stat-val" style="color:var(--crit)">{result.critical_count}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-val" style="color:var(--high)">{result.high_count}</div><div class="stat-label">High</div></div>
<div class="stat"><div class="stat-val" style="color:var(--crit)">{len(result.chains)}</div><div class="stat-label">Chains</div></div>
</div>
{f'<h2>Attack Chains</h2>{chains_html}' if chains_html else ''}
<h2>Findings</h2>
{findings_html if findings_html else '<p>No findings.</p>'}
</body></html>"""

    with open(path, "w") as fh:
        fh.write(page)


def _serialize_fingerprint(result: ScanResult) -> dict | None:
    fp = result.fingerprint
    if not fp:
        return None
    return {
        "web_server": fp.web_server,
        "framework": fp.framework,
        "waf": fp.waf,
        "reverse_proxy": fp.reverse_proxy,
        "cdn": fp.cdn,
        "language": fp.language,
        "layers": fp.layer_count,
    }


def _serialize_finding(f) -> dict:
    return {
        "title": f.title,
        "category": f.category.value,
        "severity": f.severity.value,
        "description": f.description,
        "evidence": f.evidence,
        "module": f.module,
        "chainable": f.chainable,
        "chain_tags": f.chain_tags,
    }


def _serialize_chain(c) -> dict:
    return {
        "name": c.name,
        "severity": c.severity.value,
        "steps": c.steps,
        "impact": c.impact,
        "finding_count": len(c.findings),
    }
