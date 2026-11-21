"""
PHANTOM Web Server — FastAPI backend for the live scanning dashboard.
"""
from __future__ import annotations

import asyncio
import random
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from phantom.core.models import ScanConfig, Severity
from phantom.ai.analyzer import synthesize_chains

app = FastAPI(title="PHANTOM", version="1.0.0")
STATIC_DIR = Path(__file__).parent / "static"
START_TIME = time.time()
scans: dict[str, dict] = {}

MODULE_KEYS = ["fingerprint", "differential", "smuggling", "confusion", "header"]
MODULE_NAMES = {
    "fingerprint": "Fingerprint",
    "differential": "Parser Differential",
    "smuggling": "HTTP Smuggling",
    "confusion": "Confusion Attacks",
    "header": "Header Injection",
}


def _new_scan_state(scan_id: str, target: str, modules: str) -> dict:
    return {
        "id": scan_id,
        "target": target,
        "status": "running",
        "started": time.time(),
        "ended": None,
        "modules": modules,
        "current_module": "starting",
        "progress": 0,
        "findings": [],
        "chains": [],
        "fingerprint": None,
        "requests_sent": 0,
        "errors": [],
        "logs": [],
        "request_timeline": [],
        "stop_requested": False,
        "module_status": {k: "pending" for k in MODULE_KEYS},
    }


def _serialize_finding(f) -> dict:
    fd = {
        "title": f.title,
        "category": f.category.value,
        "severity": f.severity.value,
        "description": f.description,
        "evidence": f.evidence,
        "module": f.module,
        "chainable": f.chainable,
        "chain_tags": f.chain_tags,
        "remediation": f.remediation,
    }
    if f.differential:
        fd["differential"] = {
            "probe": f.differential.probe_description,
            "exploitable": f.differential.exploitable,
            "raw_request": f.differential.raw_request,
            "layers": [
                {"name": l.layer_name, "interpretation": l.interpretation, "status": l.status_code}
                for l in f.differential.layers
            ],
        }
    return fd


def _serialize_scan(s: dict) -> dict:
    findings_data = [_serialize_finding(f) for f in s["findings"]]
    chains_data = [
        {
            "name": c.name,
            "severity": c.severity.value,
            "impact": c.impact,
            "description": c.description,
            "steps": c.steps,
            "finding_count": len(c.findings),
        }
        for c in s["chains"]
    ]

    fp_data = None
    if s["fingerprint"]:
        fp = s["fingerprint"]
        fp_data = {
            "cdn": fp.cdn, "waf": fp.waf, "reverse_proxy": fp.reverse_proxy,
            "web_server": fp.web_server, "web_server_version": fp.web_server_version,
            "framework": fp.framework, "language": fp.language,
            "layer_count": fp.layer_count,
            "layers": [{"label": k, "value": v} for k, v in fp.summary_lines()],
            "interesting_headers": fp.interesting_headers,
        }

    sev_counts = {sv.value: 0 for sv in Severity}
    cat_counts: dict[str, int] = {}
    mod_counts: dict[str, int] = {}
    for f in s["findings"]:
        sev_counts[f.severity.value] += 1
        cat_counts[f.category.value] = cat_counts.get(f.category.value, 0) + 1
        mod_counts[f.module] = mod_counts.get(f.module, 0) + 1

    duration = (s["ended"] or time.time()) - s["started"]

    return {
        "id": s["id"],
        "target": s["target"],
        "status": s["status"],
        "started": s["started"],
        "duration": round(duration, 1),
        "current_module": s["current_module"],
        "progress": s["progress"],
        "requests_sent": s["requests_sent"],
        "findings": findings_data,
        "chains": chains_data,
        "fingerprint": fp_data,
        "severity": sev_counts,
        "categories": cat_counts,
        "modules_breakdown": mod_counts,
        "module_status": s.get("module_status", {}),
        "logs": s.get("logs", [])[-80:],
        "request_timeline": s.get("request_timeline", []),
        "errors": s["errors"],
    }


class ScanRequest(BaseModel):
    target: str
    modules: str = "all"
    timeout: float = 10.0
    verify_ssl: bool = True


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse((STATIC_DIR / "index.html").read_text())


@app.get("/api/status")
async def server_status():
    total_findings = sum(len(s.get("findings", [])) for s in scans.values())
    return {
        "version": "1.0.0",
        "uptime": int(time.time() - START_TIME),
        "total_scans": len(scans),
        "total_findings": total_findings,
        "active_scans": sum(1 for s in scans.values() if s["status"] == "running"),
    }


@app.post("/api/scan")
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = uuid.uuid4().hex[:8]
    target = req.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    scans[scan_id] = _new_scan_state(scan_id, target, req.modules)
    bg.add_task(_run_scan, scan_id, target, req.modules, req.timeout, req.verify_ssl)
    return {"scan_id": scan_id}


@app.post("/api/demo")
async def start_demo(bg: BackgroundTasks):
    scan_id = uuid.uuid4().hex[:8]
    scans[scan_id] = _new_scan_state(scan_id, "https://demo-target.com", "all")
    bg.add_task(_run_demo, scan_id)
    return {"scan_id": scan_id}


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    s = scans.get(scan_id)
    if not s:
        return JSONResponse({"error": "not found"}, 404)
    s["stop_requested"] = True
    return {"status": "stopping"}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    s = scans.get(scan_id)
    if not s:
        return JSONResponse({"error": "not found"}, 404)
    return _serialize_scan(s)


@app.get("/api/scans")
async def list_scans():
    result = []
    for s in sorted(scans.values(), key=lambda x: x["started"], reverse=True):
        duration = (s["ended"] or time.time()) - s["started"]
        sev = {sv.value: 0 for sv in Severity}
        for f in s["findings"]:
            sev[f.severity.value] += 1
        result.append({
            "id": s["id"],
            "target": s["target"],
            "status": s["status"],
            "findings_count": len(s["findings"]),
            "chains_count": len(s["chains"]),
            "critical": sev["critical"],
            "high": sev["high"],
            "medium": sev["medium"],
            "low": sev["low"],
            "info": sev["info"],
            "duration": round(duration, 1),
            "started": s["started"],
        })
    return result


def _add_log(s: dict, msg: str, log_type: str = "info"):
    s["logs"].append({"time": round(time.time() - s["started"], 2), "msg": msg, "type": log_type})


async def _run_scan(
    scan_id: str, target: str, modules: str, timeout: float, verify_ssl: bool
) -> None:
    from phantom.core.engine import ALL_MODULES
    from phantom.utils.http import PhantomHTTP

    s = scans[scan_id]
    config = ScanConfig(
        target=target, modules=modules.split(","), timeout=timeout, verify_ssl=verify_ssl,
    )
    http = PhantomHTTP(timeout=timeout, verify_ssl=verify_ssl)

    module_list = list(ALL_MODULES.items()) if "all" in config.modules else [
        (k, ALL_MODULES[k]) for k in config.modules if k in ALL_MODULES
    ]
    total = len(module_list)
    fingerprint = None

    _add_log(s, f"Starting scan on {target}", "start")

    for i, (mod_key, (mod_name, scanner_cls)) in enumerate(module_list):
        if s["stop_requested"]:
            _add_log(s, "Scan stopped by user", "stop")
            break

        s["current_module"] = mod_name
        s["progress"] = int((i / total) * 100)
        s["module_status"][mod_key] = "running"
        _add_log(s, f"Starting {mod_name}...", "module")

        scanner = scanner_cls(http=http, config=config, fingerprint=fingerprint)
        try:
            findings = await scanner.run()
            s["findings"].extend(findings)
            for f in findings:
                _add_log(s, f"[{f.severity.value.upper()}] {f.title}", "finding")
            if hasattr(scanner, "fingerprint") and scanner.fingerprint:
                fingerprint = scanner.fingerprint
                s["fingerprint"] = fingerprint
            s["module_status"][mod_key] = "completed"
            _add_log(s, f"Completed {mod_name} ({len(findings)} findings)", "module")
        except Exception as e:
            s["errors"].append(f"{mod_name}: {e}")
            s["module_status"][mod_key] = "error"
            _add_log(s, f"Error in {mod_name}: {e}", "error")

        s["requests_sent"] = http.request_count
        elapsed = time.time() - s["started"]
        s["request_timeline"].append({"t": round(elapsed, 1), "n": http.request_count})

    s["requests_sent"] = http.request_count
    await http.close()

    _add_log(s, "Synthesizing attack chains...", "info")
    chainable = [f for f in s["findings"] if f.chainable]
    s["chains"] = synthesize_chains(chainable)
    _add_log(s, f"Found {len(s['chains'])} attack chains", "info")

    s["progress"] = 100
    s["current_module"] = "complete"
    s["status"] = "completed"
    s["ended"] = time.time()
    _add_log(s, "Scan complete", "done")


async def _run_demo(scan_id: str) -> None:
    from phantom.core.demo import build_demo_result

    s = scans[scan_id]
    result = build_demo_result()

    findings_by_mod: dict[str, list] = {}
    for f in result.findings:
        findings_by_mod.setdefault(f.module, []).append(f)

    _add_log(s, f"Starting scan on {s['target']}", "start")
    req_count = 0

    for i, mod_key in enumerate(MODULE_KEYS):
        if s["stop_requested"]:
            _add_log(s, "Scan stopped by user", "stop")
            break

        mod_name = MODULE_NAMES[mod_key]
        s["current_module"] = mod_name
        s["progress"] = int((i / len(MODULE_KEYS)) * 100)
        s["module_status"][mod_key] = "running"
        _add_log(s, f"Starting {mod_name}...", "module")

        await asyncio.sleep(2.0)

        if mod_key == "fingerprint" and result.fingerprint:
            s["fingerprint"] = result.fingerprint
            _add_log(s, f"Detected {result.fingerprint.layer_count} parsing layers", "finding")

        mod_findings = findings_by_mod.get(mod_key, [])
        for f in mod_findings:
            s["findings"].append(f)
            req_count += random.randint(8, 25)
            s["requests_sent"] = req_count
            _add_log(s, f"[{f.severity.value.upper()}] {f.title}", "finding")
            elapsed = time.time() - s["started"]
            s["request_timeline"].append({"t": round(elapsed, 1), "n": req_count})
            await asyncio.sleep(0.6)

        req_count += random.randint(10, 30)
        s["requests_sent"] = req_count
        s["module_status"][mod_key] = "completed"
        _add_log(s, f"Completed {mod_name} ({len(mod_findings)} findings)", "module")

    _add_log(s, "Synthesizing attack chains...", "info")
    s["chains"] = result.chains
    s["requests_sent"] = result.requests_sent
    _add_log(s, f"Found {len(s['chains'])} attack chains", "info")

    s["progress"] = 100
    s["current_module"] = "complete"
    s["status"] = "completed"
    s["ended"] = time.time()
    _add_log(s, "Scan complete", "done")
