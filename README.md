# PHANTOM

**Protocol Hallucination & Anomaly Network Testing Oracle Machine**

An inter-layer semantic gap exploitation framework that discovers vulnerabilities existing *between* protocol parsing layers, not within any single component.

---

## The Problem

Every web application has multiple layers that parse the same HTTP request:

```
Client → CDN → WAF → Reverse Proxy → Web Server → Application Framework → ORM/DB
```

Each layer may interpret the **same request differently**. These mismatches — **parser differentials** — are the root cause of the most dangerous classes of web vulnerabilities:

- HTTP Request Smuggling (CL.TE / TE.CL / TE.TE desync)
- WAF Bypass via encoding mismatches
- Path confusion leading to ACL bypass
- Cache poisoning via unkeyed headers
- Method confusion and verb tampering
- Host-header injection / routing manipulation

## The Innovation

Most security tools ask: *"What vulnerability does this endpoint have?"*

PHANTOM asks: **"Where do these layers disagree — and how can I exploit the gap?"**

### What Makes PHANTOM Different

1. **Parser Differential Engine** — Systematically probes how each layer interprets encoding, paths, methods, headers, and content types differently
2. **Timing-Based Smuggling Detection** — Uses differential timing to safely detect HTTP smuggling without poisoning production traffic
3. **Chain Synthesis Engine** — Automatically combines low-severity findings into high-impact exploit chains using a graph-based recipe system
4. **Multi-Layer Fingerprinting** — Identifies each parsing layer (CDN, WAF, proxy, server, framework) to predict where differentials will occur

## Installation

```bash
cd phantom
pip install -e .
```

## Usage

### Basic Scan

```bash
python phantom.py scan https://target.com
```

### Select Specific Modules

```bash
python phantom.py scan https://target.com -m differential,smuggling
```

### With Proxy (Burp Suite)

```bash
python phantom.py scan https://target.com --proxy http://127.0.0.1:8080 --no-ssl-verify
```

### Custom Headers

```bash
python phantom.py scan https://target.com -H "Authorization: Bearer token123"
```

### Export Report

```bash
# JSON report
python phantom.py scan https://target.com -o report.json

# HTML report
python phantom.py scan https://target.com -o report.html
```

### List Modules

```bash
python phantom.py modules
```

## Scanner Modules

| Module | Description |
|--------|-------------|
| `fingerprint` | Fingerprint the technology stack and enumerate parsing layers |
| `differential` | Discover parser mismatches between protocol layers (encoding, path, content-type, method, headers, Unicode normalization, parameter pollution) |
| `smuggling` | Detect HTTP request smuggling via timing-based differential probes (CL.TE, TE.CL, TE.TE, CL.0) |
| `confusion` | Cache poisoning, hop-by-hop header abuse, verb tampering, Accept-header confusion |
| `header` | CRLF injection, header reflection, XFF trust analysis, WebSocket upgrade, CORS misconfiguration |

## Architecture

```
phantom/
├── phantom.py              # CLI entry point
├── core/
│   ├── engine.py           # Scan orchestration
│   ├── models.py           # Data models (Finding, Chain, Differential)
│   └── report.py           # JSON + HTML report generation
├── scanners/
│   ├── base.py             # Base scanner class
│   ├── fingerprint.py      # Stack fingerprinting
│   ├── differential.py     # Parser differential engine
│   ├── smuggling.py        # HTTP smuggling detection
│   ├── confusion.py        # Confusion attacks
│   └── header.py           # Header injection
├── ai/
│   └── analyzer.py         # Chain synthesis engine
└── utils/
    ├── http.py             # Async HTTP + raw-socket client
    └── display.py          # Rich terminal UI
```

## Chain Synthesis

PHANTOM doesn't just find individual bugs — it chains them. The synthesis engine uses 15 pre-built chain recipes that model real-world attack paths:

- **WAF Bypass → Backend Exploitation** — Encoding mismatch lets payload through WAF
- **Request Smuggling → Cache Poisoning** — Desync poisons cached responses
- **Host Injection → Cache Poisoning → XSS** — Full chain from header to stored XSS
- **Hop-by-Hop → Auth Stripping** — Connection header strips Authorization
- **CRLF → Response Splitting → Cache Poisoning** — Header injection to persistent content injection

## Responsible Use

This tool is designed for authorized security testing only. Always obtain written permission before testing any target. PHANTOM uses safe, non-destructive detection techniques (timing-based smuggling probes, no persistent cache poisoning) suitable for production environments.
