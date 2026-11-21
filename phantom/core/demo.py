"""
Demo data — pre-loaded scan results that showcase every PHANTOM feature.
Used by `python cli.py demo` for presentations and screenshots.
"""

from __future__ import annotations

import time
from phantom.core.models import (
    AttackChain,
    Differential,
    Finding,
    FindingCategory,
    LayerBehavior,
    ScanResult,
    Severity,
    StackFingerprint,
)
from phantom.ai.analyzer import synthesize_chains


def build_demo_result() -> ScanResult:
    fp = StackFingerprint(
        cdn="Cloudflare",
        waf="Cloudflare WAF",
        reverse_proxy="Nginx 1.25.3",
        web_server="Gunicorn",
        web_server_version="21.2.0",
        framework="Django 4.2",
        language="Python",
        os_hint="Linux",
        technologies=[
            "Allowed methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
        ],
        interesting_headers=[
            "X-Request-Id: a3f8c2e1-9b4d-4e7a-b8c3-1d2e3f4a5b6c",
            "Server-Timing: cdn;dur=2, edge;dur=18, origin;dur=142",
            "X-Backend-Server: api-prod-east-02",
        ],
    )

    findings = [
        Finding(
            title="CL.TE HTTP Request Smuggling",
            category=FindingCategory.HTTP_SMUGGLING,
            severity=Severity.CRITICAL,
            description=(
                "The front-end (Cloudflare) uses Content-Length while the back-end "
                "(Gunicorn) uses Transfer-Encoding. An attacker can smuggle a "
                "request prefix that poisons the next user's request, enabling "
                "credential theft, cache poisoning, and request hijacking."
            ),
            evidence=(
                "Fast probe:    48ms   (normal round-trip)\n"
                "Smuggle probe: 10,241ms (back-end waited for chunk terminator)\n"
                "Timing ratio:  213x — confirms CL.TE desync"
            ),
            differential=Differential(
                probe_description="CL.TE desync: Content-Length vs Transfer-Encoding",
                layers=[
                    LayerBehavior("Cloudflare CDN", "Uses Content-Length — forwards 6 bytes", 200),
                    LayerBehavior("Nginx Proxy", "Passes through unchanged", 200),
                    LayerBehavior("Gunicorn Backend", "Uses Transfer-Encoding — waits for chunk end", 0),
                ],
                mismatch_type="smuggling_cl_te",
                exploitable=True,
                raw_request=(
                    "POST / HTTP/1.1\r\n"
                    "Host: target.com\r\n"
                    "Content-Length: 6\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "0\r\n\r\nX"
                ),
            ),
            remediation="Configure the CDN/proxy to normalize Transfer-Encoding or reject ambiguous requests.",
            chainable=True,
            chain_tags=["smuggling", "desync", "cl_te"],
            module="smuggling",
        ),
        Finding(
            title="Double-encoding bypass on /admin",
            category=FindingCategory.ENCODING_BYPASS,
            severity=Severity.HIGH,
            description=(
                "Single URL-encoding of /admin returns 403 (blocked by WAF), "
                "but double-encoding returns 200. The Cloudflare WAF decodes "
                "once and sees '%2fadmin' (benign), while Django decodes "
                "again and serves /admin."
            ),
            evidence=(
                "Single:  GET /%2fadmin       → 403 Forbidden\n"
                "Double:  GET /%252fadmin     → 200 OK\n"
                "WAF sees '%2fadmin', backend resolves to '/admin'"
            ),
            differential=Differential(
                probe_description="Double-encoding: WAF decodes once, backend decodes twice",
                layers=[
                    LayerBehavior("Cloudflare WAF", "Decodes once → sees '%2fadmin' → ALLOW", 200),
                    LayerBehavior("Django Backend", "Decodes twice → resolves '/admin' → serves page", 200),
                ],
                mismatch_type="double_encoding",
                exploitable=True,
            ),
            remediation="Reject double-encoded URLs at the edge. Normalize before routing.",
            chainable=True,
            chain_tags=["acl_bypass", "double_encode", "waf_bypass", "encoding_mismatch"],
            module="differential",
        ),
        Finding(
            title="Cache poisoning via X-Forwarded-Host",
            category=FindingCategory.CACHE_POISONING,
            severity=Severity.HIGH,
            description=(
                "The X-Forwarded-Host header is reflected in the response "
                "body (inside <link> and <script> tags) but is NOT included "
                "in the cache key. Poisoning one response serves malicious "
                "assets to every subsequent visitor."
            ),
            evidence=(
                "Injected:  X-Forwarded-Host: evil.com\n"
                "Reflected: <script src=\"https://evil.com/static/app.js\">\n"
                "Cache:     CF-Cache-Status: HIT (poisoned response cached)"
            ),
            differential=Differential(
                probe_description="Cache key excludes X-Forwarded-Host — unkeyed input reflected",
                layers=[
                    LayerBehavior("Cloudflare Cache", "Ignores X-Forwarded-Host in key → caches response", 200),
                    LayerBehavior("Django Backend", "Reflects X-Forwarded-Host in HTML assets", 200),
                ],
                mismatch_type="cache_key_mismatch",
                exploitable=True,
            ),
            chainable=True,
            chain_tags=["cache_poison", "xss_vector", "host_injection"],
            module="confusion",
        ),
        Finding(
            title="Path override via X-Original-URL",
            category=FindingCategory.HEADER_INJECTION,
            severity=Severity.HIGH,
            description=(
                "The backend honors X-Original-URL to rewrite the request "
                "path. An attacker routes through '/' (allowed by Nginx ACL) "
                "while X-Original-URL: /admin/users reaches the admin panel."
            ),
            evidence=(
                "GET /                            → 200 (public)\n"
                "GET / + X-Original-URL: /admin   → 200 (admin panel!)\n"
                "GET /admin (direct)              → 403 (blocked by proxy)"
            ),
            differential=Differential(
                probe_description="Nginx routes to '/', Django serves '/admin' via header override",
                layers=[
                    LayerBehavior("Nginx Proxy", "Routes based on URL path: '/' → ALLOW", 200),
                    LayerBehavior("Django Backend", "Uses X-Original-URL: '/admin' → serves admin", 200),
                ],
                mismatch_type="header_path_override",
                exploitable=True,
            ),
            chainable=True,
            chain_tags=["acl_bypass", "header_override"],
            module="differential",
        ),
        Finding(
            title="CORS allows arbitrary origins with credentials",
            category=FindingCategory.AUTH_BYPASS,
            severity=Severity.HIGH,
            description=(
                "The server reflects any Origin in Access-Control-Allow-Origin "
                "with Allow-Credentials: true. An attacker on evil.com can "
                "make authenticated API requests and steal user data."
            ),
            evidence=(
                "Origin: https://evil.com\n"
                "Access-Control-Allow-Origin: https://evil.com\n"
                "Access-Control-Allow-Credentials: true"
            ),
            chainable=True,
            chain_tags=["cors", "credential_theft"],
            module="header",
        ),
        Finding(
            title="Hop-by-hop stripping of Authorization header",
            category=FindingCategory.HEADER_INJECTION,
            severity=Severity.MEDIUM,
            description=(
                "Listing 'Authorization' in the Connection header causes "
                "Nginx to strip it before forwarding. Backend sees an "
                "unauthenticated request, falling back to default/anonymous access."
            ),
            evidence=(
                "Connection: close, Authorization\n"
                "Baseline (with auth):    200 OK\n"
                "Stripped (no auth):      200 OK (anonymous access granted!)"
            ),
            chainable=True,
            chain_tags=["hop_by_hop", "auth_bypass"],
            module="confusion",
        ),
        Finding(
            title="HTTP Parameter Pollution accepted",
            category=FindingCategory.PARSER_DIFFERENTIAL,
            severity=Severity.MEDIUM,
            description=(
                "Duplicate query parameters produce different behavior. "
                "Cloudflare WAF inspects the first 'role=user', while Django "
                "uses the last 'role=admin' — enabling privilege escalation."
            ),
            evidence=(
                "?role=user              → 200 (normal user view)\n"
                "?role=user&role=admin   → 200 (admin view!)\n"
                "WAF checks first, backend uses last"
            ),
            differential=Differential(
                probe_description="HPP: Cloudflare inspects first param, Django uses last",
                layers=[
                    LayerBehavior("Cloudflare WAF", "Inspects role=user → ALLOW", 200),
                    LayerBehavior("Django Backend", "Uses role=admin (last wins)", 200),
                ],
                mismatch_type="parameter_pollution",
                exploitable=True,
            ),
            chainable=True,
            chain_tags=["hpp", "waf_bypass"],
            module="differential",
        ),
        Finding(
            title="Verbose technology disclosure via headers",
            category=FindingCategory.INFO_DISCLOSURE,
            severity=Severity.LOW,
            description="The server exposes technology stack details in response headers.",
            evidence=(
                "Server: gunicorn/21.2.0\n"
                "X-Powered-By: Django 4.2\n"
                "X-Backend-Server: api-prod-east-02"
            ),
            remediation="Remove or obfuscate version-disclosing headers in production.",
            chainable=True,
            chain_tags=["info_leak", "version_disclosure"],
            module="fingerprint",
        ),
        Finding(
            title="Multi-layer parsing stack detected (5 layers)",
            category=FindingCategory.INFO_DISCLOSURE,
            severity=Severity.INFO,
            description=(
                "Detected 5 distinct parsing layers. More layers exponentially "
                "increase parser differential probability. This stack is a "
                "high-value target for inter-layer exploitation."
            ),
            evidence=(
                "Layer 1: Cloudflare CDN\n"
                "Layer 2: Cloudflare WAF\n"
                "Layer 3: Nginx 1.25.3 (Reverse Proxy)\n"
                "Layer 4: Gunicorn 21.2.0 (Web Server)\n"
                "Layer 5: Django 4.2 (Framework)"
            ),
            module="fingerprint",
        ),
    ]

    chains = synthesize_chains([f for f in findings if f.chainable])

    result = ScanResult(
        target="https://target-app.com",
        start_time=time.time() - 32.7,
        end_time=time.time(),
        fingerprint=fp,
        findings=findings,
        chains=chains,
        requests_sent=247,
    )
    return result
