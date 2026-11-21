"""
Advanced confusion attacks — cache poisoning, hop-by-hop abuse,
and stateful sequence exploitation.
"""

from __future__ import annotations

import asyncio
import hashlib
from phantom.core.models import (
    Differential,
    Finding,
    FindingCategory,
    LayerBehavior,
    Severity,
)
from phantom.scanners.base import BaseScanner


class ConfusionScanner(BaseScanner):
    name = "confusion"
    description = "Cache poisoning, hop-by-hop abuse, and verb tampering"

    async def run(self) -> list[Finding]:
        await asyncio.gather(
            self._test_cache_poisoning(),
            self._test_hop_by_hop_abuse(),
            self._test_verb_tampering(),
            self._test_accept_header_confusion(),
            self._test_range_abuse(),
            self._test_host_routing_differential(),
        )
        return self.findings

    async def _test_cache_poisoning(self) -> None:
        base = self.target.rstrip("/")
        canary = hashlib.md5(b"phantom-probe").hexdigest()[:12]

        poison_headers = [
            ("X-Forwarded-Host", f"{canary}.evil.com"),
            ("X-Forwarded-Scheme", "nothttps"),
            ("X-Original-URL", f"/phantom-{canary}"),
            ("X-Forwarded-Prefix", f"/phantom-{canary}"),
        ]

        baseline = await self.http.get(base)
        if baseline.error:
            return

        for header, value in poison_headers:
            resp = await self.http.get(base, headers={header: value})
            if resp.error:
                continue
            if canary in resp.body or value in resp.body:
                cache_hit = resp.headers.get("x-cache", resp.headers.get("cf-cache-status", ""))
                self.add(Finding(
                    title=f"Cache poisoning via {header}",
                    category=FindingCategory.CACHE_POISONING,
                    severity=Severity.HIGH,
                    description=(
                        f"The header {header}: {value} is reflected in the "
                        "response body. If the response is cached, every "
                        "subsequent visitor receives the poisoned content."
                    ),
                    evidence=(
                        f"Injected: {header}: {value}\n"
                        f"Reflected in body: yes\n"
                        f"Cache header: {cache_hit or 'not observed'}"
                    ),
                    differential=Differential(
                        probe_description=f"Cache key does not include {header}",
                        layers=[
                            LayerBehavior("Cache layer", "Ignores header, caches response"),
                            LayerBehavior("Origin", f"Reflects {header} value in body"),
                        ],
                        mismatch_type="cache_key_mismatch",
                        exploitable=True,
                    ),
                    chainable=True,
                    chain_tags=["cache_poison", "xss_vector"],
                ))

    async def _test_hop_by_hop_abuse(self) -> None:
        """Inject Connection header listing security-critical hop-by-hop headers."""
        base = self.target.rstrip("/")

        targets_to_strip = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Forwarded-Host",
            "Cookie",
            "Authorization",
        ]

        baseline = await self.http.get(base)
        if baseline.error:
            return

        for header in targets_to_strip:
            resp = await self.http.get(
                base,
                headers={
                    "Connection": f"close, {header}",
                    header: "phantom-injected",
                },
            )
            if resp.error:
                continue
            if resp.status_code != baseline.status_code:
                self.add(Finding(
                    title=f"Hop-by-hop header stripping: {header}",
                    category=FindingCategory.HEADER_INJECTION,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Listing '{header}' in the Connection header causes "
                        f"the proxy to strip it, changing the response from "
                        f"{baseline.status_code} to {resp.status_code}. This "
                        "can bypass IP allowlists, auth, or host restrictions."
                    ),
                    evidence=(
                        f"Connection: close, {header}\n"
                        f"Baseline: {baseline.status_code}\n"
                        f"Stripped: {resp.status_code}"
                    ),
                    chainable=True,
                    chain_tags=["hop_by_hop", "auth_bypass"],
                ))

    async def _test_verb_tampering(self) -> None:
        base = self.target.rstrip("/")
        path = f"{base}/admin"

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

        results: dict[str, int] = {}
        for method in methods:
            resp = await self.http.request(method, path)
            if not resp.error:
                results[method] = resp.status_code

        status_groups: dict[int, list[str]] = {}
        for m, s in results.items():
            status_groups.setdefault(s, []).append(m)

        if len(status_groups) > 1:
            denied = {m for m, s in results.items() if s in {401, 403, 405}}
            allowed = {m for m, s in results.items() if 200 <= s < 400}

            if denied and allowed:
                evidence = "\n".join(f"  {m}: {results[m]}" for m in methods if m in results)
                self.add(Finding(
                    title="Verb tampering: inconsistent method enforcement",
                    category=FindingCategory.METHOD_CONFUSION,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The path /admin denies {', '.join(sorted(denied))} "
                        f"but allows {', '.join(sorted(allowed))}. An attacker "
                        "may access restricted functionality via an unexpected method."
                    ),
                    evidence=evidence,
                    chainable=True,
                    chain_tags=["verb_tamper", "acl_bypass"],
                ))

        if "TRACE" in results and results["TRACE"] == 200:
            self.add(Finding(
                title="TRACE method enabled — XST risk",
                category=FindingCategory.METHOD_CONFUSION,
                severity=Severity.LOW,
                description=(
                    "The TRACE method is enabled. Combined with XSS, this "
                    "allows Cross-Site Tracing to steal HttpOnly cookies."
                ),
                evidence=f"TRACE /admin → {results['TRACE']}",
                chainable=True,
                chain_tags=["xst", "cookie_theft"],
            ))

    async def _test_accept_header_confusion(self) -> None:
        base = self.target.rstrip("/")
        accept_types = [
            ("text/html", "HTML"),
            ("application/json", "JSON"),
            ("application/xml", "XML"),
            ("text/csv", "CSV"),
            ("application/pdf", "PDF"),
        ]

        responses: dict[str, tuple[int, str]] = {}
        for accept, label in accept_types:
            resp = await self.http.get(base, headers={"Accept": accept})
            if not resp.error:
                ct = resp.headers.get("content-type", "")
                responses[label] = (resp.status_code, ct)

        content_types = {ct for _, ct in responses.values()}
        if len(content_types) > 1:
            evidence = "\n".join(
                f"  Accept: {label} → {s}, Content-Type: {ct}"
                for label, (s, ct) in responses.items()
            )
            self.add(Finding(
                title="Accept header controls response format",
                category=FindingCategory.CONTENT_CONFUSION,
                severity=Severity.LOW,
                description=(
                    "The server returns different content types based on "
                    "the Accept header. If WAF rules only inspect HTML "
                    "responses, JSON or XML responses may be unfiltered."
                ),
                evidence=evidence,
                chainable=True,
                chain_tags=["content_confusion", "waf_bypass"],
            ))

    async def _test_range_abuse(self) -> None:
        base = self.target.rstrip("/")
        resp = await self.http.get(
            base, headers={"Range": "bytes=0-0, 1-1, 2-2, 3-3, 4-4"},
        )
        if resp.error:
            return
        if resp.status_code == 206 and "multipart" in resp.headers.get("content-type", ""):
            self.add(Finding(
                title="Multi-range response supported — DoS vector",
                category=FindingCategory.INFO_DISCLOSURE,
                severity=Severity.LOW,
                description=(
                    "The server supports multi-range requests. Crafted "
                    "range headers can cause amplified response sizes."
                ),
                evidence=f"Range: bytes=0-0,1-1,2-2,3-3,4-4 → {resp.status_code}",
            ))

    async def _test_host_routing_differential(self) -> None:
        """Send requests with different Host headers to find internal routing."""
        base = self.target.rstrip("/")

        baseline = await self.http.get(base)
        if baseline.error:
            return

        hosts = ["localhost", "127.0.0.1", "0.0.0.0", "internal", "[::1]"]
        for h in hosts:
            resp = await self.http.get(base, headers={"Host": h})
            if resp.error:
                continue
            if (
                resp.status_code != baseline.status_code
                and resp.status_code not in {400, 421}
                and resp.status_code < 500
            ):
                self.add(Finding(
                    title=f"Host-based routing differential: Host={h}",
                    category=FindingCategory.AUTH_BYPASS,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Host: {h} returns {resp.status_code} vs the "
                        f"normal {baseline.status_code}. The server may "
                        "expose internal virtual hosts or admin panels."
                    ),
                    evidence=(
                        f"Normal: {baseline.status_code}\n"
                        f"Host: {h} → {resp.status_code}"
                    ),
                    chainable=True,
                    chain_tags=["host_routing", "internal_access"],
                ))
