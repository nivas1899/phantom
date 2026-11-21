"""
Advanced header injection and smuggling tests.
"""

from __future__ import annotations

import asyncio
from phantom.core.models import (
    Differential,
    Finding,
    FindingCategory,
    LayerBehavior,
    Severity,
)
from phantom.scanners.base import BaseScanner


class HeaderScanner(BaseScanner):
    name = "header"
    description = "Header injection, CRLF, and response splitting"

    async def run(self) -> list[Finding]:
        await asyncio.gather(
            self._test_crlf_injection(),
            self._test_header_reflection(),
            self._test_xff_trust(),
            self._test_websocket_upgrade(),
            self._test_cors_misconfiguration(),
        )
        return self.findings

    async def _test_crlf_injection(self) -> None:
        base = self.target.rstrip("/")
        payloads = [
            ("%0d%0aX-Injected: phantom", "url-encoded CRLF"),
            ("%0aX-Injected: phantom", "url-encoded LF only"),
            ("%E5%98%8A%E5%98%8DX-Injected: phantom", "Unicode CRLF (U+560A/U+560D)"),
            ("\r\nX-Injected: phantom", "raw CRLF"),
        ]

        for payload, label in payloads:
            url = f"{base}/phantom-test{payload}"
            resp = await self.http.get(url)
            if resp.error:
                continue

            if "x-injected" in resp.headers:
                self.add(Finding(
                    title=f"CRLF Injection via {label}",
                    category=FindingCategory.HEADER_INJECTION,
                    severity=Severity.HIGH,
                    description=(
                        f"Injecting {label} in the URL path creates a new "
                        "response header. This enables response splitting, "
                        "cache poisoning, and XSS via injected headers."
                    ),
                    evidence=f"Injected header observed: X-Injected: phantom",
                    request=f"GET /phantom-test{payload}",
                    chainable=True,
                    chain_tags=["crlf", "response_splitting", "xss_vector"],
                ))
                break

            if "x-injected" in resp.body.lower():
                self.add(Finding(
                    title=f"CRLF reflected in body via {label}",
                    category=FindingCategory.HEADER_INJECTION,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The {label} payload is reflected in the response "
                        "body, indicating partial CRLF processing."
                    ),
                    evidence=f"Payload reflected in body",
                    chainable=True,
                    chain_tags=["crlf", "reflection"],
                ))
                break

    async def _test_header_reflection(self) -> None:
        base = self.target.rstrip("/")
        canary = "PhAnToM-rEfLeCt-7x7"

        injection_points = [
            ("Referer", canary),
            ("X-Forwarded-For", canary),
            ("X-Custom-Header", canary),
            ("User-Agent", canary),
            ("Accept-Language", canary),
            ("From", canary),
        ]

        for header, value in injection_points:
            resp = await self.http.get(base, headers={header: value})
            if resp.error:
                continue
            if canary in resp.body:
                self.add(Finding(
                    title=f"Header value reflected in body: {header}",
                    category=FindingCategory.HEADER_INJECTION,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The value of the {header} header is reflected in "
                        "the response body without encoding. This may allow "
                        "XSS if HTML context is reached."
                    ),
                    evidence=f"{header}: {canary} → reflected in body",
                    chainable=True,
                    chain_tags=["reflection", "xss_vector"],
                ))

    async def _test_xff_trust(self) -> None:
        base = self.target.rstrip("/")

        normal = await self.http.get(base)
        if normal.error:
            return

        spoofed = await self.http.get(
            base,
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        if spoofed.error:
            return

        if spoofed.status_code != normal.status_code:
            self.add(Finding(
                title="X-Forwarded-For trusted for access control",
                category=FindingCategory.AUTH_BYPASS,
                severity=Severity.HIGH,
                description=(
                    "Setting X-Forwarded-For: 127.0.0.1 changes the "
                    f"response from {normal.status_code} to "
                    f"{spoofed.status_code}, indicating the server trusts "
                    "this header for IP-based access control."
                ),
                evidence=(
                    f"Normal: {normal.status_code}\n"
                    f"X-Forwarded-For: 127.0.0.1 → {spoofed.status_code}"
                ),
                differential=Differential(
                    probe_description="XFF trust boundary",
                    layers=[
                        LayerBehavior("Client-visible", "Real IP", normal.status_code),
                        LayerBehavior("Backend perception", "127.0.0.1 via XFF", spoofed.status_code),
                    ],
                    mismatch_type="xff_trust",
                    exploitable=True,
                ),
                chainable=True,
                chain_tags=["auth_bypass", "ip_spoof"],
            ))

    async def _test_websocket_upgrade(self) -> None:
        base = self.target.rstrip("/")
        resp = await self.http.get(
            base,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            },
        )
        if resp.error:
            return

        if resp.status_code == 101:
            self.add(Finding(
                title="WebSocket upgrade accepted on HTTP endpoint",
                category=FindingCategory.PARSER_DIFFERENTIAL,
                severity=Severity.MEDIUM,
                description=(
                    "The server accepts WebSocket upgrades. If the proxy "
                    "does not understand WebSocket, post-upgrade traffic "
                    "may bypass proxy-level controls (WebSocket smuggling)."
                ),
                evidence=f"Upgrade: websocket → {resp.status_code}",
                chainable=True,
                chain_tags=["websocket", "smuggling"],
            ))

    async def _test_cors_misconfiguration(self) -> None:
        base = self.target.rstrip("/")
        origins = [
            "https://evil.com",
            "null",
            self.target,
        ]

        for origin in origins:
            resp = await self.http.get(
                base, headers={"Origin": origin},
            )
            if resp.error:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if origin == "https://evil.com" and acao == origin:
                sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                self.add(Finding(
                    title="CORS allows arbitrary origins",
                    category=FindingCategory.AUTH_BYPASS,
                    severity=sev,
                    description=(
                        "The server reflects arbitrary Origin values in "
                        "Access-Control-Allow-Origin. "
                        + ("Combined with Allow-Credentials: true, this "
                           "allows full credential theft from any origin."
                           if acac.lower() == "true" else
                           "Data exfiltration is possible from any origin.")
                    ),
                    evidence=(
                        f"Origin: https://evil.com\n"
                        f"ACAO: {acao}\n"
                        f"ACAC: {acac or 'not set'}"
                    ),
                    chainable=True,
                    chain_tags=["cors", "credential_theft"],
                ))
                break

            if origin == "null" and acao == "null":
                self.add(Finding(
                    title="CORS allows null origin",
                    category=FindingCategory.AUTH_BYPASS,
                    severity=Severity.MEDIUM,
                    description=(
                        "The server accepts Origin: null, which is sent by "
                        "sandboxed iframes and redirects. An attacker can "
                        "forge a null-origin request to exfiltrate data."
                    ),
                    evidence=f"Origin: null → ACAO: null, ACAC: {acac or 'not set'}",
                    chainable=True,
                    chain_tags=["cors", "null_origin"],
                ))
                break
