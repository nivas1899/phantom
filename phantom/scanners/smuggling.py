"""
HTTP Request Smuggling detection.

Tests CL.TE, TE.CL, TE.TE, and H2.CL desync vectors using time-based
differential techniques so the probe is safe for production targets
(no persistent poisoning).
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from phantom.core.models import (
    Differential,
    Finding,
    FindingCategory,
    LayerBehavior,
    Severity,
)
from phantom.scanners.base import BaseScanner


class SmugglingScanner(BaseScanner):
    name = "smuggling"
    description = "Detect HTTP request smuggling via timing-based differential probes"

    async def run(self) -> list[Finding]:
        parsed = urlparse(self.target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        tls = parsed.scheme == "https"
        path = parsed.path or "/"

        await asyncio.gather(
            self._test_cl_te(host, port, path, tls),
            self._test_te_cl(host, port, path, tls),
            self._test_te_te(host, port, path, tls),
            self._test_cl_0(host, port, path, tls),
            self._test_transfer_encoding_variants(host, port, path, tls),
        )
        return self.findings

    async def _test_cl_te(self, host: str, port: int, path: str, tls: bool) -> None:
        """CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding."""
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        ).encode()

        fast = await self._timed_probe(host, port, payload, tls, timeout=5.0)
        if fast is None:
            return

        confirm_payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1\r\n"
            "Z\r\n"
            "Q"
        ).encode()

        slow = await self._timed_probe(host, port, confirm_payload, tls, timeout=10.0)
        if slow is None:
            return

        if slow > fast * 3 and slow > 4000:
            self.add(Finding(
                title="CL.TE HTTP Request Smuggling",
                category=FindingCategory.HTTP_SMUGGLING,
                severity=Severity.CRITICAL,
                description=(
                    "The front-end uses Content-Length while the back-end "
                    "uses Transfer-Encoding. An attacker can smuggle a "
                    "request prefix that poisons the next user's request."
                ),
                evidence=(
                    f"Fast probe: {fast:.0f}ms\n"
                    f"Smuggle probe: {slow:.0f}ms (back-end waited for more data)"
                ),
                differential=Differential(
                    probe_description="CL.TE desync: timing differential",
                    layers=[
                        LayerBehavior("Front-end", "Uses Content-Length → forwards 6 bytes"),
                        LayerBehavior("Back-end", "Uses chunked → waits for chunk end"),
                    ],
                    mismatch_type="smuggling_cl_te",
                    exploitable=True,
                ),
                chainable=True,
                chain_tags=["smuggling", "desync", "cl_te"],
            ))

    async def _test_te_cl(self, host: str, port: int, path: str, tls: bool) -> None:
        """TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length."""
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 3\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "8\r\n"
            "SMUGGLED\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        resp = await self.http.smuggle_probe(self.target, "TE.CL", payload)
        if resp.error:
            return

        normal = await self.http.get(self.target)
        if normal.error:
            return

        if resp.status_code != normal.status_code and resp.status_code not in {400, 0}:
            self.add(Finding(
                title="TE.CL HTTP Request Smuggling (potential)",
                category=FindingCategory.HTTP_SMUGGLING,
                severity=Severity.HIGH,
                description=(
                    "The front-end uses Transfer-Encoding while the back-end "
                    "uses Content-Length. Response status differs from normal, "
                    "suggesting a desync."
                ),
                evidence=(
                    f"Normal request:   {normal.status_code}\n"
                    f"Smuggle attempt:  {resp.status_code}"
                ),
                differential=Differential(
                    probe_description="TE.CL desync probe",
                    layers=[
                        LayerBehavior("Front-end", "Uses Transfer-Encoding", normal.status_code),
                        LayerBehavior("Back-end", "Uses Content-Length", resp.status_code),
                    ],
                    mismatch_type="smuggling_te_cl",
                    exploitable=True,
                ),
                chainable=True,
                chain_tags=["smuggling", "desync", "te_cl"],
            ))

    async def _test_te_te(self, host: str, port: int, path: str, tls: bool) -> None:
        """TE.TE: both layers use Transfer-Encoding but one can be confused."""
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked\x0b",
            "X: x\r\nTransfer-Encoding: chunked",
        ]

        normal = await self.http.get(self.target)
        if normal.error:
            return

        for obf in obfuscations:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                f"{obf}\r\n"
                "\r\n"
                "1\r\n"
                "Z\r\n"
                "0\r\n"
                "\r\n"
            ).encode()

            resp = await self.http.smuggle_probe(self.target, "TE.TE", payload)
            if resp.error or resp.status_code == 0:
                continue
            if resp.status_code != normal.status_code and resp.status_code not in {400}:
                self.add(Finding(
                    title=f"TE.TE smuggling via obfuscated Transfer-Encoding",
                    category=FindingCategory.HTTP_SMUGGLING,
                    severity=Severity.HIGH,
                    description=(
                        "An obfuscated Transfer-Encoding header is handled "
                        "differently by the front-end and back-end, creating "
                        "a desync."
                    ),
                    evidence=(
                        f"Obfuscation: {obf!r}\n"
                        f"Normal:  {normal.status_code}\n"
                        f"Smuggle: {resp.status_code}"
                    ),
                    chainable=True,
                    chain_tags=["smuggling", "desync", "te_te"],
                ))
                break

    async def _test_cl_0(self, host: str, port: int, path: str, tls: bool) -> None:
        """CL.0: back-end ignores Content-Length entirely."""
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 10\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode()

        resp = await self.http.smuggle_probe(self.target, "CL.0", payload)
        if resp.error or resp.status_code == 0:
            return
        if resp.status_code < 400:
            self.add(Finding(
                title="CL.0 desync: back-end ignores Content-Length",
                category=FindingCategory.HTTP_SMUGGLING,
                severity=Severity.MEDIUM,
                description=(
                    "The back-end responded before receiving the full body "
                    "as specified by Content-Length, suggesting it ignores "
                    "the CL header — a CL.0 desync."
                ),
                evidence=f"Sent CL:10 with empty body → got {resp.status_code}",
                chainable=True,
                chain_tags=["smuggling", "desync", "cl_0"],
            ))

    async def _test_transfer_encoding_variants(
        self, host: str, port: int, path: str, tls: bool
    ) -> None:
        """Test non-standard TE header spellings the front-end might miss."""
        variants = [
            "Transfer-Encoding: cow",
            "Content-Encoding: chunked",
            "Transfer_Encoding: chunked",
        ]

        normal = await self.http.get(self.target)
        if normal.error:
            return

        for header in variants:
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{header}\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "0\r\n\r\n"
            ).encode()

            resp = await self.http.smuggle_probe(self.target, "TE-variant", payload)
            if resp.error or resp.status_code == 0:
                continue
            if resp.status_code != normal.status_code and resp.status_code not in {400, 501}:
                self.add(Finding(
                    title=f"Non-standard Transfer-Encoding accepted",
                    category=FindingCategory.HTTP_SMUGGLING,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The server accepted the header '{header}' and "
                        f"responded differently ({resp.status_code}). "
                        "This may indicate parsing inconsistencies."
                    ),
                    evidence=f"Header: {header}\nResponse: {resp.status_code}",
                    chainable=True,
                    chain_tags=["smuggling", "header_parsing"],
                ))

    async def _timed_probe(
        self, host: str, port: int, data: bytes, tls: bool, timeout: float
    ) -> float | None:
        import time
        start = time.monotonic()
        resp = await self.http.raw_request(host, port, data, use_tls=tls, timeout=timeout)
        elapsed = (time.monotonic() - start) * 1000
        if resp.error and "timeout" not in resp.error.lower():
            return None
        return elapsed
