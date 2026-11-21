"""
Parser Differential Engine — the core innovation of PHANTOM.

Most vulnerabilities exist not within a single layer but in the *gaps* between
how two layers interpret the same request.  This module systematically discovers
those gaps by sending semantically-equivalent-but-structurally-different probes
and comparing how each observed layer responds.

Categories of differentials detected:
  1. Encoding differentials  — URL-encoding, double-encoding, Unicode
  2. Path-normalization gaps — dot-segments, backslash, case folding
  3. Content-type confusion  — JSON vs form vs XML interpretation
  4. Method confusion        — override headers, GET-with-body
  5. Header-parsing gaps     — duplicate headers, folded lines, spacing
"""

from __future__ import annotations

import asyncio
import urllib.parse
from phantom.core.models import (
    Differential,
    Finding,
    FindingCategory,
    LayerBehavior,
    Severity,
)
from phantom.scanners.base import BaseScanner


class DifferentialScanner(BaseScanner):
    name = "differential"
    description = "Discover parser mismatches between protocol layers"

    async def run(self) -> list[Finding]:
        tasks = [
            self._test_encoding_differentials(),
            self._test_path_normalization(),
            self._test_content_type_confusion(),
            self._test_method_confusion(),
            self._test_header_parsing(),
            self._test_double_encoding(),
            self._test_unicode_normalization(),
            self._test_parameter_pollution(),
        ]
        await asyncio.gather(*tasks)
        return self.findings

    # ── Encoding differentials ──────────────────────────────────────

    async def _test_encoding_differentials(self) -> None:
        base_path = self.target.rstrip("/")
        probe_path = "/admin"

        variants = [
            ("plain", f"{base_path}{probe_path}"),
            ("url-encoded", f"{base_path}/{urllib.parse.quote('admin')}"),
            ("double-encoded", f"{base_path}/{urllib.parse.quote(urllib.parse.quote('admin'))}"),
            ("unicode", f"{base_path}/adm%C4%B1n"),
            ("null-byte", f"{base_path}/admin%00.html"),
            ("overlong-utf8", f"{base_path}/%c0%61dmin"),
            ("backslash", f"{base_path}\\admin"),
            ("mixed-slash", f"{base_path}/./admin"),
        ]

        responses = {}
        for label, url in variants:
            resp = await self.http.get(url)
            if not resp.error:
                responses[label] = resp

        if len(responses) < 2:
            return

        plain = responses.get("plain")
        if not plain:
            return

        for label, resp in responses.items():
            if label == "plain":
                continue
            if resp.status_code != plain.status_code:
                diff = Differential(
                    probe_description=(
                        f"Encoding variant '{label}' returns {resp.status_code} "
                        f"while plain returns {plain.status_code}"
                    ),
                    layers=[
                        LayerBehavior(
                            layer_name="Direct (plain)",
                            interpretation=f"Status {plain.status_code}",
                            status_code=plain.status_code,
                        ),
                        LayerBehavior(
                            layer_name=f"Encoded ({label})",
                            interpretation=f"Status {resp.status_code}",
                            status_code=resp.status_code,
                        ),
                    ],
                    mismatch_type="encoding",
                    exploitable=_is_access_change(plain.status_code, resp.status_code),
                )

                severity = Severity.HIGH if diff.exploitable else Severity.MEDIUM
                self.add(Finding(
                    title=f"Encoding differential: '{label}' bypasses access control",
                    category=FindingCategory.PARSER_DIFFERENTIAL,
                    severity=severity,
                    description=(
                        f"The path '{probe_path}' returns {plain.status_code} when "
                        f"requested normally but {resp.status_code} with the "
                        f"'{label}' encoding variant. This indicates the WAF / "
                        "reverse-proxy and the backend parse the URL differently."
                    ),
                    evidence=(
                        f"Normal:  GET {probe_path} → {plain.status_code}\n"
                        f"Variant: GET ('{label}') → {resp.status_code}"
                    ),
                    differential=diff,
                    remediation="Normalize all URL encodings at the edge before routing.",
                    chainable=True,
                    chain_tags=["acl_bypass", "encoding_mismatch"],
                ))

    async def _test_double_encoding(self) -> None:
        base = self.target.rstrip("/")
        paths = ["/admin", "/api", "/internal", "/debug", "/config"]

        for path in paths:
            single = urllib.parse.quote(path)
            double = urllib.parse.quote(single)

            r_single = await self.http.get(f"{base}{single}")
            r_double = await self.http.get(f"{base}{double}")

            if r_single.error or r_double.error:
                continue
            if r_single.status_code == r_double.status_code:
                continue
            if _is_access_change(r_single.status_code, r_double.status_code):
                self.add(Finding(
                    title=f"Double-encoding bypass on {path}",
                    category=FindingCategory.ENCODING_BYPASS,
                    severity=Severity.HIGH,
                    description=(
                        f"Single-encoding returns {r_single.status_code} but "
                        f"double-encoding returns {r_double.status_code}. The "
                        "proxy decodes once, leaving the second layer to decode "
                        "again, bypassing path-based ACLs."
                    ),
                    evidence=(
                        f"Single: GET {single} → {r_single.status_code}\n"
                        f"Double: GET {double} → {r_double.status_code}"
                    ),
                    chainable=True,
                    chain_tags=["acl_bypass", "double_encode"],
                ))

    # ── Path normalization gaps ─────────────────────────────────────

    async def _test_path_normalization(self) -> None:
        base = self.target.rstrip("/")

        normalization_tricks = [
            ("dot-segment", "/foo/../admin"),
            ("double-dot-encoded", "/foo/..%2fadmin"),
            ("dot-segment-encoded", "/foo/%2e%2e/admin"),
            ("backslash", "/foo/..\\admin"),
            ("double-slash", "//admin"),
            ("trailing-dot", "/admin."),
            ("trailing-slash", "/admin/"),
            ("case-variation", "/Admin"),
            ("semicolon-strip", "/admin;anything"),
            ("fragment-trick", "/admin#"),
            ("null-extension", "/admin%00.json"),
            ("tab-inject", "/admin\t"),
        ]

        ref = await self.http.get(f"{base}/admin")
        if ref.error:
            return
        ref_status = ref.status_code

        for label, trick_path in normalization_tricks:
            resp = await self.http.get(f"{base}{trick_path}")
            if resp.error:
                continue
            if resp.status_code != ref_status and _is_access_change(ref_status, resp.status_code):
                self.add(Finding(
                    title=f"Path confusion via {label}",
                    category=FindingCategory.PATH_CONFUSION,
                    severity=Severity.HIGH,
                    description=(
                        f"Path normalization trick '{label}' changes the response "
                        f"from {ref_status} to {resp.status_code}. The routing "
                        "layer and the backend disagree on the canonical path."
                    ),
                    evidence=(
                        f"Reference: GET /admin → {ref_status}\n"
                        f"Trick:     GET {trick_path} → {resp.status_code}"
                    ),
                    differential=Differential(
                        probe_description=f"Path confusion: {label}",
                        layers=[
                            LayerBehavior("Router/Proxy", f"Sees '{trick_path}'", ref_status),
                            LayerBehavior("Backend", f"Resolves to /admin", resp.status_code),
                        ],
                        mismatch_type="path_normalization",
                        exploitable=True,
                    ),
                    chainable=True,
                    chain_tags=["acl_bypass", "path_confusion"],
                ))

    # ── Content-type confusion ──────────────────────────────────────

    async def _test_content_type_confusion(self) -> None:
        base = self.target.rstrip("/")
        test_body = '{"test": "phantom"}'

        content_types = [
            ("application/json", "JSON"),
            ("application/x-www-form-urlencoded", "Form"),
            ("text/xml", "XML"),
            ("application/xml", "XML"),
            ("text/plain", "Plain"),
            ("multipart/form-data; boundary=X", "Multipart"),
            ("application/json; charset=utf-7", "JSON+UTF7"),
        ]

        responses: dict[str, tuple[int, str]] = {}
        for ct, label in content_types:
            resp = await self.http.post(
                base, headers={"Content-Type": ct}, body=test_body,
            )
            if not resp.error:
                responses[label] = (resp.status_code, resp.body[:200])

        seen_statuses = {s for s, _ in responses.values()}
        if len(seen_statuses) > 1:
            evidence_lines = [f"  {label}: {s}" for label, (s, _) in responses.items()]
            exploitable = any(
                s < 400 for s, _ in responses.values()
            ) and any(
                s >= 400 for s, _ in responses.values()
            )

            self.add(Finding(
                title="Content-Type confusion: inconsistent parsing across types",
                category=FindingCategory.CONTENT_CONFUSION,
                severity=Severity.MEDIUM if not exploitable else Severity.HIGH,
                description=(
                    "The server responds differently depending on the "
                    "Content-Type header for the same body. A WAF inspecting "
                    "one format may miss payloads smuggled as another."
                ),
                evidence="\n".join(evidence_lines),
                chainable=True,
                chain_tags=["waf_bypass", "content_confusion"],
            ))

    # ── Method confusion ────────────────────────────────────────────

    async def _test_method_confusion(self) -> None:
        base = self.target.rstrip("/")
        target_path = f"{base}/admin"

        direct_get = await self.http.get(target_path)
        if direct_get.error:
            return

        override_tests = [
            ("X-HTTP-Method-Override", "GET"),
            ("X-HTTP-Method", "GET"),
            ("X-Method-Override", "GET"),
            ("_method", "GET"),
        ]

        for header, value in override_tests:
            resp = await self.http.post(
                target_path, headers={header: value},
            )
            if resp.error:
                continue

            if resp.status_code != direct_get.status_code and _is_access_change(
                direct_get.status_code, resp.status_code
            ):
                self.add(Finding(
                    title=f"Method override bypass via {header}",
                    category=FindingCategory.METHOD_CONFUSION,
                    severity=Severity.HIGH,
                    description=(
                        f"POST with '{header}: {value}' returns "
                        f"{resp.status_code} while direct GET returns "
                        f"{direct_get.status_code}. The proxy sees POST, "
                        "but the backend treats it as GET — ACL mismatch."
                    ),
                    evidence=(
                        f"GET /admin → {direct_get.status_code}\n"
                        f"POST /admin + {header}: {value} → {resp.status_code}"
                    ),
                    differential=Differential(
                        probe_description=f"Method override via {header}",
                        layers=[
                            LayerBehavior("Proxy/WAF", "Sees POST", direct_get.status_code),
                            LayerBehavior("Backend", f"Treats as GET ({header})", resp.status_code),
                        ],
                        mismatch_type="method_confusion",
                        exploitable=True,
                    ),
                    chainable=True,
                    chain_tags=["acl_bypass", "method_confusion"],
                ))

    # ── Header-parsing differentials ────────────────────────────────

    async def _test_header_parsing(self) -> None:
        base = self.target.rstrip("/")

        dupe_host = await self.http.get(
            base, headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
        )
        normal = await self.http.get(base)

        if (
            not dupe_host.error
            and not normal.error
            and dupe_host.status_code != normal.status_code
        ):
            self.add(Finding(
                title="Host header manipulation accepted",
                category=FindingCategory.HEADER_INJECTION,
                severity=Severity.MEDIUM,
                description=(
                    "The server responds differently when Host or "
                    "X-Forwarded-Host is overridden, indicating host-header "
                    "injection potential (cache poisoning, SSRF, password-reset "
                    "poisoning)."
                ),
                evidence=(
                    f"Normal Host → {normal.status_code}\n"
                    f"Host: evil.com → {dupe_host.status_code}"
                ),
                chainable=True,
                chain_tags=["host_injection", "cache_poison"],
            ))

        for header_name in ["X-Original-URL", "X-Rewrite-URL"]:
            resp = await self.http.get(
                base, headers={header_name: "/admin"},
            )
            if resp.error or normal.error:
                continue
            if resp.status_code != normal.status_code:
                self.add(Finding(
                    title=f"Path override via {header_name}",
                    category=FindingCategory.HEADER_INJECTION,
                    severity=Severity.HIGH,
                    description=(
                        f"The backend honors {header_name} to rewrite the "
                        "request path. An attacker can bypass proxy-level "
                        "ACLs by routing through an allowed path and "
                        f"overriding with {header_name}: /admin."
                    ),
                    evidence=(
                        f"GET / → {normal.status_code}\n"
                        f"GET / + {header_name}: /admin → {resp.status_code}"
                    ),
                    differential=Differential(
                        probe_description=f"Path override via {header_name}",
                        layers=[
                            LayerBehavior("Proxy", "Routes to /", normal.status_code),
                            LayerBehavior("Backend", "Sees /admin via header", resp.status_code),
                        ],
                        mismatch_type="header_path_override",
                        exploitable=True,
                    ),
                    chainable=True,
                    chain_tags=["acl_bypass", "header_override"],
                ))

    # ── Unicode normalization ───────────────────────────────────────

    async def _test_unicode_normalization(self) -> None:
        base = self.target.rstrip("/")

        unicode_pairs = [
            ("fullwidth-A", "/Ａdmin"),
            ("turkish-i", "/admın"),
            ("roman-numeral", "/admiⅱ"),
            ("superscript", "/ᴀdmin"),
        ]

        ref = await self.http.get(f"{base}/admin")
        if ref.error:
            return

        for label, path in unicode_pairs:
            encoded = urllib.parse.quote(path, safe="/")
            resp = await self.http.get(f"{base}{encoded}")
            if resp.error:
                continue
            if resp.status_code != ref.status_code and _is_access_change(
                ref.status_code, resp.status_code
            ):
                self.add(Finding(
                    title=f"Unicode normalization bypass ({label})",
                    category=FindingCategory.ENCODING_BYPASS,
                    severity=Severity.HIGH,
                    description=(
                        f"Unicode variant '{label}' normalizes to '/admin' "
                        "at the backend but not at the proxy, bypassing ACLs."
                    ),
                    evidence=(
                        f"GET /admin → {ref.status_code}\n"
                        f"GET {encoded} → {resp.status_code}"
                    ),
                    chainable=True,
                    chain_tags=["acl_bypass", "unicode_normalization"],
                ))

    # ── HTTP Parameter Pollution ────────────────────────────────────

    async def _test_parameter_pollution(self) -> None:
        base = self.target.rstrip("/")

        single = await self.http.get(f"{base}/?role=user")
        double = await self.http.get(f"{base}/?role=user&role=admin")

        if single.error or double.error:
            return

        if single.body != double.body or single.status_code != double.status_code:
            self.add(Finding(
                title="HTTP Parameter Pollution accepted",
                category=FindingCategory.PARSER_DIFFERENTIAL,
                severity=Severity.MEDIUM,
                description=(
                    "Duplicate query parameters produce different behavior. "
                    "The proxy may inspect the first value while the backend "
                    "uses the last, allowing parameter pollution attacks."
                ),
                evidence=(
                    f"?role=user       → {single.status_code}\n"
                    f"?role=user&role=admin → {double.status_code}"
                ),
                differential=Differential(
                    probe_description="HPP: duplicate 'role' parameter",
                    layers=[
                        LayerBehavior("Proxy/WAF", "Inspects role=user", single.status_code),
                        LayerBehavior("Backend", "Uses role=admin (last wins)", double.status_code),
                    ],
                    mismatch_type="parameter_pollution",
                    exploitable=single.status_code != double.status_code,
                ),
                chainable=True,
                chain_tags=["hpp", "waf_bypass"],
            ))


def _is_access_change(status_a: int, status_b: int) -> bool:
    """True if one status denies access while the other grants it."""
    denied = {401, 403, 404, 405, 451}
    granted = set(range(200, 400))
    a_denied = status_a in denied
    b_denied = status_b in denied
    a_granted = status_a in granted
    b_granted = status_b in granted
    return (a_denied and b_granted) or (a_granted and b_denied)
