"""
AI-powered attack chain synthesis and finding analysis.

This module doesn't call an external LLM — it uses a deterministic
graph-based approach to chain findings by their tags, then scores
each chain by cumulative severity and real-world impact.
"""

from __future__ import annotations

from itertools import combinations
from phantom.core.models import AttackChain, Finding, Severity


CHAIN_RECIPES: list[dict] = [
    {
        "name": "WAF Bypass → Backend Exploitation",
        "requires": [{"waf_bypass", "encoding_mismatch"}, {"acl_bypass"}],
        "impact": (
            "Attacker bypasses the WAF using an encoding the WAF does not "
            "normalize, then reaches a restricted endpoint on the backend."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Request Smuggling → Cache Poisoning",
        "requires": [{"smuggling"}, {"cache_poison"}],
        "impact": (
            "Attacker smuggles a request that poisons the cache, serving "
            "malicious content to every visitor of the affected URL."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Request Smuggling → Credential Theft",
        "requires": [{"smuggling"}, {"reflection"}],
        "impact": (
            "Attacker smuggles a prefix that captures the next user's "
            "request (including cookies/auth headers) and reflects it."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Path Confusion → Authorization Bypass",
        "requires": [{"path_confusion"}, {"acl_bypass"}],
        "impact": (
            "Attacker exploits path normalization differences to reach "
            "admin endpoints that the proxy believes are blocked."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "Host Injection → Cache Poisoning → XSS",
        "requires": [{"host_injection"}, {"cache_poison"}, {"xss_vector"}],
        "impact": (
            "Attacker poisons the cache via host-header injection, serving "
            "XSS payloads to every visitor through the cached response."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Header Override → Admin Access",
        "requires": [{"header_override"}, {"acl_bypass"}],
        "impact": (
            "Attacker uses X-Original-URL or X-Rewrite-URL to route "
            "through an allowed proxy path while the backend serves "
            "the admin panel."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Method Confusion → Restricted Action",
        "requires": [{"method_confusion"}, {"verb_tamper"}],
        "impact": (
            "Attacker changes the HTTP method or uses override headers "
            "to perform restricted actions (DELETE, PUT) that the WAF "
            "only blocks on certain verbs."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "XFF Spoof → Internal Access",
        "requires": [{"ip_spoof"}, {"internal_access"}],
        "impact": (
            "Attacker spoofs X-Forwarded-For to appear as localhost, "
            "bypassing IP-based restrictions to reach internal services."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "CORS Misconfiguration → Data Exfiltration",
        "requires": [{"cors"}, {"credential_theft"}],
        "impact": (
            "Attacker hosts a page on evil.com that makes credentialed "
            "cross-origin requests, stealing the victim's data."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "CRLF → Response Splitting → Cache Poisoning",
        "requires": [{"crlf"}, {"response_splitting"}],
        "impact": (
            "Attacker injects headers via CRLF to split the response, "
            "then poisons the cache with arbitrary content."
        ),
        "severity": Severity.CRITICAL,
    },
    {
        "name": "Information Leak → Targeted Exploitation",
        "requires": [{"info_leak", "version_disclosure"}, {"acl_bypass"}],
        "impact": (
            "Version disclosure reveals specific software versions with "
            "known CVEs, combined with an ACL bypass to reach the "
            "vulnerable component."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "Double Encoding → WAF Evasion",
        "requires": [{"double_encode"}, {"waf_bypass"}],
        "impact": (
            "Double-encoded payloads pass the WAF (which decodes once "
            "and sees benign input) but the backend decodes twice, "
            "executing the malicious payload."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "HPP → Parameter Injection",
        "requires": [{"hpp"}, {"waf_bypass"}],
        "impact": (
            "Duplicate parameters let the attacker supply one value "
            "the WAF inspects and a different value the backend uses."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "Unicode Normalization → ACL Bypass",
        "requires": [{"unicode_normalization"}, {"acl_bypass"}],
        "impact": (
            "Unicode characters that normalize to ASCII at the backend "
            "bypass proxy-level ACL rules that only match ASCII paths."
        ),
        "severity": Severity.HIGH,
    },
    {
        "name": "Hop-by-Hop → Auth Stripping",
        "requires": [{"hop_by_hop"}, {"auth_bypass"}],
        "impact": (
            "Listing Authorization in the Connection header causes the "
            "proxy to strip auth headers, letting requests reach the "
            "backend unauthenticated."
        ),
        "severity": Severity.CRITICAL,
    },
]


def synthesize_chains(findings: list[Finding]) -> list[AttackChain]:
    """Build attack chains from findings using tag-based graph matching."""
    if not findings:
        return []

    all_tags: set[str] = set()
    tag_to_findings: dict[str, list[Finding]] = {}
    for f in findings:
        for tag in f.chain_tags:
            all_tags.add(tag)
            tag_to_findings.setdefault(tag, []).append(f)

    chains: list[AttackChain] = []

    for recipe in CHAIN_RECIPES:
        matched_groups: list[list[Finding]] = []
        all_matched = True

        for required_tags in recipe["requires"]:
            group_findings: list[Finding] = []
            if required_tags & all_tags:
                for tag in required_tags:
                    group_findings.extend(tag_to_findings.get(tag, []))
            if not group_findings:
                all_matched = False
                break
            matched_groups.append(group_findings)

        if not all_matched:
            continue

        chain_findings: list[Finding] = []
        seen_titles: set[str] = set()
        for group in matched_groups:
            for f in group:
                if f.title not in seen_titles:
                    seen_titles.add(f.title)
                    chain_findings.append(f)

        if len(chain_findings) < 2:
            continue

        steps = [
            f"Exploit: {f.title} ({f.category.value})" for f in chain_findings
        ]

        chains.append(AttackChain(
            name=recipe["name"],
            description=f"Chain of {len(chain_findings)} findings",
            severity=recipe["severity"],
            findings=chain_findings,
            impact=recipe["impact"],
            steps=steps,
        ))

    chains.sort(key=lambda c: c.severity.score, reverse=True)
    return chains


def assess_finding_impact(finding: Finding) -> str:
    """Generate a one-line impact statement."""
    impact_map = {
        "acl_bypass": "Unauthorized access to restricted resources",
        "smuggling": "Request pipeline poisoning affecting other users",
        "cache_poison": "Persistent content injection via cache",
        "credential_theft": "Theft of authentication credentials",
        "xss_vector": "Client-side code execution in victim's browser",
        "auth_bypass": "Complete authentication bypass",
        "ip_spoof": "Bypass of IP-based access restrictions",
    }
    for tag in finding.chain_tags:
        if tag in impact_map:
            return impact_map[tag]
    return "Security control bypass"
