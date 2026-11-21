from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        return {
            "info": "blue",
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }[self.value]

    @property
    def score(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[
            self.value
        ]


class FindingCategory(Enum):
    PARSER_DIFFERENTIAL = "Parser Differential"
    HTTP_SMUGGLING = "HTTP Request Smuggling"
    PATH_CONFUSION = "Path Confusion"
    METHOD_CONFUSION = "Method Confusion"
    CONTENT_CONFUSION = "Content-Type Confusion"
    HEADER_INJECTION = "Header Injection"
    ENCODING_BYPASS = "Encoding Bypass"
    INFO_DISCLOSURE = "Information Disclosure"
    CACHE_POISONING = "Cache Poisoning"
    AUTH_BYPASS = "Authorization Bypass"


@dataclass
class LayerBehavior:
    layer_name: str
    interpretation: str
    status_code: Optional[int] = None
    response_snippet: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Differential:
    probe_description: str
    layers: list[LayerBehavior] = field(default_factory=list)
    mismatch_type: str = ""
    exploitable: bool = False
    raw_request: str = ""


@dataclass
class Finding:
    title: str
    category: FindingCategory
    severity: Severity
    description: str
    evidence: str
    differential: Optional[Differential] = None
    request: str = ""
    response: str = ""
    remediation: str = ""
    chainable: bool = False
    chain_tags: list[str] = field(default_factory=list)
    module: str = ""


@dataclass
class AttackChain:
    name: str
    description: str
    severity: Severity
    findings: list[Finding] = field(default_factory=list)
    impact: str = ""
    steps: list[str] = field(default_factory=list)


@dataclass
class StackFingerprint:
    web_server: Optional[str] = None
    web_server_version: Optional[str] = None
    framework: Optional[str] = None
    waf: Optional[str] = None
    reverse_proxy: Optional[str] = None
    cdn: Optional[str] = None
    language: Optional[str] = None
    os_hint: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    interesting_headers: list[str] = field(default_factory=list)

    @property
    def layer_count(self) -> int:
        return sum(
            1
            for v in [self.waf, self.cdn, self.reverse_proxy, self.web_server, self.framework]
            if v
        )

    def summary_lines(self) -> list[tuple[str, str]]:
        lines: list[tuple[str, str]] = []
        if self.cdn:
            lines.append(("CDN", self.cdn))
        if self.waf:
            lines.append(("WAF", self.waf))
        if self.reverse_proxy:
            lines.append(("Reverse Proxy", self.reverse_proxy))
        if self.web_server:
            ver = f" {self.web_server_version}" if self.web_server_version else ""
            lines.append(("Web Server", f"{self.web_server}{ver}"))
        if self.framework:
            lines.append(("Framework", self.framework))
        if self.language:
            lines.append(("Language", self.language))
        return lines


@dataclass
class ScanConfig:
    target: str
    threads: int = 10
    timeout: float = 10.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    modules: list[str] = field(default_factory=lambda: ["all"])
    use_ai: bool = False
    verbose: bool = False
    output_file: Optional[str] = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    fingerprint: Optional[StackFingerprint] = None
    findings: list[Finding] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    requests_sent: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda x: x.severity.score, reverse=True):
            result.setdefault(f.severity, []).append(f)
        return result
