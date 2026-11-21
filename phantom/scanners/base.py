from __future__ import annotations

import abc
from typing import TYPE_CHECKING

from phantom.core.models import Finding

if TYPE_CHECKING:
    from phantom.utils.http import PhantomHTTP
    from phantom.core.models import ScanConfig, StackFingerprint


class BaseScanner(abc.ABC):
    """Every scanner inherits this and implements run()."""

    name: str = "base"
    description: str = ""

    def __init__(
        self,
        http: PhantomHTTP,
        config: ScanConfig,
        fingerprint: StackFingerprint | None = None,
    ):
        self.http = http
        self.config = config
        self.target = config.target
        self.fingerprint = fingerprint
        self.findings: list[Finding] = []

    @abc.abstractmethod
    async def run(self) -> list[Finding]:
        ...

    def add(self, finding: Finding) -> None:
        finding.module = self.name
        self.findings.append(finding)
