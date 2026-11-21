"""
PHANTOM Engine — orchestrates all scanner modules and synthesizes results.
"""

from __future__ import annotations

import asyncio
import time

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)

from phantom.core.models import ScanConfig, ScanResult
from phantom.utils.display import console, show_fingerprint
from phantom.utils.http import PhantomHTTP
from phantom.scanners.fingerprint import FingerprintScanner
from phantom.scanners.differential import DifferentialScanner
from phantom.scanners.smuggling import SmugglingScanner
from phantom.scanners.confusion import ConfusionScanner
from phantom.scanners.header import HeaderScanner
from phantom.ai.analyzer import synthesize_chains


ALL_MODULES = {
    "fingerprint": ("Fingerprint", FingerprintScanner),
    "differential": ("Parser Differential", DifferentialScanner),
    "smuggling": ("HTTP Smuggling", SmugglingScanner),
    "confusion": ("Confusion Attacks", ConfusionScanner),
    "header": ("Header Injection", HeaderScanner),
}


class PhantomEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.http = PhantomHTTP(
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
            proxy=config.proxy,
            custom_headers=config.custom_headers,
        )
        self.result = ScanResult(target=config.target)

    async def run(self) -> ScanResult:
        self.result.start_time = time.time()

        modules_to_run = self._resolve_modules()

        console.print(f"\n[bold cyan]Target:[/bold cyan] {self.config.target}")
        console.print(f"[bold cyan]Modules:[/bold cyan] {', '.join(m[0] for m in modules_to_run)}")
        console.print()

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
            TextColumn("[dim]{task.fields[status]}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:

            main_task = progress.add_task(
                "PHANTOM Scan", total=len(modules_to_run), status="starting..."
            )

            fingerprint = None

            for module_name, scanner_cls in modules_to_run:
                progress.update(main_task, status=f"[cyan]{module_name}[/cyan]")

                scanner = scanner_cls(
                    http=self.http,
                    config=self.config,
                    fingerprint=fingerprint,
                )

                try:
                    findings = await scanner.run()
                    self.result.findings.extend(findings)

                    if hasattr(scanner, "fingerprint") and scanner.fingerprint:
                        fingerprint = scanner.fingerprint
                        self.result.fingerprint = fingerprint

                except Exception as e:
                    self.result.errors.append(f"{module_name}: {e}")
                    if self.config.verbose:
                        console.print(f"[red]Error in {module_name}: {e}[/red]")

                progress.advance(main_task)

            progress.update(main_task, status="[bold green]complete[/bold green]")

        if self.result.fingerprint:
            show_fingerprint(self.result.fingerprint)

        console.print("[dim]Synthesizing attack chains...[/dim]")
        chainable = [f for f in self.result.findings if f.chainable]
        self.result.chains = synthesize_chains(chainable)

        self.result.requests_sent = self.http.request_count
        self.result.end_time = time.time()

        await self.http.close()
        return self.result

    def _resolve_modules(self) -> list[tuple[str, type]]:
        if "all" in self.config.modules:
            return [(name, cls) for name, cls in ALL_MODULES.values()]

        result = []
        result.append(ALL_MODULES["fingerprint"])

        for mod in self.config.modules:
            if mod in ALL_MODULES and mod != "fingerprint":
                result.append(ALL_MODULES[mod])
        return result
