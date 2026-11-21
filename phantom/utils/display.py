from __future__ import annotations

from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich import box

from phantom.core.models import (
    AttackChain,
    Finding,
    ScanResult,
    Severity,
    StackFingerprint,
)

console = Console()

BANNER = r"""[bold cyan]
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/bold cyan]
[dim]  Protocol Hallucination & Anomaly Network Testing Oracle Machine[/dim]
[dim]  ─────────────────────────────────────────────────────────────────[/dim]
[dim italic]  Inter-Layer Semantic Gap Exploitation Framework  v1.0.0[/dim italic]
"""


def show_banner() -> None:
    console.print(BANNER)


def severity_badge(sev: Severity) -> str:
    icons = {
        Severity.INFO: "[blue]◆ INFO[/blue]",
        Severity.LOW: "[green]▲ LOW[/green]",
        Severity.MEDIUM: "[yellow]■ MEDIUM[/yellow]",
        Severity.HIGH: "[red]● HIGH[/red]",
        Severity.CRITICAL: "[bold red]✦ CRITICAL[/bold red]",
    }
    return icons[sev]


def _sev_bar(result: ScanResult) -> Text:
    counts = {}
    for sev in Severity:
        counts[sev] = sum(1 for f in result.findings if f.severity == sev)
    total = max(len(result.findings), 1)
    bar = Text()
    for sev, color in [
        (Severity.CRITICAL, "bold red"),
        (Severity.HIGH, "red"),
        (Severity.MEDIUM, "yellow"),
        (Severity.LOW, "green"),
        (Severity.INFO, "blue"),
    ]:
        width = max(1, round(counts[sev] / total * 30)) if counts[sev] else 0
        if width:
            bar.append("█" * width, style=color)
    return bar


def show_target_info(target: str, result: ScanResult) -> None:
    """Show a compact target + stats overview panel."""
    stats_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2), expand=True)
    stats_table.add_column("FINDINGS", style="bold", justify="center")
    stats_table.add_column("CRITICAL", style="bold red", justify="center")
    stats_table.add_column("HIGH", style="red", justify="center")
    stats_table.add_column("CHAINS", style="bold magenta", justify="center")
    stats_table.add_column("REQUESTS", style="cyan", justify="center")
    stats_table.add_column("DURATION", style="dim", justify="center")

    stats_table.add_row(
        f"[bold]{len(result.findings)}[/bold]",
        f"[bold red]{result.critical_count}[/bold red]",
        f"[red]{result.high_count}[/red]",
        f"[bold magenta]{len(result.chains)}[/bold magenta]",
        str(result.requests_sent),
        f"{result.duration:.1f}s",
    )

    inner = Text()
    inner.append("Target:  ", style="dim")
    inner.append(f"{target}\n\n", style="bold cyan")

    console.print(Panel(
        Group(inner, _sev_bar(result), Text(), stats_table),
        title="[bold cyan]━━ Scan Overview ━━[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))


def show_fingerprint(fp: StackFingerprint) -> None:
    table = Table(
        title="[bold]Stack Fingerprint — Parsing Layers[/bold]",
        box=box.HEAVY_EDGE,
        title_style="bold cyan",
        show_header=True,
        header_style="bold",
        padding=(0, 2),
    )
    table.add_column("Layer", style="cyan", width=18)
    table.add_column("Technology", style="white")
    table.add_column("Risk Surface", style="dim", width=30)

    risk_map = {
        "CDN": "Cache key manipulation, cache poisoning",
        "WAF": "Encoding bypass, rule evasion",
        "Reverse Proxy": "Path confusion, header injection",
        "Web Server": "Request smuggling, method confusion",
        "Framework": "Routing differentials, param handling",
        "Language": "Type coercion, encoding quirks",
    }

    for label, value in fp.summary_lines():
        risk = risk_map.get(label, "")
        table.add_row(label, value, risk)

    layer_bar = "[bold green]█[/bold green]" * fp.layer_count + "[dim]░[/dim]" * (5 - fp.layer_count)
    threat_level = {0: "Minimal", 1: "Low", 2: "Moderate", 3: "High", 4: "Very High", 5: "Critical"}
    tl = threat_level.get(fp.layer_count, "Unknown")
    tl_color = "green" if fp.layer_count < 3 else "yellow" if fp.layer_count < 4 else "red"
    table.add_row(
        "Parsing Depth",
        f"{layer_bar}  ({fp.layer_count}/5)",
        f"[{tl_color}]Differential risk: {tl}[/{tl_color}]",
    )

    if fp.interesting_headers:
        console.print()
        console.print(table)
        header_panel = "\n".join(f"  [cyan]→[/cyan] {h}" for h in fp.interesting_headers)
        console.print(Panel(
            header_panel,
            title="[dim]Notable Headers (information leakage)[/dim]",
            border_style="dim",
            padding=(0, 1),
        ))
    else:
        console.print()
        console.print(table)
    console.print()


def show_differential(finding: Finding) -> None:
    diff = finding.differential
    if not diff:
        return

    console.print(f"  [dim]Probe:[/dim] {diff.probe_description}")
    if diff.raw_request:
        console.print(Panel(
            diff.raw_request,
            title="[dim]Raw Request[/dim]",
            border_style="dim",
            padding=(0, 1),
        ))

    if len(diff.layers) >= 2:
        table = Table(box=box.SIMPLE_HEAVY, padding=(0, 1), expand=True)
        table.add_column("Layer", style="cyan", width=22)
        table.add_column("Interpretation", style="white")
        table.add_column("Status", justify="center", width=8)
        for layer in diff.layers:
            status = str(layer.status_code) if layer.status_code else "—"
            style = "green" if layer.status_code and layer.status_code < 400 else "red"
            table.add_row(layer.layer_name, layer.interpretation, f"[{style}]{status}[/{style}]")
        console.print(table)

    if diff.exploitable:
        console.print("  [bold red]⚡ Exploitable mismatch detected[/bold red]")


def show_finding(finding: Finding, index: int) -> None:
    badge = severity_badge(finding.severity)
    title = f"{badge}  {finding.title}"

    panel_content = Text()
    panel_content.append(f"Category: {finding.category.value}\n", style="dim")
    panel_content.append(f"Module:   {finding.module}\n", style="dim")
    panel_content.append(f"\n{finding.description}\n")
    if finding.chainable:
        panel_content.append("\n")
        panel_content.append("Chain Tags: ", style="yellow")
        panel_content.append("  ".join(f"#{t}" for t in finding.chain_tags), style="yellow bold")
        panel_content.append("\n")
    if finding.remediation:
        panel_content.append(f"\nFix: {finding.remediation}\n", style="dim italic")

    console.print(Panel(
        panel_content,
        title=f"[bold]#{index} {title}[/bold]",
        border_style=finding.severity.color,
        padding=(1, 2),
    ))

    if finding.differential:
        show_differential(finding)

    if finding.evidence:
        console.print(Panel(
            finding.evidence,
            title="[dim]Evidence[/dim]",
            border_style="dim",
            padding=(0, 1),
        ))

    console.print()


def show_chain(chain: AttackChain, index: int) -> None:
    tree = Tree(
        f"[bold red]⛓  Chain #{index}: {chain.name}[/bold red]  [{severity_badge(chain.severity)}]"
    )
    desc_node = tree.add("[dim]Description[/dim]")
    desc_node.add(chain.description)

    steps_node = tree.add("[bold]Attack Steps[/bold]")
    for i, step in enumerate(chain.steps, 1):
        steps_node.add(f"[cyan]{i}.[/cyan] {step}")

    findings_node = tree.add("[bold]Linked Findings[/bold]")
    for f in chain.findings:
        findings_node.add(f"{severity_badge(f.severity)}  {f.title}")

    impact_node = tree.add("[bold red]Impact[/bold red]")
    impact_node.add(chain.impact)

    console.print(Panel(tree, border_style="red", padding=(1, 2)))
    console.print()


def show_summary(result: ScanResult) -> None:
    table = Table(
        title="[bold]Scan Summary[/bold]",
        box=box.DOUBLE_EDGE,
        title_style="bold cyan",
        show_header=False,
        padding=(0, 2),
    )
    table.add_column("Key", style="cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row("Target", result.target)
    table.add_row("Duration", f"{result.duration:.1f}s")
    table.add_row("Requests Sent", str(result.requests_sent))
    table.add_row("Total Findings", str(len(result.findings)))
    table.add_row("Attack Chains", str(len(result.chains)))

    sev_counts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sum(1 for f in result.findings if f.severity == sev)
        if count:
            sev_counts.append(f"[{sev.color}]{count} {sev.value.upper()}[/{sev.color}]")
    if sev_counts:
        table.add_row("Severity Breakdown", " | ".join(sev_counts))

    if result.errors:
        table.add_row("Errors", f"[red]{len(result.errors)}[/red]")

    console.print()
    console.print(table)
    console.print()


def show_results(result: ScanResult) -> None:
    show_target_info(result.target, result)

    if not result.findings and not result.chains:
        console.print("[dim]No findings discovered.[/dim]")
        show_summary(result)
        return

    if result.chains:
        console.print()
        console.rule("[bold red]⛓  Attack Chains — Exploitable Combinations[/bold red]")
        console.print()
        for i, chain in enumerate(result.chains, 1):
            show_chain(chain, i)

    if result.findings:
        console.print()
        console.rule("[bold cyan]◆  Findings[/bold cyan]")
        console.print()
        sorted_findings = sorted(result.findings, key=lambda f: f.severity.score, reverse=True)
        for i, finding in enumerate(sorted_findings, 1):
            show_finding(finding, i)

    show_summary(result)
