#!/usr/bin/env python3
"""
PHANTOM — Protocol Hallucination & Anomaly Network Testing Oracle Machine

An inter-layer semantic gap exploitation framework that discovers
vulnerabilities existing *between* protocol parsing layers, not within
any single component.

Usage:
    python cli.py scan <target> [options]
    python cli.py scan https://example.com --dashboard
    python cli.py scan https://example.com -m differential,smuggling -o report.json
"""

from __future__ import annotations

import asyncio
import os
import sys
import webbrowser

import click
from rich.panel import Panel
from rich.text import Text

from phantom.utils.display import console, show_banner, show_fingerprint, show_results
from phantom.core.models import ScanConfig
from phantom.core.engine import PhantomEngine
from phantom.core.report import export_json, export_html
from phantom.core.dashboard import generate_dashboard
from phantom.core.demo import build_demo_result


@click.group()
@click.version_option("1.0.0", prog_name="phantom")
def cli():
    """PHANTOM — Inter-Layer Semantic Gap Exploitation Framework"""
    pass


@cli.command()
@click.argument("target")
@click.option(
    "-m", "--modules",
    default="all",
    help="Comma-separated modules: fingerprint,differential,smuggling,confusion,header,all",
)
@click.option("-t", "--threads", default=10, help="Concurrent request limit")
@click.option("--timeout", default=10.0, help="HTTP timeout in seconds")
@click.option("-o", "--output", default=None, help="Output file (.json or .html)")
@click.option("-d", "--dashboard", is_flag=True, help="Launch interactive web dashboard after scan")
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL verification")
@click.option("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
@click.option("-H", "--header", multiple=True, help="Custom header (Name: Value)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(
    target: str,
    modules: str,
    threads: int,
    timeout: float,
    output: str | None,
    dashboard: bool,
    no_ssl_verify: bool,
    proxy: str | None,
    header: tuple[str, ...],
    verbose: bool,
):
    """Run a PHANTOM scan against a target."""
    show_banner()

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    custom_headers: dict[str, str] = {}
    for h in header:
        if ": " in h:
            k, v = h.split(": ", 1)
            custom_headers[k] = v
        elif ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k] = v.strip()

    config = ScanConfig(
        target=target,
        threads=threads,
        timeout=timeout,
        follow_redirects=True,
        verify_ssl=not no_ssl_verify,
        modules=modules.split(","),
        verbose=verbose,
        output_file=output,
        custom_headers=custom_headers,
        proxy=proxy,
    )

    info_text = Text()
    info_text.append("PHANTOM ", style="bold cyan")
    info_text.append("discovers vulnerabilities in the ", style="dim")
    info_text.append("gaps between protocol layers", style="bold")
    info_text.append(".\nWhere the proxy sees one thing and the backend sees another — ", style="dim")
    info_text.append("that's where bugs live.", style="bold yellow")
    console.print(Panel(info_text, border_style="cyan", padding=(1, 2)))
    console.print()

    result = asyncio.run(_run_scan(config))

    show_results(result)

    if output:
        if output.endswith(".json"):
            export_json(result, output)
        elif output.endswith(".html"):
            export_html(result, output)
        else:
            export_json(result, output)
        console.print(f"[bold green]Report saved:[/bold green] {output}")

    if dashboard:
        dash_path = os.path.abspath("phantom_dashboard.html")
        generate_dashboard(result, dash_path)
        console.print(f"\n[bold cyan]Dashboard:[/bold cyan] {dash_path}")
        console.print("[dim]Opening in browser...[/dim]")
        webbrowser.open(f"file://{dash_path}")

    if result.critical_count > 0:
        console.print(
            Panel(
                f"[bold red]{result.critical_count} CRITICAL finding(s) require immediate attention.[/bold red]",
                border_style="red",
            )
        )

    console.print("[dim]PHANTOM v1.0.0 — Inter-Layer Semantic Gap Exploitation Framework[/dim]\n")


@cli.command()
def modules():
    """List available scanner modules."""
    show_banner()
    from phantom.core.engine import ALL_MODULES

    console.print("[bold cyan]Available Modules:[/bold cyan]\n")
    for key, (name, cls) in ALL_MODULES.items():
        console.print(f"  [cyan]{key:14s}[/cyan]  {cls.description}")
    console.print()


@cli.command()
def info():
    """Show information about PHANTOM's approach."""
    show_banner()
    text = """
[bold]What makes PHANTOM different?[/bold]

Most security tools test individual endpoints for known vulnerability patterns.
PHANTOM takes a fundamentally different approach: it tests the [bold cyan]gaps between
protocol parsing layers[/bold cyan].

Every web application has multiple layers that parse the same HTTP request:
  [cyan]CDN -> WAF -> Reverse Proxy -> Web Server -> Application Framework[/cyan]

Each layer may interpret the [bold]same request differently[/bold]. These differences
-- called [bold yellow]parser differentials[/bold yellow] -- are the root cause of:

  * HTTP Request Smuggling (CL.TE / TE.CL desync)
  * WAF bypass via encoding mismatches
  * Path confusion leading to ACL bypass
  * Cache poisoning via unkeyed headers
  * Method confusion and verb tampering
  * Host-header injection attacks

PHANTOM systematically discovers these inter-layer mismatches and then uses
its [bold yellow]chain synthesis engine[/bold yellow] to combine low-severity findings into
high-impact exploit chains.

[bold]The Innovation:[/bold]
  Not "what vulnerability does this endpoint have?"
  But "[bold cyan]where do these layers disagree -- and how can I exploit the gap?[/bold cyan]"
"""
    console.print(Panel(text, border_style="cyan", padding=(1, 2)))


@cli.command()
@click.option("-d", "--dashboard", is_flag=True, help="Also generate and open the web dashboard")
def demo(dashboard: bool):
    """Run PHANTOM with showcase data — perfect for presentations and screenshots."""
    show_banner()

    info_text = Text()
    info_text.append("DEMO MODE ", style="bold yellow")
    info_text.append("— Showcasing all PHANTOM capabilities with pre-loaded results.\n", style="dim")
    info_text.append("In production, run: ", style="dim")
    info_text.append("python cli.py scan <target>", style="bold cyan")
    console.print(Panel(info_text, border_style="yellow", padding=(1, 2)))
    console.print()

    import time
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    modules_list = ["Fingerprint", "Parser Differential", "HTTP Smuggling", "Confusion Attacks", "Header Injection"]

    console.print(f"[bold cyan]Target:[/bold cyan] https://target-app.com")
    console.print(f"[bold cyan]Modules:[/bold cyan] {', '.join(modules_list)}")
    console.print()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
        TextColumn("[dim]{task.fields[status]}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("PHANTOM Scan", total=5, status="starting...")
        for mod in modules_list:
            progress.update(task, status=f"[cyan]{mod}[/cyan]")
            time.sleep(0.4)
            progress.advance(task)
        progress.update(task, status="[bold green]complete[/bold green]")

    result = build_demo_result()

    if result.fingerprint:
        show_fingerprint(result.fingerprint)

    console.print("[dim]Synthesizing attack chains...[/dim]")
    console.print()

    show_results(result)

    if dashboard:
        dash_path = os.path.abspath("phantom_dashboard.html")
        generate_dashboard(result, dash_path)
        console.print(f"\n[bold cyan]Dashboard:[/bold cyan] {dash_path}")
        console.print("[dim]Opening in browser...[/dim]")
        webbrowser.open(f"file://{dash_path}")

    if result.critical_count > 0:
        console.print(
            Panel(
                f"[bold red]⚠  {result.critical_count} CRITICAL finding(s) require immediate attention.[/bold red]",
                border_style="red",
            )
        )

    console.print("[dim]PHANTOM v1.0.0 — Inter-Layer Semantic Gap Exploitation Framework[/dim]\n")


@cli.command()
@click.option("-p", "--port", default=8080, help="Port to serve on")
@click.option("--host", default="0.0.0.0", help="Host to bind to")
def web(port: int, host: str):
    """Launch the PHANTOM web dashboard."""
    show_banner()
    console.print(f"[bold cyan]Starting PHANTOM Web UI[/bold cyan]")
    console.print(f"[dim]  Server:[/dim] http://{host}:{port}")
    console.print(f"[dim]  Dashboard:[/dim] http://localhost:{port}")
    console.print()

    import uvicorn
    uvicorn.run("phantom.web.server:app", host=host, port=port, log_level="info")


async def _run_scan(config: ScanConfig) -> "ScanResult":
    engine = PhantomEngine(config)
    return await engine.run()


if __name__ == "__main__":
    cli()
