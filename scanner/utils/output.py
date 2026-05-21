"""
Rich-based terminal output helpers.
"""
from __future__ import annotations

from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TaskProgressColumn,
)

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "info":     "cyan",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "ℹ️ ",
}

VULN_SEVERITY = {
    "xss":              "high",
    "sqli":             "critical",
    "rce":              "critical",
    "file_inclusion":   "critical",
    "lfi":              "critical",
    "rfi":              "critical",
    "ssrf":             "high",
    "csrf":             "medium",
    "open_redirect":    "medium",
    "cors":             "medium",
    "ssl_tls":          "medium",
    "subdomain_takeover": "high",
    "xxe":              "high",
    "nosql":            "high",
    "ssti":             "high",
}


def severity_of(vuln_type: str) -> str:
    return VULN_SEVERITY.get(vuln_type.lower(), "medium")


def banner() -> None:
    art = r"""
    _   ____      _   ____ _   _ _   _ _____
   / \ |  _ \    / \ / ___| | | | \ | | ____|
  / _ \| |_) |  / _ \ |   | |_| |  \| |  _|
 / ___ \  _ <  / ___ \ |___|  _  | |\  | |___
/_/   \_\_| \_\/_/   \_\____|_| |_|_| \_|_____|
    """
    console.print(Panel(
        Text(art, style="bold cyan", justify="center"),
        subtitle="[dim]ARACHNE v2.0  //  web vulnerability framework  //  authorized use only[/dim]",
        border_style="cyan",
    ))


def info(msg: str) -> None:
    console.print(f"[dim cyan][[*]][/dim cyan] {msg}")


def success(msg: str) -> None:
    console.print(f"[bold green][[+]][/bold green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][[!]][/yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red][[✗]][/bold red] {msg}")


def vuln(finding: Dict[str, Any]) -> None:
    vtype    = finding.get("type", "unknown")
    sev      = finding.get("severity", severity_of(vtype))
    color    = SEVERITY_COLORS.get(sev, "white")
    icon     = SEVERITY_ICONS.get(sev, "•")
    url      = finding.get("url", "N/A")
    param    = finding.get("parameter", "N/A")
    payload  = finding.get("payload", "N/A")

    console.print(
        f"{icon} [{color}]{vtype.upper()}[/{color}]  "
        f"[dim]param=[/dim][cyan]{param}[/cyan]  "
        f"[dim]url=[/dim]{url}"
    )
    if payload and payload != "N/A":
        console.print(f"   [dim]payload →[/dim] [magenta]{payload[:80]}[/magenta]")


def summary_table(findings: List[Dict[str, Any]], target: str) -> None:
    """Print a summary table of all findings."""
    table = Table(
        title=f"Scan results — {target}",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("#",         style="dim",         width=4)
    table.add_column("Severity",  style="bold",        width=10)
    table.add_column("Type",      style="bold white",  width=18)
    table.add_column("Parameter", style="cyan",        width=14)
    table.add_column("URL",       style="dim white",   no_wrap=False)

    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for i, f in enumerate(findings, 1):
        vtype = f.get("type", "unknown")
        sev   = f.get("severity", severity_of(vtype))
        color = SEVERITY_COLORS.get(sev, "white")
        counts[sev] = counts.get(sev, 0) + 1
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            vtype,
            f.get("parameter", "N/A"),
            f.get("url", "N/A"),
        )

    console.print(table)

    # Severity summary bar
    parts = []
    for sev, cnt in counts.items():
        if cnt:
            col = SEVERITY_COLORS[sev]
            parts.append(f"[{col}]{SEVERITY_ICONS[sev]} {sev.capitalize()}: {cnt}[/{col}]")
    if parts:
        console.print("  " + "   ".join(parts))


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )
