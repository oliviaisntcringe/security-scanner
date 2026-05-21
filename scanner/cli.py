"""
VulnScan CLI — entry point.

Usage:
    arachne scan <target> [options]
    arachne scan -f targets.txt [options]
    arachne report --last
    arachne config
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

import click

from scanner.utils.output import banner, console, info, success, warn, error, summary_table, make_progress
from scanner.core.orchestrator import Orchestrator, MODULES
from scanner.utils import report as report_util
from scanner.config import REPORTS_DIR, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

# ── Helpers ────────────────────────────────────────────────────────────────────

def _validate_modules(ctx, param, value: str) -> List[str]:
    if not value or value.lower() == "all":
        return list(MODULES.keys())
    mods = [m.strip().lower() for m in value.split(",")]
    invalid = [m for m in mods if m not in MODULES]
    if invalid:
        raise click.BadParameter(
            f"Unknown modules: {', '.join(invalid)}. "
            f"Valid: {', '.join(MODULES.keys())}"
        )
    return mods


def _run(coro):
    """Run an async coroutine from sync context."""
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        warn("Interrupted.")
        sys.exit(0)


# ── CLI root ───────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """
    \b
    VulnScan — web vulnerability scanner
    For authorized security testing only.
    """
    if ctx.invoked_subcommand is None:
        banner()
        click.echo(ctx.get_help())


# ── scan command ───────────────────────────────────────────────────────────────

@main.command()
@click.argument("targets", nargs=-1, metavar="TARGET...")
@click.option("-f", "--file",    "targets_file",
              type=click.Path(exists=True), default=None,
              help="File with target URLs (one per line).")
@click.option("-m", "--modules", "modules",
              default="all", callback=_validate_modules, is_eager=True,
              show_default=True,
              help="Comma-separated modules to run, or 'all'. "
                   f"Available: {', '.join(MODULES.keys())}")
@click.option("-d", "--depth",   default=3,  show_default=True,
              help="Crawl depth.")
@click.option("-u", "--max-urls", default=50, show_default=True,
              help="Max URLs to test per target.")
@click.option("-T", "--threads", default=5,  show_default=True,
              help="Concurrent scan tasks.")
@click.option("-t", "--timeout", default=30, show_default=True,
              help="HTTP request timeout (seconds).")
@click.option("--proxy",         default=None,
              help="HTTP proxy (e.g. http://127.0.0.1:8080).")
@click.option("--no-ml",         is_flag=True, default=False,
              help="Disable ML-based detection.")
@click.option("-o", "--output",  default=None,
              help="Output file path (auto-generated if omitted).")
@click.option("--format",  "fmt",
              type=click.Choice(["html", "json", "txt"]), default="html",
              show_default=True, help="Report format.")
@click.option("--telegram", is_flag=True, default=False,
              help="Send report via Telegram after scan.")
@click.option("--notify-each", is_flag=True, default=False,
              help="Send Telegram alert for each finding immediately.")
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Verbose output.")
def scan(
    targets: tuple,
    targets_file: Optional[str],
    modules: List[str],
    depth: int,
    max_urls: int,
    threads: int,
    timeout: int,
    proxy: Optional[str],
    no_ml: bool,
    output: Optional[str],
    fmt: str,
    telegram: bool,
    notify_each: bool,
    verbose: bool,
) -> None:
    """Scan one or more targets for web vulnerabilities."""
    banner()

    # Build target list
    target_list: List[str] = list(targets)
    if targets_file:
        lines = Path(targets_file).read_text().splitlines()
        target_list += [l.strip() for l in lines if l.strip() and not l.startswith("#")]

    if not target_list:
        error("No targets specified. Use arachne scan <url> or -f <file>.")
        sys.exit(1)

    # Telegram sanity check
    if (telegram or notify_each) and not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        warn("Telegram credentials not set. Set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID env vars.")
        telegram = notify_each = False

    info(f"Modules : {', '.join(modules)}")
    info(f"Depth   : {depth}   Max URLs: {max_urls}   Threads: {threads}")
    info(f"ML      : {'disabled' if no_ml else 'enabled'}")
    if proxy:
        info(f"Proxy   : {proxy}")
    console.rule()

    orc = Orchestrator(
        modules=modules,
        depth=depth,
        max_urls=max_urls,
        threads=threads,
        proxy=proxy,
        timeout=timeout,
        use_ml=not no_ml,
        verbose=verbose,
        notify_each=notify_each,
    )

    all_findings = []

    for target in target_list:
        console.rule(f"[bold cyan]{target}[/bold cyan]")
        result = _run(orc.scan_target(target))

        all_findings.extend(result.findings)

        if result.findings:
            summary_table(result.findings, target)
        else:
            success("No vulnerabilities found.")

        info(f"Done in {result.elapsed:.1f}s — {result.summary()}")
        if result.errors and verbose:
            for e in result.errors[:5]:
                warn(f"Error: {e}")

    # ── Report ─────────────────────────────────────────────────────────────────
    if not all_findings:
        console.rule()
        success("Scan complete — no vulnerabilities found across all targets.")
        return

    out_path = Path(output) if output else None
    report_path = report_util.generate(
        target=", ".join(target_list),
        findings=all_findings,
        urls_crawled=sum(1 for _ in all_findings),  # approximate
        elapsed=0,
        fmt=fmt,
        output=out_path,
    )
    console.rule()
    success(f"Report saved → [bold]{report_path}[/bold]")

    # ── Telegram ───────────────────────────────────────────────────────────────
    if telegram:
        from scanner.utils.notify import notify_report
        counts = {}
        for f in all_findings:
            from scanner.utils.output import severity_of
            sev = f.get("severity", severity_of(f.get("type", "")))
            counts[sev] = counts.get(sev, 0) + 1
        summary_str = (
            f"Target(s): {', '.join(target_list)}\n"
            + "\n".join(f"  {k.upper()}: {v}" for k, v in counts.items())
        )
        _run(notify_report(report_path, summary_str))
        success("Report sent via Telegram.")


# ── report command ─────────────────────────────────────────────────────────────

@main.command()
@click.option("--last",  is_flag=True, help="Open the most recent report.")
@click.option("--list",  "list_reports", is_flag=True, help="List all reports.")
def report(last: bool, list_reports: bool) -> None:
    """View generated reports."""
    all_reports = sorted(REPORTS_DIR.glob("arachne_*"), key=lambda p: p.stat().st_mtime, reverse=True)

    if list_reports or (not last and not list_reports):
        if not all_reports:
            warn("No reports found yet. Run 'arachne scan' first.")
            return
        from rich.table import Table
        from rich import box as rbox
        t = Table(title="Saved reports", box=rbox.SIMPLE, header_style="bold cyan")
        t.add_column("#", width=4)
        t.add_column("File")
        t.add_column("Size", justify="right")
        t.add_column("Date")
        import datetime
        for i, p in enumerate(all_reports, 1):
            stat = p.stat()
            t.add_row(
                str(i),
                p.name,
                f"{stat.st_size // 1024} KB",
                datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            )
        console.print(t)

    if last and all_reports:
        import subprocess, platform
        path = str(all_reports[0])
        if platform.system() == "Darwin":
            subprocess.run(["open", path])
        elif platform.system() == "Linux":
            subprocess.run(["xdg-open", path])
        else:
            subprocess.run(["start", path], shell=True)
        success(f"Opened {path}")


# ── config command ─────────────────────────────────────────────────────────────

@main.command("config")
@click.option("--set", "kv", metavar="KEY=VALUE", multiple=True,
              help="Set a config value in ~/.arachne.conf")
def config_cmd(kv: tuple) -> None:
    """Show or set configuration values."""
    import configparser, os
    conf_path = Path.home() / ".arachne.conf"
    conf = configparser.ConfigParser()
    if conf_path.exists():
        conf.read(conf_path)
    if "DEFAULT" not in conf:
        conf["DEFAULT"] = {}

    if kv:
        for item in kv:
            if "=" not in item:
                error(f"Invalid format: '{item}'. Use KEY=VALUE.")
                continue
            key, _, val = item.partition("=")
            conf["DEFAULT"][key.strip()] = val.strip()
        with open(conf_path, "w") as f:
            conf.write(f)
        success(f"Saved to {conf_path}")
    else:
        # Show current config
        from rich.table import Table
        from rich import box as rbox
        t = Table(title="VulnScan Configuration", box=rbox.SIMPLE, header_style="bold cyan")
        t.add_column("Key")
        t.add_column("Value")
        t.add_column("Source")

        _show_key(t, "TELEGRAM_TOKEN",   TELEGRAM_TOKEN,   "env/conf")
        _show_key(t, "TELEGRAM_CHAT_ID", TELEGRAM_CHAT_ID, "env/conf")

        import os
        from scanner import config as cfg
        for attr in ["REQUEST_TIMEOUT", "MAX_CRAWL_DEPTH", "MAX_URLS",
                     "CONCURRENT_TASKS", "SCAN_DELAY", "ML_CONFIDENCE_THRESHOLD"]:
            val = getattr(cfg, attr, "?")
            _show_key(t, attr, str(val), "env/conf/default")
        console.print(t)
        info(f"Config file: {conf_path}")
        info("Set values with: arachne config --set KEY=VALUE")
        info("Or export env vars: export TELEGRAM_TOKEN=xxx")


def _show_key(table, key, value, source):
    if value and "TOKEN" in key:
        display = value[:6] + "…" + value[-4:]
    else:
        display = str(value) if value else "[dim]not set[/dim]"
    table.add_row(key, display, f"[dim]{source}[/dim]")


# ── web command ────────────────────────────────────────────────────────────────

@main.command("web")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=5001,        show_default=True, help="Port.")
@click.option("--debug", is_flag=True, default=False, help="Flask debug mode.")
def web_cmd(host: str, port: int, debug: bool) -> None:
    """Launch the web dashboard (optional UI)."""
    try:
        from app import create_app, socketio
        banner()
        info(f"Starting web dashboard on http://{host}:{port}")
        info("Press Ctrl+C to stop.")
        app = create_app()
        socketio.run(app, host=host, port=port, debug=debug, use_reloader=False)
    except ImportError as exc:
        error(f"Web UI dependencies missing: {exc}")
        error("Install with: pip install flask flask-socketio")


# ── console command ────────────────────────────────────────────────────────────

@main.command("console")
def console_cmd() -> None:
    """Launch the interactive Metasploit-style console."""
    from scanner.console import launch
    launch()


if __name__ == "__main__":
    main()
