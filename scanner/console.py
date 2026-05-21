"""
VulnScan interactive console — Metasploit-style REPL.

Commands: use, set, unset, show, run/exploit, back,
          vulns, targets, sessions, report, workspace, help, exit
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Any

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter, NestedCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from scanner.core.orchestrator import Orchestrator, MODULES, ScanResult
from scanner.utils import report as report_util
from scanner.utils.output import severity_of, SEVERITY_COLORS, SEVERITY_ICONS
from scanner.config import REPORTS_DIR, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

console = Console()

# ── Palette ────────────────────────────────────────────────────────────────────
PROMPT_STYLE = Style.from_dict({
    "prompt.base":   "ansicyan bold",
    "prompt.module": "ansimagenta bold",
    "prompt.arrow":  "ansiwhite",
})

# ── ASCII art banner ───────────────────────────────────────────────────────────
BANNER = r"""
 __   ___   _ _     _   _ ____   ____    _    _   _
 \ \ / / | | | |   | \ | / ___| / ___|  / \  | \ | |
  \ V /| | | | |   |  \| \___ \| |     / _ \ |  \| |
   | | | |_| | |___| |\  |___) | |___ / ___ \| |\  |
   |_|  \___/|_____|_| \_|____/ \____/_/   \_\_| \_|
"""

VERSION_LINE = "       v2.0  //  Web Vulnerability Scanner  //  MIT License"

STATS_LINE = (
    f"    Modules: {len(MODULES)}  |  "
    "ML: enabled  |  "
    "Type 'help' for commands"
)

# ── Module option schema ───────────────────────────────────────────────────────
OPTION_SCHEMA: Dict[str, Dict[str, Any]] = {
    "TARGET":     {"required": True,  "default": "",      "desc": "Target URL to scan"},
    "DEPTH":      {"required": True,  "default": "3",     "desc": "Crawl depth"},
    "THREADS":    {"required": True,  "default": "5",     "desc": "Concurrent scan tasks"},
    "TIMEOUT":    {"required": True,  "default": "30",    "desc": "HTTP timeout (seconds)"},
    "MAX_URLS":   {"required": True,  "default": "50",    "desc": "Max URLs to test per target"},
    "PROXY":      {"required": False, "default": "",      "desc": "HTTP proxy (e.g. http://127.0.0.1:8080)"},
    "FORMAT":     {"required": True,  "default": "html",  "desc": "Report format: html / json / txt"},
    "OUTPUT":     {"required": False, "default": "",      "desc": "Output file path (auto if empty)"},
    "ML":         {"required": True,  "default": "true",  "desc": "Enable ML-based detection"},
    "TELEGRAM":   {"required": False, "default": "false", "desc": "Send report via Telegram"},
    "VERBOSE":    {"required": False, "default": "false", "desc": "Verbose output"},
}


class VulnScanConsole:
    def __init__(self) -> None:
        self.module: Optional[str] = None          # current selected module(s)
        self.options: Dict[str, str] = {           # current option values
            k: v["default"] for k, v in OPTION_SCHEMA.items()
        }
        self.sessions: List[Dict[str, Any]] = []   # completed scan results
        self.all_vulns: List[Dict[str, Any]] = []  # all findings ever
        self.targets:   List[str] = []             # known targets

        hist_path = Path.home() / ".vulnscan_history"
        self.session = PromptSession(
            history=FileHistory(str(hist_path)),
            style=PROMPT_STYLE,
            completer=self._build_completer(),
        )

    # ── Prompt ─────────────────────────────────────────────────────────────────

    def _build_completer(self) -> NestedCompleter:
        module_names = list(MODULES.keys()) + ["all"]
        return NestedCompleter.from_nested_dict({
            "use":    {m: None for m in module_names},
            "set":    {k: None for k in OPTION_SCHEMA},
            "unset":  {k: None for k in OPTION_SCHEMA},
            "show":   {"options": None, "modules": None, "vulns": None, "sessions": None},
            "run":    None,
            "exploit":None,
            "back":   None,
            "vulns":  None,
            "targets":None,
            "sessions":None,
            "report": {"html": None, "json": None, "txt": None},
            "help":   None,
            "exit":   None,
            "quit":   None,
        })

    def _prompt_text(self) -> HTML:
        if self.module:
            return HTML(
                f"<prompt.base>vulnscan</prompt.base>"
                f"<prompt.arrow> (</prompt.arrow>"
                f"<prompt.module>scanner/{self.module}</prompt.module>"
                f"<prompt.arrow>)</prompt.arrow>"
                f"<prompt.arrow> &gt; </prompt.arrow>"
            )
        return HTML("<prompt.base>vulnscan</prompt.base><prompt.arrow> &gt; </prompt.arrow>")

    # ── Main loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._print_banner()
        while True:
            try:
                raw = self.session.prompt(self._prompt_text()).strip()
            except KeyboardInterrupt:
                console.print("\n[dim]Use 'exit' to quit.[/dim]")
                continue
            except EOFError:
                break

            if not raw:
                continue

            parts = raw.split()
            cmd   = parts[0].lower()
            args  = parts[1:]

            dispatch = {
                "use":     self._cmd_use,
                "back":    self._cmd_back,
                "set":     self._cmd_set,
                "unset":   self._cmd_unset,
                "show":    self._cmd_show,
                "run":     self._cmd_run,
                "exploit": self._cmd_run,
                "vulns":   self._cmd_vulns,
                "targets": self._cmd_targets,
                "sessions":self._cmd_sessions,
                "report":  self._cmd_report,
                "help":    self._cmd_help,
                "?":       self._cmd_help,
                "exit":    self._cmd_exit,
                "quit":    self._cmd_exit,
            }

            handler = dispatch.get(cmd)
            if handler:
                try:
                    handler(args)
                except SystemExit:
                    raise
                except Exception as e:
                    console.print(f"[red][-][/red] Error: {e}")
            else:
                console.print(f"[yellow][-][/yellow] Unknown command: [bold]{cmd}[/bold]  (type 'help')")

    # ── Commands ───────────────────────────────────────────────────────────────

    def _cmd_use(self, args: List[str]) -> None:
        if not args:
            console.print("[yellow][-][/yellow] Usage: use <module|all>")
            return
        name = args[0].lower()
        valid = list(MODULES.keys()) + ["all"]
        if name not in valid:
            console.print(f"[red][-][/red] Unknown module '{name}'")
            console.print(f"    Available: {', '.join(valid)}")
            return
        self.module = name
        console.print(f"[cyan][*][/cyan] Using module [magenta]scanner/{name}[/magenta]")

    def _cmd_back(self, _args) -> None:
        self.module = None
        console.print("[cyan][*][/cyan] Returned to root context")

    def _cmd_set(self, args: List[str]) -> None:
        if len(args) < 2:
            console.print("[yellow][-][/yellow] Usage: set <KEY> <value>")
            return
        key = args[0].upper()
        val = " ".join(args[1:])
        if key not in OPTION_SCHEMA:
            console.print(f"[red][-][/red] Unknown option '{key}'")
            return
        self.options[key] = val
        console.print(f"[green]{key}[/green] => {val}")

    def _cmd_unset(self, args: List[str]) -> None:
        if not args:
            console.print("[yellow][-][/yellow] Usage: unset <KEY>")
            return
        key = args[0].upper()
        if key in OPTION_SCHEMA:
            self.options[key] = OPTION_SCHEMA[key]["default"]
            console.print(f"[dim]{key} reset to default ({self.options[key]})[/dim]")

    def _cmd_show(self, args: List[str]) -> None:
        sub = args[0].lower() if args else "options"
        if sub == "options":
            self._show_options()
        elif sub == "modules":
            self._show_modules()
        elif sub in ("vulns", "vulnerabilities"):
            self._cmd_vulns([])
        elif sub == "sessions":
            self._cmd_sessions([])
        else:
            console.print(f"[yellow][-][/yellow] show [options|modules|vulns|sessions]")

    def _show_options(self) -> None:
        mod_label = f"scanner/{self.module}" if self.module else "(no module selected)"
        t = Table(
            title=f"Module options ({mod_label})",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            show_lines=False,
        )
        t.add_column("Name",            style="bold white",  min_width=12)
        t.add_column("Current Setting", style="green",       min_width=20)
        t.add_column("Required",        style="yellow",      width=9)
        t.add_column("Description",     style="dim white")

        for key, meta in OPTION_SCHEMA.items():
            val      = self.options.get(key, meta["default"])
            required = "[red]yes[/red]" if meta["required"] else "no"
            t.add_row(key, val or "[dim]<not set>[/dim]", required, meta["desc"])

        console.print(t)

    def _show_modules(self) -> None:
        t = Table(title="Available modules", box=box.SIMPLE, header_style="bold cyan")
        t.add_column("Name",     style="magenta", min_width=18)
        t.add_column("Detects")
        descriptions = {
            "xss":           "Reflected XSS in URL params and forms",
            "sqli":          "Error / time / boolean-based SQL injection",
            "ssrf":          "Server-Side Request Forgery incl. cloud metadata",
            "lfi":           "Local / Remote File Inclusion, path traversal",
            "rce":           "OS command injection (output + time-based)",
            "csrf":          "Missing CSRF tokens, insecure cookie flags",
            "cors":          "CORS misconfiguration (origin reflection, wildcard)",
            "open_redirect": "Unvalidated URL redirects",
        }
        for name, desc in descriptions.items():
            t.add_row(f"scanner/{name}", desc)
        t.add_row("[bold]scanner/all[/bold]", "[bold]Run all modules above[/bold]")
        console.print(t)

    def _cmd_run(self, _args) -> None:
        target = self.options.get("TARGET", "").strip()
        if not target:
            console.print("[red][-][/red] TARGET not set. Use: set TARGET https://example.com")
            return

        modules = (
            list(MODULES.keys())
            if self.module in (None, "all")
            else [self.module]
        )

        proxy   = self.options.get("PROXY") or None
        use_ml  = self.options.get("ML", "true").lower() == "true"
        verbose = self.options.get("VERBOSE", "false").lower() == "true"
        fmt     = self.options.get("FORMAT", "html")
        out_str = self.options.get("OUTPUT", "").strip()
        telegram= self.options.get("TELEGRAM", "false").lower() == "true"

        try:
            depth   = int(self.options.get("DEPTH", "3"))
            threads = int(self.options.get("THREADS", "5"))
            timeout = int(self.options.get("TIMEOUT", "30"))
            max_urls= int(self.options.get("MAX_URLS", "50"))
        except ValueError as e:
            console.print(f"[red][-][/red] Invalid numeric option: {e}")
            return

        console.print(f"\n[cyan][*][/cyan] Module  : [magenta]{'scanner/'+self.module if self.module else 'scanner/all'}[/magenta]")
        console.print(f"[cyan][*][/cyan] Target  : {target}")
        console.print(f"[cyan][*][/cyan] Modules : {', '.join(modules)}")
        console.print(f"[cyan][*][/cyan] Depth   : {depth}  Max-URLs: {max_urls}  Threads: {threads}")
        console.print(f"[cyan][*][/cyan] ML      : {'enabled' if use_ml else 'disabled'}")
        console.print()

        orc = Orchestrator(
            modules=modules,
            depth=depth,
            max_urls=max_urls,
            threads=threads,
            proxy=proxy,
            timeout=timeout,
            use_ml=use_ml,
            verbose=verbose,
            notify_each=False,
        )

        t0 = time.monotonic()
        try:
            result: ScanResult = asyncio.run(orc.scan_target(target))
        except KeyboardInterrupt:
            console.print("\n[yellow][!][/yellow] Scan interrupted by user")
            return

        elapsed = time.monotonic() - t0
        sid = len(self.sessions) + 1

        # Store session
        self.sessions.append({
            "id":      sid,
            "target":  target,
            "modules": modules,
            "elapsed": round(elapsed, 1),
            "findings":result.findings,
        })
        self.all_vulns.extend(result.findings)
        if target not in self.targets:
            self.targets.append(target)

        # Print results
        if result.findings:
            console.print(f"\n[green][+][/green] Scan complete — [bold]{len(result.findings)}[/bold] finding(s) in {elapsed:.1f}s")
            self._print_vulns(result.findings)
        else:
            console.print(f"\n[green][+][/green] Scan complete — no vulnerabilities found ({elapsed:.1f}s)")

        # Report
        out_path = Path(out_str) if out_str else None
        rp = report_util.generate(
            target=target,
            findings=result.findings,
            urls_crawled=result.urls_crawled,
            elapsed=elapsed,
            fmt=fmt,
            output=out_path,
        )
        console.print(f"[cyan][*][/cyan] Report  → [bold]{rp}[/bold]  (session #{sid})")

        # Telegram
        if telegram and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
            from scanner.utils.notify import notify_report
            c: Dict[str, int] = {}
            for f in result.findings:
                s = f.get("severity", "medium")
                c[s] = c.get(s, 0) + 1
            summary = f"Target: {target}\n" + "\n".join(f"  {k.upper()}: {v}" for k, v in c.items())
            asyncio.run(notify_report(rp, summary))
            console.print("[cyan][*][/cyan] Report sent via Telegram")

        console.print()

    def _cmd_vulns(self, _args) -> None:
        if not self.all_vulns:
            console.print("[dim]No vulnerabilities recorded yet. Run a scan first.[/dim]")
            return
        self._print_vulns(self.all_vulns, title=f"All vulnerabilities ({len(self.all_vulns)})")

    def _print_vulns(self, vulns: List[Dict], title: str = "Findings") -> None:
        t = Table(title=title, box=box.ROUNDED, header_style="bold cyan", show_lines=True)
        t.add_column("#",         style="dim",        width=4)
        t.add_column("Severity",  style="bold",       width=10)
        t.add_column("Type",      style="bold white", width=18)
        t.add_column("Parameter", style="cyan",       width=14)
        t.add_column("Payload",   style="magenta",    width=30)
        t.add_column("URL",       no_wrap=False)

        for i, f in enumerate(vulns, 1):
            vtype  = f.get("type", "?")
            sev    = f.get("severity", severity_of(vtype))
            color  = SEVERITY_COLORS.get(sev, "white")
            icon   = SEVERITY_ICONS.get(sev, "•")
            t.add_row(
                str(i),
                f"[{color}]{icon} {sev.upper()}[/{color}]",
                vtype.upper(),
                f.get("parameter", "N/A"),
                str(f.get("payload", "N/A"))[:40],
                f.get("url", "N/A"),
            )
        console.print(t)

        # Severity counts
        c: Dict[str, int] = {}
        for f in vulns:
            s = f.get("severity", severity_of(f.get("type", "")))
            c[s] = c.get(s, 0) + 1
        parts = [
            f"[{SEVERITY_COLORS[s]}]{SEVERITY_ICONS[s]} {s.capitalize()}: {n}[/{SEVERITY_COLORS[s]}]"
            for s, n in c.items() if n
        ]
        if parts:
            console.print("  " + "   ".join(parts) + "\n")

    def _cmd_targets(self, _args) -> None:
        if not self.targets:
            console.print("[dim]No targets scanned yet.[/dim]")
            return
        t = Table(title="Known targets", box=box.SIMPLE, header_style="bold cyan")
        t.add_column("#",       width=4, style="dim")
        t.add_column("Target",  style="cyan")
        t.add_column("Vulns",   style="bold red", justify="right")
        for i, tgt in enumerate(self.targets, 1):
            cnt = sum(1 for v in self.all_vulns if v.get("url", "").startswith(tgt))
            t.add_row(str(i), tgt, str(cnt) if cnt else "0")
        console.print(t)

    def _cmd_sessions(self, _args) -> None:
        if not self.sessions:
            console.print("[dim]No sessions yet. Run a scan first.[/dim]")
            return
        t = Table(title="Scan sessions", box=box.SIMPLE, header_style="bold cyan")
        t.add_column("ID",      width=4,  style="dim")
        t.add_column("Target",  style="cyan")
        t.add_column("Modules", style="dim")
        t.add_column("Elapsed", justify="right")
        t.add_column("Findings",style="bold red", justify="right")
        for s in self.sessions:
            t.add_row(
                str(s["id"]),
                s["target"],
                ",".join(s["modules"]) if len(s["modules"]) < 4 else f"{len(s['modules'])} modules",
                f"{s['elapsed']}s",
                str(len(s["findings"])),
            )
        console.print(t)

    def _cmd_report(self, args: List[str]) -> None:
        fmt = args[0].lower() if args else self.options.get("FORMAT", "html")
        if fmt not in ("html", "json", "txt"):
            fmt = "html"
        if not self.all_vulns:
            console.print("[yellow][-][/yellow] No vulnerabilities to report.")
            return
        out_str = self.options.get("OUTPUT", "").strip()
        rp = report_util.generate(
            target=", ".join(self.targets) or "unknown",
            findings=self.all_vulns,
            fmt=fmt,
            output=Path(out_str) if out_str else None,
        )
        console.print(f"[green][+][/green] Report saved → [bold]{rp}[/bold]")

    def _cmd_help(self, _args) -> None:
        help_text = """
[bold cyan]Core commands[/bold cyan]
  [bold]use[/bold] <module|all>         Select scan module
  [bold]set[/bold] <KEY> <value>        Set an option
  [bold]unset[/bold] <KEY>              Reset option to default
  [bold]show[/bold] options             Show current options
  [bold]show[/bold] modules             List available modules
  [bold]run[/bold]  /  exploit          Start the scan
  [bold]back[/bold]                     Deselect current module

[bold cyan]Results[/bold cyan]
  [bold]vulns[/bold]                    Show all found vulnerabilities
  [bold]targets[/bold]                  List scanned targets
  [bold]sessions[/bold]                 Show completed scan sessions
  [bold]report[/bold] [html|json|txt]   Generate report from all sessions

[bold cyan]Workflow example[/bold cyan]
  vulnscan > use sqli
  vulnscan (scanner/sqli) > set TARGET https://example.com
  vulnscan (scanner/sqli) > set DEPTH 3
  vulnscan (scanner/sqli) > show options
  vulnscan (scanner/sqli) > run
  vulnscan (scanner/sqli) > vulns
  vulnscan (scanner/sqli) > report html
"""
        console.print(Panel(help_text, title="Help", border_style="cyan", expand=False))

    def _cmd_exit(self, _args) -> None:
        console.print("\n[dim]Goodbye.[/dim]\n")
        sys.exit(0)

    # ── Banner ─────────────────────────────────────────────────────────────────

    def _print_banner(self) -> None:
        console.print(Text(BANNER, style="bold cyan", justify="center"))
        console.print(Text(VERSION_LINE, style="bold white", justify="center"))
        console.print(Text(STATS_LINE,   style="dim cyan",  justify="center"))
        console.print()
        # Quick tips
        tips = [
            "[cyan]==[/cyan] [bold white]use scanner/all[/bold white]     — run all modules",
            "[cyan]==[/cyan] [bold white]set TARGET <url>[/bold white]    — set your target",
            "[cyan]==[/cyan] [bold white]run[/bold white]                  — start scanning",
        ]
        for tip in tips:
            console.print(f"    {tip}")
        console.print()


def launch() -> None:
    """Entry point for 'vulnscan console' command."""
    VulnScanConsole().run()
