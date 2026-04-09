from rich.console import Console
from rich.panel import Panel
console = Console()

def banner():
    console.print(Panel.fit("[bold red]THREATMAP INFRA[/bold red]\n[dim]VAPT Scanner & EASM Tool[/dim]", border_style="red"))

banner()

from rich.console import Console
from rich.panel import Panel
console = Console()

def banner():
    console.print(Panel.fit("[bold red]THREATMAP INFRA[/bold red]\n[dim]VAPT Scanner & EASM Tool[/dim]", border_style="red"))

banner()

"""
main.py — ThreatMap Infra entry point.
"""

import logging
import os
import sys
import shutil
import platform
import subprocess
import threading
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.align import Align
from rich.text import Text
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn,
)

from scanner_core import (
    Target, ScannerKit, ParallelOrchestrator,
    MODE_BALANCED, MODE_AGGRESSIVE,
)
from report_parser import ThreatMapParser
from db_manager import DBManager
from evidence_collector import EvidenceCollector
from report_generator import generate_excel
from ai_triage import run_ai_triage
from authorization_gate import AuthorizationGate

console = Console()

# ---------------------------------------------------------------------------
# Big banner — spaced letters give visual mass without ASCII art libraries
# ---------------------------------------------------------------------------

THREATMAP_ART = """\
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗ 
    ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
    ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██╔████╔██║███████║██████╔╝ 
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝  
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║      
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \
"""


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _configure_logging(log_path: str) -> None:
    root = logging.getLogger("threatmap")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(fh)
    root.propagate = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_env() -> None:
    if os.path.exists("reports"):
        shutil.rmtree("reports")
    os.makedirs("reports")


def open_file(path: str) -> None:
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.Popen(["xdg-open", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == "Darwin":
            subprocess.Popen(["open", path])
        elif system == "Windows":
            os.startfile(path)
    except Exception as exc:
        console.print(f"[dim]Could not open {path}: {exc}[/dim]")


def _print_banner() -> None:
    console.print()
    # Big ASCII art in cyan — fits a standard 120-wide terminal
    art_text = Text(THREATMAP_ART, style="bold cyan")
    console.print(Align.center(art_text))
    console.print()

    # Minimal one-line sub-header
    sub = Text.assemble(
        ("  I N F R A  ", "bold white"),
        ("─── ", "dim"),
        ("Vulnerability Assessment & EASM Scanner  ", "dim"),
        ("v1.0", "dim cyan"),
    )
    console.print(Align.center(sub))
    console.print(Align.center(Text(
        "For authorized security testing only.  Unauthorized use is illegal.",
        style="dim",
    )))
    console.print()


def _print_scan_config(target: str, mode: str, log_path: str) -> None:
    mode_str = (
        "[bold cyan]Balanced[/bold cyan]"
        if mode == MODE_BALANCED
        else "[bold red]Aggressive[/bold red]"
    )
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column(style="bold white")
    t.add_row("Target", target)
    t.add_row("Mode",   mode_str)
    t.add_row("Log",    log_path)
    console.print(
        Panel(t, title="[bold]Scan Configuration[/bold]",
              border_style="dim", padding=(0, 1))
    )
    console.print()


# ---------------------------------------------------------------------------
# Post-scan menu — persistent loop
# ---------------------------------------------------------------------------

def _post_scan_menu(excel_path: str, evidence_path: str, log_path: str) -> None:
    console.print()
    console.print(Rule("[dim]Outputs[/dim]", style="dim"))

    CHOICES = [
        f"📊  Excel Report       → {excel_path}",
        f"🌐  Evidence Gallery   → {evidence_path}",
        f"📋  Scan Log           → {log_path}",
        "❌  Exit",
    ]

    while True:
        choice = questionary.select(
            "Open an output (select again to open another):",
            choices=CHOICES,
            style=questionary.Style([
                ("selected", "fg:cyan bold"),
                ("pointer",  "fg:cyan bold"),
            ]),
        ).ask()

        if not choice or "Exit" in choice:
            console.print(
                "\n[bold cyan]ThreatMap Infra[/bold cyan] — "
                "[dim]scan complete.[/dim]\n"
            )
            break
        elif "Excel" in choice:
            open_file(excel_path)
        elif "Evidence" in choice:
            open_file(evidence_path)
        elif "Log" in choice:
            open_file(log_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _print_banner()

    # ── Target ────────────────────────────────────────────────────────
    target_input = questionary.text(
        "Target (domain, URL, or IP):",
        validate=lambda v: True if v.strip() else "Target cannot be empty.",
    ).ask()
    if not target_input:
        return

    # ── Authorization ─────────────────────────────────────────────────
    gate = AuthorizationGate()
    if not gate.validate(target_input.strip()):
        console.print("[red]Scan aborted.[/red]")
        return

    # ── Scan mode ─────────────────────────────────────────────────────
    mode_raw = questionary.select(
        "Scan mode:",
        choices=[
            "⚖️   Balanced   — Recommended. Fast, focused, low noise.",
            "🔥  Aggressive — All ports, full templates. Loud. Explicit auth required.",
        ],
        style=questionary.Style([
            ("selected", "fg:cyan bold"),
            ("pointer",  "fg:cyan bold"),
        ]),
    ).ask()
    if not mode_raw:
        return

    mode = MODE_AGGRESSIVE if "Aggressive" in mode_raw else MODE_BALANCED

    if mode == MODE_AGGRESSIVE:
        console.print()
        ok = questionary.confirm(
            "Aggressive mode scans all 65,535 ports and runs every Nuclei template. "
            "Confirm explicit authorization for high-intensity scanning?",
            default=False,
        ).ask()
        if not ok:
            console.print("[yellow]Switching to Balanced mode.[/yellow]")
            mode = MODE_BALANCED

    # ── Subdomain discovery ───────────────────────────────────────────
    full_scan = questionary.confirm(
        "Enumerate subdomains?  (No = single-host targeted scan)",
        default=False,
    ).ask()

    # ── Setup ─────────────────────────────────────────────────────────
    ensure_env()
    log_path = "reports/scan.log"
    _configure_logging(log_path)

    target  = Target(target_input.strip())
    _print_scan_config(target.domain, mode, log_path)

    db      = DBManager()
    scan_id = db.init_scan(target=target.domain, scan_mode=mode, max_workers=6)
    parser  = ThreatMapParser(target.domain)

    live_hosts:  list[str]      = []
    host_id_map: dict[str, int] = {}

    # ── Progress ──────────────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description:<26}"),
        BarColumn(bar_width=28),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        # Phase 0 — Discovery
        task_disc = progress.add_task("[cyan]Discovery", total=3)

        if full_scan:
            subs_sf = ScannerKit.run_subfinder(target)
            progress.advance(task_disc)
            subs_af = ScannerKit.run_assetfinder(target)
            progress.advance(task_disc)
            all_subs = list(set(subs_sf + subs_af))
            if all_subs:
                Path("reports/subdomains.txt").write_text("\n".join(all_subs))
            live_hosts = ScannerKit.run_httpx()
            progress.advance(task_disc)
            if not live_hosts:
                console.log("[yellow][!] No live subdomains — scanning primary target.[/yellow]")
                live_hosts = [target.url]
        else:
            live_hosts = [target.url]
            progress.update(task_disc, completed=3)

        # Phase 1 — Scanning
        task_scan    = progress.add_task("[cyan]Scanning Hosts", total=len(live_hosts))
        orchestrator = ParallelOrchestrator(mode=mode)
        scan_results: dict[str, dict] = {}
        lock = threading.Lock()

        def _scan_one(host: str) -> None:
            result = orchestrator._scan_single_host(host)
            with lock:
                scan_results[host] = result
            progress.advance(task_scan)

        threads = [threading.Thread(target=_scan_one, args=(h,), daemon=True)
                   for h in live_hosts]
        for t in threads: t.start()
        for t in threads: t.join()

        # Phase 2 — Persist
        task_db = progress.add_task("[cyan]Saving Results", total=len(scan_results))
        for host, result in scan_results.items():
            if result.get("error"):
                progress.advance(task_db)
                continue
            ht      = Target(host)
            host_id = db.upsert_host(scan_id, host, ht.domain)
            host_id_map[host] = host_id
            if result.get("nmap"):
                db.insert_ports(host_id, result["nmap"])
            parser.parse_host_reports(host)
            progress.advance(task_db)

        # Phase 3 — Evidence
        http_hosts = [h for h in host_id_map if h.startswith("http")]
        task_ev = progress.add_task("[cyan]Evidence", total=max(len(http_hosts), 1))
        if http_hosts:
            collector = EvidenceCollector(db=db, scan_id=scan_id)
            collector.capture_screenshots(hosts=http_hosts, output_dir="reports",
                                          host_id_map=host_id_map)
        progress.update(task_ev, completed=max(len(http_hosts), 1))

        # Phase 4 — AI Triage
        task_ai = progress.add_task("[cyan]AI Triage", total=1)
        run_ai_triage(db=db, scan_id=scan_id)
        progress.advance(task_ai)

        # Phase 5 — Report
        task_rep = progress.add_task("[cyan]Generating Report", total=1)
        parser.save_and_cleanup()
        db.complete_scan(scan_id)
        evidence_html = "reports/evidence_report.html"
        db.generate_evidence_report(scan_id, evidence_html)
        excel_path = generate_excel(db)
        progress.advance(task_rep)

    # ── Summary ───────────────────────────────────────────────────────
    triage_rows = db.get_all_triage()
    sev_counts: dict[str, int] = {}
    for r in triage_rows:
        s = r["severity"] or "Info"
        sev_counts[s] = sev_counts.get(s, 0) + 1

    summary = Table(
        title="[bold]Findings Summary[/bold]",
        border_style="cyan", show_header=True,
    )
    summary.add_column("Severity",  style="bold",    min_width=12)
    summary.add_column("Count",     justify="right", min_width=7)

    sla_map = {
        "Critical": ("red",          "Remediate within 24 hours"),
        "Low":      ("bright_yellow","Quarterly review"),
    }
    for sev, (color, sla) in sla_map.items():
        count = sev_counts.get(sev, 0)
        if count:
            summary.add_row(f"[{color}]{sev}[/{color}]",
                            f"[{color}]{count}[/{color}]", sla)
    summary.add_section()
    summary.add_row("[dim]Hosts[/dim]",    str(len(host_id_map)), "")
    summary.add_row("[dim]Findings[/dim]", str(len(triage_rows)), "")

    console.print()
    console.print(summary)
    console.print(
        f"\n[green]✔[/green]  [cyan]{excel_path}[/cyan]\n"
        f"[green]✔[/green]  [cyan]{evidence_html}[/cyan]\n"
        f"[green]✔[/green]  [cyan]{log_path}[/cyan]\n"
    )

    _post_scan_menu(excel_path, evidence_html, log_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        if os.path.exists("reports"):
            shutil.rmtree("reports")
        sys.exit(0)
