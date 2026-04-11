"""
main.py — ThreatMap Infra entry point
Metasploit-style terminal UX. Clean, no duplicate banner, no HF noise.
"""

import logging
import os
import sys
import shutil
import platform
import subprocess
import threading
import warnings
from pathlib import Path
from datetime import datetime

# ── Suppress third-party noise before any imports ───────────────────────────
warnings.filterwarnings("ignore")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich import box

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

SEV_COLORS = {
    "Critical": "red",
    "High":     "orange1",
    "Medium":   "yellow",
    "Low":      "green",
    "Info":     "bright_blue",
}
SEV_SLA = {
    "Critical": "Patch within 24 hours",
    "High":     "Patch within 7 days",
    "Medium":   "Fix within 30 days",
    "Low":      "Quarterly review",
    "Info":     "Informational",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


# ── Logging ──────────────────────────────────────────────────────────────────

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


# ── Environment ───────────────────────────────────────────────────────────────

def ensure_env() -> None:
    if os.path.exists("reports"):
        shutil.rmtree("reports")
    os.makedirs("reports")


def open_file(path: str) -> None:
    try:
        if platform.system() == "Linux":
            subprocess.Popen(["xdg-open", path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        elif platform.system() == "Windows":
            os.startfile(path)
    except Exception:
        pass


# ── Questionary style ────────────────────────────────────────────────────────

Q = questionary.Style([
    ("qmark",       "fg:red bold"),
    ("question",    "fg:white bold"),
    ("answer",      "fg:cyan bold"),
    ("pointer",     "fg:red bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected",    "fg:cyan"),
    ("instruction", "fg:gray"),
])


# ── Status line printers (Metasploit style) ───────────────────────────────────

def _i(msg):  console.print(f"  [bold blue][[*]][/bold blue]  {msg}")
def _ok(msg): console.print(f"  [bold green][[+]][/bold green]  {msg}")
def _w(msg):  console.print(f"  [bold yellow][[!]][/bold yellow]  {msg}")
def _e(msg):  console.print(f"  [bold red][[-]][/bold red]  {msg}")


# ── Banner — printed ONCE ─────────────────────────────────────────────────────

def _banner() -> None:
    console.print()
    art_lines = [
        "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗  ",
        "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗ ",
        "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██╔████╔██║███████║██████╔╝  ",
        "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝   ",
        "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║        ",
        "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝       ",
    ]
    for line in art_lines:
        console.print(f"[bold red]{line}[/bold red]")
    console.print()

    info = Table.grid(padding=(0, 4))
    info.add_column(min_width=12)
    info.add_column()
    info.add_row("[dim]Version[/dim]",  "[white]1.0[/white]  [dim]·  VAPT + EASM Scanner[/dim]")
    info.add_row("[dim]Platform[/dim]", "[white]Kali Linux[/white]  [dim]·  Authorized use only[/dim]")
    info.add_row("[dim]AI Triage[/dim]","[white]SLM / Groq / OpenAI / Rule-based[/white]")
    console.print(info)
    console.print()
    console.print(Rule(style="dim red"))
    console.print()


# ── Scan config display ───────────────────────────────────────────────────────

def _scan_config(target: str, mode: str, log: str) -> None:
    console.print()
    console.print(Rule("[dim]Scan Configuration[/dim]", style="dim red"))
    t = Table.grid(padding=(0, 3))
    t.add_column(style="dim", min_width=20)
    t.add_column(style="bold white")
    mode_str = (
        "[bold cyan]Balanced[/bold cyan]"
        if mode == MODE_BALANCED
        else "[bold red]Aggressive[/bold red]"
    )
    t.add_row("  [bold blue][[*]][/bold blue]  Target",  target)
    t.add_row("  [bold blue][[*]][/bold blue]  Mode",    mode_str)
    t.add_row("  [bold blue][[*]][/bold blue]  Log",     log)
    t.add_row("  [bold blue][[*]][/bold blue]  Started", datetime.now().strftime("%H:%M:%S"))
    console.print(t)
    console.print()


# ── Summary table ─────────────────────────────────────────────────────────────

def _summary(triage_rows, host_id_map, excel_path, log_path) -> None:
    console.print()
    console.print(Rule("[dim]Scan Complete[/dim]", style="dim green"))
    console.print()

    sev_counts: dict[str, int] = {}
    for r in triage_rows:
        s = r["severity"] or "Info"
        sev_counts[s] = sev_counts.get(s, 0) + 1

    ai_count = sum(1 for r in triage_rows if r["ai_enhanced"])

    t = Table(
        box=box.SIMPLE, show_header=True,
        header_style="bold dim", pad_edge=False, show_edge=False,
    )
    t.add_column("  Severity",  min_width=12, style="bold")
    t.add_column("  Count",     min_width=7,  justify="right")
    t.add_column("  SLA",       min_width=26, style="dim")

    for sev in SEV_ORDER:
        cnt = sev_counts.get(sev, 0)
        if cnt > 0:
            col = SEV_COLORS.get(sev, "white")
            t.add_row(
                f"  [{col}]{sev}[/{col}]",
                f"  [{col}]{cnt}[/{col}]",
                f"  {SEV_SLA.get(sev, '')}",
            )

    t.add_section()
    t.add_row("  [dim]Hosts[/dim]",
              f"  [white]{len(host_id_map)}[/white]", "")
    t.add_row("  [dim]Findings[/dim]",
              f"  [white]{len(triage_rows)}[/white]",
              f"  [dim]{ai_count} AI-enhanced[/dim]")

    console.print(t)
    console.print()
    console.print(Rule("[dim]Outputs[/dim]", style="dim"))
    console.print()
    _ok(f"Report  →  [cyan]{excel_path}[/cyan]")
    _ok(f"Log     →  [cyan]{log_path}[/cyan]")
    console.print()


# ── Post-scan menu ────────────────────────────────────────────────────────────

def _menu(excel_path: str, log_path: str) -> None:
    console.print(Rule("[dim]Actions[/dim]", style="dim"))
    console.print()

    CHOICES = [
        f"Open Excel Report  ({excel_path})",
        f"Open Scan Log      ({log_path})",
        "Exit",
    ]

    while True:
        choice = questionary.select(
            "  Select action:", choices=CHOICES, style=Q,
        ).ask()

        if not choice or "Exit" in choice:
            console.print()
            _ok("Session complete.")
            console.print()
            break
        elif "Report" in choice:
            open_file(excel_path)
            _i("Opening report...")
        elif "Log" in choice:
            open_file(log_path)
            _i("Opening scan log...")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    _banner()

    # ── Target ──────────────────────────────────────────────────────────
    target_input = questionary.text(
        "  tm> ? target:",
        validate=lambda v: True if v.strip() else "Target cannot be empty.",
        style=Q,
    ).ask()
    if not target_input:
        return
    console.print()

    # ── Authorization ────────────────────────────────────────────────────
    gate = AuthorizationGate()
    if not gate.validate(target_input.strip()):
        _e("Scan aborted — authorization not confirmed.")
        return
    console.print()

    # ── Mode ─────────────────────────────────────────────────────────────
    mode_raw = questionary.select(
        "  tm> ? mode:",
        choices=[
            "balanced   — Recommended. Fast, focused, low noise.",
            "aggressive — All 65,535 ports + full Nuclei templates. Loud.",
        ],
        style=Q,
    ).ask()
    if not mode_raw:
        return

    mode = MODE_AGGRESSIVE if "aggressive" in mode_raw else MODE_BALANCED

    if mode == MODE_AGGRESSIVE:
        console.print()
        ok = questionary.confirm(
            "  Aggressive mode scans all 65,535 ports. Confirm authorization?",
            default=False, style=Q,
        ).ask()
        if not ok:
            _w("Switching to balanced mode.")
            mode = MODE_BALANCED
    console.print()

    # ── Subdomain sweep ───────────────────────────────────────────────────
    full_scan = questionary.confirm(
        "  tm> ? enumerate subdomains?",
        default=False, style=Q,
    ).ask()
    console.print()

    # ── Setup ─────────────────────────────────────────────────────────────
    ensure_env()
    log_path = "reports/scan.log"
    _configure_logging(log_path)

    target      = Target(target_input.strip())
    db          = DBManager()
    scan_id     = db.init_scan(target=target.domain, scan_mode=mode, max_workers=4)
    parser      = ThreatMapParser(target.domain)
    live_hosts  : list[str]      = []
    host_id_map : dict[str, int] = {}

    _scan_config(target.domain, mode, log_path)

    # ── Progress ──────────────────────────────────────────────────────────
    with Progress(
        TextColumn("  [bold blue]  [*][/bold blue]  [progress.description]{task.description:<28}"),
        SpinnerColumn(spinner_name="dots", style="red"),
        BarColumn(bar_width=22, complete_style="red", finished_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        # Phase 0 — Discovery
        task_disc = progress.add_task("Discovery", total=3)
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
                live_hosts = [target.url]
        else:
            live_hosts = [target.url]
            progress.update(task_disc, completed=3)

        # Phase 1 — Scanning
        task_scan    = progress.add_task("Scanning", total=len(live_hosts))
        orchestrator = ParallelOrchestrator(mode=mode)
        scan_results : dict[str, dict] = {}
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
        task_db = progress.add_task("Saving Results", total=max(len(scan_results), 1))
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

        # Phase 3 — Evidence (HTTP probe only — no browser/screenshots)
        http_hosts = [h for h in host_id_map if h.startswith("http")]
        task_ev = progress.add_task("Evidence Collection", total=max(len(http_hosts), 1))
        if http_hosts:
            collector = EvidenceCollector(db=db, scan_id=scan_id)
            collector.capture_screenshots(
                hosts=http_hosts,
                output_dir="reports",
                host_id_map=host_id_map,
            )
        progress.update(task_ev, completed=max(len(http_hosts), 1))

        # Phase 4 — AI Triage (stderr suppressed)
        task_ai = progress.add_task("AI Triage", total=1)
        import io, contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            run_ai_triage(db=db, scan_id=scan_id)
        progress.advance(task_ai)

        # Phase 5 — Report
        task_rep = progress.add_task("Generating Report", total=1)
        parser.save_and_cleanup()
        db.complete_scan(scan_id)
        excel_path = generate_excel(db)
        if not excel_path:
            _w("No findings to report — check scan.log for details.")
            return
        progress.advance(task_rep)

    # ── Final summary and menu ─────────────────────────────────────────────
    triage_rows = db.get_all_triage()
    _summary(triage_rows, host_id_map, excel_path, log_path)
    _menu(excel_path, log_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print()
        _w("Interrupted.")
        if os.path.exists("reports"):
            shutil.rmtree("reports")
        sys.exit(0)
