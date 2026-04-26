"""
main.py — ThreatMap Infra v1.0
Full flow: banner → target → auth → options → scan → AI report → menu
Program does NOT exit until user selects Exit from menu.
"""

import contextlib, io, logging, os, shutil, subprocess, sys, threading, warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
logging.getLogger("huggingface_hub").setLevel(logging.CRITICAL)
logging.getLogger("llama_cpp").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.ERROR)

try:
    import questionary
    HAS_QUESTIONARY = True
except ImportError:
    questionary = None
    HAS_QUESTIONARY = False

from rich.console import Console
from rich.table   import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich import box

from core.scan_logger import configure as configure_logging, get_logger
from core.env_check import ToolRegistry, ScanDirs
from core.scanner_core import (
    Target, ScannerKit, ParallelOrchestrator,
    MODE_BALANCED, MODE_AGGRESSIVE,
)
from db.db_manager import DBManager
from core.evidence_collector import EvidenceCollector
from ai.ai_triage import run_ai_triage
from ai.ai_reporter import generate_all_reports
from cli.cli_menu import PostScanMenu
from cli.authorization_gate import AuthorizationGate
from utils.severity import SEVERITY_ORDER

log     = get_logger("main")
console = Console()

SEV_COLOR = {"Critical":"red","High":"orange1","Medium":"yellow","Low":"green","Info":"bright_blue"}
SEV_SLA   = {
    "Critical": "Patch within 24h",
    "High":     "Patch within 7 days",
    "Medium":   "Fix within 30 days",
    "Low":      "Quarterly review",
    "Info":     "Informational",
}
SEV_ORDER = [s.title() for s in SEVERITY_ORDER]

Q = questionary.Style([
    ("qmark","fg:red bold"),("question","fg:white bold"),("answer","fg:cyan bold"),
    ("pointer","fg:red bold"),("highlighted","fg:cyan bold"),("selected","fg:cyan"),
    ("instruction","fg:gray"),
])


def _i(msg):  console.print(f"  [bold blue][[*]][/bold blue]  {msg}")
def _ok(msg): console.print(f"  [bold green][[+]][/bold green]  {msg}")
def _w(msg):  console.print(f"  [bold yellow][[!]][/bold yellow]  {msg}")
def _e(msg):  console.print(f"  [bold red][[-]][/bold red]  {msg}")


def _banner() -> None:
    for line in [
        "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███╗   ███╗ █████╗ ██████╗  ",
        "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗ ",
        "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██╔████╔██║███████║██████╔╝  ",
        "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝   ",
        "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║        ",
        "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝       ",
    ]:
        console.print(f"[bold red]{line}[/bold red]")
    console.print()
    info = Table.grid(padding=(0,4))
    info.add_column(min_width=12); info.add_column()
    info.add_row("[dim]Version[/dim]",   "[white]1.0[/white]  [dim]·  VAPT + EASM Scanner[/dim]")
    info.add_row("[dim]Platform[/dim]",  "[white]Kali Linux[/white]  [dim]·  Authorized use only[/dim]")
    info.add_row("[dim]Storage[/dim]",   "[white]100% Local[/white]  [dim]·  No data leaves your machine[/dim]")
    info.add_row("[dim]Local Analysis (SLM)[/dim]", "[white]Built-in[/white]")
    console.print(info)
    console.print()


def main() -> str:
    _banner()

    # 1. Target
    target_input = questionary.text(
        "  tm> ? target:",
        validate=lambda v: True if v.strip() else "Target cannot be empty.",
        style=Q,
    ).ask()
    if not target_input:
        return "exit"
    console.print()

    target = Target(target_input.strip())
    dirs = ScanDirs.create(base="scans", target=target.domain)

    # 2. Authorization
    if not AuthorizationGate().validate(target_input.strip(), report_dir=dirs.report_dir):
        _e("Scan aborted.")
        return "exit"
    console.print()

    # 3. Mode
    mode_raw = questionary.select(
        "  tm> ? scan mode:",
        choices=[
            "balanced   — Recommended. Fast, focused, low noise.",
            "aggressive — All 65,535 ports + full Nuclei. Loud.",
        ],
        style=Q,
    ).ask()
    if not mode_raw:
        return "exit"
    mode = MODE_AGGRESSIVE if "aggressive" in mode_raw else MODE_BALANCED
    if mode == MODE_AGGRESSIVE:
        console.print()
        if not questionary.confirm(
            "  Aggressive mode scans all 65,535 ports. Confirm?",
            default=False, style=Q,
        ).ask():
            _w("Switching to balanced mode."); mode = MODE_BALANCED
    console.print()

    # 4. Subdomain sweep
    full_scan = questionary.confirm(
        "  tm> ? enumerate subdomains?", default=False, style=Q,
    ).ask()
    console.print()

    # 5. Output folder
    default_save = str(Path.home() / "ThreatMap-Reports")
    save_raw = questionary.text(
        "  tm> ? save reports to:",
        default=default_save,
        instruction="(press Enter for default)",
        style=Q,
    ).ask()
    save_dir = (save_raw or default_save).strip()
    try:
        Path(save_dir).mkdir(parents=True, exist_ok=True)
        _ok(f"Reports → [cyan]{save_dir}[/cyan]")
    except Exception as exc:
        _w(f"Cannot create directory ({exc}) — using default.")
        save_dir = default_save
        Path(save_dir).mkdir(parents=True, exist_ok=True)
    console.print()

    # 6. Setup
    configure_logging(verbose=False, log_file=dirs.log_file)
    log.info("scan started: target=%s mode=%s", target.domain, mode)

    registry = ToolRegistry()
    all_ok, missing = registry.validate()
    if not all_ok:
        registry.print_install_guide(missing)
        if not questionary.confirm(
            "  Some required tools are missing. Continue anyway?",
            default=False, style=Q,
        ).ask():
            _e("Scan aborted.")
            return "exit"
        console.print()

    db          = DBManager()
    scan_id     = db.init_scan(target=target.domain, scan_mode=mode, max_workers=4)
    live_hosts  : list[str]     = []
    host_id_map : dict[str,int] = {}

    _i(f"Scanning [bold white]{target.domain}[/bold white]  "
       f"[dim]({'Balanced' if mode==MODE_BALANCED else 'Aggressive'})[/dim]")
    console.print()

    # 7. SCAN
    with Progress(
        TextColumn("  [bold blue][[*]][/bold blue]  "
                   "[progress.description]{task.description:<28}"),
        SpinnerColumn(spinner_name="dots", style="red"),
        BarColumn(bar_width=22, complete_style="red", finished_style="green"),
        TaskProgressColumn(), TimeElapsedColumn(),
        console=console, transient=False,
    ) as progress:

        disc = progress.add_task("Discovery: Target Expansion", total=3)
        if full_scan:
            subs = ScannerKit.discover_subdomains(target, dirs)
            progress.advance(disc); progress.advance(disc)
            live_hosts = ScannerKit.filter_live_hosts(subs, dirs) or [target.url]
            progress.advance(disc)
        else:
            live_hosts = [target.url]
            progress.update(disc, completed=3)

        task_scan    = progress.add_task("Scanning: Host & Port Analysis", total=len(live_hosts))
        orchestrator = ParallelOrchestrator(mode=mode)
        scan_results : dict[str,dict] = {}
        lock = threading.Lock()

        def _scan_one(host: str) -> None:
            result = orchestrator.scan_host(host, dirs)
            with lock: scan_results[host] = result
            progress.advance(task_scan)

        threads = [threading.Thread(target=_scan_one, args=(h,), daemon=True) for h in live_hosts]
        for t in threads: t.start()
        for t in threads: t.join()

        task_db = progress.add_task("Saving results", total=max(len(scan_results),1))
        for host, result in scan_results.items():
            if result.get("error"): progress.advance(task_db); continue
            ht      = Target(host)
            host_id = db.upsert_host(scan_id, host, ht.domain)
            host_id_map[host] = host_id
            if result.get("nmap"): db.insert_ports(host_id, result["nmap"])
            progress.advance(task_db)

        http_hosts = [h for h in host_id_map if h.startswith("http")]
        task_ev = progress.add_task("Web analysis: HTTP Evidence Collection", total=max(len(http_hosts),1))
        if http_hosts:
            EvidenceCollector().probe_hosts(hosts=http_hosts, output_dir=dirs.report_dir)
        progress.update(task_ev, completed=max(len(http_hosts),1))

        task_ai = progress.add_task("Vulnerability analysis: Risk Classification", total=1)
        with contextlib.redirect_stderr(io.StringIO()):
            run_ai_triage(db=db, scan_id=scan_id, raw_dir=dirs.raw_dir, report_dir=dirs.report_dir)
        progress.advance(task_ai)

        db.complete_scan(scan_id)

        task_rep = progress.add_task("Generating report files", total=1)
        report_paths = generate_all_reports(db=db, scan_id=scan_id, output_dir=save_dir)
        progress.advance(task_rep)

    console.print()
    _ok("Scan complete.")
    console.print()

    action = PostScanMenu(
        report_paths=report_paths,
        log_path=dirs.log_file,
        output_dir=save_dir,
    ).run()

    return action


if __name__ == "__main__":
    try:
        while True:
            action = main()
            if action != "continue":
                break
            console.print()
        console.print("  [green][[✔]][/green]  Goodbye.")
    except KeyboardInterrupt:
        console.print()
        console.print("  [yellow][[!]][/yellow]  Interrupted.")
        sys.exit(0)
