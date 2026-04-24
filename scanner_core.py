"""
scanner_core.py — ThreatMap Infra Scanner

Uses:
  scan_runner.py  — safe subprocess execution with timeout + kill
  env_check.py    — tool path cache + validation
  scan_logger.py  — centralized logging

Key fixes:
  - nmap args are now separate list items (was single string — caused silent no-findings)
  - every tool call goes through run_tool(), never subprocess.run() directly
  - pipeline never crashes; failed tools are logged and skipped
"""

import json
import random
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from env_check  import ToolRegistry, ScanDirs
from scan_runner import run_tool, ToolResult, ToolStatus, ExecutionPipeline
from scan_logger import get_logger

log = get_logger("scanner")

# Shared registry — populated once per process, reused across all scans
_registry = ToolRegistry()

MODE_BALANCED   = "balanced"
MODE_AGGRESSIVE = "aggressive"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _ua() -> str:
    return random.choice(USER_AGENTS)

def _delay(mode: str) -> None:
    time.sleep(random.uniform(0.5, 1.5) if mode == MODE_BALANCED
               else random.uniform(0.1, 0.5))

def _tool(name: str) -> Optional[str]:
    return _registry.get(name)


def _failure_message(tool: str, status: ToolStatus, error: str) -> str:
    reason = "execution error"
    if status == ToolStatus.TIMEOUT:
        reason = "timed out"
    elif status == ToolStatus.SKIPPED:
        reason = "not available in environment"
    elif error:
        reason = error

    impact = "this scan area may have reduced coverage"
    if tool in {"nmap"}:
        impact = "port and service visibility may be incomplete"
    elif tool in {"nuclei", "nikto", "gobuster", "whatweb", "wafw00f"}:
        impact = "web vulnerability visibility may be partial"
    elif tool in {"whois", "dig", "subfinder", "assetfinder", "httpx"}:
        impact = "discovery scope may be reduced"
    return f"{tool} failed ({reason}); {impact}"


# ── Target ────────────────────────────────────────────────────────────────────

class Target:
    def __init__(self, raw: str) -> None:
        self.raw    = raw.strip()
        clean       = self.raw.replace("https://","").replace("http://","")
        self.domain = clean.split("/")[0].split("?")[0]
        self.url    = f"https://{self.domain}"

    def __repr__(self) -> str:
        return f"Target({self.domain})"


# ── Environment check ─────────────────────────────────────────────────────────

def validate_environment() -> tuple[bool, list]:
    """
    Run before any scan. Returns (all_required_ok, missing_tools).
    Caller (main.py) decides whether to abort or warn.
    """
    return _registry.validate()


# ── Individual tool wrappers ──────────────────────────────────────────────────
# Each returns ToolResult. Never raises.

def run_subfinder(target: Target, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("subfinder")
    if not bin_path:
        return ToolResult(tool="subfinder", status=ToolStatus.SKIPPED,
                          error="not installed")
    out = dirs.raw_file("subdomains.txt")
    result = run_tool("subfinder",
                    [bin_path, "-d", target.domain, "-silent", "-o", out],
                    timeout=120)

    # Save raw output to evidence
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "subdomains.txt").write_text(content)

    return result


def run_assetfinder(target: Target, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("assetfinder")
    if not bin_path:
        return ToolResult(tool="assetfinder", status=ToolStatus.SKIPPED,
                          error="not installed")
    result = run_tool("assetfinder",
                      [bin_path, "--subs-only", target.domain],
                      timeout=60)
    if result.ok and result.stdout:
        out = dirs.raw_file("subdomains_af.txt")
        Path(out).write_text(result.stdout)

    # Save raw output to evidence
    if result.ok and result.stdout:
        Path(dirs.evidence / "subdomains_af.txt").write_text(result.stdout)

    return result


def run_httpx(subs_file: str, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("httpx")
    if not bin_path or not Path(subs_file).exists():
        return ToolResult(tool="httpx", status=ToolStatus.SKIPPED,
                          error="not installed or no subs file")
    out = dirs.raw_file("live_hosts.txt")
    return run_tool("httpx",
                    [bin_path, "-l", subs_file, "-silent", "-o", out],
                    timeout=120)


def run_whois(target: Target, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("whois")
    if not bin_path:
        return ToolResult(tool="whois", status=ToolStatus.SKIPPED, error="not installed")
    result = run_tool("whois", [bin_path, target.domain],
                    timeout=20,
                    output_file=dirs.raw_file(f"whois_{target.domain}.txt"))

    # Save raw output to evidence
    out = dirs.raw_file(f"whois_{target.domain}.txt")
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "whois.txt").write_text(content)

    return result


def run_dig(target: Target, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("dig")
    if not bin_path:
        return ToolResult(tool="dig", status=ToolStatus.SKIPPED, error="not installed")

    out_path = dirs.raw_file(f"dig_{target.domain}.txt")
    combined = []
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        r = run_tool(f"dig:{rtype}",
                     [bin_path, target.domain, rtype, "+short"],
                     timeout=10)
        combined.append(f"\n=== {rtype} ===\n{r.stdout or '(none)'}")
    Path(out_path).write_text("\n".join(combined))
    result = ToolResult(tool="dig", status=ToolStatus.SUCCESS,
                      stdout="\n".join(combined))

    # Save raw output to evidence
    if result.ok and result.stdout:
        Path(dirs.evidence / "dig.txt").write_text(result.stdout)

    return result


def run_nmap(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    """
    FIXED: every flag is a separate list element.
    Was: ["-T4 --top-ports 100"]  ← nmap ignored the whole thing
    Now: ["-T4", "--top-ports", "1000"]  ← correct
    """
    _delay(mode)
    out = dirs.raw_file(f"nmap_{target.domain}.xml")

    if mode == MODE_AGGRESSIVE:
        cmd = [
            "nmap", "-sV", "-sC", "-A", "-Pn", "-p-",
            "--min-rate", "2000", "--max-retries", "1",
            "-T4", "-oX", out, target.domain,
        ]
        fallback_cmd = [
            "nmap", "-sV", "-sC", "-Pn",
            "--top-ports", "5000",
            "-T4", "-oX", out, target.domain,
        ]
        timeout = 900
    else:
        cmd = [
            "nmap", "-sV", "-sC", "-Pn",
            "--top-ports", "1000",
            "-T4", "--max-retries", "1",
            "-oX", out, target.domain,
        ]
        fallback_cmd = [
            "nmap", "-Pn",
            "--top-ports", "200",
            "-T3", "-oX", out, target.domain,
        ]
        timeout = 300

    result = run_tool("nmap", cmd, timeout=timeout)

    if result.status == ToolStatus.TIMEOUT:
        log.warning("[nmap] primary timed out, running fallback")
        result = run_tool("nmap:fallback", fallback_cmd, timeout=timeout // 2)

    # Save raw output to evidence
    if result.ok and result.stdout:
        Path(dirs.evidence / "nmap.txt").write_text(result.stdout)

    return result


def run_whatweb(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    _delay(mode)
    bin_path = _tool("whatweb")
    if not bin_path:
        return ToolResult(tool="whatweb", status=ToolStatus.SKIPPED, error="not installed")
    out = dirs.raw_file(f"whatweb_{target.domain}.json")
    result = run_tool("whatweb",
                    [bin_path, "-v", "--user-agent", _ua(),
                     f"--log-json={out}", target.url],
                    timeout=60)

    # Save raw output to evidence
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "whatweb.json").write_text(content)

    return result


def run_wafw00f(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    _delay(mode)
    bin_path = _tool("wafw00f")
    if not bin_path:
        return ToolResult(tool="wafw00f", status=ToolStatus.SKIPPED, error="not installed")
    result = run_tool("wafw00f",
                    [bin_path, "-a", target.url],
                    timeout=30,
                    output_file=dirs.raw_file(f"wafw00f_{target.domain}.txt"))

    # Save raw output to evidence
    out = dirs.raw_file(f"wafw00f_{target.domain}.txt")
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "wafw00f.txt").write_text(content)

    return result


def run_nikto(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    _delay(mode)
    bin_path = _tool("nikto")
    if not bin_path:
        return ToolResult(tool="nikto", status=ToolStatus.SKIPPED, error="not installed")
    maxtime = "5m" if mode == MODE_AGGRESSIVE else "3m"
    out = dirs.raw_file(f"nikto_{target.domain}.txt")
    result = run_tool("nikto",
                    ["nikto", "-h", target.url,
                     "-useragent", _ua(),
                     "-output", out,
                     "-maxtime", maxtime,
                     "-nointeractive"],
                    timeout=360)

    # Save raw output to evidence
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "nikto.txt").write_text(content)

    return result


def run_gobuster(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    _delay(mode)
    bin_path = _tool("gobuster")
    if not bin_path:
        return ToolResult(tool="gobuster", status=ToolStatus.SKIPPED, error="not installed")

    wordlists_aggressive = [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/big.txt",
    ]
    wordlists_balanced = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    ]
    wordlists = wordlists_aggressive if mode == MODE_AGGRESSIVE else wordlists_balanced
    wordlist  = next((w for w in wordlists if Path(w).exists()), None)
    if not wordlist:
        log.warning("[gobuster] no wordlist found — skipping (apt install seclists)")
        return ToolResult(tool="gobuster", status=ToolStatus.SKIPPED,
                          error="no wordlist found")

    out      = dirs.raw_file(f"gobuster_{target.domain}.txt")
    threads  = "80" if mode == MODE_AGGRESSIVE else "50"
    result = run_tool("gobuster",
                    ["gobuster", "dir",
                     "-u", target.url,
                     "-w", wordlist,
                     "-a", _ua(),
                     "-o", out,
                     "-b", "404,301,302",
                     "-t", threads,
                     "--timeout", "8s",
                     "-q"],
                    timeout=300)

    # Save raw output to evidence
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "gobuster.txt").write_text(content)

    return result


def run_sslscan(target: Target, dirs: ScanDirs) -> ToolResult:
    bin_path = _tool("sslscan")
    if not bin_path:
        return ToolResult(tool="sslscan", status=ToolStatus.SKIPPED, error="not installed")
    result = run_tool("sslscan",
                    ["sslscan", "--no-colour", target.domain],
                    timeout=60,
                    output_file=dirs.raw_file(f"sslscan_{target.domain}.txt"))

    # Save raw output to evidence
    out = dirs.raw_file(f"sslscan_{target.domain}.txt")
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "sslscan.txt").write_text(content)

    return result


def run_curl_headers(target: Target, dirs: ScanDirs) -> ToolResult:
    result = run_tool("curl",
                    ["curl", "-s", "-I", "-L",
                     "--max-redirs", "5",
                     "-A", _ua(),
                     "--connect-timeout", "8",
                     "--max-time", "15",
                     target.url],
                    timeout=20,
                    output_file=dirs.raw_file(f"curl_headers_{target.domain}.txt"))

    # Save raw output to evidence
    out = dirs.raw_file(f"curl_headers_{target.domain}.txt")
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "curl_headers.txt").write_text(content)

    return result


def run_nuclei(target: Target, dirs: ScanDirs, mode: str = MODE_BALANCED) -> ToolResult:
    bin_path = _tool("nuclei")
    if not bin_path:
        return ToolResult(tool="nuclei", status=ToolStatus.SKIPPED, error="not installed")

    out = dirs.raw_file(f"nuclei_{target.domain}.txt")
    if mode == MODE_AGGRESSIVE:
        cmd = [
            bin_path, "-u", target.url, "-o", out, "-silent",
            "-timeout", "10", "-rate-limit", "150",
            "-bulk-size", "30", "-c", "30",
        ]
        timeout = 900
    else:
        cmd = [
            bin_path, "-u", target.url, "-o", out, "-silent",
            "-severity", "critical,high,medium",
            "-tags", "cve,exposure,misconfig,default-login,takeover",
            "-timeout", "8", "-rate-limit", "80",
            "-bulk-size", "20", "-c", "20",
        ]
        timeout = 300

    result = run_tool("nuclei", cmd, timeout=timeout)

    # Save raw output to evidence
    if result.ok and Path(out).exists():
        content = Path(out).read_text()
        Path(dirs.evidence / "nuclei.txt").write_text(content)

    return result


# ── Nmap XML parser ───────────────────────────────────────────────────────────

def parse_nmap_xml(xml_path: str) -> list[dict]:
    """
    Parse nmap XML output. Returns list of open port dicts.
    Returns [] gracefully if file missing or malformed.
    """
    try:
        tree = ET.parse(xml_path)
    except Exception as exc:
        log.warning("[nmap:parse] %s — %s", xml_path, exc)
        return []

    results = []
    for port in tree.getroot().findall(".//port"):
        state_el = port.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc = port.find("service")
        ver_parts = []
        if svc is not None:
            for attr in ["product", "version", "extrainfo"]:
                v = svc.get(attr, "")
                if v:
                    ver_parts.append(v)
        results.append({
            "port":     port.get("portid"),
            "protocol": port.get("protocol", "tcp"),
            "state":    "open",
            "service":  svc.get("name", "unknown") if svc is not None else "unknown",
            "version":  " ".join(ver_parts),
            "cpe":      [c.text for c in port.findall(".//cpe") if c.text],
        })
    log.debug("[nmap:parse] %d open ports from %s", len(results), xml_path)
    return results


# ── Parallel orchestrator ─────────────────────────────────────────────────────

class ParallelOrchestrator:
    """
    Coordinates the full scan suite for one or more hosts.

    Uses ExecutionPipeline for per-host step management.
    All tools run through run_tool() — no direct subprocess calls.
    Pipeline continues even if individual tools fail or timeout.
    """

    MAX_WORKERS = {MODE_BALANCED: 4, MODE_AGGRESSIVE: 6}

    def __init__(self, mode: str = MODE_BALANCED) -> None:
        self.mode        = mode
        self.max_workers = self.MAX_WORKERS.get(mode, 4)
        log.info("[orchestrator] mode=%s workers=%d", mode, self.max_workers)

    def run_scan_suite(self, hosts: list[str], dirs: ScanDirs) -> dict[str, dict]:
        """Scan all hosts in parallel. Returns {host: result_dict}."""
        log.info("[orchestrator] scanning %d host(s)", len(hosts))
        results: dict[str, dict] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            future_map = {
                ex.submit(self.scan_host, h, dirs): h
                for h in hosts
            }
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    results[host] = future.result()
                except Exception as exc:
                    log.error("[orchestrator] host %s failed: %s", host, exc)
                    results[host] = {"host": host, "error": str(exc),
                                     "nmap": [], "open_ports": []}
        return results

    def scan_host(self, host: str, dirs: ScanDirs) -> dict:
        """
        Public host scan API used by callers outside this class.
        """
        return self._scan_single_host(host, dirs)

    def _scan_single_host(self, host: str, dirs: ScanDirs) -> dict:
        target = Target(host)
        log.info("━━━ scanning: %s [%s] ━━━", host, self.mode)

        result: dict = {
            "host":       host,
            "nmap":       [],
            "open_ports": [],
            "error":      None,
            "tool_status":{},
        }

        # Build pipeline for this host
        pipeline = ExecutionPipeline(name=target.domain)

        # OSINT — fast, no delays, no web contact
        pipeline.add("whois",  lambda: run_whois(target, dirs))
        pipeline.add("dig",    lambda: run_dig(target, dirs))

        # Fingerprint — parallel pair
        pipeline.add("whatweb", lambda: run_whatweb(target, dirs, self.mode))
        pipeline.add("wafw00f", lambda: run_wafw00f(target, dirs, self.mode))

        # Port scan — must run before web tools
        def _nmap():
            r = run_nmap(target, dirs, self.mode)
            nmap_out = dirs.raw_file(f"nmap_{target.domain}.xml")
            ports = parse_nmap_xml(nmap_out) if r.status != ToolStatus.FAILED else []
            result["nmap"]       = ports
            result["open_ports"] = [p["port"] for p in ports]
            return r

        pipeline.add("nmap", _nmap)

        # Web tools — run only if web ports found
        def _web_tools():
            open_ports = set(result.get("open_ports", []))
            has_web = (
                bool(open_ports & {"80","443","8080","8443","8000","8888"})
                or host.startswith("http")
            )
            if not has_web:
                log.info("[%s] no web ports — skipping web tools", target.domain)
                return ToolResult(tool="web_tools", status=ToolStatus.SKIPPED,
                                  error="no web ports detected")

            web_pipeline = ExecutionPipeline(name=f"{target.domain}:web")
            web_pipeline.add("nikto",   lambda: run_nikto(target, dirs, self.mode))
            web_pipeline.add("curl",    lambda: run_curl_headers(target, dirs))
            web_pipeline.add("gobuster",lambda: run_gobuster(target, dirs, self.mode))
            if "443" in open_ports or host.startswith("https"):
                web_pipeline.add("sslscan", lambda: run_sslscan(target, dirs))
            web_pipeline.run()
            return ToolResult(tool="web_tools", status=ToolStatus.SUCCESS)

        pipeline.add("web_tools", _web_tools)

        # Nuclei — after ports are known
        def _nuclei():
            open_ports = set(result.get("open_ports", []))
            has_web    = bool(open_ports) or host.startswith("http")
            if not has_web:
                return ToolResult(tool="nuclei", status=ToolStatus.SKIPPED,
                                  error="no ports")
            return run_nuclei(target, dirs, self.mode)

        pipeline.add("nuclei", _nuclei)

        # Run everything
        tool_results = pipeline.run()
        result["tool_status"] = {k: v.status.value for k, v in tool_results.items()}
        for name, tr in tool_results.items():
            if tr.status in {ToolStatus.FAILED, ToolStatus.TIMEOUT, ToolStatus.SKIPPED}:
                log.warning("[%s] %s", target.domain, _failure_message(name, tr.status, tr.error))

        log.info("━━━ done: %s  ports=%s ━━━",
                 host, result["open_ports"] or "none")
        return result


# ── Subdomain discovery (separate from per-host pipeline) ────────────────────

class ScannerKit:
    """
    Static helpers for subdomain discovery and host filtering.
    Used by main.py before per-host scanning begins.
    """

    @staticmethod
    def discover_subdomains(target: Target, dirs: ScanDirs) -> list[str]:
        """Run subfinder + assetfinder, merge results, return unique list."""
        subs: set[str] = set()

        with ThreadPoolExecutor(max_workers=2) as ex:
            f_sf = ex.submit(run_subfinder, target, dirs)
            f_af = ex.submit(run_assetfinder, target, dirs)
            sf = f_sf.result()
            af = f_af.result()

        if sf.ok:
            subs_file = dirs.raw_file("subdomains.txt")
            if Path(subs_file).exists():
                subs.update(
                    s.strip() for s in Path(subs_file).read_text().splitlines()
                    if s.strip()
                )

        if af.ok and af.stdout:
            subs.update(
                s.strip() for s in af.stdout.splitlines()
                if s.strip() and target.domain in s
            )

        if subs:
            merged = dirs.raw_file("subdomains_all.txt")
            Path(merged).write_text("\n".join(sorted(subs)))

        log.info("[discovery] %d unique subdomains found", len(subs))
        return sorted(subs)

    @staticmethod
    def filter_live_hosts(subs: list[str], dirs: ScanDirs) -> list[str]:
        """Run httpx to filter live HTTP/S hosts from subdomain list."""
        if not subs:
            return []
        subs_file = dirs.raw_file("subdomains_all.txt")
        result = run_httpx(subs_file, dirs)
        if not result.ok:
            return []
        live_file = dirs.raw_file("live_hosts.txt")
        if not Path(live_file).exists():
            return []
        hosts = [h.strip() for h in Path(live_file).read_text().splitlines() if h.strip()]
        log.info("[discovery] %d live hosts after httpx", len(hosts))
        return hosts
