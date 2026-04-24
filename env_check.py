"""
env_check.py — ThreatMap Infra Environment Validation

Validates required tools before a scan starts.
Caches tool paths for reuse across the scan.
Creates the per-scan directory structure.

Usage:
    from env_check import ToolRegistry, ScanDirs

    registry = ToolRegistry()
    ok, missing = registry.validate()
    if not ok:
        registry.print_install_guide(missing)

    dirs = ScanDirs.create(base="scans", target="example.com")
    nmap_out = dirs.raw / "nmap.xml"
"""

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from scan_logger import get_logger

log = get_logger("env")


# ── Tool definitions ──────────────────────────────────────────────────────────

@dataclass
class ToolDef:
    name:      str           # binary name
    required:  bool          # if True, warn clearly when missing
    install:   str           # short install command shown to user
    verify:    list[str] = field(default_factory=list)   # args that prove it works
    version_flag: str = "--version"


TOOLS: list[ToolDef] = [
    # Required — scan returns nothing without these
    ToolDef("nmap",      True,  "sudo apt install -y nmap"),
    ToolDef("nikto",     True,  "sudo apt install -y nikto"),
    ToolDef("gobuster",  True,  "sudo apt install -y gobuster"),
    ToolDef("sslscan",   True,  "sudo apt install -y sslscan"),
    ToolDef("whatweb",   True,  "sudo apt install -y whatweb"),
    ToolDef("curl",      True,  "sudo apt install -y curl"),
    ToolDef("whois",     True,  "sudo apt install -y whois"),
    ToolDef("dig",       True,  "sudo apt install -y dnsutils"),

    # Optional — tool skipped gracefully if absent
    ToolDef("subfinder",   False, "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolDef("httpx",       False, "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolDef("assetfinder", False, "go install github.com/tomnomnom/assetfinder@latest"),
    ToolDef("nuclei",      False, "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ToolDef("wafw00f",     False, "pip install wafw00f"),
]


class ToolRegistry:
    """
    Validates installed tools and caches their resolved paths.
    Thread-safe for concurrent scanner use.
    """

    def __init__(self) -> None:
        self._paths:   dict[str, Optional[str]] = {}
        self._checked: bool = False

    def validate(self) -> tuple[bool, list[ToolDef]]:
        """
        Check all defined tools. Returns (all_required_present, missing_list).
        Populates the internal path cache.
        """
        missing: list[ToolDef] = []
        for tool in TOOLS:
            path = self._resolve(tool.name)
            if path:
                log.debug("[env] %-16s found: %s", tool.name, path)
            else:
                log.debug("[env] %-16s NOT found", tool.name)
                if tool.required:
                    missing.append(tool)

        self._checked = True
        all_ok = len(missing) == 0
        if all_ok:
            log.info("[env] all required tools present")
        else:
            names = ", ".join(t.name for t in missing)
            log.warning("[env] missing required tools: %s", names)

        return all_ok, missing

    def get(self, name: str) -> Optional[str]:
        """
        Return cached path for tool, or None if not installed.
        Falls back to shutil.which if not yet cached.
        """
        if name not in self._paths:
            self._paths[name] = self._resolve(name)
        return self._paths[name]

    def available(self, name: str) -> bool:
        return self.get(name) is not None

    def print_install_guide(self, missing: list[ToolDef]) -> None:
        """Print clear install instructions for missing tools."""
        print()
        print("  \033[31m[!]\033[0m  Missing required tools — scan may return no findings")
        print()
        for tool in missing:
            print(f"  \033[33m{tool.name}\033[0m")
            print(f"      Install:  {tool.install}")
        print()
        print("  After installing, re-run:  ./run.sh")
        print()

    def print_status_table(self) -> None:
        """Print a ✔/○ table of all tools."""
        print()
        required_ok = True
        for tool in TOOLS:
            path = self.get(tool.name)
            found = path is not None
            if not found and tool.required:
                required_ok = False
            tag   = "\033[32m✔\033[0m" if found else ("\033[31m✗\033[0m" if tool.required else "\033[33m○\033[0m")
            label = "required" if tool.required else "optional"
            where = path if path else "not installed"
            print(f"  {tag}  {tool.name:<16} [{label}]  {where}")
        print()

    def _resolve(self, name: str) -> Optional[str]:
        # Check env override first (e.g. NMAP_PATH=/custom/nmap)
        env_key = f"{name.upper().replace('-','_')}_PATH"
        override = os.environ.get(env_key)
        if override and Path(override).is_file():
            self._paths[name] = override
            return override

        path = shutil.which(name)
        self._paths[name] = path
        return path


# ── Per-scan directory structure ──────────────────────────────────────────────

@dataclass
class ScanDirs:
    """
    Canonical directory layout for a single scan run.

    scans/
      <target>_<timestamp>/
        logs/       → scan.log
        raw/        → nmap.xml, nikto.txt, whatweb.json, ...
        parsed/     → structured JSON intermediates
        report/     → final HTML / Excel output
        evidence/   → raw tool outputs for audit
    """
    root:   Path
    logs:   Path
    raw:    Path
    parsed: Path
    report: Path
    evidence: Path

    @classmethod
    def create(cls, base: str, target: str, timestamp: str = None) -> "ScanDirs":
        """
        Create the directory tree and return a ScanDirs instance.

        Args:
            base:      Base directory, e.g. "scans"
            target:    Domain or IP, e.g. "example.com"
            timestamp: Override timestamp (for tests). Defaults to now.
        """
        ts    = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        slug  = _safe_slug(target)
        root  = Path(base) / f"{slug}_{ts}"

        dirs = cls(
            root   = root,
            logs   = root / "logs",
            raw    = root / "raw",
            parsed = root / "parsed",
            report = root / "report",
            evidence = root / "evidence",
        )
        for d in [dirs.logs, dirs.raw, dirs.parsed, dirs.report, dirs.evidence]:
            d.mkdir(parents=True, exist_ok=True)

        log.debug("[env] scan dir: %s", root)
        return dirs

    @property
    def log_file(self) -> str:
        return str(self.logs / "scan.log")

    @property
    def log_dir(self) -> str:
        return str(self.logs)

    @property
    def raw_dir(self) -> str:
        return str(self.raw)

    @property
    def report_dir(self) -> str:
        return str(self.report)

    @property
    def evidence_dir(self) -> str:
        return str(self.evidence)

    def raw_file(self, name: str) -> str:
        return str(self.raw / name)

    def report_file(self, name: str) -> str:
        return str(self.report / name)

    def __str__(self) -> str:
        return str(self.root)


def _safe_slug(text: str) -> str:
    return (
        text.lower()
            .replace("https://","").replace("http://","")
            .replace("/","_").replace(":","_").replace(".","_")
    )
