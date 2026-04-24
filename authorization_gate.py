"""
authorization_gate.py — ThreatMap Infra Legal & Ethics Gate

Single-step flow:
  1. Display legal disclaimer panel
  2. One confirm prompt — Yes / No
  3. Cloud provider detection adds a one-line warning + one extra confirm
  4. Audit log written to the active scan report directory
"""

import socket
import os
import datetime
import ipaddress
import logging
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel

logger = logging.getLogger("threatmap.auth")
console = Console()

_CLOUD_DOMAINS = [
    "amazonaws.com", "ec2.internal", "googleusercontent.com",
    "appspot.com", "run.app", "azurewebsites.net", "cloudapp.azure.com",
    "core.windows.net", "heroku.com", "netlify.app", "vercel.app", "fly.dev",
]

DISCLAIMER = """\
[bold yellow]⚠  Legal Disclaimer — Read Before Scanning[/bold yellow]

ThreatMap Infra is for [bold]authorized security testing only[/bold].
Scanning systems without permission is illegal in most jurisdictions
(US CFAA · UK Computer Misuse Act · India IT Act 2000 · EU Directive 2013/40/EU).

[bold cyan]Authorized use:[/bold cyan]
  ✓  Your own infrastructure
  ✓  Client systems under a signed pen-test agreement
  ✓  Bug bounty targets explicitly listed in scope
  ✓  Lab / CTF environments (HackTheBox, TryHackMe, DVWA…)

[dim]Misuse may result in criminal prosecution. The ThreatMap project
is not responsible for unauthorized or illegal use.[/dim]\
"""


class AuthorizationGate:

    def validate(self, target: str, report_dir: str = ".") -> bool:
        console.print()
        console.print(Panel.fit(DISCLAIMER, border_style="yellow", padding=(1, 3)))
        console.print()

        confirmed = questionary.confirm(
            f"I confirm I am authorized to scan '{target}'",
            default=False,
            style=questionary.Style([("answer", "fg:cyan bold")]),
        ).ask()

        if not confirmed:
            return False

        # Cloud provider extra warning (still just one confirm)
        cloud = self._detect_cloud(target)
        if cloud:
            console.print(
                f"\n[bold orange1]⚠  Cloud provider detected:[/bold orange1] "
                f"[white]{cloud}[/white]\n"
                f"[dim]Review that provider's pen-test policy before proceeding.[/dim]\n"
            )
            ok = questionary.confirm(
                "I have reviewed the provider's scanning policy and I am authorized to proceed",
                default=False,
            ).ask()
            if not ok:
                return False

        self._write_audit_log(target, cloud, report_dir)
        console.print(
            f"\n[bold green]✔  Authorization confirmed.[/bold green]  "
            f"[dim]Logged → {report_dir}/authorization_log.txt[/dim]\n"
        )
        return True

    # ------------------------------------------------------------------

    def _detect_cloud(self, target: str) -> str | None:
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        for suffix in _CLOUD_DOMAINS:
            if host.endswith(suffix):
                return self._provider_name(suffix)
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            for cidr in ["3.0.0.0/8", "52.0.0.0/8", "34.64.0.0/10",
                         "20.0.0.0/8", "104.16.0.0/12"]:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return f"cloud provider (resolved {ip})"
        except Exception:
            pass
        return None

    @staticmethod
    def _provider_name(d: str) -> str:
        if "amazonaws" in d or "ec2" in d:   return "Amazon Web Services (AWS)"
        if "google" in d or "appspot" in d:   return "Google Cloud Platform (GCP)"
        if "azure" in d or "windows.net" in d: return "Microsoft Azure"
        if "heroku" in d:  return "Heroku"
        if "vercel" in d:  return "Vercel"
        if "netlify" in d: return "Netlify"
        return "a cloud / CDN provider"

    @staticmethod
    def _write_audit_log(target: str, cloud: str | None, report_dir: str) -> None:
        os.makedirs(report_dir, exist_ok=True)
        entry = (
            f"\n{'='*60}\n"
            f"AUTHORIZED  {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
            f"  Target : {target}\n"
            f"  Cloud  : {cloud or 'No'}\n"
            f"{'='*60}\n"
        )
        log_path = Path(report_dir) / "authorization_log.txt"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(entry)
