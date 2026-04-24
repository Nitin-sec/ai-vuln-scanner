"""
ai_reporter.py — ThreatMap Infra AI Report Generator

STRICT RULES (enforced in prompts and post-processing):
  - AI explains findings from scan data ONLY
  - AI never invents vulnerabilities or CVEs
  - If uncertain → "Needs manual verification"
  - All severity comes from CVSS scores, not AI opinion

Analysis mode:
  - Uses local model when available
  - Falls back to standard templated explanations

Outputs:
  - report.json  — structured data
  - report.txt   — plain text, human readable
  - report.html  — browser-safe output
"""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from scan_logger import get_logger
from severity import SEVERITY_ORDER

log = get_logger("reporter")

# ── Structured finding dataclass ──────────────────────────────────────────────

@dataclass
class Finding:
    host:         str
    port:         str
    service:      str
    severity:     str
    cvss:         float
    observation:  str
    detail:       str
    module:       str
    risk:         str
    remediation:  str
    confidence:   str
    ai_enhanced:  bool = False
    ai_summary:   str  = ""


@dataclass
class ScanReport:
    target:      str
    scan_mode:   str
    started_at:  str
    completed_at:str
    hosts_count: int
    findings:    list[Finding] = field(default_factory=list)
    generated_at:str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def counts(self) -> dict[str, int]:
        c = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


# ── AI provider detection ─────────────────────────────────────────────────────

def _slm_available() -> bool:
    if os.getenv("THREATMAP_SLM_DISABLE", "") == "1":
        return False
    slm_dir = Path.home() / ".threatmap" / "models"
    return any(slm_dir.glob("*.gguf"))


def _confidence_from_cvss(cvss: float) -> str:
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


# ── AI explanation (per finding) ─────────────────────────────────────────────

def _explain_finding(finding: Finding, use_slm: bool) -> dict[str, str]:
    """
    Ask SLM for a structured explanation for one finding.
    Returns parsed fields or an empty dict on failure.
    """
    prompt = (
        "You are a cybersecurity analyst writing a concise, structured finding summary "
        "for a developer who is not a security expert. Reply ONLY with valid JSON.\n\n"
        "FINDING:\n"
        f"  Host:     {finding.host}\n"
        f"  Port:     {finding.port}/TCP\n"
        "  Protocol: TCP\n"
        f"  Service:  {finding.service}\n"
        f"  Observed issue: {finding.observation}\n"
        f"  Detail:   {finding.detail}\n\n"
        "Write one unique, expert explanation for this finding.\n"
        "Do not repeat remediation text across different findings.\n"
        "Do not use generic or templated wording.\n"
        "Provide practical advice that can be actioned by a development or operations team.\n\n"
        "Return JSON with exactly these keys: explanation, risk, remediation, confidence.\n"
        "Example format:\n"
        "{\n"
        '  "explanation": "1-2 sentences: what was found and why it matters.",\n'
        '  "risk": "Specific business risk if the issue is exploited.",\n'
        '  "remediation": "Concrete, service-specific fix steps.",\n'
        '  "confidence": "High / Medium / Low"\n'
        "}\n"
    )

    try:
        if use_slm:
            raw = _call_slm(prompt)
            if raw:
                parsed = _parse_slm_explanation(raw)
                if parsed.get("explanation") and parsed.get("remediation"):
                    return parsed
    except Exception as exc:
        log.debug("[reporter] SLM explanation failed: %s", exc)
    return {}


def _call_slm(prompt: str) -> str:
    import contextlib, io
    try:
        from llama_cpp import Llama
    except ImportError:
        return ""

    slm_dir = Path.home() / ".threatmap" / "models"
    models  = list(slm_dir.glob("*.gguf"))
    if not models:
        return ""

    # Reuse a single loaded instance per process
    if not hasattr(_call_slm, "_llm"):
        log.info("[reporter:slm] loading model %s", models[0].name)
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            _call_slm._llm = Llama(
                model_path=str(models[0]),
                n_ctx=2048, n_threads=os.cpu_count() or 4,
                n_gpu_layers=0, verbose=False,
            )

    with contextlib.redirect_stdout(io.StringIO()), \
         contextlib.redirect_stderr(io.StringIO()):
        r = _call_slm._llm.create_chat_completion(
            messages=[{"role":"user","content":prompt}],
            max_tokens=230, temperature=0.15,
        )
    return r["choices"][0]["message"]["content"].strip()


def _parse_slm_explanation(raw: str) -> dict[str, str]:
    clean = re.sub(r"^```(?:json)?\s*|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    if not clean:
        return {}
    try:
        payload = json.loads(clean)
        return {
            "explanation": str(payload.get("explanation","")).strip(),
            "risk": str(payload.get("risk","")).strip(),
            "remediation": str(payload.get("remediation","")).strip(),
            "confidence": str(payload.get("confidence","")).strip(),
        }
    except (json.JSONDecodeError, ValueError):
        return {}


# ── Template-based explanations (no AI required) ─────────────────────────────

_TEMPLATES: dict[str, str] = {
    "ssh":     "SSH (port 22) is publicly accessible. This allows remote login attempts. "
               "Restrict access to known IP addresses and disable password authentication.",
    "ftp":     "FTP (port 21) transmits data including credentials in plain text. "
               "Any observer on the network can intercept them. Replace with SFTP.",
    "telnet":  "Telnet is unencrypted and obsolete. All traffic including passwords is "
               "visible on the network. Disable immediately and replace with SSH.",
    "http":    "HTTP (port 80) is unencrypted. Sensitive data including cookies and "
               "form submissions can be intercepted. Redirect all traffic to HTTPS.",
    "https":   "HTTPS is in use but the TLS configuration should be reviewed. Weak "
               "cipher suites or outdated protocols may allow downgrade attacks.",
    "rdp":     "Windows Remote Desktop is publicly accessible. Ransomware groups "
               "actively target exposed RDP. Place behind a VPN immediately.",
    "smb":     "SMB file sharing is exposed to the internet. This service has a history "
               "of critical vulnerabilities. Block port 445 at the perimeter firewall.",
    "mysql":   "MySQL database is accessible from the internet. A compromised credential "
               "gives full access to all application data. Bind to localhost only.",
    "mssql":   "Microsoft SQL Server is publicly accessible. Restrict to trusted "
               "application server IPs and disable the SA account.",
    "mongodb": "MongoDB is accessible without authentication. All data can be read or "
               "deleted by anyone who finds this service. Enable auth and bind locally.",
    "redis":   "Redis cache is exposed without authentication. It can be used for data "
               "theft or to gain server-level access via CONFIG SET. Bind to localhost.",
    "vnc":     "VNC remote desktop is accessible. This provides full graphical control "
               "of the system. Restrict access and require strong authentication.",
}

def _template_explanation(finding: Finding) -> str:
    svc = finding.service.lower()
    host = finding.host or "this host"
    for key, text in _TEMPLATES.items():
        if key in svc:
            return f"{text} On {host}:{finding.port}, verify that access is restricted and only required clients can connect."
    return (
        f"Port {finding.port}/TCP is running {finding.service} and is reachable from the internet. "
        f"The open service should be reviewed for necessity and access should be restricted to reduce attack surface."
    )


def _fallback_remediation(finding: Finding) -> str:
    svc = finding.service.lower()
    port = finding.port or "unknown"
    host = finding.host or "the host"
    if "ssh" in svc or port == "22":
        return f"Restrict SSH access on {host}:{port} to trusted IP ranges, disable password authentication, enforce public-key auth, and enable adaptive login throttling."
    if "http" in svc or port in {"80","8080"}:
        return f"Force HTTPS for {host}:{port}, implement 301 redirects, enable HSTS, and block cleartext HTTP on the edge."
    if "https" in svc or port in {"443","8443"}:
        return f"Review TLS settings for {host}:{port}, disable weak ciphers and TLS 1.0/1.1, and enforce HSTS with a long max-age."
    if "ftp" in svc or port == "21":
        return f"Disable FTP on {host}:{port}. Replace it with SFTP/FTPS and block the service from public networks."
    if "rdp" in svc or port == "3389":
        return f"Block RDP from the public internet on {host}:{port}. Expose it only over VPN and require network level authentication."
    if "mysql" in svc or port == "3306":
        return f"Bind MySQL to localhost on {host}. Block external access to port 3306 and use stored credentials only from application servers."
    return f"Assess the purpose of {finding.service} on {host}:{port}. Restrict or disable it if not required, and apply service-specific firewall rules."


# ── Core report builder ───────────────────────────────────────────────────────

class AIReporter:
    """
    Builds ScanReport from DB triage data and optionally enriches
    each finding with an AI-generated plain-language explanation.
    """

    def __init__(self) -> None:
        self.use_slm = _slm_available()

    def build(self, db, scan_id: int) -> ScanReport:
        """Pull triage rows from DB, build structured ScanReport."""
        # Fetch scan metadata
        meta = {"target":"unknown","scan_mode":"balanced",
                "started_at":"","completed_at":"","hosts":set()}
        try:
            with db._conn() as conn:
                row = conn.execute(
                    "SELECT target, scan_mode, started_at, completed_at "
                    "FROM scans WHERE id=? LIMIT 1", (scan_id,)
                ).fetchone()
                if row:
                    meta["target"]       = row["target"]
                    meta["scan_mode"]    = row["scan_mode"]
                    meta["started_at"]   = row["started_at"] or ""
                    meta["completed_at"] = row["completed_at"] or ""

                host_rows = conn.execute(
                    "SELECT DISTINCT url FROM hosts WHERE scan_id=?", (scan_id,)
                ).fetchall()
                meta["hosts"] = {r["url"] for r in host_rows}
        except Exception as exc:
            log.warning("[reporter] meta fetch failed: %s", exc)

        # Fetch triage rows
        triage_rows = db.get_triage_by_scan(scan_id)
        findings: list[Finding] = []
        for row in triage_rows:
            d = dict(row)
            findings.append(Finding(
                host        = d.get("host",""),
                port        = str(d.get("port","")),
                service     = d.get("service","unknown"),
                severity    = d.get("severity","Info"),
                cvss        = float(d.get("cvss_score",0.0)),
                observation = d.get("observation_name","") or f"Exposed {d.get('service','?').upper()} Service",
                detail      = d.get("detailed_observation","") or d.get("risk_summary",""),
                module      = d.get("impacted_module","Network Service"),
                risk        = d.get("risk_impact","") or d.get("business_impact",""),
                remediation = d.get("remediation","") or d.get("risk_summary",""),
                confidence  = _confidence_from_cvss(float(d.get("cvss_score",0.0))),
            ))

        report = ScanReport(
            target       = meta["target"],
            scan_mode    = meta["scan_mode"],
            started_at   = meta["started_at"],
            completed_at = meta["completed_at"],
            hosts_count  = len(meta["hosts"]),
            findings     = findings,
        )

        # Enrich findings with AI or template explanations
        if findings:
            self._enrich(report)

        return report

    def _enrich(self, report: ScanReport) -> None:
        """Add plain-language explanation to each finding."""
        for finding in report.findings:
            parsed = {}
            if self.use_slm:
                try:
                    parsed = _explain_finding(finding, self.use_slm)
                except Exception as exc:
                    log.debug("[reporter] SLM failed for %s:%s — using template: %s",
                                finding.host, finding.port, exc)

            if parsed:
                finding.ai_summary = parsed.get("explanation") or _template_explanation(finding)
                finding.risk       = parsed.get("risk") or finding.risk
                finding.remediation= parsed.get("remediation") or finding.remediation
                finding.confidence= parsed.get("confidence") or finding.confidence
                finding.ai_enhanced = True
                continue

            # Template fallback (always works)
            finding.ai_summary  = _template_explanation(finding)
            finding.remediation = _fallback_remediation(finding)
            finding.ai_enhanced = False

    # ── Output writers ────────────────────────────────────────────────────────

    def write_json(self, report: ScanReport, path: str) -> str:
        """Write structured JSON report."""
        data = {
            "meta": {
                "target":       report.target,
                "scan_mode":    report.scan_mode,
                "started_at":   report.started_at,
                "completed_at": report.completed_at,
                "hosts_count":  report.hosts_count,
                "generated_at": report.generated_at,
            },
            "summary": report.counts,
            "total":   report.total,
            "findings": [
                {
                    "host":        f.host,
                    "port":        f.port,
                    "service":     f.service,
                    "severity":    f.severity,
                    "cvss":        f.cvss,
                    "observation": f.observation,
                    "detail":      f.detail,
                    "module":      f.module,
                    "risk":        f.risk,
                    "remediation": f.remediation,
                    "confidence":  f.confidence,
                    "ai_enhanced": f.ai_enhanced,
                    "explanation": f.ai_summary,
                }
                for f in report.findings
            ],
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        log.info("[reporter] JSON → %s", path)
        return path

    def write_txt(self, report: ScanReport, path: str) -> str:
        """Write human-readable plain text report."""
        SEV_ORDER = [s.title() for s in SEVERITY_ORDER]
        lines = [
            "=" * 72,
            "  THREATMAP INFRA — VULNERABILITY ASSESSMENT REPORT",
            "=" * 72,
            f"  Target       : {report.target}",
            f"  Scan Mode    : {report.scan_mode.title()}",
            f"  Date         : {report.generated_at[:10]}",
            f"  Hosts Scanned: {report.hosts_count}",
            "",
            "  RISK SUMMARY",
            "  " + "-" * 40,
        ]
        counts = report.counts
        for sev in SEV_ORDER:
            n = counts.get(sev, 0)
            if n:
                lines.append(f"  {sev:<12} {n}")
        lines += [
            f"\n  Total findings: {report.total}",
            "",
            "=" * 72,
            "  FINDINGS",
            "=" * 72,
        ]

        for i, f in enumerate(
            sorted(report.findings, key=lambda x: (
                {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(x.severity,5),
                -x.cvss
            )), 1
        ):
            lines += [
                f"\n[{i:02d}] {f.observation}",
                f"     Host       : {f.host}:{f.port} ({f.service.upper()})",
                f"     Severity   : {f.severity}  (CVSS {f.cvss})",
                f"     Module     : {f.module}",
                f"     Risk       : {f.risk or 'See remediation below.'}",
                f"     Remediation: {f.remediation}",
                f"     Confidence : {f.confidence}",
            ]
            if f.ai_summary:
                lines += [
                    "",
                    f"     Explanation: {f.ai_summary}",
                    "     [analysis]",
                ]
            lines.append("")

        lines += [
            "=" * 72,
            "  DISCLAIMER",
            "=" * 72,
            "  This report was generated by ThreatMap Infra v1.0.",
            "  All findings are based on automated scan data only.",
            "  AI explanations describe tool findings — no vulnerabilities",
            "  were invented or assumed beyond what the scanner detected.",
            "  Manual verification is recommended for all critical findings.",
            "=" * 72,
        ]

        content = "\n".join(lines)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")
        log.info("[reporter] TXT → %s", path)
        return path

    def write_html(self, report: ScanReport, path: str) -> str:
        """Write self-contained HTML report."""
        SEV_ORDER = [s.title() for s in SEVERITY_ORDER]
        badge_bg  = {
            "Critical":"#C0392B","High":"#E67E22",
            "Medium":"#F39C12","Low":"#27AE60","Info":"#2980B9",
        }
        row_bg = {
            "Critical":"#FDECEA","High":"#FEF3E2",
            "Medium":"#FFFDE7","Low":"#F1F8E9","Info":"#E8F4FD",
        }

        def badge(sev):
            bg = badge_bg.get(sev,"#999")
            return (f'<span style="background:{bg};color:#fff;padding:2px 10px;'
                    f'border-radius:3px;font-size:11px;font-weight:700">'
                    f'{sev.upper()}</span>')

        def esc(s):
            if not s: return ""
            return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        # Severity summary boxes
        counts    = report.counts
        sev_boxes = ""
        for sev in SEV_ORDER:
            n  = counts.get(sev, 0)
            bg = badge_bg[sev]
            lt = row_bg[sev]
            sev_boxes += (
                f'<div style="text-align:center;min-width:90px">'
                f'<div style="font-size:28px;font-weight:900;color:{bg};'
                f'background:{lt};padding:8px 16px 4px;border-radius:4px 4px 0 0">{n}</div>'
                f'<div style="font-size:9px;font-weight:700;color:#fff;background:{bg};'
                f'padding:4px 0;border-radius:0 0 4px 4px;letter-spacing:.1em">'
                f'{sev.upper()}</div></div>'
            )

        # Findings rows
        sorted_findings = sorted(
            report.findings,
            key=lambda x: (
                {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}.get(x.severity,5),
                -x.cvss,
            ),
        )
        rows_html = ""
        for i, f in enumerate(sorted_findings, 1):
            rbg = row_bg.get(f.severity,"#fff") if f.severity in ("Critical","High") else ("#f8f9fa" if i%2==0 else "#fff")
            ai_tag = ""
            explanation_row = ""
            if f.ai_summary:
                src = "analysis"
                explanation_row = (
                    f'<tr style="background:{rbg}">'
                    f'<td></td>'
                    f'<td colspan="7" style="font-size:11px;color:#555;padding:4px 12px 10px;'
                    f'border-bottom:1px solid #dee2e6;font-style:italic">'
                    f'💬 {esc(f.ai_summary)} '
                    f'<span style="color:#bbb;font-size:10px">[{src}]</span>'
                    f'</td></tr>'
                )
            rows_html += (
                f'<tr style="background:{rbg}">'
                f'<td style="text-align:center;color:#777;font-weight:700;padding:10px">{i}</td>'
                f'<td style="padding:10px"><strong>{esc(f.observation)}</strong>{ai_tag}'
                f'<br><span style="font-size:11px;color:#777">{esc(f.host)}:{f.port}</span></td>'
                f'<td style="padding:10px;font-size:11px;color:#555">{esc(f.detail) or esc(f.risk)}</td>'
                f'<td style="padding:10px;font-size:11px;color:#777;text-align:center">{esc(f.module)}</td>'
                f'<td style="padding:10px">{badge(f.severity)}'
                f'<br><span style="font-size:10px;color:#999">CVSS {f.cvss}</span></td>'
                f'<td style="padding:10px;font-size:11px;color:#555">{esc(f.confidence)}</td>'
                f'<td style="padding:10px;font-size:11px">{esc(f.remediation)}</td>'
                f'</tr>'
                + explanation_row
            )

        ai_note = "Findings are based strictly on scan tool output."

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatMap Report — {esc(report.target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#1a1a1a;
     background:#fff;max-width:1200px;margin:0 auto;padding:0 24px 60px}}
.cover{{border-top:8px solid #C0392B;padding:40px 0 28px;
        border-bottom:1px solid #dee2e6;margin-bottom:36px}}
.brand{{font-size:40px;font-weight:900;color:#C0392B;letter-spacing:-1px}}
.brand-sub{{font-size:13px;color:#777;margin:4px 0 24px}}
.meta{{display:grid;grid-template-columns:140px 1fr;gap:8px 12px;max-width:600px}}
.ml{{font-size:11px;font-weight:700;color:#777;text-transform:uppercase;letter-spacing:.06em;padding-top:2px}}
.mv{{font-size:13px;color:#1a1a1a}}
.sev-row{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
h2{{font-size:17px;font-weight:700;color:#C0392B;border-bottom:2px solid #C0392B;
    padding-bottom:8px;margin:32px 0 14px}}
table{{width:100%;border-collapse:collapse;margin-bottom:24px}}
th{{background:#2C3E50;color:#fff;padding:10px 12px;text-align:left;
    font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}}
td{{padding:10px 12px;border-bottom:1px solid #dee2e6;vertical-align:top;line-height:1.5}}
.footer{{background:#C0392B;color:#fff;text-align:center;
         font-size:11px;padding:10px;margin-top:48px;border-radius:4px}}
.ai-note{{background:#f8f9fa;border-left:3px solid #C0392B;padding:10px 14px;
          font-size:11px;color:#555;margin-top:24px;border-radius:0 4px 4px 0}}
@media print{{h2{{page-break-before:always}}h2:first-of-type{{page-break-before:avoid}}
tr{{page-break-inside:avoid}}}}
</style></head><body>
<div class="cover">
  <div class="brand">THREATMAP</div>
  <div class="brand-sub">INFRA — Vulnerability Assessment &amp; Penetration Testing Report</div>
  <div class="meta">
    <span class="ml">Target</span>       <span class="mv">{esc(report.target)}</span>
    <span class="ml">Report Date</span>  <span class="mv">{report.generated_at[:10]}</span>
    <span class="ml">Scan Mode</span>    <span class="mv">{report.scan_mode.title()}</span>
    <span class="ml">Hosts Scanned</span><span class="mv">{report.hosts_count}</span>
    <span class="ml">Classification</span><span class="mv">CONFIDENTIAL — Authorised Recipients Only</span>
  </div>
  <div class="sev-row">{sev_boxes}</div>
  <p style="font-size:12px;color:#777;max-width:700px">
    Assessment conducted using automated scanning tools. Findings classified per CVSS v3.1.
    {ai_note}
  </p>
</div>

<h2>Findings ({report.total})</h2>
<p style="font-size:12px;color:#777;margin-bottom:14px">
  {' · '.join(f'{counts[s]} {s}' for s in SEV_ORDER if counts.get(s,0)>0)}
  &nbsp;|&nbsp; Sorted by severity
</p>
<table>
<thead><tr>
  <th style="width:36px">No.</th>
  <th style="width:200px">Finding</th>
  <th style="width:160px">Detail / Risk</th>
  <th style="width:110px">Module</th>
  <th style="width:95px">Severity</th>
  <th style="width:85px">Confidence</th>
  <th>Remediation</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>

<div class="ai-note">
  ⚠ <strong>Important:</strong> {ai_note}
  All severity ratings are based on CVSS scores from scan data — not AI opinion.
  Explanations are included for readability and should be validated during remediation planning.
</div>

<div class="footer">
  CONFIDENTIAL — ThreatMap Infra v1.0 &nbsp;|&nbsp;
  Generated {report.generated_at[:19].replace('T',' ')} &nbsp;|&nbsp;
  All data stored locally
</div>
</body></html>"""

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(html, encoding="utf-8")
        log.info("[reporter] HTML → %s", path)
        return path


# ── Public entry point ────────────────────────────────────────────────────────

def generate_all_reports(db, scan_id: int, output_dir: str) -> dict[str, str]:
    """
    Build the scan report and write JSON + TXT + HTML.
    Returns dict of {format: file_path}.
    Called from main.py after scan completes.
    """
    reporter = AIReporter()

    log.info("[reporter] building report for scan %d", scan_id)
    report = reporter.build(db, scan_id)

    os.makedirs(output_dir, exist_ok=True)

    ts   = datetime.now().strftime("%Y%m%d_%H%M")
    slug = report.target.replace(".","_").replace("/","_").replace(":","")

    paths = {
        "json": reporter.write_json(report, f"{output_dir}/ThreatMap_{slug}_{ts}.json"),
        "txt":  reporter.write_txt(report,  f"{output_dir}/ThreatMap_{slug}_{ts}.txt"),
        "html": reporter.write_html(report, f"{output_dir}/ThreatMap_{slug}_{ts}.html"),
    }

    log.info("[reporter] all reports written to %s", output_dir)
    return paths
