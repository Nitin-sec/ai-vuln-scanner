"""
ai_triage.py - ThreatMap Infra analysis triage
Auto-migrates DB columns. Local SLM optional, rule-based always works.
"""
import json, logging, os, re, threading
from pathlib import Path
from typing import TYPE_CHECKING
logger = logging.getLogger("threatmap.triage")
if TYPE_CHECKING:
    from db_manager import DBManager

SLM_MODELS = {
    "qwen-3b": {
        "repo_id":"Qwen/Qwen2.5-3B-Instruct-GGUF",
        "filename":"qwen2.5-3b-instruct-q4_k_m.gguf",
        "desc":"Qwen2.5-3B Q4_K_M ~2GB — best quality",
        "n_ctx":4096,"chat_fmt":"chatml"
    },
    "qwen-1.5b": {"repo_id":"Qwen/Qwen2.5-1.5B-Instruct-GGUF","filename":"qwen2.5-1.5b-instruct-q4_k_m.gguf","desc":"Qwen2.5-1.5B Q4_K_M ~1GB VM-safe","n_ctx":4096,"chat_fmt":"chatml"},
    "phi3-mini": {"repo_id":"microsoft/Phi-3-mini-4k-instruct-gguf","filename":"Phi-3-mini-4k-instruct-q4.gguf","desc":"Phi-3-mini Q4 ~2.2GB higher quality","n_ctx":4096,"chat_fmt":"chatml"},
}
SLM_DIR = Path.home() / ".threatmap" / "models"

PORT_SVC = {"21":"ftp","22":"ssh","23":"telnet","25":"smtp","53":"dns","80":"http","110":"pop3","111":"rpcbind","143":"imap","443":"https","445":"smb","465":"smtps","873":"rsync","993":"imaps","995":"pop3s","1433":"mssql","1521":"oracle","2049":"nfs","3306":"mysql","3389":"rdp","5432":"postgres","5900":"vnc","6379":"redis","8080":"http-alt","8443":"https-alt","9100":"jetdirect","9200":"elastic","11211":"memcached","27017":"mongodb"}
PORT_CVSS = {"21":7.5,"22":5.3,"23":9.1,"25":5.8,"53":6.5,"80":5.0,"110":5.8,"111":7.2,"143":5.8,"443":3.7,"445":9.8,"465":5.8,"873":7.5,"993":5.8,"995":5.8,"1433":8.1,"1521":8.5,"2049":7.5,"3306":7.2,"3389":8.8,"5432":7.2,"5900":8.0,"6379":9.8,"8080":5.0,"9100":7.5,"9200":9.8,"11211":8.0,"27017":9.8}

CVSS_BANDS = [
    ((9.0,10.0),("Critical",1,"Exploit-ready or KEV. Patch within 24h.")),
    ((7.0, 8.9),("High",    2,"Patch within 7 days.")),
    ((4.0, 6.9),("Medium",  3,"Fix within 30 days.")),
    ((0.1, 3.9),("Low",     4,"Quarterly review.")),
    ((0.0, 0.0),("Info",    5,"Informational.")),
]

RULE_OBS = {
    "ssh":("SSH Remote Access Exposed to Internet","Remote Access"),
    "ftp":("Insecure FTP Service Detected","File Transfer"),
    "telnet":("Insecure Telnet Service Exposed","Remote Access"),
    "http":("Cleartext HTTP Web Service Detected","Web Server"),
    "https":("HTTPS TLS Configuration Review Required","Web Server"),
    "rdp":("Windows RDP Accessible from Internet","Remote Desktop"),
    "smb":("Windows SMB File Sharing Exposed","File Sharing"),
    "smtps":("SMTP Mail Service Publicly Accessible","Mail Server"),
    "smtp":("SMTP Mail Service Publicly Accessible","Mail Server"),
    "mysql":("MySQL Database Exposed to Internet","Database"),
    "mssql":("Microsoft SQL Server Accessible","Database"),
    "mongodb":("MongoDB Database Publicly Accessible","Database"),
    "redis":("Redis Cache Exposed to Internet","Cache Layer"),
    "elastic":("Elasticsearch Index Publicly Accessible","Search Engine"),
    "vnc":("VNC Remote Desktop Service Exposed","Remote Desktop"),
    "jetdirect":("Printer Raw Print Service Exposed Port 9100","Network Service"),
    "memcached":("Memcached Cache Service Exposed","Cache Layer"),
    "rpcbind":("RPC Portmapper Service Exposed","Network Service"),
    "pop3":("POP3 Mail Service Exposed","Mail Server"),
    "imap":("IMAP Mail Service Exposed","Mail Server"),
    "nfs":("NFS Network File System Exposed","File Sharing"),
    "oracle":("Oracle Database Listener Exposed","Database"),
    "postgres":("PostgreSQL Database Exposed","Database"),
    "dns":("DNS Service Configuration Review Required","DNS Infrastructure"),
}
DEFAULT_OBS = ("Unnecessary Network Service Exposed","Network Service")

RULE_RISK = {
    "ssh":"Brute-force attacks may grant full shell access to the server.",
    "ftp":"FTP transmits credentials in plaintext making interception trivial.",
    "telnet":"All session data including credentials travels unencrypted.",
    "http":"Session tokens and credentials can be intercepted by any network observer.",
    "https":"Weak TLS configuration may allow protocol downgrade and MITM attacks.",
    "rdp":"Ransomware operators primarily target exposed RDP for initial access.",
    "smb":"Remote code execution via EternalBlue MS17-010 and share data accessible.",
    "smtps":"May allow brute-force of email credentials or spam relay abuse.",
    "smtp":"Open relay potential and brute-force of email credentials possible.",
    "mysql":"Credential compromise exposes all application database records directly.",
    "mssql":"Full DB access and potential OS command execution via xp_cmdshell.",
    "mongodb":"Unauthenticated read/write to all data enabling theft or ransomware.",
    "redis":"Cache poisoning, data exfiltration, or RCE via CONFIG SET.",
    "elastic":"Unauthenticated access to all indexed data; frequent source of mass breaches.",
    "vnc":"Full graphical remote control of the system with weak or no authentication.",
    "jetdirect":"Data interception, unauthorized printing, or lateral movement pivot.",
    "memcached":"Cached data exposure; UDP amplification enables large DDoS attacks.",
}
DEFAULT_RISK = "Unnecessary exposed services increase attack surface and may contain unpatched vulnerabilities."

RULE_REC = {
    "ssh":"Restrict port 22 to trusted IPs. Disable password auth and enforce SSH keys. Deploy fail2ban.",
    "ftp":"Disable FTP entirely. Replace with SFTP or FTPS. Block port 21.",
    "telnet":"Disable Telnet immediately. Replace with SSH for all remote access.",
    "http":"Force HTTPS redirect (301 permanent). Add HSTS: max-age=31536000; includeSubDomains.",
    "https":"Enforce TLS 1.2+. Disable weak ciphers. Add HSTS, X-Frame-Options, Content-Security-Policy.",
    "rdp":"Block port 3389. Expose RDP only via VPN. Enable NLA. Patch Windows immediately.",
    "smb":"Block port 445. Apply MS17-010 patch. Disable SMBv1 via Group Policy or registry.",
    "smtps":"Restrict SMTP to trusted relay IPs. Implement rate limiting and auth failure monitoring.",
    "smtp":"Disable open relay. Enable SPF/DKIM/DMARC. Restrict SMTP to trusted IPs only.",
    "mysql":"Bind to 127.0.0.1. Block port 3306. Application connects via localhost socket only.",
    "mssql":"Block port 1433. Restrict to app server IP. Disable SA account and xp_cmdshell.",
    "mongodb":"Enable MongoDB auth. Bind to 127.0.0.1. Block port 27017 externally.",
    "redis":"Enable requirepass. Bind to 127.0.0.1. Block port 6379. Rename FLUSHALL and CONFIG.",
    "elastic":"Enable X-Pack security. Bind to internal network. Block port 9200 at perimeter.",
    "vnc":"VPN-gate VNC. Require strong password. Restrict port 5900 to known IPs.",
    "jetdirect":"Block port 9100. Restrict printer to internal network VLAN only.",
    "memcached":"Bind to 127.0.0.1. Disable UDP. Block port 11211 externally.",
}
DEFAULT_REC = "Identify service purpose. Disable or restrict access via firewall if not required."

class SLMManager:
    _lock = threading.Lock()
    _instance = None

    def __init__(self, preset="qwen-1.5b"):
        self.cfg = SLM_MODELS.get(preset, SLM_MODELS["qwen-1.5b"])
        self.llm = None
        self.ready = False
        self._load()

    def _load(self):
        try:
            from llama_cpp import Llama
        except ImportError:
            return
        path = self._get_model()
        if not path:
            return
        with self._lock:
            if SLMManager._instance:
                self.llm = SLMManager._instance
                self.ready = True
                return
            n = int(os.getenv("THREATMAP_SLM_THREADS", str(os.cpu_count() or 4)))
            try:
                from llama_cpp import Llama
                self.llm = Llama(model_path=str(path), n_ctx=self.cfg["n_ctx"],
                                 n_threads=n, n_gpu_layers=0, verbose=False,
                                 chat_format=self.cfg["chat_fmt"])
                SLMManager._instance = self.llm
                self.ready = True
            except Exception as e:
                logger.debug("[SLM] Load failed: %s", e)

    def _get_model(self):
        SLM_DIR.mkdir(parents=True, exist_ok=True)
        p = SLM_DIR / self.cfg["filename"]
        if p.exists():
            logger.debug("[SLM] Model found: %s (%.1f GB)", p.name, p.stat().st_size/1e9)
            return p
        try:
            from huggingface_hub import hf_hub_download
        except ImportError:
            return None
        try:
            dl = hf_hub_download(repo_id=self.cfg["repo_id"], filename=self.cfg["filename"],
                                 local_dir=str(SLM_DIR), local_dir_use_symlinks=False)
            pp = Path(dl)
            return pp
        except Exception as e:
            logger.debug("[SLM] Download failed: %s", e)
            return None

    def generate(self, prompt, max_tokens=600):
        if not self.ready or not self.llm:
            return None
        try:
            r = self.llm.create_chat_completion(
                messages=[
                    {"role":"system","content":"You are a senior cybersecurity consultant writing executive-level vulnerability reports for business stakeholders. Respond ONLY with valid JSON. No markdown fences, no explanation, no preamble."},
                    {"role":"user","content":prompt}],
                max_tokens=max_tokens, temperature=0.15, top_p=0.9, repeat_penalty=1.1)
            return r["choices"][0]["message"]["content"]
        except Exception as e:
            logger.debug("[SLM] Inference error: %s", e)
            return None


class TriageEngine:

    def __init__(self, raw_dir: str | None = None, report_dir: str | None = None):
        self.use_slm = False
        self.raw_dir = Path(raw_dir or ".")
        self.report_dir = Path(report_dir or ".")
        self._slm = None
        if os.getenv("THREATMAP_SLM_DISABLE","") != "1":
            self._try_slm()

    def _try_slm(self):
        preset = os.getenv("THREATMAP_SLM_MODEL","qwen-1.5b").lower()
        if preset not in SLM_MODELS:
            preset = "qwen-1.5b"
        try:
            s = SLMManager(preset)
            if s.ready:
                self._slm = s
                self.use_slm = True
        except Exception as e:
            logger.debug("[SLM] Init: %s", e)

    def triage(self, finding, ctx=None):
        base = self._rule(finding)
        if not self.use_slm:
            return base
        try:
            raw = self._call(self._prompt(finding, base, ctx or {}))
            if raw:
                p = self._parse(raw)
                NEED = {"observation_name","detailed_observation","impacted_module","risk_impact","recommendation"}
                if p and NEED.issubset(p):
                    return {**base, **p, "ai_enhanced":True, "triage_method":"local_slm"}
        except Exception as e:
            logger.debug("[Triage] SLM failed: %s", e)
        return base

    def run_for_scan(self, db, scan_id):
        self._ensure_columns(db)
        db.delete_triage_by_scan(scan_id)
        with db._conn() as conn:
            rows = conn.execute(
                "SELECT h.id AS host_id, h.url AS host, h.domain, p.port, p.service "
                "FROM hosts h JOIN open_ports p ON h.id=p.host_id WHERE h.scan_id=?",
                (scan_id,)).fetchall()
        ctxs = self._contexts(scan_id, db)
        count = 0
        for row in rows:
            svc = (row["service"] or PORT_SVC.get(str(row["port"]),"unknown")).lower()
            finding = {"host":row["host"],"domain":row["domain"],
                       "port":str(row["port"]),"service":svc}
            result = self.triage(finding, ctxs.get(row["host"],{}))
            result.update({"host":row["host"],"port":str(row["port"]),
                           "service":svc,"host_id":row["host_id"]})
            db.insert_triage(result)
            count += 1
            logger.info("[%s] %s:%s (%s) -> %s",
                result["severity"],row["host"],row["port"],svc,
                result.get("observation_name","rule"))
        return count

    @staticmethod
    def _ensure_columns(db):
        import sqlite3 as _sq
        NEW = [("observation_name","TEXT"),("detailed_observation","TEXT"),
               ("impacted_module","TEXT"),("risk_impact","TEXT")]
        conn = _sq.connect(db.db_path)
        try:
            existing = {r[1] for r in conn.execute("PRAGMA table_info(triage)")}
            for col,typ in NEW:
                if col not in existing:
                    conn.execute("ALTER TABLE triage ADD COLUMN %s %s" % (col, typ))
                    logger.info("[DB] Added column: triage.%s", col)
            conn.commit()
        finally:
            conn.close()

    def _contexts(self, scan_id, db):
        import glob as _g
        ctxs = {}
        with db._conn() as conn:
            hrows = conn.execute(
                "SELECT h.url, h.domain, "
                "GROUP_CONCAT(p.port||char(47)||COALESCE(p.service,char(63)),char(44)||char(32)) AS ports_summary "
                "FROM hosts h LEFT JOIN open_ports p ON h.id=p.host_id "
                "WHERE h.scan_id=? GROUP BY h.id",
                (scan_id,)).fetchall()
        for row in hrows:
            host,domain = row["url"],row["domain"]
            ctx = {"ports_summary": row["ports_summary"] or ""}
            try:
                waf = (self.raw_dir / ("wafw00f_%s.txt" % domain)).read_text()
                ctx["waf"] = any(k in waf.lower() for k in ["is behind","detected"])
            except FileNotFoundError:
                ctx["waf"] = None
            try:
                data = json.loads((self.raw_dir / ("whatweb_%s.json" % domain)).read_text())
                ctx["tech"] = list(set(p for e in data if "plugins" in e for p in e["plugins"]))[:12]
            except Exception:
                ctx["tech"] = []
            try:
                ctx["nuclei"] = [l.strip() for l in
                    (self.raw_dir / ("nuclei_%s.txt" % domain)).read_text().splitlines()
                    if l.strip()][:15]
            except FileNotFoundError:
                ctx["nuclei"] = []
            evs = _g.glob(str(self.report_dir / ("evidence_%s*.json" % domain)))
            if evs:
                try:
                    d = json.loads(Path(evs[0]).read_text())
                    ctx["title"] = d.get("title","")
                    ctx["server"] = d.get("server","")
                    ctx["missing"] = d.get("missing_security_headers",[])
                except Exception:
                    pass
            ctxs[host] = ctx
        return ctxs

    def _rule(self, finding):
        port = str(finding.get("port",""))
        svc  = self._normalize_service(port, finding.get("service","").lower())
        cvss = float(finding.get("cvss_score") or PORT_CVSS.get(port, 0.0))
        sev,pri,sla = self._band(cvss)
        obs,mod = RULE_OBS.get(svc, DEFAULT_OBS)
        ver = finding.get("version","")
        if ver:
            detail = f"Host {finding.get('host','unknown')}:{port} is reachable and running {svc.upper()} ({ver})."
        else:
            detail = f"Host {finding.get('host','unknown')}:{port} is reachable and running {svc.upper()}."
        recommendation = RULE_REC.get(svc, DEFAULT_REC)
        recommendation = self._unique_recommendation(recommendation, finding.get("host",""), port)
        risk = RULE_RISK.get(svc, DEFAULT_RISK)
        return {
            "severity":sev,"priority_rank":pri,"cvss_score":cvss,"actively_exploited":False,
            "observation_name":obs,"detailed_observation":detail,"impacted_module":mod,
            "risk_impact":risk,
            "recommendation":recommendation,
            "risk_summary":detail,"business_impact":risk,
            "remediation":recommendation,"attack_scenario":None,
            "false_positive_likelihood":"Low","triage_method":"rule_based","ai_enhanced":False,
        }

    def _band(self, cvss):
        for (lo,hi),vals in CVSS_BANDS:
            if lo <= cvss <= hi:
                return vals
        return ("Info",5,"Informational.")

    def _normalize_service(self, port: str, svc: str) -> str:
        if port == "8080":
            return "http-alt"
        if port == "8443":
            return "https-alt"
        if port == "443" and svc == "unknown":
            return "https"
        if port == "80" and svc == "unknown":
            return "http"
        return svc

    def _unique_recommendation(self, recommendation: str, host: str, port: str) -> str:
        if host and port:
            return f"{recommendation} Apply this specifically to {host}:{port}."
        return recommendation

    def _prompt(self, finding, base, ctx):
        tech   = ", ".join(ctx.get("tech",[]))  or "unknown"
        ports  = ctx.get("ports_summary","")
        waf    = ("YES" if ctx.get("waf") else
                  "NO"  if ctx.get("waf") is False else "not checked")
        nuclei = "\n".join(ctx.get("nuclei",[])) or "none"
        server = ctx.get("server","") or "unknown"
        observed = base.get("observation_name", "Unknown finding")
        detail   = base.get("detailed_observation", "No additional detail provided.")
        title  = ctx.get("title","")  or "unknown"
        miss   = ", ".join(ctx.get("missing",[])) or "none"
        return (
            "You are a senior VAPT consultant writing detailed professional reports writing a professional pentest report.\n"
            "Rule engine found: %s (CVSS %.1f)\n\n" % (base["severity"], base["cvss_score"]) +
            "FINDING:\n  Host: %s\n  Port: %s/TCP\n  Protocol: TCP\n  Service: %s\n  Observed issue: %s\n  Detail: %s\n\n" % (finding["host"],finding["port"],finding["service"], observed, detail) +
            "HOST CONTEXT:\n  Other ports: %s\n  Technologies: %s\n" % (ports,tech) +
            "  Server: %s | Title: %s\n  WAF: %s | Missing headers: %s\n\n" % (server,title,waf,miss) +
            "NUCLEI HITS:\n%s\n\n" % nuclei +
            "Write a concise, specific, professional assessment for THIS finding on THIS host.\n"
            "Ensure the explanation is unique for each finding and avoid repeating identical remediation.\n"
            "Use practical, actionable advice.\n\n"
            "Return ONLY valid JSON - no markdown, no extra text.\n\n"
            "{\n"
            '  "observation_name": "Short professional title",\n'
            '  "detailed_observation": "1-2 sentences: what was found, including port and service.",\n'
            '  "impacted_module": "Remote Access / Web Server / Database / Mail Server / DNS Infrastructure / Application Layer / File Sharing / Network Service / Cache Layer",\n'
            '  "risk_impact": "Specific business risk if exploited.",\n'
            '  "recommendation": "Concrete remediation steps with service details.",\n'
            '  "explanation": "Short unique explanation of the issue.",\n'
            '  "confidence": "High / Medium / Low"\n'
            "}"
        )

    def _call(self, prompt):
        if self.use_slm and self._slm:
            return self._slm.generate(prompt)
        return None

    @staticmethod
    def _parse(raw):
        try:
            clean = re.sub(r"^```json\s*|^```\s*|```$","",raw.strip(),flags=re.MULTILINE).strip()
            m = re.search(r"\{.*\}",clean,re.DOTALL)
            if m: clean = m.group(0)
            payload = json.loads(clean)
            if "recommendation" in payload and "remediation" not in payload:
                payload["remediation"] = payload["recommendation"]
            if "risk" in payload and "risk_impact" not in payload:
                payload["risk_impact"] = payload["risk"]
            return payload
        except (json.JSONDecodeError,ValueError):
            return {}


def run_ai_triage(db, scan_id, raw_dir=None, report_dir=None):
    engine = TriageEngine(raw_dir=raw_dir, report_dir=report_dir)
    count  = engine.run_for_scan(db, scan_id)
    logger.info("[Triage] %d findings processed", count)
    return count
