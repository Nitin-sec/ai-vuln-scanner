"""
evidence_collector.py — ThreatMap Infra HTTP Evidence Collector

Screenshots completely removed. HTTP probe only.
No database dependency. No EyeWitness. No browser automation.

Probes each host for:
  - HTTP status code
  - Page title
  - Server banner
  - Response time
  - Missing security headers (OWASP checklist)
  - Redirect chain

Results saved as JSON files in output_dir.
"""

import json
import os
import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

logger = logging.getLogger("threatmap.evidence")

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_PROBE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
}


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()


def _extract_title(html: str) -> str:
    p = _TitleParser()
    try:
        p.feed(html[:8192])
    except Exception:
        pass
    return p.title[:200] if p.title else ""


class EvidenceCollector:
    """
    HTTP-only evidence collection. No screenshots, no browser, no EyeWitness.
    Probes each host and saves structured JSON per host to output_dir.
    """

    def probe_hosts(self, hosts: list[str], output_dir: str) -> dict[str, dict]:
        """
        Probe all hosts concurrently.
        Returns {url: evidence_dict}.
        """
        if not hosts:
            return {}

        if not _REQUESTS_OK:
            logger.warning("[Evidence] 'requests' not installed — skipping HTTP probes")
            return {}

        os.makedirs(output_dir, exist_ok=True)
        results: dict[str, dict] = {}
        lock = threading.Lock()

        def _probe(url: str) -> None:
            evidence = self._http_probe(url)
            with lock:
                results[url] = evidence
            self._save_json(url, evidence, output_dir)

        workers = min(8, max(1, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(_probe, h) for h in hosts]
            for future in as_completed(futures, timeout=30):
                try:
                    future.result()
                except Exception as exc:
                    logger.warning("[Evidence] probe worker failed: %s", exc)

        ok = sum(1 for e in results.values() if e.get("status_code"))
        logger.info("[Evidence] HTTP probed %d/%d hosts successfully", ok, len(hosts))
        return results

    @staticmethod
    def _http_probe(url: str) -> dict:
        result = {
            "url": url,
            "status_code": None,
            "title": "",
            "server": "",
            "response_time_ms": None,
            "redirect_chain": [],
            "security_headers": {},
            "missing_security_headers": [],
            "error": None,
        }
        try:
            t0 = time.perf_counter()
            resp = requests.get(
                url, headers=_PROBE_HEADERS,
                timeout=12, verify=False, allow_redirects=True,
            )
            elapsed = int((time.perf_counter() - t0) * 1000)
            result["status_code"]     = resp.status_code
            result["response_time_ms"]= elapsed
            result["server"]          = resp.headers.get("Server", "")
            result["title"]           = _extract_title(resp.text)
            result["redirect_chain"]  = [r.url for r in resp.history]

            for h in SECURITY_HEADERS:
                value = resp.headers.get(h)
                result["security_headers"][h] = value
                if value is None:
                    result["missing_security_headers"].append(h)

        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused / host unreachable"
        except requests.exceptions.Timeout:
            result["error"] = "Request timed out (12s)"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    @staticmethod
    def _save_json(url: str, evidence: dict, output_dir: str) -> str:
        safe = (
            url.replace("https://","").replace("http://","")
               .replace("/","_").replace(":","_")
        )
        path = os.path.join(output_dir, f"evidence_{safe}.json")
        try:
            Path(path).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        except Exception:
            pass
        return path
