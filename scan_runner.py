"""
scan_runner.py — ThreatMap Infra Safe Execution Layer

Every tool invocation goes through run_tool().
Guarantees: never raises, always returns ToolResult, kills hung processes.
"""

import os
import signal
import subprocess
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from scan_logger import get_logger

log = get_logger("runner")
def _friendly_failure(name: str) -> str:
    tool = name.split(":")[0].lower()
    if tool == "gobuster":
        return "Directory scan could not complete (likely timeout or blocked by target)"
    if tool == "nmap":
        return "Port scan could not complete (target may be rate-limiting or unreachable)"
    if tool == "nuclei":
        return "Vulnerability template scan could not complete (target may be blocking requests)"
    if tool in {"whatweb", "nikto", "wafw00f", "sslscan", "curl"}:
        return "Web analysis step could not complete (target may be blocking or unstable)"
    if tool in {"subfinder", "assetfinder", "httpx", "whois", "dig"}:
        return "Discovery step could not complete (network/tool availability issue)"
    return "Scan step could not complete"



class ToolStatus(Enum):
    SUCCESS  = "success"
    FAILED   = "failed"
    TIMEOUT  = "timeout"
    SKIPPED  = "skipped"   # tool not installed


@dataclass
class ToolResult:
    tool:     str
    status:   ToolStatus
    elapsed:  float = 0.0
    stdout:   str   = ""
    stderr:   str   = ""
    exit_code: Optional[int] = None
    error:    str   = ""

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.SUCCESS


def run_tool(
    name:    str,
    cmd:     list[str],
    timeout: int  = 300,
    cwd:     Optional[str] = None,
    env:     Optional[dict] = None,
    output_file: Optional[str] = None,
) -> ToolResult:
    """
    Execute a system command safely.

    Guarantees:
    - Never raises an exception
    - Kills the process tree on timeout
    - Returns ToolResult with full status

    Args:
        name:        Human-readable tool name for logging
        cmd:         Command as a list of strings (never a single shell string)
        timeout:     Seconds before SIGKILL. Default 300.
        cwd:         Working directory. Defaults to current.
        env:         Additional env vars merged with current env
        output_file: If set, stdout is written directly to this file path
    """
    t0 = time.perf_counter()

    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    # Validate command before launching
    if not cmd:
        return ToolResult(tool=name, status=ToolStatus.FAILED,
                          error="Empty command list")

    log.debug("[%s] cmd: %s", name, " ".join(str(c) for c in cmd))

    try:
        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w") as fout:
                proc = subprocess.Popen(
                    cmd,
                    stdout=fout,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=run_env,
                    start_new_session=True,   # own process group for clean kill
                )
        else:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=run_env,
                start_new_session=True,
            )

        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc, name)
            elapsed = time.perf_counter() - t0
            log.warning("[%s] %s", name, _friendly_failure(name))
            return ToolResult(
                tool=name,
                status=ToolStatus.TIMEOUT,
                elapsed=elapsed,
                error=f"Timed out after {timeout}s",
            )

        elapsed = time.perf_counter() - t0
        stdout = "" if output_file else (stdout_bytes or b"").decode("utf-8", errors="replace")
        stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")

        if proc.returncode == 0:
            log.debug("[%s] done in %.1fs", name, elapsed)
            return ToolResult(tool=name, status=ToolStatus.SUCCESS,
                              elapsed=elapsed, stdout=stdout, stderr=stderr,
                              exit_code=proc.returncode)
        else:
            log.warning("[%s] %s", name, _friendly_failure(name))
            return ToolResult(tool=name, status=ToolStatus.FAILED,
                              elapsed=elapsed, stdout=stdout, stderr=stderr,
                              exit_code=proc.returncode,
                              error=f"Exit code {proc.returncode}")

    except FileNotFoundError:
        elapsed = time.perf_counter() - t0
        log.warning("[%s] Required tool is unavailable on this system", name)
        return ToolResult(tool=name, status=ToolStatus.SKIPPED,
                          elapsed=elapsed,
                          error=f"Binary not found: {cmd[0]}")
    except PermissionError as exc:
        elapsed = time.perf_counter() - t0
        log.warning("[%s] Scan step could not run due to system permissions", name)
        return ToolResult(tool=name, status=ToolStatus.FAILED,
                          elapsed=elapsed, error=str(exc))
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        log.error("[%s] unexpected error: %s", name, exc)
        return ToolResult(tool=name, status=ToolStatus.FAILED,
                          elapsed=elapsed, error=str(exc))


def _kill_process_tree(proc: subprocess.Popen, name: str) -> None:
    """Kill the process and all its children cleanly."""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
        log.debug("[%s] process group %d killed", name, pgid)
    except ProcessLookupError:
        pass   # already dead
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    finally:
        try:
            proc.wait(timeout=3)
        except Exception:
            pass


# ── Execution manager ─────────────────────────────────────────────────────────

@dataclass
class PipelineStep:
    name:    str
    fn:      object        # callable → ToolResult or None
    result:  Optional[ToolResult] = field(default=None, repr=False)
    skipped: bool = False


class ExecutionPipeline:
    """
    Runs a list of steps in order, tracking status and allowing interruption.

    Usage:
        pipeline = ExecutionPipeline(name="scan:example.com")
        pipeline.add("nmap",    lambda: run_nmap(target))
        pipeline.add("nikto",   lambda: run_nikto(target))
        results = pipeline.run()
    """

    def __init__(self, name: str, stop_on_failure: bool = False):
        self.name            = name
        self.stop_on_failure = stop_on_failure
        self._steps:  list[PipelineStep] = []
        self._stopped = threading.Event()
        self.summary: dict[str, ToolStatus] = {}

    def add(self, name: str, fn) -> "ExecutionPipeline":
        self._steps.append(PipelineStep(name=name, fn=fn))
        return self

    def stop(self) -> None:
        """Signal the pipeline to stop after the current step."""
        self._stopped.set()

    def run(self) -> dict[str, ToolResult]:
        log.info("[pipeline:%s] starting %d steps", self.name, len(self._steps))
        results: dict[str, ToolResult] = {}

        for step in self._steps:
            if self._stopped.is_set():
                log.info("[pipeline:%s] interrupted before %s", self.name, step.name)
                step.skipped = True
                continue

            log.info("[pipeline:%s] → %s", self.name, step.name)
            try:
                result = step.fn()
                if result is None:
                    result = ToolResult(tool=step.name, status=ToolStatus.SUCCESS)
                step.result = result
                results[step.name] = result
                self.summary[step.name] = result.status

                if result.status == ToolStatus.TIMEOUT:
                    log.warning("[pipeline:%s] %s timed out — continuing", self.name, step.name)
                elif result.status == ToolStatus.FAILED:
                    log.warning("[pipeline:%s] %s failed — continuing", self.name, step.name)
                    if self.stop_on_failure:
                        self._stopped.set()
                else:
                    log.info("[pipeline:%s] %s OK (%.1fs)",
                             self.name, step.name, result.elapsed)

            except KeyboardInterrupt:
                log.warning("[pipeline:%s] keyboard interrupt at %s", self.name, step.name)
                self._stopped.set()
                break
            except Exception as exc:
                log.error("[pipeline:%s] unhandled error in %s: %s", self.name, step.name, exc)
                result = ToolResult(tool=step.name, status=ToolStatus.FAILED, error=str(exc))
                step.result = result
                results[step.name] = result
                self.summary[step.name] = ToolStatus.FAILED

        ok      = sum(1 for s in self.summary.values() if s == ToolStatus.SUCCESS)
        failed  = sum(1 for s in self.summary.values() if s == ToolStatus.FAILED)
        timeout = sum(1 for s in self.summary.values() if s == ToolStatus.TIMEOUT)
        log.info("[pipeline:%s] done — ok:%d failed:%d timeout:%d",
                 self.name, ok, failed, timeout)
        return results
