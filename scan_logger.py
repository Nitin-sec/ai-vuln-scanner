"""
scan_logger.py — ThreatMap Infra Centralized Logger

Two modes:
  clean   — user-facing, info+ only, no internal noise
  verbose — full debug output for development

Usage:
    from scan_logger import get_logger, configure
    configure(verbose=False, log_file="scans/run.log")
    log = get_logger("scanner")
    log.info("...")
"""

import logging
import os
import sys
from pathlib import Path

# ── Internal state ────────────────────────────────────────────────────────────

_CONFIGURED   = False
_VERBOSE      = False
_LOG_FILE     = None
_ROOT_LOGGER  = "threatmap"

# Libraries that spam stdout/stderr — silenced at startup
_NOISY_LIBS = [
    "huggingface_hub", "huggingface_hub.utils",
    "llama_cpp", "llama_cpp.llama",
    "urllib3", "urllib3.connectionpool",
    "httpx", "httpcore",
    "transformers",
]

_CLEAN_FMT   = "%(message)s"
_VERBOSE_FMT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FMT    = "%H:%M:%S"


def configure(
    verbose:  bool = False,
    log_file: str  = None,
) -> None:
    """
    Configure the logging system. Call once at startup in main.py.

    Args:
        verbose:  True = DEBUG to console + file. False = INFO to file only (clean terminal).
        log_file: Path to write full logs. Created if needed.
    """
    global _CONFIGURED, _VERBOSE, _LOG_FILE
    _VERBOSE  = verbose
    _LOG_FILE = log_file

    # Silence noisy third-party libraries immediately
    for lib in _NOISY_LIBS:
        logging.getLogger(lib).setLevel(logging.CRITICAL)
        logging.getLogger(lib).propagate = False

    root = logging.getLogger(_ROOT_LOGGER)
    root.setLevel(logging.DEBUG)   # capture everything; handlers filter
    root.handlers.clear()
    root.propagate = False

    # File handler — always verbose, captures everything for debugging
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(_VERBOSE_FMT, datefmt=_DATE_FMT))
        root.addHandler(fh)

    # Console handler — verbose mode shows debug, clean mode shows nothing
    # (Rich progress bars handle the user-facing output; logger is file-only in clean mode)
    if verbose:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter(_VERBOSE_FMT, datefmt=_DATE_FMT))
        root.addHandler(ch)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the threatmap root.

    Example:
        log = get_logger("scanner")    → threatmap.scanner
        log = get_logger("triage")     → threatmap.triage
    """
    if not _CONFIGURED:
        # Lazy default config so imports don't break if configure() wasn't called
        configure(verbose=False)
    return logging.getLogger(f"{_ROOT_LOGGER}.{name}")


# ── Scan-level status printer (used by main.py only) ─────────────────────────
# These write directly to stdout so Rich doesn't swallow them.

def print_step_ok(msg: str) -> None:
    """Print a [+] success line. Used for major milestones."""
    print(f"  \033[32m[+]\033[0m  {msg}")

def print_step_warn(msg: str) -> None:
    print(f"  \033[33m[!]\033[0m  {msg}")

def print_step_err(msg: str) -> None:
    print(f"  \033[31m[-]\033[0m  {msg}")

def print_step_info(msg: str) -> None:
    print(f"  \033[34m[*]\033[0m  {msg}")
