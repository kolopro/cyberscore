"""The scan engine: orchestrates every module for one target.

This is the single entry point that a CLI, a Python API, a web app or a SaaS
worker would all call. Keep it free of presentation concerns.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict

from scanner.models import ModuleResult, ScanResult
from scanner.utils import normalize_target
from scanner.http import checker as http_checker
from scanner.tls import checker as tls_checker
from scanner.dns import checker as dns_checker
from scanner.email import checker as email_checker
from scanner.technology import detector as tech_detector
from scanner.scoring import scorer

# Ordered registry of passive modules. name -> callable(host) -> ModuleResult
MODULES: Dict[str, Callable[[str], ModuleResult]] = {
    "http": http_checker.run,
    "tls": tls_checker.run,
    "dns": dns_checker.run,
    "email": email_checker.run,
    "technology": tech_detector.run,
}


def scan(target: str, parallel: bool = True) -> ScanResult:
    """Run all passive modules against a target and return a scored result."""
    host = normalize_target(target)
    result = ScanResult(target=host)

    if parallel:
        with ThreadPoolExecutor(max_workers=len(MODULES)) as ex:
            futures = {ex.submit(fn, host): name for name, fn in MODULES.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    result.modules[name] = fut.result()
                except Exception as exc:  # never let one module kill the scan
                    mr = ModuleResult(name=name, error=f"{type(exc).__name__}: {exc}")
                    result.modules[name] = mr
    else:
        for name, fn in MODULES.items():
            try:
                result.modules[name] = fn(host)
            except Exception as exc:
                result.modules[name] = ModuleResult(
                    name=name, error=f"{type(exc).__name__}: {exc}")

    return scorer.score(result)
