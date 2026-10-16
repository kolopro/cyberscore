#!/usr/bin/env python3
"""Security Scanner v0.1 — passive, non-invasive website security scanner.

Usage:
    python main.py example.com
    python main.py example.com --json
    python main.py example.com --json-out result.json
    python main.py example.com --no-parallel

v0.1 performs ONLY passive / non-invasive checks (HTTP headers, TLS handshake,
DNS lookups, public technology fingerprinting). It does not attempt any
exploitation. Only scan systems you own or are authorised to test.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys

from scanner.engine import scan
from reports import console
from reports import pdf as pdf_report


def _open_file(path: str) -> None:
    """Open a file with the operating system's default handler."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as exc:  # opening is a convenience, never fatal
        print(f"note: could not auto-open {path} ({exc})", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberscore",
        description="CyberScore — passive website security scanner (v0.1).",
    )
    p.add_argument("target", help="Domain or URL, e.g. example.com")
    p.add_argument("--json", action="store_true",
                   help="Print JSON to stdout instead of the console report.")
    p.add_argument("--json-out", metavar="PATH",
                   help="Also write the full JSON result to PATH.")
    p.add_argument("--pdf", nargs="?", const="__auto__", metavar="PATH",
                   help="Write a PDF report (with remediation plan). "
                        "Optionally give a path; defaults to "
                        "security-report-<target>.pdf")
    p.add_argument("--open", action="store_true",
                   help="Open the PDF report when done (implies --pdf).")
    p.add_argument("--no-parallel", action="store_true",
                   help="Run modules sequentially (easier to debug).")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = scan(args.target, parallel=not args.no_parallel)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)

    # --open implies producing a PDF to open.
    pdf_arg = args.pdf
    if args.open and pdf_arg is None:
        pdf_arg = "__auto__"

    pdf_path = None
    if pdf_arg is not None:
        pdf_path = (pdf_report.default_filename(result.target)
                    if pdf_arg == "__auto__" else pdf_arg)
        stamp = "Generated " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        pdf_report.render(result, pdf_path, generated_at=stamp)
        print(f"PDF report written to {pdf_path}", file=sys.stderr)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(console.render(result))

    if args.open and pdf_path:
        _open_file(pdf_path)

    # Exit code reflects worst finding, useful for CI / automation.
    counts = result.counts()
    if counts["HIGH"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
