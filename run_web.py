#!/usr/bin/env python3
"""Start the Security Scanner web app and open it in the browser.

Usage:  python run_web.py            # http://127.0.0.1:8000
        python run_web.py --port 9000 --no-open
"""
from __future__ import annotations

import argparse
import threading
import webbrowser

import uvicorn


def main() -> None:
    p = argparse.ArgumentParser(description="Run the Security Scanner web app.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-open", action="store_true", help="Do not open the browser.")
    args = p.parse_args()

    url = f"http://{args.host if args.host != '0.0.0.0' else '127.0.0.1'}:{args.port}"
    if not args.no_open:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    print(f"\nCyberScore web app running at {url}  (Ctrl+C to stop)\n")
    uvicorn.run("web.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
