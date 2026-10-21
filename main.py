"""SentryScan Capstone Executable Entry Point.

Run a complete multi-agent security simulation with:
    python main.py --demo
Or launch the live web dashboard gateway with:
    python main.py --serve --port 8000
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure src is in Python path for direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sentryscan.capstone import run_capstone
from sentryscan.dashboard_gateway.server import create_app
from sentryscan.storage.store import SQLiteRunStore


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentryscan",
        description="SentryScan: Autonomous Security Telemetry Analysis & Capstone Orchestration",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Execute the full multi-agent capstone demonstration with Rich CLI & Gateway",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Launch only the loopback FastAPI & WebSocket dashboard gateway",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="HTTP/WebSocket port for the dashboard gateway (default: 8000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic pseudo-random seed (default: 42)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress interactive Rich CLI terminal animations",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/runs/capstone_demo",
        help="Output directory for database and JSONL traces",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="",
        help="Path to existing SQLite run store for --serve mode",
    )

    args = parser.parse_args()

    if args.serve:
        import uvicorn
        db_path = args.db or ":memory:"
        store = SQLiteRunStore(db_path)
        app = create_app(store=store)
        print(f"[*] Starting SentryScan Dashboard Gateway on http://127.0.0.1:{args.port}")
        uvicorn.run(app, host="127.0.0.1", port=args.port)
        return

    # Default to running capstone demo
    print(f"[*] Launching SentryScan Capstone Simulation (seed={args.seed})...")
    res = run_capstone(
        seed=args.seed,
        port=args.port,
        output_dir=args.output_dir,
        launch_gateway=not args.quiet,
        quiet=args.quiet,
    )

    if res.get("gateway_url"):
        print(f"\n[+] Live Dashboard Available at: {res['gateway_url']}")
    print(
        f"[+] Run completed successfully. Status: {res.get('phase')}, "
        f"Parity: {res.get('parity_passed')}"
    )


if __name__ == "__main__":
    main()
