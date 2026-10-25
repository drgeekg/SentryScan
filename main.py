"""SentryScan Capstone Executable Entry Point.

Run a complete multi-agent security simulation with:
    python main.py --demo
Or launch the live web dashboard gateway with:
    python main.py --serve --port 8000
Or test high-frequency human workstation traffic (Windows/Linux) with:
    python main.py --test-human
Or run live continuous SOC with human workstations on:
    python main.py --live --devices 4 --pace 0.5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Ensure src is in Python path for direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sentryscan.capstone import run_capstone, run_eval
from sentryscan.dashboard_gateway.server import create_app
from sentryscan.simulation.human_tester import run_human_workstation_test
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

    parser.add_argument(
        "--live",
        action="store_true",
        help="Run a never-ending SOC simulation (continuous fleet telemetry + agents) with the dashboard",
    )
    parser.add_argument(
        "--devices",
        type=int,
        default=None,
        help="Total fleet size (default: 8, or the sum of --fleet when given)",
    )
    parser.add_argument(
        "--fleet",
        type=str,
        default=None,
        help="Per-type counts, e.g. 'windows=2,linux_workstation=2,cisco_router=1,aws=1,m365=1'. "
             "Unlisted types are filled randomly (seeded) up to --devices.",
    )
    parser.add_argument(
        "--industry",
        type=str,
        default="generic",
        help="Industry profile in fixtures/profiles (default: generic)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default="enterprise",
        choices=["enterprise", "human_workstations", "standard"],
        help="Simulation profile: 'human_workstations' (Windows/Linux human user interaction) or 'standard'",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=1.0,
        help="Sleep multiplier for --live (lower = faster, e.g. 0.2)",
    )
    parser.add_argument(
        "--eval",
        action="store_true",
        help="Execute deterministic ground-truth evaluation harness",
    )
    parser.add_argument(
        "--test-human",
        action="store_true",
        help="Execute high-frequency human workstation test across Windows & Linux devices",
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=5,
        help="Number of simulation cycles for --eval / --test-human (default: 5)",
    )

    args = parser.parse_args()

    if args.test_human:
        out_dir = (
            args.output_dir
            if args.output_dir != "data/runs/capstone_demo"
            else "data/runs/human_test"
        )
        print(f"[*] Executing High-Frequency Human Workstation Test ({args.devices or 4} devices, {args.cycles} cycles)...")
        res = run_human_workstation_test(
            seed=args.seed,
            cycles=args.cycles,
            device_count=args.devices or 4,
            output_dir=out_dir,
            fleet_spec=args.fleet,
        )
        print("\n=================================================================")
        print(f"   SENTRYSCAN HUMAN WORKSTATION TEST RESULTS (Seed {res['seed']})")
        print("=================================================================")
        print(f"  * Status               : COMPLETED (Parity: {res['parity_passed']})")
        print(f"  * Devices Simulated    : {res['device_count']} endpoints (Windows & Linux)")
        print(f"  * Total Records        : {res['total_records']}")
        print(f"  * Interactive Bursts   : {res['total_bursts']}")
        print(f"  * Anomalies Blocked    : {res['total_anomalies_rejected']}")
        print(f"  * Clean Records Passed : {res['total_clean_records']}")
        print(f"  * Findings Detected    : {res['total_findings']}")
        print(f"  * Quarantined Hosts    : {res['quarantined_hosts'] or 'None'}")
        print(f"  * Throughput           : {res['records_per_second']:.1f} records/sec")
        print(f"  * Dual-Sink Parity     : SQLite ({res['sqlite_event_count']}) == JSONL ({res['jsonl_event_count']})")
        print("  * Workstation Activity Breakdown:")
        for host, count in res["host_record_counts"].items():
            print(f"      - {host:<20}: {count} records emitted")
        print("  * User Action Types:")
        for action, count in res["burst_actions"].items():
            print(f"      - {action:<22}: {count} bursts")
        print("=================================================================\n")
        return

    if args.eval:
        out_dir = (
            args.output_dir
            if args.output_dir != "data/runs/capstone_demo"
            else "data/runs/eval"
        )
        res = run_eval(seed=args.seed, cycles=args.cycles, output_dir=out_dir)
        m = res["eval_metrics"]
        print(
            f"[*] Eval Complete (seed={res['seed']}, cycles={res['cycles']}, "
            f"parity={res['parity_passed']})"
        )
        print(
            f"    detection_precision   : {m['detection_precision']:.4f} "
            f"(TP={m['true_positives']}, FP={m['false_positives']})\n"
            f"    detection_recall      : {m['detection_recall']:.4f} "
            f"(FN={m['false_negatives']})\n"
            f"    false_quarantine_rate : {m['false_quarantine_rate']:.4f} "
            f"(quarantined={m['quarantined_hosts']})\n"
            f"    time_to_contain_cycles: {m['time_to_contain_cycles']:.4f}\n"
            f"    cost_per_cycle        : {m['cost_per_cycle']:.4f}"
        )
        return

    if args.live:
        import threading

        import uvicorn

        from sentryscan.live import run_live

        out = Path(args.output_dir if args.output_dir != "data/runs/capstone_demo" else "data/live")
        out.mkdir(parents=True, exist_ok=True)
        for stale in out.glob("run-live.*"):
            stale.unlink()
        store = SQLiteRunStore(out / "run-live.db")
        stop = threading.Event()
        threading.Thread(
            target=run_live,
            kwargs={
                "store": store,
                "trace_path": out / "run-live.jsonl",
                "stop": stop,
                "device_count": args.devices,
                "pace": args.pace,
                "seed": args.seed,
                "profile": args.profile,
                "fleet_spec": args.fleet,
                "industry": args.industry,
            },
            daemon=True,
        ).start()
        print(
            f"[*] Live SOC on http://127.0.0.1:{args.port} ({args.devices or 'auto'} devices, "
            f"profile='{args.profile}'). Ctrl+C to stop."
        )
        try:
            uvicorn.run(create_app(store=store), host="127.0.0.1", port=args.port, log_level="warning")
        finally:
            stop.set()
        return

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
