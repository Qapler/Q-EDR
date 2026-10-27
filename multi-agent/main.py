"""
Q-EDR Graph-Native Rule-Based Threat Detection Engine.
Production CLI and main orchestration entry point.

Usage:
    python main.py scan [--dry-run] [--category CATEGORY]
    python main.py start [--interval SECONDS] [--workers N]
    python main.py rules [--category CATEGORY] [--severity SEVERITY]
    python main.py schema [--apply]
    python main.py seed [--scenario SCENARIO] [--clear]
    python main.py health
    python main.py test
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from typing import List, Optional

from threat_engine.config import EngineConfig
from threat_engine.graph.client import GraphClient, GraphDBError
from threat_engine.graph.schema import apply_schema
from threat_engine.graph.seeder import GraphSeeder
from threat_engine.rules.base import RuleCategory, Severity
from threat_engine.rules.registry import RuleRegistry
from threat_engine.alerts.manager import AlertManager
from threat_engine.engine.detector import ThreatDetector
from threat_engine.engine.pipeline import DetectionPipeline
from threat_engine.observability.logger import configure_logging
from threat_engine.observability.metrics import EngineMetrics
from threat_engine.observability.health import HealthCheck

logger = logging.getLogger("threat_engine")


def banner() -> None:
    print(r"""
========================================================================
   ____        ______ ____  ____     _____ _                      _   
  / __ \      |  ____|  _ \|  _ \   |_   _| |                    | |  
 | |  | |_____| |__  | | | | |_) |    | | | |__  _ __ ___  __ _| |_ 
 | |  | |_____|  __| | | | |  _ <     | | | '_ \| '__/ _ \/ _` | __|
 | |__| |     | |____| |_| | |_) |    | | | | | | | |  __/ (_| | |_ 
  \___\_\     |______|____/|____/     \_/ |_| |_|_|  \___|\__,_|\__|
   Graph-Native Rule-Based Threat Detection Engine (Neo4j Aligned)
========================================================================
    """)


def get_components(config: EngineConfig, mock_mode: bool = False, scenario: Optional[str] = None):
    """Instantiate and wire up core engine components."""
    client = GraphClient(
        uri=config.neo4j.uri,
        username=config.neo4j.username,
        password=config.neo4j.password,
        database=config.neo4j.database,
        max_connection_pool_size=config.neo4j.max_connection_pool_size,
        connection_timeout=config.neo4j.connection_timeout,
        max_retry_time=config.neo4j.max_retry_time,
        mock_mode=mock_mode,
    )
    if scenario:
        client.set_simulation_scenario(scenario)
    registry = RuleRegistry()
    metrics = EngineMetrics()
    alert_mgr = AlertManager(
        dedup_window_seconds=config.alert_dedup_window_seconds,
        output_file=config.alert_output_file,
        graph_client=client,
    )
    detector = ThreatDetector(
        graph_client=client,
        rule_registry=registry,
        alert_manager=alert_mgr,
        metrics=metrics,
        max_workers=config.max_workers,
        rule_timeout=float(config.rule_timeout_seconds),
        dry_run=config.dry_run,
    )
    health = HealthCheck(
        graph_client=client,
        rule_registry=registry,
        alert_manager=alert_mgr,
    )
    return client, registry, alert_mgr, detector, metrics, health


def cmd_scan(args: argparse.Namespace, config: EngineConfig) -> int:
    """Run a single detection scan cycle."""
    banner()
    simulate = getattr(args, "simulate", False)
    scenario = getattr(args, "scenario", None)
    if simulate:
        print(f"[*] Running Threat Detection Scan (SIMULATION MODE, scenario='{scenario or 'all'}')...")
    else:
        print("[*] Running Threat Detection Scan...")
    client, registry, alert_mgr, detector, metrics, health = get_components(config, mock_mode=simulate, scenario=scenario)

    if args.dry_run:
        detector._dry_run = True
        print("[!] DRY RUN mode active (no alerts will be persisted)")

    if args.category:
        try:
            cat = RuleCategory(args.category.lower())
            detector._enabled_categories = [cat]
            print(f"[*] Filtered scan for category: {cat.value}")
        except ValueError:
            print(f"[-] Invalid rule category: {args.category}")
            return 1

    try:
        client.connect()
        print(f"[+] Connected to Neo4j graph at {config.neo4j.uri}")
    except Exception as exc:
        print(f"[!] Warning: Could not connect to Neo4j ({exc}). Using mock/dry execution.")

    try:
        summary = detector.run_scan()
        print("\n" + "=" * 60)
        print("               SCAN SUMMARY RESULTS")
        print("=" * 60)
        print(f" Scan ID          : {summary['scan_id']}")
        print(f" Timestamp        : {summary['timestamp']}")
        print(f" Rules Evaluated  : {summary['total_rules']}")
        print(f" Threats Matched  : {summary['matched_rules']}")
        print(f" Alerts Generated : {summary['alerts_generated']}")
        print(f" Execution Errors : {summary['error_rules']}")
        print(f" Scan Duration    : {summary['elapsed_seconds']}s")
        print("=" * 60)

        if summary["matched_rules"] > 0:
            print("\n[!] DETECTED THREATS:")
            for a in summary.get("alerts", []):
                print(f"  [{a['severity']}] {a['rule_id']}: {a['rule_name']}")
                print(f"      MITRE  : {a.get('mitre_tactic')} - {a.get('mitre_technique')} ({a.get('mitre_technique_name')})")
                print(f"      Matches: {a.get('match_count')} events")
                print(f"      Desc   : {a.get('description')}")
                print()
        else:
            print("\n[+] No threats detected. All systems clear.")

        return 0
    finally:
        client.close()


def cmd_start(args: argparse.Namespace, config: EngineConfig) -> int:
    """Start continuous daemon detection pipeline."""
    banner()
    interval = args.interval or config.scan_interval_seconds
    simulate = getattr(args, "simulate", False)
    print(f"[*] Starting Q-EDR Detection Pipeline daemon (interval={interval}s, simulate={simulate})...")
    client, registry, alert_mgr, detector, metrics, health = get_components(config, mock_mode=simulate)

    try:
        client.connect()
        print(f"[+] Connected to Neo4j at {config.neo4j.uri}")
    except Exception as exc:
        print(f"[!] Neo4j connection pending ({exc}). Pipeline will retry automatically.")

    # Start health/metrics HTTP endpoint
    health_port = args.health_port or config.health_port
    try:
        health.start_http_server(health_port)
        print(f"[+] Health & Metrics endpoint running at http://0.0.0.0:{health_port}/health")
    except Exception as exc:
        print(f"[!] Could not bind health HTTP server to port {health_port}: {exc}")

    pipeline = DetectionPipeline(detector=detector, interval_seconds=interval)
    pipeline.start()
    print("[+] Detection loop running in background thread. Press Ctrl+C to terminate.\n")

    stop_requested = False

    def handle_signal(sig, frame):
        nonlocal stop_requested
        print("\n[!] Shutdown signal received. Stopping pipeline cleanly...")
        stop_requested = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not stop_requested:
            time.sleep(1)
            last = pipeline.get_last_scan_result()
            if last:
                logger.debug(f"Last scan: matched={last.get('matched_rules')}, alerts={last.get('alerts_generated')}")
    finally:
        pipeline.stop()
        health.stop_http_server()
        client.close()
        print("[+] Q-EDR Detection Engine stopped cleanly.")

    return 0


def cmd_rules(args: argparse.Namespace, config: EngineConfig) -> int:
    """List and inspect loaded rules."""
    banner()
    registry = RuleRegistry()
    rules = registry.get_all()

    if args.category:
        try:
            cat = RuleCategory(args.category.lower())
            rules = [r for r in rules if r.category == cat]
        except ValueError:
            print(f"[-] Invalid category: {args.category}")
            return 1

    if args.severity:
        try:
            sev = Severity(args.severity.upper())
            rules = [r for r in rules if r.severity == sev]
        except ValueError:
            print(f"[-] Invalid severity: {args.severity}")
            return 1

    print(f"[*] Total Rules Loaded: {len(rules)} (out of {len(registry)} available)")
    print("-" * 90)
    print(f"{'ID':<12} | {'SEVERITY':<8} | {'CATEGORY':<22} | {'NAME':<42}")
    print("-" * 90)
    for r in sorted(rules, key=lambda x: (x.category.value, x.rule_id)):
        sev = r.severity.value
        cat = r.category.value
        print(f"{r.rule_id:<12} | {sev:<8} | {cat:<22} | {r.rule_name[:40]:<42}")
    print("-" * 90)

    summary = registry.summary()
    print("\nSummary by Category:")
    for cat, count in sorted(summary["by_category"].items()):
        print(f"  {cat:<25}: {count} rules")
    print("\nSummary by Severity:")
    for sev, count in sorted(summary["by_severity"].items()):
        print(f"  {sev:<10}: {count} rules")
    return 0


def cmd_schema(args: argparse.Namespace, config: EngineConfig) -> int:
    """Apply Neo4j graph schema constraints and indexes."""
    banner()
    print("[*] Applying Graph Schema DDL (Constraints & Indexes)...")
    client = GraphClient(
        uri=config.neo4j.uri,
        username=config.neo4j.username,
        password=config.neo4j.password,
        database=config.neo4j.database,
    )
    try:
        client.connect()
        result = apply_schema(client)
        print(f"[+] Constraints Applied : {result['constraints_applied']}")
        print(f"[+] Indexes Applied     : {result['indexes_applied']}")
        if result["errors"]:
            print(f"[!] Warnings / Errors   : {len(result['errors'])}")
            for err in result["errors"]:
                print(f"    - {err}")
        else:
            print("[+] All schema objects applied cleanly.")
        return 0
    except Exception as exc:
        print(f"[-] Failed to apply schema to Neo4j: {exc}")
        return 1
    finally:
        client.close()


def cmd_seed(args: argparse.Namespace, config: EngineConfig) -> int:
    """Seed synthetic attack graph data for detection rule validation."""
    banner()
    print("[*] Seeding Threat Graph Scenarios into Neo4j...")
    client = GraphClient(
        uri=config.neo4j.uri,
        username=config.neo4j.username,
        password=config.neo4j.password,
        database=config.neo4j.database,
    )
    try:
        client.connect()
        seeder = GraphSeeder(client)
        if args.clear:
            res = seeder.clear_all()
            print(f"[!] Cleared existing graph: {res}")

        summary = seeder.seed_all()
        print("\n[+] Graph Seeding Complete:")
        for scenario, res in summary.items():
            print(f"  - {scenario:<24}: {res}")
        return 0
    except Exception as exc:
        print(f"[-] Seeding error: {exc}")
        return 1
    finally:
        client.close()


def cmd_health(args: argparse.Namespace, config: EngineConfig) -> int:
    """Run health check and print status."""
    banner()
    simulate = getattr(args, "simulate", False)
    client, registry, alert_mgr, detector, metrics, health = get_components(config, mock_mode=simulate)
    if simulate:
        client.connect()
    report = health.check_all()
    print(json.dumps(report, indent=2))
    return 0 if health.is_healthy() else 1


def cmd_test(args: argparse.Namespace, config: EngineConfig) -> int:
    """Run built-in automated test suite."""
    banner()
    print("[*] Running Q-EDR Test Suite...")
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover("threat_engine/tests")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def cmd_verify(args: argparse.Namespace, config: EngineConfig) -> int:
    """Run end-to-end attack scenario verification suite."""
    banner()
    from threat_engine.tests.verify_scenarios import run_scenario_verification
    success = run_scenario_verification()
    return 0 if success else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Q-EDR Graph-Native Rule-Based Threat Detection Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run a single threat detection cycle")
    p_scan.add_argument("--dry-run", action="store_true", help="Evaluate rules without storing alerts")
    p_scan.add_argument("--simulate", action="store_true", help="Run against simulated attack graph data")
    p_scan.add_argument("--scenario", type=str, help="Attack scenario: all, ransomware, lateral_movement, pth, lsass")
    p_scan.add_argument("--category", type=str, help="Run only rules in this category")

    # start
    p_start = subparsers.add_parser("start", help="Start continuous detection daemon")
    p_start.add_argument("--interval", type=int, help="Scan interval in seconds (default: 60)")
    p_start.add_argument("--simulate", action="store_true", help="Run in simulation mode")
    p_start.add_argument("--health-port", type=int, help="Health & Metrics HTTP port (default: 8001)")

    # rules
    p_rules = subparsers.add_parser("rules", help="List and inspect detection rules")
    p_rules.add_argument("--category", type=str, help="Filter by rule category")
    p_rules.add_argument("--severity", type=str, help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")

    # schema
    subparsers.add_parser("schema", help="Apply Neo4j constraints and indexes")

    # seed
    p_seed = subparsers.add_parser("seed", help="Seed attack scenario graph data into Neo4j")
    p_seed.add_argument("--clear", action="store_true", help="Clear graph before seeding")

    # health
    p_health = subparsers.add_parser("health", help="Check engine, database, and rule health")
    p_health.add_argument("--simulate", action="store_true", help="Simulate healthy Neo4j database")

    # test
    subparsers.add_parser("test", help="Execute the automated test suite")

    # verify
    subparsers.add_parser("verify", help="Execute end-to-end attack scenario verification suite")

    args = parser.parse_args()

    # Configure logging
    config = EngineConfig.from_env()
    configure_logging(level=config.log_level, fmt=config.log_format, log_file=config.log_file)

    if not args.command or args.command == "scan":
        # Default to scan if no command provided
        if not args.command:
            args.dry_run = True
            args.category = None
        return cmd_scan(args, config)
    elif args.command == "start":
        return cmd_start(args, config)
    elif args.command == "rules":
        return cmd_rules(args, config)
    elif args.command == "schema":
        return cmd_schema(args, config)
    elif args.command == "seed":
        return cmd_seed(args, config)
    elif args.command == "health":
        return cmd_health(args, config)
    elif args.command == "test":
        return cmd_test(args, config)
    elif args.command == "verify":
        return cmd_verify(args, config)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
