#!/usr/bin/env python3
"""Orchestrate running process_cowrie.py for multiple sensors from a TOML config.

This runs sensors sequentially, passing per-sensor log paths and credentials,
and writes to a shared central SQLite database with sensor tagging.
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

import tomli as tomllib


def load_config(path: Path) -> dict:
    """Load TOML configuration from the given path."""
    with open(path, 'rb') as f:
        return tomllib.load(f)


def build_cmd(processor: Path, db: str, sensor_cfg: dict, overrides: dict) -> list:
    """Build a process_cowrie.py command for a sensor configuration."""
    cmd = [sys.executable, str(processor)]

    # Required basics
    cmd += ["--sensor", sensor_cfg["name"]]
    cmd += ["--logpath", sensor_cfg["logpath"]]
    cmd += ["--db", db]

    # Summarize days: override > sensor > global default 1
    summarizedays = overrides.get("summarizedays") or sensor_cfg.get("summarizedays") or 1
    cmd += ["--summarizedays", str(summarizedays)]

    # Optional keys if present
    for k in ["vtapi", "urlhausapi", "spurapi", "email", "dbxapi", "dbxkey", "dbxsecret", "dbxrefreshtoken"]:
        if sensor_cfg.get(k):
            cmd += [f"--{k}", str(sensor_cfg[k])]

    return cmd


def run_with_retries(cmd: list, max_retries: int = 2, base_sleep: float = 5.0) -> int:
    """Run a command with retry and linear backoff."""
    attempt = 0
    while True:
        attempt += 1
        print(f"[orchestrate] Running: {' '.join(cmd)} (attempt {attempt})")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(result.stderr, file=sys.stderr)
                return 0
            else:
                print(result.stdout)
                print(result.stderr, file=sys.stderr)
        except Exception as e:  # pragma: no cover
            print(f"[orchestrate] Exception: {e}", file=sys.stderr)

        if attempt > max_retries:
            print(f"[orchestrate] Failed after {max_retries} retries", file=sys.stderr)
            return 1
        sleep_for = base_sleep * attempt
        print(f"[orchestrate] Retry in {sleep_for:.1f}s...")
        time.sleep(sleep_for)


def main():
    """CLI entrypoint for orchestrating sensors from TOML config."""
    ap = argparse.ArgumentParser(description="Run Cowrie processors for multiple sensors via TOML")
    ap.add_argument("--config", default="sensors.toml", help="Path to TOML configuration")
    ap.add_argument("--only", nargs="*", help="Subset of sensor names to run")
    ap.add_argument("--processor", default="process_cowrie.py", help="Path to process_cowrie.py")
    ap.add_argument("--db", help="Override central DB path")
    ap.add_argument("--summarizedays", type=int, help="Override summarizedays for all sensors")
    ap.add_argument("--max-retries", type=int, default=2, help="Max retries per sensor (default: 2)")
    ap.add_argument("--pause-seconds", type=float, default=10.0, help="Pause between sensors (default: 10s)")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    global_cfg = cfg.get("global", {})
    sensors = cfg.get("sensor", [])
    if not sensors:
        print("[orchestrate] No sensors defined in config", file=sys.stderr)
        sys.exit(1)

    # Determine DB
    db = args.db or global_cfg.get("db") or "../cowrieprocessor.sqlite"
    processor = Path(args.processor)

    # Filter sensors if requested
    if args.only:
        names = set(args.only)
        sensors = [s for s in sensors if s.get("name") in names]

    failures = 0
    for i, sensor_cfg in enumerate(sensors):
        if not sensor_cfg.get("name") or not sensor_cfg.get("logpath"):
            print(f"[orchestrate] Skipping incomplete sensor entry: {sensor_cfg}")
            continue
        cmd = build_cmd(processor, db, sensor_cfg, {"summarizedays": args.summarizedays})
        rc = run_with_retries(cmd, max_retries=args.max_retries)
        if rc != 0:
            failures += 1
        if i < len(sensors) - 1:
            time.sleep(args.pause_seconds)

    if failures:
        print(f"[orchestrate] Completed with {failures} failures", file=sys.stderr)
        sys.exit(1)
    else:
        print("[orchestrate] All sensors completed successfully")


if __name__ == "__main__":
    main()
