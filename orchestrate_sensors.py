#!/usr/bin/env python3
"""Orchestrate running process_cowrie.py for multiple sensors from a TOML config.

This runs sensors sequentially, passing per-sensor log paths and credentials,
and writes to a shared central SQLite database with sensor tagging.
"""

import argparse
import json
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

    # Optional output directory (sensor-level override or global)
    report_dir = sensor_cfg.get("report_dir") or overrides.get("report_dir")
    if report_dir:
        cmd += ["--output-dir", str(report_dir)]

    # Bulk-load flags
    if overrides.get("bulk_load"):
        cmd += ["--bulk-load"]
    if overrides.get("buffer_bytes"):
        cmd += ["--buffer-bytes", str(overrides["buffer_bytes"])]

    return cmd


def run_with_retries(cmd: list, max_retries: int = 2, base_sleep: float = 5.0,
                     status_file: Path | None = None, poll_seconds: float = 0.0) -> int:
    """Run a command with retry and optional status polling."""
    attempt = 0
    while True:
        attempt += 1
        print(f"[orchestrate] Running: {' '.join(cmd)} (attempt {attempt})")
        try:
            if status_file and poll_seconds > 0:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    while proc.poll() is None:
                        time.sleep(poll_seconds)
                        try:
                            if status_file.exists():
                                data = json.loads(status_file.read_text())
                                total = data.get('total_files', 0)
                                done = data.get('processed_files', 0)
                                current = data.get('current_file', '')
                                state = data.get('state', '')
                                print(f"[status] {state} {done}/{total} {current}")
                        except Exception:
                            pass
                    out, err = proc.communicate()
                    if out:
                        print(out)
                    if err:
                        print(err, file=sys.stderr)
                    if proc.returncode == 0:
                        return 0
                except KeyboardInterrupt:
                    proc.terminate()
                    raise
            else:
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
    ap.add_argument(
        "--status-poll-seconds",
        type=float,
        default=60.0,
        help="Poll status during runs (sec; 0=off)",
    )
    ap.add_argument("--bulk-load", action='store_true', help="Pass --bulk-load to processor for faster ingest")
    ap.add_argument("--buffer-bytes", type=int, help="Override --buffer-bytes for processor")
    ap.add_argument("--days", type=int, help="Process last N days (overrides summarizedays)")
    ap.add_argument(
        "--date-range",
        nargs=2,
        metavar=("START", "END"),
        help="Date range YYYY-MM-DD YYYY-MM-DD; stage only matching files",
    )
    ap.add_argument("--keep-staging", action='store_true', help="Keep staging directory used for date-range runs")
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
    # Determine log dir for status files
    log_dir = Path(global_cfg.get("log_dir") or "/mnt/dshield/data/logs")

    # Filter sensors if requested
    if args.only:
        names = set(args.only)
        sensors = [s for s in sensors if s.get("name") in names]

    failures = 0
    for i, sensor_cfg in enumerate(sensors):
        if not sensor_cfg.get("name") or not sensor_cfg.get("logpath"):
            print(f"[orchestrate] Skipping incomplete sensor entry: {sensor_cfg}")
            continue
        # Per-sensor overrides fall back to global in config
        overrides = {
            "summarizedays": args.days or args.summarizedays,
            "report_dir": global_cfg.get("report_dir"),
            "bulk_load": args.bulk_load,
            "buffer_bytes": args.buffer_bytes,
        }

        # Optional date-range staging
        staging_dir = None
        if args.date_range:
            start, end = args.date_range
            try:
                logpath = Path(sensor_cfg["logpath"])  # original
                staging_base = Path(global_cfg.get("staging_base", "/mnt/dshield/data/temp/cowrieprocessor/staging"))
                staging_dir = staging_base / sensor_cfg["name"] / f"{start}_{end}"
                staging_dir.mkdir(parents=True, exist_ok=True)
                import re
                pat = re.compile(r".*(\d{4}-\d{2}-\d{2}).*")
                from datetime import datetime as dt
                start_d = dt.strptime(start, "%Y-%m-%d").date()
                end_d = dt.strptime(end, "%Y-%m-%d").date()
                count = 0
                for p in sorted(logpath.iterdir()):
                    m = pat.match(p.name)
                    if not m:
                        continue
                    try:
                        d = dt.strptime(m.group(1), "%Y-%m-%d").date()
                    except Exception:
                        continue
                    if start_d <= d <= end_d:
                        dest = staging_dir / p.name
                        if not dest.exists():
                            try:
                                dest.symlink_to(p)
                            except Exception:
                                import shutil
                                shutil.copy2(p, dest)
                        count += 1
                if count == 0:
                    print(f"[orchestrate] No files matched date range for {sensor_cfg['name']}")
                sensor_cfg = dict(sensor_cfg)
                sensor_cfg["logpath"] = str(staging_dir)
                overrides["summarizedays"] = count or 1
            except Exception as e:
                print(f"[orchestrate] Failed to prepare staging for {sensor_cfg['name']}: {e}", file=sys.stderr)
                staging_dir = None

        cmd = build_cmd(processor, db, sensor_cfg, overrides)
        status_path = log_dir / 'status' / f"{sensor_cfg['name']}.json"
        rc = run_with_retries(cmd, max_retries=args.max_retries, base_sleep=5.0,
                              status_file=status_path, poll_seconds=args.status_poll_seconds)
        if rc != 0:
            failures += 1
        if staging_dir and not args.keep_staging:
            try:
                import shutil
                shutil.rmtree(staging_dir)
            except Exception:
                pass
        if i < len(sensors) - 1:
            time.sleep(args.pause_seconds)

    if failures:
        print(f"[orchestrate] Completed with {failures} failures", file=sys.stderr)
        sys.exit(1)
    else:
        print("[orchestrate] All sensors completed successfully")


if __name__ == "__main__":
    main()
