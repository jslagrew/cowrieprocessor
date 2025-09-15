#!/usr/bin/env python3
"""Simple status dashboard that tails processor status files and renders a summary.

Reads JSON status files written by process_cowrie.py (one per sensor) and prints
a compact dashboard showing progress for each sensor. Intended for long bulk runs.

Usage:
  python status_dashboard.py \
    --status-dir /mnt/dshield/data/logs/status \
    --refresh 2

Options:
  --status-dir   Directory containing <sensor>.json status files
  --refresh      Refresh interval seconds (default: 2)
  --oneshot      Print once and exit
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path


def human_ts(ts: int) -> str:
    """Return a human-readable UTC timestamp string for an epoch value."""
    try:
        return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') + 'Z'
    except Exception:
        return str(ts)


def scan_status(status_dir: Path) -> list[dict]:
    """Read all *.json status files in a directory and return parsed entries."""
    entries = []
    for p in status_dir.glob('*.json'):
        try:
            data = json.loads(p.read_text())
            data['file'] = str(p)
            entries.append(data)
        except Exception:
            continue
    # Sort by sensor name
    entries.sort(key=lambda d: d.get('sensor', ''))
    return entries


def render(entries: list[dict]) -> str:
    """Render a compact table view of status entries for the dashboard."""
    lines = []
    lines.append("sensor           state       progress          current_file")
    lines.append("---------------  ----------  ----------------  --------------------------------")
    for e in entries:
        sensor = str(e.get('sensor', ''))[:15].ljust(15)
        state = str(e.get('state', ''))[:10].ljust(10)
        total = int(e.get('total_files', 0))
        done = int(e.get('processed_files', 0))
        prog = f"{done}/{total}".ljust(16)
        current = str(e.get('current_file', ''))[:32].ljust(32)
        lines.append(f"{sensor}  {state}  {prog}  {current}")
    if entries:
        ts = max(int(e.get('timestamp', 0)) for e in entries)
        lines.append("")
        lines.append(f"Last update: {human_ts(ts)}")
    return "\n".join(lines)


def main():
    """CLI entrypoint for the simple status dashboard."""
    ap = argparse.ArgumentParser(description="Tail processor status files and render dashboard")
    ap.add_argument('--status-dir', default='/mnt/dshield/data/logs/status', help='Directory with <sensor>.json files')
    ap.add_argument('--refresh', type=float, default=2.0, help='Refresh interval seconds (default: 2)')
    ap.add_argument('--oneshot', action='store_true', help='Print once and exit')
    args = ap.parse_args()

    status_dir = Path(args.status_dir)
    if not status_dir.exists():
        print(f"Status dir not found: {status_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        while True:
            entries = scan_status(status_dir)
            sys.stdout.write("\x1b[2J\x1b[H")  # clear screen
            print(render(entries))
            if args.oneshot:
                break
            time.sleep(args.refresh)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
