#!/usr/bin/env python3
"""Cleanup audit logs older than retention period.

Usage:
    python cleanup.py                  # default 7-day retention
    python cleanup.py --days 30        # 30-day retention
    python cleanup.py --dry-run        # preview only
"""

import argparse
import re
import shutil
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_AUDIT_DIR = str(Path(__file__).resolve().parent.parent / 'openclaw-security-audit')
DATE_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def cleanup(audit_dir, days, dry_run=False):
    audit_path = Path(audit_dir)
    if not audit_path.exists():
        print(f'Audit directory not found: {audit_dir}')
        return

    cutoff = datetime.now() - timedelta(days=days)
    removed = 0

    for entry in sorted(audit_path.iterdir()):
        if not entry.is_dir() or not DATE_PATTERN.match(entry.name):
            continue
        try:
            dir_date = datetime.strptime(entry.name, '%Y-%m-%d')
        except ValueError:
            continue

        if dir_date < cutoff:
            if dry_run:
                print(f'[DRY-RUN] Would remove: {entry}')
            else:
                shutil.rmtree(entry)
                print(f'[REMOVED] {entry}')
            removed += 1

    unit = 'directory' if removed == 1 else 'directories'
    prefix = 'would be ' if dry_run else ''
    print(f'Total: {removed} {unit} {prefix}removed.')


def main():
    parser = argparse.ArgumentParser(description='Cleanup old audit logs')
    parser.add_argument('--days', type=int, default=7,
                        help='Retention period in days (default: 7)')
    parser.add_argument('--audit-dir', default=DEFAULT_AUDIT_DIR,
                        help='Audit directory path')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be removed without deleting')
    args = parser.parse_args()

    cleanup(args.audit_dir, args.days, args.dry_run)


if __name__ == '__main__':
    main()
