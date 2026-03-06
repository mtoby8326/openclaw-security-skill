#!/usr/bin/env python3
"""OpenClaw Security Audit Worker — PII detection and local NDJSON logging.

Usage:
    echo "text" | python audit_worker.py --session-id S001 --source-type input
    python audit_worker.py --session-id S001 --source-type input --text "inline text"
    python audit_worker.py --session-id S001 --source-type knowledge_base --file path.txt
    python audit_worker.py --session-id S001 --source-type input --text "text" --json
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure detectors package is importable
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from detectors import ALL_DETECTORS
from detectors.base import Match

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VERSION = "0.1.0"

DEFAULT_AUDIT_DIR = os.environ.get(
    'OPENCLAW_AUDIT_DIR',
    str(SCRIPT_DIR.parent / 'openclaw-security-audit')
)

HIGH_RISK_LABELS = {'NATIONAL_ID', 'PASSPORT', 'BANK_CARD'}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def dedupe_overlapping(matches):
    """Remove lower-confidence matches whose character ranges overlap with
    higher-confidence matches.  Higher confidence wins."""
    sorted_matches = sorted(matches, key=lambda m: -m.confidence)
    result = []
    used_ranges = []
    for m in sorted_matches:
        overlaps = False
        for s, e in used_ranges:
            if m.start < e and m.end > s:
                overlaps = True
                break
        if not overlaps:
            result.append(m)
            used_ranges.append((m.start, m.end))
    return result


def compute_risk(labels):
    """Determine risk level based on detected label set.

    HIGH: any single high-risk label, or the combo PERSON_NAME + contact + ADDRESS.
    LOW:  everything else.
    """
    label_set = set(labels)
    if label_set & HIGH_RISK_LABELS:
        return 'high'
    has_name = 'PERSON_NAME' in label_set
    has_contact = bool(label_set & {'PHONE', 'EMAIL'})
    has_address = 'ADDRESS' in label_set
    if has_name and has_contact and has_address:
        return 'high'
    return 'low'


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
def scan(text, session_id, source_type, audit_dir):
    """Run all detectors, dedupe, compute risk, write NDJSON record.

    Returns a summary dict (never raises on detection failure).
    """
    all_matches = []
    for detector in ALL_DETECTORS:
        try:
            hits = detector.detect(text)
            all_matches.extend(hits)
        except Exception as exc:
            print(f'[WARN] Detector {detector.label} error: {exc}', file=sys.stderr)

    all_matches = dedupe_overlapping(all_matches)

    if not all_matches:
        return {"status": "clean", "matched_count": 0}

    labels = sorted(set(m.label for m in all_matches))
    risk = compute_risk(labels)
    content_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]

    record = {
        "event_id": str(uuid.uuid4()),
        "session_id": session_id,
        "source_type": source_type,
        "labels": labels,
        "risk_level": risk,
        "detector_version": VERSION,
        "matched_count": len(all_matches),
        "matches": [
            {
                "label": m.label,
                "confidence": m.confidence,
                "masked_preview": m.masked_preview,
            }
            for m in all_matches
        ],
        "content_hash": content_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Persist to NDJSON (one line per event, partitioned by date)
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    day_dir = Path(audit_dir) / today
    day_dir.mkdir(parents=True, exist_ok=True)

    out_file = day_dir / 'events.ndjson'
    with open(out_file, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')

    return {
        "status": "detected",
        "risk_level": risk,
        "labels": labels,
        "matched_count": len(all_matches),
        "audit_file": str(out_file),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='OpenClaw PII Audit Worker — detect and log sensitive data'
    )
    parser.add_argument('--session-id', default='unknown',
                        help='Session identifier (default: unknown)')
    parser.add_argument('--source-type',
                        choices=['input', 'prompt', 'context', 'knowledge_base'],
                        default='input',
                        help='Content source type (default: input)')
    parser.add_argument('--file',
                        help='Read content from file instead of stdin')
    parser.add_argument('--text',
                        help='Inline text to scan')
    parser.add_argument('--audit-dir', default=DEFAULT_AUDIT_DIR,
                        help='Audit output directory')
    parser.add_argument('--json', action='store_true',
                        help='Output result as JSON')
    args = parser.parse_args()

    # --- Read input ---
    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    if not text.strip():
        print('No input provided.', file=sys.stderr)
        sys.exit(1)

    # --- Scan ---
    result = scan(text, args.session_id, args.source_type, args.audit_dir)

    # --- Output ---
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if result['status'] == 'clean':
            print('[CLEAN] No PII detected.')
        else:
            print(f'[{result["risk_level"].upper()}] '
                  f'Detected {result["matched_count"]} PII match(es)')
            print(f'  Labels: {", ".join(result["labels"])}')
            print(f'  Audit:  {result["audit_file"]}')


if __name__ == '__main__':
    main()
