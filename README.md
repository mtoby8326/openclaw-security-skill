# OpenClaw Security Skill 🔒

An async PII (Personally Identifiable Information) detection engine that runs as an OpenClaw Skill. It scans session content for sensitive data and logs audit events locally in NDJSON format.

## ✨ Features

- **8 PII Categories** — Phone, Email, National ID, Passport, Bank Card, Person Name, Address, Social Account
- **Zero Dependencies** — Pure Python stdlib, works out of the box
- **Async & Non-blocking** — Audit is decoupled from the main workflow, never blocks user responses
- **Smart False Positive Control** — National ID checksum, Bank Card Luhn validation, context-keyword gating for Passport/Name/Address
- **Overlap Dedup** — When multiple detectors match the same text range, highest confidence wins
- **Risk Scoring** — Two-level (high/low) with single-label and combo rules
- **Local Storage** — NDJSON format, partitioned by date, grep/SIEM-friendly
- **Auto Cleanup** — Configurable retention period (default: 7 days)

## 🚀 Quick Start

```bash
git clone https://github.com/mtoby8326/openclaw-security-skill.git
cd openclaw-security-skill
```

### Scan Text

```bash
# Inline text
python scripts/audit_worker.py --session-id S001 --source-type input \
  --text "Name: Zhang San, Phone: 13812345678, Email: test@gmail.com"

# Scan from file
python scripts/audit_worker.py --session-id S001 --source-type knowledge_base \
  --file path/to/content.txt

# JSON output
python scripts/audit_worker.py --session-id S001 --source-type input \
  --text "ID: 110101199003076536" --json
```

### Sample Output

```
[HIGH] Detected 3 PII match(es)
  Labels: EMAIL, PERSON_NAME, PHONE
  Audit:  openclaw-security-audit/2026-03-06/events.ndjson
```

JSON mode:

```json
{
  "status": "detected",
  "risk_level": "high",
  "labels": ["EMAIL", "PERSON_NAME", "PHONE"],
  "matched_count": 3,
  "audit_file": "openclaw-security-audit/2026-03-06/events.ndjson"
}
```

## 🏷️ Detection Labels

| Label | Description | Confidence | Validation |
|-------|-------------|------------|------------|
| `PHONE` | CN mobile, landline, international | 0.90 | Digit count |
| `EMAIL` | Email address | 0.95 | Format match |
| `NATIONAL_ID` | Chinese ID card (18-digit) | 0.98 | ISO 7064 checksum |
| `PASSPORT` | Passport number | 0.85 | Context-keyword gated |
| `BANK_CARD` | Bank card (13-19 digits) | 0.92 | Luhn algorithm |
| `PERSON_NAME` | Chinese/English name | 0.70 | Context-keyword gated |
| `ADDRESS` | Chinese address (province/city/district) | 0.75 | Structural pattern + keyword |
| `SOCIAL_ACCOUNT` | WeChat/QQ/Twitter etc. | 0.80 | Context-keyword gated |

## ⚠️ Risk Level Rules

**HIGH**:
- `NATIONAL_ID`, `PASSPORT`, or `BANK_CARD` detected
- Or combo: `PERSON_NAME` + contact (`PHONE`/`EMAIL`) + `ADDRESS`

**LOW**:
- Single weak identifier (email only, phone only, social account only, etc.)

## 📁 Project Structure

```
openclaw-security/
├── SKILL.md                      # OpenClaw Skill definition
├── README.md
├── .gitignore
├── scripts/
│   ├── audit_worker.py           # Main entry: detect → risk score → NDJSON sink
│   ├── cleanup.py                # Audit log cleanup (default 7-day retention)
│   └── detectors/                # PII detector modules
│       ├── __init__.py           # Detector registry
│       ├── base.py               # Base class + Match dataclass
│       ├── phone.py              # Phone number (mobile/landline/intl)
│       ├── email_detector.py     # Email address
│       ├── national_id.py        # Chinese national ID (with checksum)
│       ├── passport.py           # Passport (keyword-gated)
│       ├── bank_card.py          # Bank card (Luhn validated)
│       ├── person_name.py        # Person name (keyword-gated)
│       ├── address.py            # Address (structural matching)
│       └── social_account.py     # Social accounts
├── references/
│   └── patterns.md               # Detection pattern reference
└── openclaw-security-audit/      # Audit log output (excluded by .gitignore)
    └── YYYY-MM-DD/
        └── events.ndjson
```

## 📋 Audit Record Schema

Each NDJSON line contains:

```json
{
  "event_id": "uuid",
  "session_id": "caller-provided session ID",
  "source_type": "input | prompt | context | knowledge_base",
  "labels": ["PHONE", "EMAIL"],
  "risk_level": "high | low",
  "detector_version": "0.1.0",
  "matched_count": 2,
  "matches": [
    {"label": "PHONE", "confidence": 0.90, "masked_preview": "138****5678"},
    {"label": "EMAIL", "confidence": 0.95, "masked_preview": "zh****@gmail.com"}
  ],
  "content_hash": "first 16 chars of SHA256 (for dedup, no raw content stored)",
  "created_at": "ISO 8601 UTC"
}
```

> **Security Principle**: Raw sensitive values are never stored — only masked previews and content hashes.

## 🧹 Log Cleanup

```bash
# Default: remove logs older than 7 days
python scripts/cleanup.py

# Custom retention
python scripts/cleanup.py --days 30

# Dry run (preview only)
python scripts/cleanup.py --dry-run
```

## ⚙️ Configuration

Override the audit log output directory via environment variable:

```bash
# Linux/macOS
export OPENCLAW_AUDIT_DIR="/path/to/custom/audit/dir"

# Windows PowerShell
$env:OPENCLAW_AUDIT_DIR = "C:\path\to\custom\audit\dir"
```

## 🔌 Usage as OpenClaw Skill

Place this directory in your OpenClaw Skills folder. The AI assistant will automatically recognize and invoke it:

```
User: "Check this text for sensitive information"
AI:   Runs audit_worker.py → returns detection results
```

Trigger keywords: `security scan`, `PII detection`, `sensitive data check`, `privacy audit`

## 🛡️ Security Design

- **No Raw Storage** — Only masked previews + SHA256 hash are persisted
- **Local Only** — Audit logs are never transmitted externally
- **Keyword Gating** — Weak signals (name/address/passport) require context keywords to fire, reducing false positives
- **Algorithm Validation** — National ID checksum and Bank Card Luhn reject format-matching but invalid numbers
- **Overlap Dedup** — Multiple matches on the same character range keep only the highest confidence result

## 🗺️ Roadmap

- [ ] Batch scan mode (`--batch`)
- [ ] `tool_output` source type support
- [ ] NER model enhancement for name/address detection
- [ ] HTML audit report generation
- [ ] PIPL / GDPR compliance label mapping
- [ ] Scheduled audit (cron / Task Scheduler)

## 📄 License

Apache 2.0

## 🤝 Contributing

Issues and PRs are welcome! To add a new detector:
1. Create a new module in `scripts/detectors/`, extending `BaseDetector`
2. Implement `detect(text)` returning a list of `Match` objects
3. Register it in `__init__.py`

---

**Made with ❤️ for the OpenClaw community**
