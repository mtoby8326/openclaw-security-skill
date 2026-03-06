---
name: openclaw-security
description: "Async PII detection for OpenClaw sessions. Scans user input, prompts, context, and knowledge base content for sensitive personal data (phone numbers, emails, names, addresses, passports, bank cards, national IDs, social accounts). Use when: (1) user asks to audit or scan for PII / sensitive data, (2) 'security scan', (3) 'check for personal information', (4) 'PII detection', (5) background audit on session content, (6) '敏感信息检测', (7) '隐私审计'."
---

# OpenClaw Security - PII Audit Skill

Async PII detection engine for OpenClaw sessions. Detects 8 categories of sensitive personal data and logs audit events locally as NDJSON.

## Quick Start

Scan inline text:
```powershell
python scripts/audit_worker.py --session-id SESSION_001 --source-type input --text "张三的手机号是13812345678"
```

Scan via stdin:
```powershell
echo "张三的手机号是13812345678" | python scripts/audit_worker.py --session-id SESSION_001 --source-type input
```

Scan a file:
```powershell
python scripts/audit_worker.py --session-id SESSION_001 --source-type knowledge_base --file path/to/content.txt
```

JSON output:
```powershell
python scripts/audit_worker.py --session-id S001 --source-type input --text "test" --json
```

## Source Types

- `input` — User input text
- `prompt` — System or user prompts
- `context` — Conversation context
- `knowledge_base` — Knowledge base content

## Detection Labels

PHONE, EMAIL, PERSON_NAME, ADDRESS, PASSPORT, BANK_CARD, NATIONAL_ID, SOCIAL_ACCOUNT

## Risk Levels

- **high**: NATIONAL_ID / PASSPORT / BANK_CARD detected, or combination of PERSON_NAME + contact info + ADDRESS
- **low**: Single weak identifier (EMAIL, SOCIAL_ACCOUNT, PHONE alone)

## Async Audit Workflow

When auditing session content as a background task:

1. **Respond to user first** — never block the main response for audit
2. Run audit in background:
```powershell
Start-Process -NoNewWindow -FilePath python -ArgumentList "scripts/audit_worker.py --session-id $sid --source-type input --text `"$content`""
```
3. Review results: `openclaw-security-audit/YYYY-MM-DD/events.ndjson`

## Retention

Default: 7 days. Cleanup:
```powershell
python scripts/cleanup.py --days 7
```

Dry run first:
```powershell
python scripts/cleanup.py --days 7 --dry-run
```

## Audit Record Schema

Each NDJSON line contains:
- `event_id` — UUID
- `session_id` — Caller-provided session ID
- `source_type` — One of: input, prompt, context, knowledge_base
- `labels` — Array of detected PII types
- `risk_level` — high or low
- `matched_count` — Number of PII matches
- `matches` — Array of {label, confidence, masked_preview}
- `content_hash` — SHA256 prefix for dedup (no raw content stored)
- `created_at` — ISO 8601 UTC timestamp

## Safety Rules

- NEVER store raw sensitive values — only masked previews + content hash
- Audit logs are local-only, never transmitted externally
- All file I/O uses UTF-8 encoding explicitly
- No external dependencies — stdlib only

## Configuration

Environment variable override for audit output directory:
```powershell
$env:OPENCLAW_AUDIT_DIR = "C:\path\to\custom\audit\dir"
```

See `references/patterns.md` for detection pattern details.
