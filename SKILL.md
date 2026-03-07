---
name: openclaw-security
description: "Multi-region async PII detection for OpenClaw sessions. Scans user input, prompts, context, and knowledge base content for sensitive personal data across CN, US, AU, UK, DE, FR, SG, MY, TH, ID regions. Detects phone numbers, emails, names, addresses, passports, bank cards, national IDs, social accounts. Use when: (1) user asks to audit or scan for PII / sensitive data, (2) 'security scan', (3) 'check for personal information', (4) 'PII detection', (5) background audit on session content, (6) 'sensitive data check', (7) 'privacy audit'."
---

# OpenClaw Security - PII Audit Skill

Multi-region async PII detection engine for OpenClaw sessions. Detects 8 categories of sensitive personal data across 10 country/region jurisdictions and logs audit events locally as NDJSON.

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

## Supported Regions

CN, US, AU, SG, MY, TH, ID, DE, UK, FR (+ INTL via +CC phone prefix)

## Risk Levels

- **high**: NATIONAL_ID / PASSPORT / BANK_CARD detected, or combination of PERSON_NAME + contact info + ADDRESS
- **low**: Single weak identifier (EMAIL, SOCIAL_ACCOUNT, PHONE alone)

## Smart Sampling

The audit worker includes built-in smart sampling to efficiently handle large contexts:

- **User input** (`input`): 100% scan rate, 5-min cache TTL — every user message is scanned, but identical repeats within 5 minutes are skipped.
- **System prompts** (`prompt`): 20% scan rate, 24-hour cache TTL — prompts rarely change; first scan is cached for 24 hours.
- **Conversation context** (`context`): 20% scan rate, 1-hour cache TTL — context overlaps heavily; only sample 1 in 5 submissions.
- **Knowledge base** (`knowledge_base`): 100% first-scan rate, 24-hour cache TTL — static content is fully scanned once, then deduped for 24 hours.

Bypass sampling for manual / forced scans:
```powershell
python scripts/audit_worker.py --session-id S001 --source-type context --text "text" --no-cache
```

## Async Audit Workflow

When auditing session content as a background task:

1. **Respond to user first** — never block the main response for audit.
2. **Feed all content types** — the script internally decides whether to actually scan based on sampling config and cache. The Agent does not need to decide when to skip.
3. Run audit in background:
```powershell
# User input — always scanned
Start-Process -NoNewWindow -FilePath python -ArgumentList "scripts/audit_worker.py --session-id $sid --source-type input --text `"$userInput`""
# System prompt — sampled at 20%, cached 24h
Start-Process -NoNewWindow -FilePath python -ArgumentList "scripts/audit_worker.py --session-id $sid --source-type prompt --text `"$systemPrompt`""
# Conversation context — sampled at 20%, cached 1h
Start-Process -NoNewWindow -FilePath python -ArgumentList "scripts/audit_worker.py --session-id $sid --source-type context --file context_snapshot.txt"
```
4. Review results: `openclaw-security-audit/YYYY-MM-DD/events.ndjson`

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
