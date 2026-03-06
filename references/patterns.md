# Detection Patterns Reference

## Label: PHONE
- **CN Mobile**: `1[3-9]X XXXX XXXX` — 11 digits starting with 1[3-9]
- **International**: `+CC XXXX...` — country code + 4-14 digits
- **CN Landline**: `0XX(X)-XXXXXXX(X)` — area code 3-4 digits + number 7-8 digits
- **Confidence**: 0.90
- **Validation**: digit count 7-15, dedup by position

## Label: EMAIL
- **Pattern**: `local@domain.tld` — standard RFC-like email regex (ASCII)
- **Confidence**: 0.95
- **Masking**: `zh****@gmail.com`

## Label: NATIONAL_ID
- **Pattern**: 18 digits — 6 region + 8 birthday (19xx/20xx) + 3 seq + 1 check
- **Confidence**: 0.98
- **Validation**: ISO 7064 Mod 11-2 checksum — only records passing checksum are kept
- **Masking**: `110101********1234`

## Label: PASSPORT
- **CN Passport**: `[EGDSPH]` + optional letter + 7-8 digits
- **Confidence**: 0.85
- **Gate**: Requires context keyword (护照/passport/visa/签证/出入境) in same text
- **Masking**: `E1****78`

## Label: BANK_CARD
- **Formatted**: `XXXX XXXX XXXX XXXX` (space/dash separated groups of 4)
- **Continuous**: 13-19 consecutive digits
- **Confidence**: 0.92
- **Validation**: Luhn algorithm — only Luhn-passing numbers are recorded
- **Masking**: `6222 **** **** 5678`

## Label: PERSON_NAME
- **Before-keyword**: 姓名/收件人/联系人/持卡人/户名/... followed by 2-4 Chinese characters
- **After-title**: 2-4 Chinese characters followed by 先生/女士/教授/律师/...
- **Structured**: `Name:` / `姓名：` followed by Chinese or English name
- **Confidence**: 0.70
- **Masking**: `张**`

## Label: ADDRESS
- **Keyword-gated**: 地址/住址/收货地址/... followed by 8-60 Chinese address characters
- **Provincial**: Province + City + district/street details (structural pattern)
- **Municipal**: 北京/上海/天津/重庆 + district + street details
- **Confidence**: 0.75
- **Masking**: `浙江省杭****路12`

## Label: SOCIAL_ACCOUNT
- **WeChat**: 微信/wechat/wx + letter-start ID (6-20 chars)
- **QQ**: QQ + 5-12 digit number
- **Twitter/X**: twitter/推特/X + @handle (1-15 chars)
- **Generic**: 账号/account + 4-30 char value
- **Confidence**: 0.80
- **Masking**: `wx****ng`

## Risk Level Rules
- **HIGH**: NATIONAL_ID / PASSPORT / BANK_CARD present, OR combo of (PERSON_NAME + PHONE/EMAIL + ADDRESS)
- **LOW**: All other single or non-combo detections

## False Positive Control
1. Regex match → format/checksum validation → context keyword confirmation
2. PERSON_NAME and ADDRESS require keyword context (low standalone confidence)
3. PASSPORT requires keyword context — no context = no detection
4. BANK_CARD requires Luhn pass — random 16-digit numbers are filtered
5. NATIONAL_ID requires checksum pass — format-only matches are dropped
6. Overlapping matches are deduped: higher confidence wins
