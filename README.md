# OpenClaw Security Skill 🔒

异步 PII（个人身份信息）检测引擎，作为 OpenClaw Skill 运行，扫描会话中的敏感数据并在本地生成审计日志。

## ✨ 特性

- **8 类敏感信息检测** — 手机号、邮箱、身份证、护照、银行卡、姓名、地址、社交账号
- **零外部依赖** — 纯 Python 标准库，开箱即用
- **异步不阻塞** — 审计与主流程解耦，不影响用户响应
- **智能误报控制** — 身份证校验位验证、银行卡 Luhn 校验、护照/姓名/地址关键词门控
- **重叠去重** — 同一文本区间多检测器命中时，高置信度优先
- **风险分级** — high / low 两级，支持单标签高风险和组合高风险
- **本地落盘** — NDJSON 格式按天分目录，便于 grep / SIEM 导入
- **自动清理** — 可配置保留期（默认 7 天）

## 🚀 快速开始

```bash
git clone https://github.com/mtoby8326/openclaw-security-skill.git
cd openclaw-security-skill
```

### 扫描文本

```bash
# 内联文本
python scripts/audit_worker.py --session-id S001 --source-type input \
  --text "收件人：张三 手机号13812345678 邮箱test@gmail.com"

# 从文件扫描
python scripts/audit_worker.py --session-id S001 --source-type knowledge_base \
  --file path/to/content.txt

# JSON 格式输出
python scripts/audit_worker.py --session-id S001 --source-type input \
  --text "身份证号110101199003076536" --json
```

### 输出示例

```
[HIGH] Detected 3 PII match(es)
  Labels: EMAIL, PERSON_NAME, PHONE
  Audit:  openclaw-security-audit/2026-03-06/events.ndjson
```

JSON 模式：

```json
{
  "status": "detected",
  "risk_level": "high",
  "labels": ["EMAIL", "PERSON_NAME", "PHONE"],
  "matched_count": 3,
  "audit_file": "openclaw-security-audit/2026-03-06/events.ndjson"
}
```

## 🏷️ 检测标签

| 标签 | 说明 | 置信度 | 验证方式 |
|------|------|--------|----------|
| `PHONE` | 中国手机号、座机、国际号码 | 0.90 | 位数校验 |
| `EMAIL` | 电子邮箱地址 | 0.95 | 格式匹配 |
| `NATIONAL_ID` | 中国身份证（18位） | 0.98 | ISO 7064 校验位 |
| `PASSPORT` | 护照号码 | 0.85 | 上下文关键词门控 |
| `BANK_CARD` | 银行卡号（13-19位） | 0.92 | Luhn 算法 |
| `PERSON_NAME` | 中英文姓名 | 0.70 | 上下文关键词门控 |
| `ADDRESS` | 中国地址（省/市/区/街道） | 0.75 | 结构化模式 + 关键词 |
| `SOCIAL_ACCOUNT` | 微信/QQ/Twitter 等 | 0.80 | 上下文关键词门控 |

## ⚠️ 风险分级规则

**HIGH（高风险）**：
- 检测到 `NATIONAL_ID`、`PASSPORT` 或 `BANK_CARD`
- 或同时出现 `PERSON_NAME` + 联系方式（`PHONE`/`EMAIL`）+ `ADDRESS` 的组合

**LOW（低风险）**：
- 单一弱标识（仅邮箱、仅手机号、仅社交账号等）

## 📁 项目结构

```
openclaw-security/
├── SKILL.md                      # OpenClaw Skill 定义
├── README.md                     # 本文件
├── .gitignore
├── scripts/
│   ├── audit_worker.py           # 主入口：检测 → 风险评级 → NDJSON 落盘
│   ├── cleanup.py                # 审计日志清理（默认 7 天保留）
│   └── detectors/                # PII 检测器模块
│       ├── __init__.py           # 检测器注册表
│       ├── base.py               # 基类 + Match 数据结构
│       ├── phone.py              # 手机号/座机/国际号码
│       ├── email_detector.py     # 邮箱
│       ├── national_id.py        # 身份证（含校验位）
│       ├── passport.py           # 护照（关键词门控）
│       ├── bank_card.py          # 银行卡（Luhn 校验）
│       ├── person_name.py        # 姓名（关键词门控）
│       ├── address.py            # 地址（省市结构匹配）
│       └── social_account.py     # 社交账号
├── references/
│   └── patterns.md               # 检测规则参考文档
└── openclaw-security-audit/      # 审计日志输出（.gitignore 已排除）
    └── YYYY-MM-DD/
        └── events.ndjson
```

## 📋 审计记录格式

每条 NDJSON 记录包含：

```json
{
  "event_id": "uuid",
  "session_id": "调用方传入的会话 ID",
  "source_type": "input | prompt | context | knowledge_base",
  "labels": ["PHONE", "EMAIL"],
  "risk_level": "high | low",
  "detector_version": "0.1.0",
  "matched_count": 2,
  "matches": [
    {"label": "PHONE", "confidence": 0.90, "masked_preview": "138****5678"},
    {"label": "EMAIL", "confidence": 0.95, "masked_preview": "zh****@gmail.com"}
  ],
  "content_hash": "sha256 前 16 位（用于去重，不存原文）",
  "created_at": "ISO 8601 UTC"
}
```

> **安全原则**：不存储原始敏感值，仅保留脱敏片段 + 内容哈希。

## 🧹 日志清理

```bash
# 默认清理 7 天前的日志
python scripts/cleanup.py

# 自定义保留期
python scripts/cleanup.py --days 30

# 预览模式（不实际删除）
python scripts/cleanup.py --dry-run
```

## ⚙️ 配置

通过环境变量自定义审计日志输出目录：

```bash
# Linux/macOS
export OPENCLAW_AUDIT_DIR="/path/to/custom/audit/dir"

# Windows PowerShell
$env:OPENCLAW_AUDIT_DIR = "C:\path\to\custom\audit\dir"
```

## 🔌 作为 OpenClaw Skill 使用

将本目录放入 OpenClaw Skills 目录后，AI 助手可自动识别并调用：

```
用户: "帮我检查这段文本有没有敏感信息"
AI:   运行 audit_worker.py 扫描 → 返回检测结果
```

触发关键词：`security scan`、`PII detection`、`敏感信息检测`、`隐私审计`

## 🛡️ 安全设计

- **不存原文** — 仅保存脱敏预览 + SHA256 哈希
- **本地存储** — 审计日志不会传输到外部
- **关键词门控** — 姓名/地址/护照等弱信号需上下文关键词才触发，降低误报
- **算法校验** — 身份证校验位、银行卡 Luhn 算法，拒绝格式匹配但无效的号码
- **重叠去重** — 同一字符区间的多个匹配，只保留最高置信度结果

## 🗺️ 路线图

- [ ] 批量扫描模式（`--batch`）
- [ ] 支持 `tool_output` 源类型
- [ ] NER 模型增强姓名/地址检测
- [ ] HTML 审计报告生成
- [ ] PIPL / GDPR 合规标签映射
- [ ] 定时审计调度（cron / Task Scheduler）

## 📄 许可证

Apache 2.0

## 🤝 贡献

欢迎 Issue 和 PR！新增检测器只需：
1. 在 `scripts/detectors/` 下创建新模块，继承 `BaseDetector`
2. 实现 `detect(text)` 方法，返回 `Match` 列表
3. 在 `__init__.py` 中注册

---

**Made with ❤️ for OpenClaw community**
