# Changelog

## v4.1 — 2026-11-19 — FIXED
- v4 PDF crash fixed — set_x + safe text + fpdf 1.7 / fpdf2 compat
- Raw cmdline storage removed — redact_cmdline()
- Regex boundaries — \b, Anthropic before OpenAI, sk-(?!ant-)
- Process High-by-default fixed — starts at 15, dedupe by binary
- Score no longer punishes NOT CONFIGURED — Coverage % separate
- Consent + client + secret opt-in wired
- Clear All Data -> Archive (append-only)
- ORDER BY risk fixed (High first)
- Misclassification fixed — Env before Secret, NOT CONFIGURED -> Coverage Gap
- Currency + law corrected — Rs. 250 Cr, DPDP 8(5)/8(6), ISO 42001 A.2/A.3/A.4/A.5, EU 7% only Art 5
- Hash chain full SHA-256, findings hash, verify_ledger_chain()
- Mask no first4/last4 oracle
- Secret scan PARTIAL + git history + git ls-files
- Process matching exact binary + \b
- Evidence DONE lines -> actual status + before/after diff
- MCP discovery NEW — Claude Desktop / Cursor / VS Code / Windsurf + repo-level
- Per-scan snapshots + diff
- GitHub public repo not auto-High, AWS S3 tags + public ACL check

## v4 — 2026-11-18
- Simplified Evidence Pack, framework map (with errors fixed in v4.1)

## v3 — Enterprise
- SQLite 19 cols fix, PDF bytearray fix, GitHub + AWS + Docker + Secrets
