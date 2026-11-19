# Architecture — Ghost Ledger v4.1

```
User (Streamlit UI)
  -> Consent + Client + Secret opt-in (required)
  -> run_enterprise_scan()
       -> Local: system, processes (dedupe by binary), python env, docker, ports, MCP, env keys
       -> Repos: local repos + secrets (opt-in, capped, git history)
       -> Cloud: GitHub (read-only), AWS S3/EC2 (1 region, tags + public check)
       -> Placeholders: Azure / GCP / Okta / Entra / Slack (NOT CONFIGURED, honest)
  -> SQLite: assets (current) + scan_assets (snapshot per scan) + ledger (full SHA-256 chain) + scans + allowlist + archive_assets
  -> Evidence Pack v4.1: PDF (safe text, set_x, fpdf 1.7/fpdf2) + JSON + before/after diff
```

## Principles
- Read-only. No writes to client cloud, no secret storage.
- Masked fingerprints only. No first4/last4. No raw cmdline.
- NOT CONFIGURED = coverage gap, not Low risk.
- Score = internal prioritisation, not audit certification.
- Fixer cannot certify own fixes — external auditor must re-perform.

## Files
- `app.py` — single-file Streamlit app (intentional, easy to demo + audit)
- `tests/test_v41.py` — regression tests for PDF, regex, score, MCP, mask, redact
- `docs/COMPLIANCE-MAPPING.md` — corrected mappings
