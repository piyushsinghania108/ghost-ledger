# 👻 Ghost Ledger — AI Compliance Discovery + Evidence

**Find every Ghost AI asset. Fix the Highs. Prove it.**

Ghost Ledger is the discovery + evidence layer for AI compliance. It finds AI tools, MCP servers, repos, secrets, cloud assets and owners in 1 day, then produces an Evidence Pack an auditor can re-perform.

> **Not a certification.** Score is internal prioritisation. Fixer cannot certify own fixes — external auditor must re-perform.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Streamlit](https://img.shields.io/badge/streamlit-1.36-red) ![License](https://img.shields.io/badge/license-MIT-green) ![Version](https://img.shields.io/badge/version-v4.1%20FIXED-00C2A8)

---

## ⚡ 3-Command Setup

```bash
git clone https://github.com/piyushsinghania108/ghost-ledger.git
cd ghost-ledger
make setup && make run
```

Open http://localhost:8501 → Enter client name → Tick consent → Click **Run Enterprise Scan**

Full setup: [`docs/SETUP.md`](docs/SETUP.md)

---

## What it finds

| Layer | What | Source |
|-------|------|--------|
| **Endpoint** | AI processes (dedupe by binary), Python AI libs, Docker, Ports | LIVE |
| **MCP** | Claude Desktop, Cursor, VS Code, Windsurf + repo-level configs | LIVE — NEW in v4.1 |
| **Repos** | Local repos + GitHub (read-only) | LIVE |
| **Secrets** | Regex + git history + `git ls-files` for `.env` — **opt-in, capped, PARTIAL** | LIVE if opted-in |
| **Cloud** | AWS S3 (tags + public ACL) + EC2 (1 region) | LIVE if creds set |
| **Placeholders** | Azure, GCP, Okta, Entra, Slack, AD | NOT CONFIGURED — honest gap, not Low risk |

## What it proves

- **Evidence Pack v4.1 PDF** — Findings in plain language, fix + owner + days, before/after diff, actual checklist status (no hardcoded DONE)
- **Hash chain** — Full SHA-256, findings hash, `verify_ledger_chain()`
- **Per-scan snapshots** — Every scan preserved, diff vs previous scan
- **Framework map** — EU AI Act, ISO 42001, NIST AI RMF, SOC 2, DPDP/GDPR — corrected in v4.1

## What it does NOT do

- Does NOT make you “audit ready” by itself
- Does NOT do SaaS/OAuth discovery for 140 tools (not built — do not claim)
- Does NOT do model testing, bias, data governance, human oversight, logging, post-market monitoring
- Those are the **Governance layer** — Ghost Ledger opens, governance closes.

See [`docs/COMPLIANCE-MAPPING.md`](docs/COMPLIANCE-MAPPING.md) for the full honest map.

---

## v4.1 — What was fixed from v4

- ✅ v4 PDF crash fixed — `set_x` + safe text + fpdf 1.7 / fpdf2 compat
- ✅ Raw cmdline storage removed — `redact_cmdline()`
- ✅ Regex boundaries — `\b`, Anthropic before OpenAI, `sk-(?!ant-)`
- ✅ Process High-by-default fixed — starts at 15, dedupe by binary
- ✅ Score no longer punishes NOT CONFIGURED — Coverage % separate
- ✅ Consent + client + secret opt-in wired
- ✅ Clear All Data → Archive (append-only)
- ✅ `ORDER BY risk` fixed, misclassification fixed
- ✅ Currency + law corrected — Rs. 250 Cr, DPDP 8(5)/8(6), ISO 42001 A.2/A.3/A.4/A.5, EU 7% only Art 5
- ✅ Hash chain full SHA-256, mask no oracle, secret scan PARTIAL + git history
- ✅ MCP discovery NEW, per-scan snapshots + diff, GitHub + AWS fixes

Full list: [`CHANGELOG.md`](CHANGELOG.md)

---

## Architecture

```
UI (Streamlit) → Consent → Scan → SQLite (assets + snapshots + ledger + scans)
                → Evidence Pack (PDF + JSON + diff)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Tests

```bash
make test
# 10 regression tests: PDF, regex, score, MCP, mask, redact, mappings
```

## Env

```bash
cp .env.example .env
# GITHUB_TOKEN (read-only) + AWS keys (read-only) if needed
# Never commit .env — see .gitignore
```

## Push to GitHub (first time)

```bash
bash scripts/push.sh https://github.com/piyushsinghania108/ghost-ledger.git
```

## License

MIT — see [`LICENSE`](LICENSE)

## Guardrail Sovereign

Ghost Ledger is the discovery layer for Guardrail Sovereign — AI Governance Operating System.
AI compliance = Discover (Ghost Ledger) → Govern (Guardrail Sovereign) → Prove (Evidence Pack).
