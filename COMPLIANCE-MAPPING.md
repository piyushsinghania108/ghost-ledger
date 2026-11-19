# Compliance Mapping — Corrected (v4.1)

Verify against primary texts, not this file:
- EU AI Act Reg (EU) 2024/1689 Art 5 / 9 / 15 / 99
- ISO/IEC 42001:2023 Annex A
- DPDP Act 2023 Sec 8(5) / 8(6)
- GDPR Art 32 / 33

## Corrections from v4
- ISO 42001: A.2 Policy, A.3 Roles, A.4 Resources, A.5 Data. NOT A.10.2 / A.6.1 / A.5.1 (those are ISO 27001).
- DPDP: Sec 8(5) safeguards, Sec 8(6) breach notice to Board + affected persons. NOT 8(4) / 8(7).
- EU AI Act: Art 15 + Art 9 ONLY if high-risk system. 7% fine ONLY for Art 5 prohibited practices. Missing owner for high-risk = up to EUR 15M or 3% (Art 99(4)).
- Secret in code alone is NOT automatically a DPDP breach. Breach needs personal data exposure.

## What Ghost Ledger proves
- Inventory (Art 9 / A.4 / A.5), security gaps (Art 15 / Art 32 / Sec 8(5)), owner gaps (A.3 / Art 26 if high-risk)
- What it does NOT prove: data governance (Art 10), documentation (Art 11), logging (Art 12), transparency (Art 13), human oversight (Art 14), post-market monitoring (Art 72)

See `app.py` FRAMEWORK_MAP + REMEDIATION_LIB for the in-code map used in Evidence Pack.
