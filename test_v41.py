"""Regression tests for Ghost Ledger v4.1 — run with: python3 -m pytest tests/ -v
These are the exact bugs fixed from v4. If any test fails, do NOT ship.
"""
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Load app.py up to UI marker, stub streamlit
import importlib.util
def load_mod():
    text = pathlib.Path(__file__).parent.parent.joinpath("app.py").read_text()
    cut = text.split("# ---------- UI ----------")[0]
    cut = cut.replace("import streamlit as st", "import types as _t; st=_t.ModuleType('st'); st.set_page_config=lambda *a,**k: None; st.markdown=lambda *a,**k: None")
    pathlib.Path("/tmp/_test_v41_load.py").write_text(cut)
    spec = importlib.util.spec_from_file_location("v41_test", "/tmp/_test_v41_load.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

mod = load_mod()

def test_pdf_two_clean_assets():
    assets = [
        {"name":"Host - Test","category":"Infrastructure","type":"Endpoint","source":"Local OS","risk":"Low","status":"Active","owner":"test","model":"x","data_access":[],"evidence":"ok","first_seen":"2026-01-01","last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"Local","region":"local","repo_url":"","scan_id":"s"},
        {"name":"Docker Images - 2 images - LIVE","category":"Software","type":"Docker","source":"Docker - LIVE","risk":"Low","status":"Active","owner":"test","model":"x","data_access":[],"evidence":"ok","first_seen":"2026-01-01","last_seen":"now","actions_count":1,"policy_violations":0,"cloud":"Local","region":"local","repo_url":"","scan_id":"s"},
    ]
    out = mod.generate_evidence_pack_v4(assets, "scan-test", client_name="TestClient")
    assert len(out) > 1000 and out[:5] == b"%PDF-"

def test_pdf_unicode():
    assets = [{"name":"Test Cafe asset "*5,"category":"Security","type":"Secret","source":"Secret Scanner - LIVE","risk":"High","status":"Active","owner":"test","model":"x","data_access":[],"evidence":"x","first_seen":"2026-01-01","last_seen":"now","actions_count":1,"policy_violations":1,"cloud":"Local","region":"local","repo_url":"","scan_id":"s"}]
    out = mod.generate_evidence_pack_v4(assets, "scan-u", client_name="Cafe")
    assert len(out) > 1000

def test_regex_no_false_positive():
    for txt in ["risk-assessment-framework-approval","disk-encryption-configuration-policy"]:
        hits = [l for l,p in mod.SECRET_PATTERNS for _ in p.finditer(txt)]
        assert hits == [], txt

def test_anthropic_no_double_fire():
    txt = "sk-ant-12345678901234567890abcdefgh"
    hits = [l for l,p in mod.SECRET_PATTERNS for _ in p.finditer(txt)]
    assert hits == ["Anthropic Key"]

def test_finding_kind_order():
    assert mod.finding_kind("Env Secrets Present - 5 keys") == "Secret in env"
    assert mod.finding_kind("GitHub - Not Configured") == "Coverage gap - Not Configured"
    assert mod.finding_kind("MCP Server: foo") == "MCP server - no auth / secret in config"

def test_score_not_punish_not_configured():
    nc = [{"name":"Azure - Not Connected","category":"Cloud","type":"x","source":"Connector - NOT CONFIGURED","risk":"Low","status":"Not Configured","owner":"unknown","model":"x","data_access":[],"evidence":"x","first_seen":"2026-01-01","last_seen":"now","actions_count":0,"policy_violations":0,"cloud":"Azure","region":"-","repo_url":"","scan_id":"s"} for _ in range(10)]
    score, _, _ = mod.simple_readiness_score(nc)
    assert score == 100
    nc2 = nc + [{"name":"Secrets Found: x","category":"Security","type":"Secret","source":"Secret Scanner - LIVE","risk":"High","status":"Active","owner":"u","model":"x","data_access":[],"evidence":"x","first_seen":"2026-01-01","last_seen":"now","actions_count":1,"policy_violations":1,"cloud":"Local","region":"local","repo_url":"","scan_id":"s"}]
    score2, _, _ = mod.simple_readiness_score(nc2)
    assert score2 == 88

def test_process_risk_not_high_by_default():
    assert mod.calc_process_risk("Cursor") != "High"
    assert mod.calc_process_risk("Cursor", is_personal=True, has_token_in_cmd=True) == "High"

def test_mask_no_oracle():
    m = mod.mask_secret("sk-1234567890abcdefghij")
    assert "sk-1" not in m and "ghij" not in m

def test_redact_cmdline():
    r = mod.redact_cmdline(["/usr/bin/cursor","--token","SECRET1234567890","--api-key=sk-1234567890","normal"])
    assert "SECRET123" not in r and "sk-123" not in r

def test_no_wrong_mappings():
    assert "A.10.2" not in str(mod.FRAMEWORK_MAP)
    assert "8(5)" in str(mod.FRAMEWORK_MAP)
    assert "Rs. 250" in mod.REMEDIATION_LIB["Secret in code"]["cost_if_ignored"]
