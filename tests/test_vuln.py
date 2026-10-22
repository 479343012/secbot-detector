from app.schemas import ScanRequest, Asset, ScanConfig
from app.detectors.vuln import run_vuln

def test_vuln_wordpress():
    req = ScanRequest(assets=[Asset(
        url="http://localhost:8082", host="localhost",
        fingerprint={"cms": "wordpress", "version": "5.2.4"})])
    resp = run_vuln(req)
    assert len(resp.risks) >= 1, "WP 靶场应至少有一条命中"
    for r in resp.risks:
        assert r.category in ("vuln", "weak_config")
        assert len(r.signature) == 64
        assert r.tool in ("nuclei", "wpscan", "headers")

def test_vuln_dvwa():
    req = ScanRequest(assets=[Asset(url="http://localhost:8081", host="localhost")])
    resp = run_vuln(req)
    titles = [r.title for r in resp.risks]
    # DVWA 有 nuclei 指纹模板；至少应命中安全头缺失
    assert len(resp.risks) >= 1
    assert any(r.tool == "headers" for r in resp.risks)