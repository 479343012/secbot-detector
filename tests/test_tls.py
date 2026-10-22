import json

from app.schemas import Asset, ScanConfig
from app.detectors.tls import run_tls
from app.utils.signature import make_signature

HTTPS_URL = "https://localhost:8443"
HTTP_URL = "http://localhost:8086"


def _cat_str(c):
    return c.value if hasattr(c, "value") else str(c)


def test_https_weak_config_detected():
    risks = run_tls([Asset(url=HTTPS_URL, host="localhost")], ScanConfig())
    assert len(risks) >= 1, "弱配置 HTTPS 靶机必须命中"
    assert all(r.category == "weak_config" for r in risks)
    # 自签名证书必报（testssl id 以 cert 开头）
    assert any("cert" in (r.template or "") for r in risks), \
        f"应命中证书类问题，实际: {[r.template for r in risks]}"
    # 验签
    for r in risks:
        payload_detail = f"testssl:{r.template}"
        expected = make_signature(r.asset_url, _cat_str(r.category), r.title, payload_detail)
        assert r.signature == expected, f"签名不符: {r.title}"
        assert len(r.signature) == 64


def test_http_asset_skipped():
    risks = run_tls([Asset(url=HTTP_URL, host="localhost")], ScanConfig())
    assert risks == []