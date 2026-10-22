from app.schemas import ScanRequest, Asset, ScanConfig
from app.detectors.discovery import run_discovery

PORTS = [8081, 8082, 8083, 8084, 8085, 8086]   # dvwa/wp/挂马/篡改/备份/正常页

def test_discovery_testbed():
    req = ScanRequest(assets=[
        Asset(url=f"http://localhost:{p}", host="localhost") for p in PORTS
    ])
    resp = run_discovery(req)
    urls = [a.url for a in resp.assets]
    assert len(urls) >= 10, f"总发现过少: {urls}"
    # 关键预期：备份靶场被 gobuster 命中
    assert any(".env.bak" in u for u in urls)
    # WP 首页被 katana 爬到（wp-content 链接多）
    assert any("8082" in u for u in urls)
    # 每个哈希要么空要么 64 位 hex
    assert all(len(a.page_hash) in (0, 64) for a in resp.assets)

def test_fingerprint_wordpress():
    from app.adapters.whatweb import WhatwebAdapter
    a = Asset(url="http://localhost:8082", host="localhost")
    fp = WhatwebAdapter().fingerprint(a, ScanConfig())
    assert fp.get("cms") == "wordpress", f"未识别出 WP: {fp}"