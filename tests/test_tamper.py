import json
import subprocess

from app.schemas import Asset, ScanConfig
from app.detectors.tamper import run_tamper
from app.utils.baseline import BaselineStore
from app.utils.signature import make_signature

TAMPER_URL = "http://localhost:8084"
CONTAINER = "tb-tamper"
HTML_PATH = "/usr/share/nginx/html/index.html"


def _read_page() -> str:
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "cat", HTML_PATH],
        capture_output=True, text=True, check=True)
    return out.stdout


def _write_page(content: str) -> None:
    subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c",
         f"cat > {HTML_PATH} << 'PAGE'\n{content}\nPAGE"],
        check=True)


def _cat_str(category) -> str:
    """签名输入归一化：枚举取 .value，其余转字符串（与 detectors 端纯字符串一致）。"""
    return category.value if hasattr(category, "value") else str(category)


def test_tamper_baseline_then_detect():
    store = BaselineStore()
    store.remove(TAMPER_URL)

    original = _read_page()  # 备份原页面，测试完还原
    try:
        cfg = ScanConfig()
        assets = [Asset(url=TAMPER_URL, host="localhost")]

        # 第 1 次扫描：只建档，不报
        assert run_tamper(assets, cfg, store) == []
        assert store.get(TAMPER_URL) is not None

        # 篡改：追加隐藏 iframe
        _write_page(original + '\n<iframe src="http://evil.example/x" style="display:none"></iframe>\n')

        # 第 2 次扫描：必报
        risks = run_tamper(assets, cfg, store)
        assert len(risks) >= 1
        r = risks[0]
        assert r.category == "tamper"
        assert r.severity == "high"  # 隐藏 iframe 直检 → high

        # ★ 验签：从 raw_output 还原 detail，重算签名，必须一致
        payload = json.loads(r.raw_output)
        assert payload["detail"].startswith("tamper:")
        assert len(payload["detail"]) == len("tamper:") + 8
        assert payload["hidden_iframe_tags"], "证据应包含 iframe 标签"
        expected_sig = make_signature(r.asset_url, _cat_str(r.category), r.title, payload["detail"])
        assert r.signature == expected_sig, "签名与 detail 约定不符"
        assert len(r.signature) == 64
    finally:
        _write_page(original)
        store.remove(TAMPER_URL)


def test_tamper_no_change_no_alert():
    store = BaselineStore()
    try:
        cfg = ScanConfig()
        assets = [Asset(url=TAMPER_URL, host="localhost")]
        run_tamper(assets, cfg, store)               # 建档
        assert run_tamper(assets, cfg, store) == []  # 未改动 → 0 报
    finally:
        store.remove(TAMPER_URL)