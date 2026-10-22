"""HTTP 层冒烟测试：防止路由重复注册/空实现回归（教训：函数级测试绕过了 HTTP 层）。"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200


def test_malware_route_returns_real_results():
    r = client.post("/scan/malware",
                    json={"assets": [{"url": "http://localhost:8083",
                                      "host": "localhost"}],
                          "config": {"timeout_sec": 30}})
    assert r.status_code == 200
    assert len(r.json()["risks"]) >= 1, "HTTP 层返回空——检查路由是否被空实现抢先注册"


def test_tamper_route_registered_once():
    paths = [r.path for r in app.routes]
    assert paths.count("/scan/tamper") == 1
    assert paths.count("/scan/malware") == 1
