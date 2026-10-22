"""签名算法契约测试：任何修改必须先过这组用例，再同步成员 A、C。

契约（contracts/signature.md）：
    signature = sha256( f"{asset_url}|{category}|{title}|{detail}" ) 的 UTF-8 hex
"""
import hashlib

from app.utils.signature import make_signature


def test_pipe_concat_golden():
    """黄金样本：钉死拼接格式。与成员 A 的 agent-core/app/clients.py 逐字节一致。"""
    sig = make_signature("http://a/login.php", "vuln", "标题T", "detailD")
    expected = hashlib.sha256("http://a/login.php|vuln|标题T|detailD".encode("utf-8")).hexdigest()
    assert sig == expected


def test_deterministic():
    """相同输入必得相同输出（去重的前提）。"""
    a = make_signature("http://x", "tamper", "t", "tamper:abcd1234")
    b = make_signature("http://x", "tamper", "t", "tamper:abcd1234")
    assert a == b and len(a) == 64


def test_any_field_change_changes_signature():
    """任一字段变化，签名必须不同（防"字段被静默忽略"类 bug）。"""
    base = ("http://x", "vuln", "title", "detail")
    base_sig = make_signature(*base)
    for i in range(4):
        mutated = list(base)
        mutated[i] = base[i] + "-changed"
        assert make_signature(*mutated) != base_sig, f"第 {i} 个字段变化未影响签名"


def test_field_order_matters():
    """字段顺序是契约一部分：title/detail 互换必须产生不同签名。"""
    a = make_signature("http://x", "vuln", "AAA", "BBB")
    b = make_signature("http://x", "vuln", "BBB", "AAA")
    assert a != b


def test_utf8_chinese():
    """中文标题/明细必须正确参与哈希（UTF-8 编码，不能 fallback 丢字符）。"""
    sig = make_signature("http://x", "tamper", "页面内容疑似被篡改", "tamper:哈希前8位")
    expected = hashlib.sha256(
        "http://x|tamper|页面内容疑似被篡改|tamper:哈希前8位".encode("utf-8")).hexdigest()
    assert sig == expected