import base64
import json
import os
from datetime import datetime, timezone

from app.adapters.base import BaseAdapter
from app.schemas import Asset, ScanConfig, RiskRecord, Evidence, Severity
from app.utils.signature import make_signature

SEV_MAP = {          # nuclei 级别 → 契约级别（对齐任务书取值）
    "critical": Severity.critical, "high": Severity.high,
    "medium": Severity.medium, "low": Severity.low,
    "info": Severity.low,
}


def _b64_or_raw(s):
    """nuclei v3 的 request/response 是 base64；兼容明文"""
    if not s:
        return None
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return s


class NucleiAdapter(BaseAdapter):
    tool_name = "nuclei"
    # 非破坏硬要求：禁用的参数（守卫在 base.guard）
    destructive_forbidden = ["-itags", "-tags", "fuzzing", "dos", "intrusive"]

    TEMPLATES_DIR = os.path.expanduser("~/nuclei-templates")

    def run(self, asset, config):
        # nuclei 需加载数千模板：进程超时放宽到 600s；HTTP 级 -timeout 仍用配置的 30s
        object.__setattr__(config, "timeout_sec", 1800)  # 若 config 可变直接用 config.timeout_sec = 600
        try:
            return super().run(asset, config)
        finally:
            object.__setattr__(config, "timeout_sec", 30)


    _CVE_WORTHY_CMS = {"wordpress", "joomla", "drupal"}

    def build_cmd(self, asset, config) -> list[str]:
        url = asset.url
        qps = getattr(config, "rate_limit_qps", None) or 5
        timeout = getattr(config, "timeout_sec", None) or 30

        # 指纹决定模板范围（任务书 4.4：按指纹过滤模板）
        fp = getattr(asset, "fingerprint", None) or {}
        cms = (fp.get("cms") or "").lower()

        template_dirs = [os.path.join(self.TEMPLATES_DIR, "http", "misconfiguration")]
        if not cms or cms in self._CVE_WORTHY_CMS:
        # 未知指纹保守走全量，防止漏报；已知 CMS 且不在白名单 → 只跑 misconfig
            template_dirs.append(os.path.join(self.TEMPLATES_DIR, "http", "cves"))

        cmd = [
            self.bin_path,
            "-u", url,
            "-duc", "-jsonl", "-silent", "-nc",
            "-etags", "dos,intrusive",
            "-rl", str(qps),
            "-timeout", str(timeout),
        ]
        for d in template_dirs:
            cmd += ["-t", d]
        return cmd

    def parse(self, stdout: str, asset: Asset) -> list[RiskRecord]:
        risks = []
        now = datetime.now(timezone.utc)
        for line in stdout.splitlines():
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = j.get("info", {})
            title = info.get("name") or j.get("template-id") or "nuclei finding"
            template = j.get("template-id") or info.get("template") or ""
            matched = j.get("matched-at") or asset.url
            sev = SEV_MAP.get((info.get("severity") or "low").lower(), Severity.low)

            desc = info.get("description") or f"命中 Nuclei 模板 {template}"
            risks.append(RiskRecord(
                asset_url=matched,
                category="vuln",
                severity=sev,
                title=title,
                description=desc,
                evidence=Evidence(
                    request_sample=_b64_or_raw(j.get("request")),
                    response_sample=_b64_or_raw(j.get("response")),
                    matched_context=info.get("description"),
                ),
                raw_output=json.dumps(j, ensure_ascii=False),
                tool="nuclei",
                template=template,                       # detail 明文落 template 字段（契约已有）
                first_seen=now,
                last_seen=now,
                signature=make_signature(matched, "vuln", title, template),  # detail = template-id
            ))
        return risks