# secbot-detector — 检测执行层（成员B）

> 网站安全风险评估与敏感信息防泄露智能巡检智能体 · 第九届浙江省大学生网络与信息安全竞赛（命题企业：杭州安恒信息）
> 本仓库是三方架构中的**检测执行层（"手脚"）**：封装全部开源检测工具，对授权目标执行发现 / 漏洞 / 篡改 / 挂马 / TLS 五类检测，按统一契约输出风险 JSON。

## 0. 三方架构中的位置

```
恒脑平台智能体（门面，成员A）
        ↓ 对话触发
agent-core 编排引擎（大脑，成员A）
        ├── detectors 检测服务（本仓库，成员B）：发现/漏洞/篡改/挂马/TLS
        └── sensitive-report 数据服务（成员C）：敏感引擎 + 账本 + 报告 + 告警
```

- **本服务对 A 暴露 HTTP 接口**，A 编排调用；B/C 之间无直接依赖。
- B 只输出检测 JSON；落库、告警、报告由 A 调成员C 的数据 API 完成。
- `category=leak` 的风险记录**不由本服务产生**（成员C 的敏感引擎职责）；本服务仅在资产发现阶段探测 `.env.bak/.git/config` 等敏感路径，命中资产以 `fingerprint.sensitive_file` 标记，供 C 圈定待检对象。

## 1. 功能总览

| 接口 | 检测器 | 底层工具 | 说明 |
|---|---|---|---|
| `GET /health` | — | — | 健康检查 |
| `POST /scan/discovery` | 资产发现 | subfinder / httpx / katana / gobuster / whatweb | 种子 URL 保底入池；公网域子域枚举；爬取+目录探测；敏感路径探测；输出含指纹/状态码/页面哈希/标题的资产对象 |
| `POST /scan/vuln` | 漏洞+弱配置 | nuclei / wpscan | nuclei 按指纹过滤模板（WordPress 走 CVE 全量+misconfig，已知其他 CMS 仅 misconfig，未知指纹保守全量）；非破坏（`-etags dos,intrusive` + guard 黑名单） |
| `POST /scan/tamper` | 篡改检测 | 自研（哈希基线） | 首次扫描建立基线（`~/.secbot/baselines.json`），动态值归一化（token/nonce/csrf）后比对，输出新旧哈希证据 |
| `POST /scan/malware` | 挂马/恶意外链 | 自研（正则+熵+黑名单） | JS 混淆熵 ≥5.5 标记、隐藏 iframe、黑名单域名外链；输出 `malware`/`bad_link` |
| `POST /scan/tls` | TLS 弱配置 | testssl.sh | 证书链/有效期/SAN/吊销、协议与弱 cipher；仅扫 https 资产 |
| `DELETE /baselines` | — | — | 清除篡改基线（复测演练用） |

**非破坏硬约束**：全部检测只读（GET）、QPS ≤ 5、HTTP 超时 ≤ 30s、不利用漏洞；nuclei 额外禁用 dos/intrusive/fuzzing 标签与危险参数（适配器 `guard()` 黑名单兜底）。说明：nuclei v3 无 `-ndc` 参数，非破坏由上述手段实现。

## 2. 快速开始

### 2.1 依赖

- Python 3.12+（开发环境 3.14，venv 安装 `requirements.txt`）
- 外部工具（需在本机 PATH 或容器内可用）：

| 工具 | 用途 | 备注 |
|---|---|---|
| nuclei ≥ v3.11 | 漏洞/弱配置 | 配 `-duc` 禁更新检查 |
| nuclei-templates | 模板库 | **2025 版目录结构：`http/cves/`、`http/misconfiguration/`**（旧版根级 `cves/` 已不存在） |
| testssl.sh | TLS 检测 | 输出 JSON 用 `--jsonfile=`（等号连写），URI 永远最后一个参数 |
| whatweb | 指纹识别 | localhost/内网目标可能哑火，本服务有 URL 特征兜底 |
| wpscan / httpx / katana / subfinder / gobuster | 发现链/WordPress | 仅相关环节调用 |

### 2.2 启动（开发模式）

```bash
cd secbot-detector
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --host 127.0.0.1 --port 8001
curl -s http://127.0.0.1:8001/health
```

> 生产/联调容器内必须 `--host 0.0.0.0`，否则 compose 网络中外部无法访问。

### 2.3 测试床（testbed）

七个 Docker 靶站，一键启动：

```bash
cd testbed && docker compose up -d
docker compose ps        # 全部 Up 再继续
```

| 容器 | 端口 | 用途 | 预期命中 |
|---|---|---|---|
| tb-dvwa | 8081 | DVWA 漏洞样例 | 信息收集（漏洞利用受非破坏约束不做） |
| tb-wordpress | 8082 | WordPress 5.2.4 | `CVE-2022-3590`（xmlrpc.php, medium） |
| tb-malware | 8083 | 挂马模拟页 | `malware`（混淆 JS）+ `bad_link`（黑名单域名） |
| tb-tamper | 8084 | 篡改模拟页 | `tamper`（注入隐藏 iframe → high） |
| tb-backup | 8085 | 备份文件样例 | 资产发现阶段标记 `.env.bak`/`backup_*.sql`（leak 风险归 C） |
| tb-normal | 8086 | **干净对照组** | 零命中（已加固：10 个安全响应头 + server_tokens off + 自定义首页） |
| tb-https | 8443 | 自签名 HTTPS | `weak_config`：`cert_chain_of_trust`(critical) 等 |

预期结果标注基准：`testbed/expected_results.json`。

## 3. 接口契约（与成员A/C 对齐版）

### 3.1 请求体

```json
{
  "assets": [{"url": "http://localhost:8082", "host": "localhost",
              "fingerprint": {"cms": "wordpress", "version": "5.2.4"}}],
  "config": {"rate_limit_qps": 5, "non_destructive": true, "timeout_sec": 30}
}
```

- `config` 字段名以本表为准（`rate_limit_qps`/`non_destructive`/`timeout_sec`）。
- **指纹由 A 携带可显著提速**：WordPress 资产走 CVE 模板约 25 分钟/资产；无指纹保守全量；纯 misconfig 仅数分钟。A 侧建议只将"路径无文件扩展名的页面资产"送 vuln（静态 .css/.js 不送）。
- 各接口建议超时：vuln ≥1800s，tls ≥300s，discovery ≥300s，tamper/malware ≥120s。**长扫描接口不可失败重试**。

### 3.2 风险记录 Schema（14 字段，全项目唯一）

```json
{
  "asset_url": "http://localhost:8082",
  "category": "vuln",
  "severity": "medium",
  "title": "WordPress xmlrpc.php DDoS... (CVE-2022-3590)",
  "description": "命中 Nuclei 模板 CVE-2022-3590 ...",
  "evidence": {"request_sample": "...", "response_sample": "...", "screenshot_ref": "", "matched_context": "..."},
  "raw_output": "{\"detail\": \"CVE-2022-3590\", ...}",
  "tool": "nuclei",
  "template": "CVE-2022-3590",
  "first_seen": "2026-10-22T00:00:00+00:00",
  "last_seen": "2026-10-22T00:00:00+00:00",
  "status": "active",
  "signature": "sha256(asset_url|category|title|detail)"
}
```

- `category ∈ {vuln, weak_config, tamper, malware, bad_link}`（`leak` 归 C）；`severity ∈ {critical, high, medium, low}`。
- **签名公式**：`sha256("{asset_url}|{category}|{title}|{detail}")`（UTF-8，管道符拼接）。`detail` 只作签名输入、不落库，明文存于 `raw_output` 的 `detail` 键。
- detail 约定：nuclei→模板 ID（`CVE-2022-3590`）；wpscan→`wpscan:{组件}`；安全头→`header:{头名}`；tamper→`tamper:{归一化内容sha256前8位}`；malware→`malware:{特征名}`；bad_link→`badlink:{域名}`；TLS→`testssl:{finding id}`。
- 时区：本服务输出 UTC；C 侧 timestamptz 存储展示自行转换。

### 3.3 资产对象（discovery 输出）

```json
{"url": "...", "host": "...", "fingerprint": {"cms": "wordpress", "server": "nginx"},
 "status_code": 200, "page_hash": "sha256(页面内容)", "title": "页面标题"}
```

`fingerprint` 可能出现 `sensitive_file` 键（本服务新增的只增字段）：标记该资产为敏感路径探测命中，供 C 优先检测。

## 4. 质量评估

```bash
python3 scripts/eval.py --quick     # 冒烟（跳过 https）
python3 scripts/eval.py             # 全量（约 25 分钟，后台跑：nohup python3 -u scripts/eval.py > eval.log 2>&1 &）
```

- 门槛：**recall ≥ 90%，fp ≤ 10%**；FP 记账口径 = 干净目标命中 + known_fp 清单内条目。
- 当前状态：最近一次全量 **recall 100%（6/6）**；剩余 fp 修复（对照组 10 项加固、跨域头补齐、指纹过滤、TLS 参数归一、ScanConfig 契约对齐）已全部落地，复测目标 fp = 0。

## 5. 部署（docker 化）

开发/联调直接跑 2.2 即可。并入 A 的编排时：

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
```

```yaml
# A 的 docker-compose.yml 片段（服务名必须是 detectors）
detectors:
  build: ./detectors
  container_name: detectors
  ports: ["8001:8001"]
  volumes:
    - ./detectors/nuclei-templates:/root/nuclei-templates:ro   # 工具链/模板可挂载宿主
```

A 侧环境变量：`DETECTOR_BASE_URL=http://detectors:8001`，`MOCK_MODE=0`。**8001 只走内网，不公网暴露**；扫描目标必须先过授权白名单。

## 6. 目录结构

```
secbot-detector/
├── app/
│   ├── main.py            # FastAPI 路由（5 接口 + /baselines + /health）
│   ├── schemas.py         # RiskRecord / Asset / ScanConfig（契约唯一出处）
│   ├── adapters/          # nuclei / testssl / whatweb / wpscan / httpx /
│   │                      # katana / subfinder / gobuster（统一 build_cmd/run/parse）
│   ├── detectors/         # discovery / vuln / tamper / malware / tls
│   └── utils/             # ratelimit(QPS≤5) / baseline(哈希基线) / runner(子进程)
├── scripts/eval.py        # 质量评估 harness（TP/FN/FP 记账 + 质量门槛）
├── tests/                 # pytest：签名 golden、篡改、恶意代码、TLS
├── testbed/               # docker-compose 七靶站 + expected_results.json
└── samples/               # 各接口真实输出样例（供 A mock 测试）
```

## 7. 踩坑清单（调试本服务前必读）

1. **代理环境变量劫持**：`http_proxy/https_proxy` 指向本地代理会让 nuclei/httpx 全部卡死。排查时先 `env | grep -i proxy`，按需 `unset`，不要全局导出。
2. **改了代码要先重启**：uvicorn 非 reload 模式，改完必须重启并用 `/health` 确认再验证。
3. **静默失败两兄弟**：pydantic `extra=ignore` 会静默丢弃未知字段（契约字段名错 = 配置白发）；探测循环里裸 `except: continue` 会静默吞错——至少留一行 `logger.warning`。
4. **同一值多处计算必须共用函数**：testssl 输出路径曾在 build_cmd/scan 两处各算一遍，算法差一点就"未产出 JSON"。
5. **str-Enum 陷阱**：`Severity.critical == "critical"` 为真，但 `str()`/f-string 得到 `"Severity.critical"`——字符串上下文一律用 `.value`（签名尤其）。
6. **接口边界防御**：上游可能传 Asset 也可能传 URL 字符串，适配器入口用 `getattr(x, "url", x)` 归一。
7. **后置覆盖**：多步骤写同一字段时，后写的必须合并（setdefault/update）不能赋值——fingerprint 的 `sensitive_file` 标记曾被 whatweb 覆盖抹掉。
8. **进程超时按工具定**：共享 30s 超时会杀掉 nuclei（模板加载+全量扫描需 ~25min，内部放宽到 1800s；HTTP 级 `-timeout` 仍 30s）。testssl 输出文件已存在会拒写，跑前必须删。
9. **clean 目标必须真干净**：对照组缺安全头会被 misconfiguration 模板报误报；加固要固进镜像源码（`docker exec` 改动容器重建即失）。
10. **每个假设先被一条命令证伪再换方向**：nuclei"卡死"先后排除了代理、缓存损坏、僵尸进程才定位到真因。
11. **bind-mount 陷阱**：挂载源路径不存在会被 Docker 自动建成目录（nginx 因此起不来）；`rm` 通配符前先看一眼路径。
12. **长任务纪律**：全量 eval 约 25 分钟，一律 `nohup python3 -u ... > log 2>&1 &`，勿前台等待勿 Ctrl+C（中断会损坏 nuclei 缓存并留孤儿进程）。
13. **eval 前冻结环境**：流水线跑一半改靶场，结果混用新旧状态；失败基线也要 commit，保留"失败→修复→PASS"轨迹。
14. **契约修改要成双**：模型字段和读取处一起改（只改读取处 = 半吊子，更隐蔽）。

## 8. TODO / 路线图

- [ ] 公网目标实测（subfinder/httpx/katana 全链路目前仅在 testbed 验证）
- [ ] nuclei info 级模板结果降噪（过滤或降级，需与 A/C 对齐口径）
- [ ] testssl 弱 cipher 明细合并为聚合条目（契约级改动，先对齐 A/C）
- [ ] 工具链打入镜像（当前建议挂载宿主工具，交付镜像需内置）
- [ ] 与 A 联调：超时表、指纹 enrichment、静态资源过滤约定的端到端验证
- [ ] 与 C 联调：`sensitive_file` 资产标记 → C 敏感引擎的衔接验证

## 9. 协作约定

- 契约只增不改；任何变更当天同步 A/C 并更新 contracts/ 目录。
- 联调问题清单三方共享，每条有唯一责任方，先记现象再改代码。
- 仓库代码即进度：完成一个模块即 commit + push，避免"目录为空"式误会。
