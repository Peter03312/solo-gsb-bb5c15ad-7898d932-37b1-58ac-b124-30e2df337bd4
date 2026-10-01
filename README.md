# TLS 证书换发核验服务（tls-cert-checker）

面向运维团队的**离线** TLS 证书换发核验服务。导入 PEM 证书链与分版本的本地信任根，
为域名登记现用（current）/拟启用（planned）证书的服务窗口，按 X.509 规则校验
签名链、CA 约束、域名 SAN 与有效期，并评估指定区间内是否存在证书覆盖断档；
仅无断档的计划可批准，批准即冻结判定依据。

- 技术栈：Python 3.11 · FastAPI · SQLite（标准库 sqlite3）· cryptography
- 全部计算在本地完成，不依赖任何外部服务，可离线运行

## 快速启动

### Docker Compose（一键启动并初始化）

```bash
docker compose up --build
```

启动后自动建库并写入演示数据（演示 CA、两个域名的证书/窗口/计划，详见下文），
服务地址：**http://localhost:8000**，交互式 API 文档：**http://localhost:8000/docs**。

### 本地运行

```bash
pip install -r requirements.txt
SEED_DEMO=1 python -m scripts.seed_demo          # 可选：写入演示数据
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `TLS_CHECKER_DB` | 容器内 `/data/tls_checker.db`，本地 `./data/tls_checker.db` | SQLite 数据库文件路径 |
| `SEED_DEMO` | `1` | 启动时是否写入演示数据（幂等，已初始化则跳过） |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | 监听地址与端口 |

## 概念与规则

- **信任根版本**：每个版本是一组 PEM 根证书；首个导入的版本自动激活，
  `POST /trust-roots/{version}/activate` 切换在用版本。
- **证书链**：导入的 PEM 中第一个块为叶子证书，其余为中间证书；
  以叶子证书 DER 的 SHA-256 为指纹，全局唯一。
- **服务窗口**：域名 + 证书指纹 + 角色（current/planned）+ UTC 半开区间
  `[start, end)`；前一窗口的 `end` 与后一窗口的 `start` 相接**不算断档**。
- **X.509 校验**：签名链必须逐级验证至在用版本信任根；链上每个签发者必须
  `basicConstraints CA=TRUE`、不超出 `pathLength`、`keyUsage` 含 `keyCertSign`；
  叶子证书 SAN 须匹配域名（支持 `*.example.com` 单标签通配）；
  评估时刻须落在整条链的有效期交集内。
- **断档评估**：在 `[eval_start, eval_end)` 内，每一时刻至少一张证书
  「处于服务窗口且验证通过」。返回全部断档区间与每张证书的不可用原因。
- **批准与冻结**：仅无断档计划可批准；批准时在**同一一致性边界**冻结
  证书指纹集合、实际参与评估的服务窗口集合、信任根版本、撤销快照版本与
  判定结果。冻结的窗口依据直接取自该次判定（不可变评估历史），后续窗口
  增删、信任根/快照切换或再次批准均无法改写；每次批准各自独立冻结。
- **审计证据包（离线复核）**：可针对任一批准下载自包含的 ZIP 证据包
  （`GET .../approvals/{id}/evidence`），内含该次批准的域名与评估区间、
  判定、实际参评服务窗口、证书链、信任根 PEM 与所选 CRL 快照 PEM，
  逐文件 SHA-256 摘要写入清单；证据包字节可复现（确定性打包）。复核端
  `POST /evidence/verify` **只使用包内材料**重算覆盖、X.509 链与撤销
  结论，不读取/导入/修改当前业务数据：逐字段一致 → `consistent`；
  材料合法但结论对不上 → `inconsistent` 并给出 `differences`；缺项、
  指纹不符、版本不符、非法时间、摘要不符等 → 带 `code` 的可解释错误。
  **本轮改造前的既有批准**缺少可还原的窗口依据，证据包接口明确返回
  `409 approval_not_replayable`，不会按当前窗口补齐；批准历史中的
  `replayable` 字段标识某条批准是否可复核。
- **待复核**：信任根换版、撤销快照切换或服务窗口增删后，相关已批准计划自动
  转为 `pending_review`；历史评估与历史批准（含冻结判定）全部保留，
  重新评估无断档后可再次批准。
- **域名级窗口变更（预演 + 原子提交）**：换发证书时可按单个域名把
  「撤下旧窗口 + 登记新窗口」组成一次变更。`POST /window-changes/preview`
  只读预演：基于候选窗口集合，按每个相关计划当前选定的信任根及可选 CRL
  快照重算，返回各计划变更前后的断档区间、阻断原因与提交校验标识
  （`change_token`），不改动窗口、评估或批准历史。`POST /window-changes/commit`
  须携带该标识：预演后域名窗口、相关计划状态或判定依据（信任根/快照选择）
  已变化 → 409 拒绝过期预演；候选状态使任一当前已批准计划出现断档 → 409
  整组拒绝、不产生部分变更；否则原子应用全部增删，相关已批准计划转待复核，
  历史冻结批准保留。空变更/重复删除/跨域删除/无效区间 → 400；
  未知窗口/证书指纹 → 404。
- **离线撤销快照（可选）**：换发计划可选择一个不可变的带版本 PEM CRL 快照。
  导入时逐张验证签名（须由已导入的 CA 证书签署且带 `cRLSign`），拒绝重复版本、
  同一签发者的冲突列表与无法解析的内容。选择快照的计划在每次评估中，须为
  证书链每张**非根证书**找到由其签发者签署的 CRL；证书仅在
  `[thisUpdate, nextUpdate)` 内且**尚未到撤销生效时刻**的时段可用，缺失、
  过期或已撤销的时段计入断档，并返回逐证书原因。撤销可用区间还须与原有服务
  窗口、证书有效期和评估区间求交；端点相接不算断档。重评可切换快照
  （显式传 `null` 取消），切换会使已批准计划先转待复核；历史评估与冻结批准
  保留各自的快照版本与判定。**未选择快照的既有计划保持原评估与响应语义。**
  非法 CRL、未知快照或不完整的撤销证据不会被静默判为安全。
- **拒绝规则**：PEM 格式错误 → 400；无效时间窗口/评估区间 → 400；
  非法/未签名/未知签发者 CRL → 400；未知信任根版本/证书指纹/快照版本 → 404；
  重复信任根版本/证书指纹 → 409；快照版本重复、同一签发者冲突/重复 CRL → 409；
  时间戳缺时区 → 422。

## API 一览（前缀 `/api/v1`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| POST | `/trust-roots` | 导入信任根版本（PEM bundle） |
| GET | `/trust-roots` | 列出版本 |
| POST | `/trust-roots/{version}/activate` | 切换在用版本（触发待复核） |
| POST | `/crl-snapshots` | 导入带版本的 PEM CRL 快照（验签/拒绝冲突） |
| GET | `/crl-snapshots` / `/crl-snapshots/{version}` | 列出/查询快照（含逐签发者有效期） |
| POST | `/certificates` | 导入 PEM 证书链 |
| GET | `/certificates` / `/certificates/{fp}` | 查询证书 |
| POST | `/service-windows` | 登记服务窗口 |
| GET | `/service-windows?domain=` | 查询窗口 |
| DELETE | `/service-windows/{id}` | 删除窗口（触发待复核） |
| POST | `/window-changes/preview` | 预演域名级窗口变更（只读，返回前后断档/阻断原因/提交校验标识） |
| POST | `/window-changes/commit` | 原子提交预演过的窗口变更（携带标识；过期或阻断 → 409） |
| POST | `/plans` | 创建计划并立即评估（可带 `crl_snapshot_version`） |
| GET | `/plans` / `/plans/{id}` | 查询计划（含最新评估与批准） |
| POST | `/plans/{id}/evaluate` | 重新评估（可换信任根版本/快照；省略沿用，null 取消快照） |
| POST | `/plans/{id}/approve` | 批准（仅无断档，冻结快照版本） |
| GET | `/plans/{id}/evaluations` | 评估历史 |
| GET | `/plans/{id}/approvals` | 批准历史（冻结判定；`replayable` 标识可否复核） |
| GET | `/plans/{id}/approvals/{approval_id}/evidence` | 下载批准的离线审计证据包（ZIP） |
| POST | `/evidence/verify` | 仅用证据包内材料离线复核（multipart 上传 ZIP） |

## 调用示例

以下示例假设服务运行于 `http://localhost:8000` 且已写入演示数据
（`SEED_DEMO=1`，演示计划 #1 已批准、计划 #2 有断档）。
完整可执行脚本见 `scripts/demo.sh`：`./scripts/demo.sh`。

### 1. 导入信任根版本

```bash
jq -n --arg v "root-2026Q3" --rawfile pem root-ca.pem '{version: $v, pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/trust-roots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"root-2026Q3","cert_count":1,"is_active":false,...}
# 版本重复 → 409；PEM 错误 → 400
```

### 2. 导入证书链（叶子在前，中间证书随后）

```bash
jq -n --arg pem "$(cat leaf-and-intermediate.pem)" '{label: "api.example.com-2026", pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/certificates \
      -H 'Content-Type: application/json' -d @-
# 201 → {"fingerprint_sha256":"ab12...","san_dns":["api.example.com"],...}
# 指纹重复 → 409
```

### 3. 登记服务窗口（现用 + 拟启用，端点相接）

```bash
FP=<上一步返回的 fingerprint_sha256>
curl -s -X POST http://localhost:8000/api/v1/service-windows \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"api.example.com\",
    \"certificate_fingerprint\": \"$FP\",
    \"role\": \"current\",
    \"start\": \"2026-01-01T00:00:00Z\",
    \"end\":   \"2026-07-01T00:00:00Z\"}"
# 再为拟启用证书登记 [2026-07-01, 2027-01-01) 的 planned 窗口……
```

### 4. 创建计划并评估

```bash
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo-gap.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z"}'
```

响应（节选，演示数据中存在 14 天断档）：

```json
{
  "plan": {"id": 3, "status": "pending", "trust_root_version": "demo-root-v1", ...},
  "evaluation": {
    "has_gaps": true,
    "gaps": [{"start": "2026-06-01T00:00:00.000Z", "end": "2026-06-15T00:00:00.000Z"}],
    "certificates": [
      {"role": "current",  "usable_intervals": [{"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-01T00:00:00.000Z"}], "reasons": []},
      {"role": "planned",  "usable_intervals": [{"start": "2026-06-15T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}], "reasons": []}
    ]
  }
}
```

证书不可用原因示例：`SAN ['x'] does not match domain '...'`、
`signature chain incomplete: ...`、`CA constraint violation: ... CA=FALSE`、
`certificate chain expires at ..., before window end ...`。

### 5. 批准计划（仅无断档）

```bash
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve
# 200 → approval 中冻结 cert_fingerprints / trust_root_version / verdict
curl -s -X POST http://localhost:8000/api/v1/plans/2/approve
# 409 → {"detail":"plan has 1 coverage gap(s); only gap-free plans can be approved"}
```

### 6. 信任根换版 → 待复核 → 复核

```bash
curl -s -X POST http://localhost:8000/api/v1/trust-roots/root-2026Q4/activate
# → {"plans_marked_pending_review": N}，冻结版本不一致的已批准计划转为 pending_review
curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"trust_root_version": "root-2026Q4"}'
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve     # 无断档后重新批准
curl -s http://localhost:8000/api/v1/plans/1/approvals           # 历史判定全部保留
```

### 7. 导入离线撤销快照（PEM CRL）

```bash
jq -n --arg v "crl-2026Q3" --rawfile crl ca-2026Q3.crl '{version: $v, pem: $crl}' \
  | curl -s -X POST http://localhost:8000/api/v1/crl-snapshots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"crl-2026Q3","crl_count":1,"items":[{"issuer":"CN=Root CA",
#          "this_update":"...","next_update":"...","revoked_count":0}]}
# 重复版本/同一签发者冲突列表 → 409；PEM 无法解析 → 400；
# 签名验证失败/签发者 CA 未导入/无 cRLSign → 400
```

### 8. 创建选择快照的计划

```bash
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "api.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z",
    "crl_snapshot_version": "crl-2026Q3"}'
```

响应中每张证书新增 `revocation`（链上每张非根证书一项），包含命中的
CRL（`this_update`/`next_update`/`revoked`）与逐证书原因；`usable_intervals`
已与 CRL 可用区间求交。例如 CRL 在评估期内过期：

```json
{"role": "current",
 "usable_intervals": [{"start": "2026-01-01T00:00:00.000Z",
                       "end":   "2026-10-01T00:00:00.000Z"}],
 "revocation": [{"subject": "CN=api.example.com",
                 "issuer": "CN=Root CA",
                 "crl": {"this_update": "2025-12-01T00:00:00.000Z",
                         "next_update": "2026-10-01T00:00:00.000Z",
                         "revoked": null},
                 "reasons": ["CN=api.example.com: CRL from issuer 'CN=Root CA'"
                             + " expires at 2026-10-01..., coverage missing after that"]}],
 "reasons": ["CN=api.example.com: CRL from issuer ... coverage missing after that"]}
```

其他典型原因：`no CRL signed by issuer '...' found in snapshot`（缺失）、
`CRL ... expired at ..., before window start ...`、
`certificate ... revoked at 2026-06-01T00:00:00.000Z`。

### 9. 重评切换快照与待复核

```bash
# 切换到另一个快照版本（未知版本 → 404，绝不静默放行）
curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": "crl-2026Q4"}'
# 已批准计划立即转为 pending_review，旧冻结批准置 superseded 但完整保留

curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": null}'   # 取消快照
# 省略该字段则沿用计划当前选择；取消后回到无快照的原始评估与响应语义
```

### 10. 域名级窗口变更：预演 → 原子提交

把「撤下旧窗口 + 登记新窗口」组成一次变更。预演只读，返回各相关计划
变更前后的断档与提交校验标识；提交携带标识，原子应用全部增删。

```bash
# 10.1 预演：撤下 demo.example.com 的 current 窗口（id=1）且无接替
curl -s -X POST http://localhost:8000/api/v1/window-changes/preview \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo.example.com",
    "delete_window_ids": [1]}'
```

响应（节选）：已批准计划 #1 变更后将出现断档 → 阻断原因；窗口/评估/批准
历史均未被改动。

```json
{
  "change_token": "wc1.98b2…",
  "would_block": true,
  "blocking_reasons": ["plan #1 is approved and the change would open 1 coverage gap(s): [2026-01-01T00:00:00.000Z, 2026-07-01T00:00:00.000Z)"],
  "plans": [{"plan_id": 1, "status": "approved",
             "before": {"has_gaps": false, "gaps": []},
             "after":  {"has_gaps": true,  "gaps": [{"start": "2026-01-01T00:00:00.000Z", "end": "2026-07-01T00:00:00.000Z"}]}}]
}
```

```bash
# 10.2 预演：撤下旧窗口并登记等价接替窗口（证书指纹 FP 为已导入证书）
FP=<current 证书指纹>
PREV=$(curl -s -X POST http://localhost:8000/api/v1/window-changes/preview \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"demo.example.com\",
    \"delete_window_ids\": [1],
    \"add_windows\": [{\"certificate_fingerprint\": \"$FP\", \"role\": \"current\",
                       \"start\": \"2026-01-01T00:00:00Z\", \"end\": \"2026-07-01T00:00:00Z\"}]}")
TOKEN=$(echo "$PREV" | python3 -c "import json,sys;print(json.load(sys.stdin)['change_token'])")
# would_block=false → 提交（标识原样带回，变更内容须与预演一致）
curl -s -X POST http://localhost:8000/api/v1/window-changes/commit \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"demo.example.com\",
    \"change_token\": \"$TOKEN\",
    \"delete_window_ids\": [1],
    \"add_windows\": [{\"certificate_fingerprint\": \"$FP\", \"role\": \"current\",
                       \"start\": \"2026-01-01T00:00:00Z\", \"end\": \"2026-07-01T00:00:00Z\"}]}"
# 200 → {"deleted_windows":[…], "created_windows":[…], "plans_marked_pending_review":1}
# 已批准计划 #1 转 pending_review，历史冻结批准置 superseded 并保留；
# 重新评估无断档后可再次批准（同第 6 节）。

# 10.3 拒绝规则
# - 预演后窗口/计划状态/判定依据变化，或提交内容与预演不一致 → 409 stale token
# - 候选状态使任一已批准计划断档 → 409 且无任何部分变更
# - 空变更/重复删除/跨域删除/无效区间 → 400；未知窗口/证书指纹 → 404
```

### 11. 导出批准证据包并在离线机器复核

证据包把一次批准的**完整判定依据**打包为自包含 ZIP：`manifest.json`
（格式、批准标识、域名、评估区间、版本、窗口数、逐文件 SHA-256 摘要）、
`verdict.json`（冻结判定）、`windows.json`（实际参评窗口）、
`materials/trust-root.pem`、`materials/certificates/<指纹>.pem`，以及选择了
撤销快照时的 `materials/crl-snapshot.pem`。

```bash
# 11.1 取计划 #1 当前有效批准（批准历史新增 replayable 字段）
curl -s http://localhost:8000/api/v1/plans/1/approvals
# → 本轮新批准: {"id":4,"replayable":true,"frozen_windows":[...], ...}
# → 本轮改造前的既有批准: {"replayable":false,"frozen_windows":null, ...}

# 11.2 下载证据包（只读，不改动任何业务数据）
curl -s -o approval-4-evidence.pkb.zip \
  http://localhost:8000/api/v1/plans/1/approvals/4/evidence
python3 -c "import zipfile;print(zipfile.ZipFile('approval-4-evidence.pkb.zip').namelist())"
# ['manifest.json', 'verdict.json', 'windows.json',
#  'materials/trust-root.pem', 'materials/certificates/<fp>.pem', ...]

# 11.3 把 ZIP 拷到离线复核机，只用包内材料重算覆盖 / X.509 / 撤销
curl -s -X POST http://offline-box:8000/api/v1/evidence/verify \
  -F "package=@approval-4-evidence.pkb.zip;type=application/zip"
```

一致时：

```json
{
  "result": "consistent",
  "format": "tls-checker-evidence/1",
  "approval_id": 4, "plan_id": 1,
  "domain": "demo.example.com",
  "eval_interval": {"start": "2026-01-01T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"},
  "trust_root_version": "demo-root-v1",
  "crl_snapshot_version": null,
  "window_count": 3,
  "cert_fingerprints": ["…", "…", "…"],
  "differences": [],
  "frozen_verdict": { "…冻结判定…" },
  "recomputed_verdict": { "…仅用包内材料重算的判定…" }
}
```

材料合法但重算结论与冻结判定对不上时，HTTP 仍为 200，`result` 为
`inconsistent`，`differences` 逐字段给出差异（如 `has_gaps`、`gaps`、
逐窗口 `usable_intervals` / `reasons` / `revocation`）。

```bash
# 11.4 复核机不导入任何材料；缺项/指纹不符/版本不符/非法时间 → 可解释错误
# HTTP 4xx，body: {"detail": "...", "code": "<错误码>"}
```

| HTTP | `code` | 触发情形 |
|---|---|---|
| 409 | `approval_not_replayable` | 既有批准无冻结窗口依据，不可复核（不用当前窗口补齐） |
| 404 | — | 未知计划 / 批准 ID |
| 400 | `malformed_package` | 非 ZIP、结构损坏、路径不安全、JSON 非法、窗口/指纹字段非法 |
| 400 | `missing_material` | 缺少清单声明的必需文件或摘要项 |
| 400 | `invalid_time` | 时间戳无法解析、缺时区、`start >= end`、CRL 时间倒置 |
| 400 | `invalid_trust_root` / `invalid_certificate` / `invalid_crl` | 包内 PEM 无法解析 |
| 422 | `unsupported_format` | 证据包格式版本不受支持 |
| 422 | `digest_mismatch` | 文件 SHA-256 与清单摘要不符（材料被改动） |
| 422 | `fingerprint_mismatch` | 证书叶子指纹与文件名/窗口声明不符 |
| 422 | `manifest_mismatch` | 冻结判定与清单头不一致（区间/版本/窗口数等） |
| 422 | `frozen_basis_mismatch` | `windows.json` 与判定的参评窗口不一致（非同一一致性边界） |
| 422 | `frozen_verdict_invalid` | 冻结判定本身有断档（不可能是有效批准） |
| 422 | `crl_signature_invalid` | 包内 CRL 在包内 CA 中找不到有效签发者 |
| 413 | `package_too_large` | 证据包超过 16 MiB |

> 复核过程零业务库访问：即使在原机器上对同一服务调用
> `/evidence/verify`，也不会读取或改动当前窗口、信任根、快照、评估与
> 批准，结论只取决于上传的包。

## 项目结构

```
app/
  main.py       FastAPI 路由
  service.py    业务逻辑（导入/窗口/CRL 快照/评估/批准/待复核/证据包生成）
  evidence.py   审计证据包：确定性 ZIP 装配与仅用包内材料的离线复核
  certutils.py  PEM 解析、签名链构建、CA 约束与 SAN 校验
  crlutils.py   PEM CRL 解析、签发者匹配与签名验证
  coverage.py   半开区间断档与求交计算
  db.py         SQLite 连接、建表与轻量迁移
  models.py     请求模型（时区强制、域名归一化）
scripts/
  seed_demo.py  离线生成演示 CA/证书/CRL 并初始化演示数据（幂等）
  demo.sh       端到端 curl 调用示例（含证据包导出/离线复核）
  docker-entrypoint.sh
tests/          pytest 测试（96 例，覆盖全部拒绝规则、CRL 证据、复核流程、
                窗口变更预演/提交，以及审计证据包冻结/导出/篡改/不可复核）
Dockerfile / docker-compose.yml
```

## 本轮变动（审计证据包）

- 批准在原有冻结基础上**新增冻结实际参评服务窗口集合**（`approvals.frozen_windows`，
  经轻量迁移自动加列）；窗口集合与判定取自同一次不可变评估，处于同一一致性边界。
- 新增证据包下载与离线复核两个 HTTP 接口；依赖新增 `python-multipart`（上传）。
- 批准历史与批准响应新增 `frozen_windows`、`replayable` 两个只读字段，
  其余既有接口的请求/响应语义保持不变。
- 既有批准（迁移前产生、无冻结窗口）一律 `replayable=false`，证据包接口返回
  `409 approval_not_replayable`；重新评估并**再次批准**后生成的新批准可正常出包。
