# M0 私有试用版 QA 执行证据模板

本模板仅在三份中文报告已获 Human 逐份接受，且候选 commit、image digest、规则/接口/环境均写入不可变清单后使用。验收定义已绑定 core `a39ba5584e5ed17cef2fe91e2dc8f4b788ca80db` 与 runtime addendum `fe1440b94405e113d64934865fae953e906e3669`，但这不是产品 PASS。当前正式执行次数为 `0`。

## 1. 冻结身份

- Run ID：
- 开始/结束时间（UTC）：
- QA owner：`swat-qa`
- 执行轮次：`1` 或唯一有界复测 `2`
- 首轮 Run ID 与允许复测用例（仅轮次 2）：
- mgr 复测授权引用（仅轮次 2）：
- M0 report/evidence core 完整 Git SHA（必须为 `a39ba5584e5ed17cef2fe91e2dc8f4b788ca80db`）：
- M0 runtime addendum 完整 Git SHA（必须为 `fe1440b94405e113d64934865fae953e906e3669`）：
- Matrix 完整 Git SHA：
- Human 索引报告 acceptance ref / artifact SHA-256：
- Human 统计报告 acceptance ref / artifact SHA-256：
- Human 重复扫描报告 acceptance ref / artifact SHA-256：
- SUT 完整 Git SHA：
- 工作树：`clean`；否则停止
- 应用 OCI image digest：
- 逐字启动命令 SHA-256：
- 启用接口清单 SHA-256：
- 延期路由清单 SHA-256：
- CLI allowlist/退出码清单 SHA-256：
- Evidence/v2 schema SHA-256：
- 规则包 SHA-256：
- 规则 ID / TiDB 边界 / 正反缺证据清单 SHA-256：
- 报告 schema/renderer SHA-256：
- 只读查询清单 SHA-256：
- 连接/查询 deadline 与禁止自动重试/重连策略 SHA-256：
- 连接成功 8 个安全字段集合 SHA-256：
- 镜像内 `asyncmy==0.2.14` distribution 文件名 / SHA-256：
- 镜像内 runtime adapter 行为探针证据 SHA-256：
- `#t23` 同 commit/image digest 定向审查 ref / result（可在 QA 执行后、总体结论前补入）：
- TiDB 环境清单 SHA-256：
- 三场景 seed/ground-truth 清单 SHA-256：

除明确标注可在总体结论前补入的 `#t23` 引用外，任一字段缺失或与冻结清单不一致，整体为 `BLOCKED`；不得先执行局部用例。Human 选择“方案 2”不能替代三份报告的逐份 acceptance ref。

## 2. 环境

- Host OS/kernel/architecture：
- Docker client/server：
- 主机时钟与时区：
- 执行前容器、卷、镜像与端口清单：
- 应用 image RepoDigest / image ID：
- 容器 inspect SHA-256：
- 容器只读根文件系统、`/tmp` tmpfs、唯一 `/data` 卷与无 `/secrets` inventory SHA-256：
- 宿主 socket 监听 SHA-256：
- Chromium/Playwright 版本与新 profile ID：
- TiDB 精确版本、拓扑与实例 ID：
- 应用专用账号与脱敏 grants SHA-256：
- 三场景 schema/dataset ID：
- 执行后清理或保留策略：

## 3. 用例记录

为矩阵中的每个 ID 复制一份：

### `<CASE-ID>`

- 冻结对象：
- 环境/场景/fault ID：
- 精确步骤或命令：
- 预期结果：
- 实际结果：
- 结果：`PASS` / `FAIL` / `BLOCKED` / `UNVERIFIED`
- 缺陷 ID 与严重度（若失败）：
- 阻塞条件与 owner（若阻塞）：
- 原始证据相对路径与 SHA-256：
- 脱敏说明：

`PASS` 必须同时具备可复现步骤、实际观察和原始证据。作者门禁、容器健康、接口 200、job completed、存在 hypothesis 或截图摘要都不充分。

## 4. 建议证据目录

```text
evidence/<run-id>/
  freeze-manifest.json
  environment.json
  commands/
  adapter/
  browser/
  cli/
  http-redacted/
  tidb-raw-redacted/
  query-audit/
  scenarios/
  reports/
  routes/
  secret-scan/
  screenshots/
  evidence-index.sha256
```

最低证据要求：

- 冻结对象：两段契约的完整 SHA、完整 SUT commit、OCI digest、各清单 digest、Human acceptance refs；不得拼接不同候选证据。
- 主旅程：新 Chromium profile 的 trace、console/network、桌面与 `390px` 截图/layout 指标和脱敏响应。
- Owner/auth：setup/status、唯一 Owner 创建、session/logout/login、第二次创建拒绝及使用同一 `/data` 卷重启后登录证据；只保存密码 canary 哈希。
- 三场景：seed/ground truth、TiDB 原始证据、Evidence/v2 schema 校验、规则命中、报告 JSON；索引场景保留 SQL 结构、普通 EXPLAIN、索引元数据、Slow Query 实测扫描放大及四角色关联；统计场景保留 `SHOW STATS_HEALTHY` 对目标非分区表的精确列集与唯一行；重复扫描场景保留 Statement Summary、匹配 Slow Query 原始列、`weightedTotalKeys`、`ROUND_HALF_UP` 加权平均及窗口稳定性独立复算。
- Evidence 来源：SQL 级角色绑定 `sql:<digest>`/窗口，表级角色绑定 SQL 结构声明的表；typed projector 结果必须经冻结 ServerQuery registry/binder equality、预算/截断、raw/typed digest 与 context 校验的 managed-Evidence wrapper 后才可作为运行时 `CollectedEvidence`。三份 Human 样例必须标记 `fixture/review-only`，不得冒充真实采集。
- 报告语义：`businessEvidenceIds=[]` 时固定显示“未提供业务影响证据，仅说明数据库技术影响”；P1 升级和 completeness 均保存独立复算证据。
- 只读：专用账号 grants、实际语句审计与冻结 registry/binder 清单的机器 diff、双语句 payload 在 driver I/O 前拒绝的证据。兼容层私有字段实现由 `#t23` 定向审查；QA 只核对同一镜像行为探针与实际语句，不重复实现审查。
- 秘密：Owner 与 TiDB 独立 canary 哈希、明确扫描范围、原文及常见编码零匹配；Owner 仅允许不可逆 verifier 持久化，TiDB 凭据不得进入 `/data`、`/proc/self/environ` 或 `/secrets` fallback；同候选行为探针/Reviewer 证据必须证明 `_password=b""`、`_password_creator=None` 后才进行 identity I/O；原始 canary 不进入证据。
- 生命周期：idle disconnect、活动 probe/query 下 logout、shutdown、重复清理、generation 竞态与 close-timeout abort；`force_close` 不返回 `M0_BUSY`，清理后无 socket/task 且 TiDB 必须重新录入。
- localhost/404/CLI：container/socket inspect、隔离网络探测、全 method/path/status 结果、禁用 `/docs`/`redoc`/`openapi.json` 的 404、UI inventory，以及只有默认/`web-api` 可进入、延期 CLI 在导入旧逻辑前退出 `64` 的证据。
- 超时/TLS/缺证据：fault ID、单调时钟时间线、`ssl.create_default_context()` 的 `CERT_REQUIRED`/hostname check 与无降级证据、5 秒总 I/O deadline、30 秒诊断上限、无自动重试/重连、取消/`force_close`、降级与重新录入恢复证据。

## 5. 脱敏与完整性

- 密码、cookie、CSRF、SQL literal、业务行数据和未经批准的原始证据不得进入聊天、提交或公开附件。
- 可以记录 secret canary 的 SHA-256，不能记录 canary 原文。任何工具输出意外包含原文时立即停止、销毁副本、轮换凭据并记 `FAIL`。
- HTTP trace 必须移除提交凭据的 request body/Authorization；仍需保留 method、route、时间、状态和关联 ID。
- 每个证据文件计算 SHA-256；`evidence-index.sha256` 自身写入 task checkpoint。
- 脱敏不能删除复现所需的版本、时间、状态、digest、引用关系和错误码。

## 6. 批次结论

- 各结果计数：
- Critical/High 缺陷：
- 产品价值阻断：
- BLOCKED/UNVERIFIED 项：
- 唯一总体结论：`PASS` / `FAIL` / `BLOCKED` / `UNVERIFIED`
- 唯一复测范围（若批准）：
- 新增非阻断 backlog（不进入本轮）：
- 残余风险与 owner：

只有 15 项全部 PASS、三份 Human acceptance ref 可追踪、所有冻结 digest 一致、`#t23` 对同一候选无未关闭 Critical/High，且三份运行时报告与真实证据一致时，整体才能为 PASS。
