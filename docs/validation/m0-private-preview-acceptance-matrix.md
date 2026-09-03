# M0 私有试用版产品与真实链路验收矩阵

状态：`FROZEN`（定义已冻结；正式执行仍为 `0` 且门禁状态为 `BLOCKED`）

唯一契约输入：

- report/evidence core：`a39ba5584e5ed17cef2fe91e2dc8f4b788ca80db`
- runtime addendum：`fe1440b94405e113d64934865fae953e906e3669`

这两个 SHA 只冻结验收定义，不证明 runtime、真实 TiDB、Chromium 或产品
PASS。三份中文报告尚未获 Human 逐份接受，候选 commit/image digest
也未冻结；因此 15 项初始结果全部保持 `UNVERIFIED`，不得执行。

负责人：`swat-qa` / `#t22`

适用范围：localhost、单用户、单 TiDB v8.5.x、一次性内存凭据、rules-only 的异常 SQL 诊断私有试用版。

## 1. 验收目标

本矩阵只回答一个问题：用户能否在一个冻结镜像上，经由一条真实浏览器旅程，把一个真实 TiDB 异常 SQL 转换为有原始只读证据支撑、可理解且可行动的中文报告。

`容器启动、接口返回 200、job completed 或存在 hypothesis 均不能单独构成 PASS`。三份样例报告未经 Human 逐份接受，或候选 commit/image digest 未冻结时，正式执行必须保持为 `0`。

## 2. 已批准边界

### 2.1 M0 只包含

- 一个仅在宿主发布 `127.0.0.1:18080` 的只读根文件系统应用容器；唯一命名可写卷是 `/data`，只保存 Owner SQLite/session material，镜像不得声明或创建 `/secrets`。
- 一个持久化的本地 Owner；保留首次 Owner 创建及 `GET /api/v1/auth/session`、`POST /api/v1/auth/login`、`POST /api/v1/auth/logout`。
- 一个 TiDB v8.5.x 实时连接；凭据只在本次进程内存中使用。首次连接失败关闭 candidate；logout、显式断开、I/O 超时或进程退出关闭已安装连接并要求重新输入；失败的 replacement 则必须保留旧 ready 连接。
- 精确 `asyncmy==0.2.14` 兼容层：握手前清除并回读 `_client_flag & MULTI_STATEMENTS == 0`；`Connection.connect()` 返回或抛错后的立即 `finally` 路径清空并回读 `_password=b""` 与 `_password_creator=None`；任一不可证就 fail closed，禁止 reconnect。
- 服务端固定的只读证据采集；用户输入和数据库内容都不能变成任意 SQL、工具或命令。
- rules-only；覆盖索引访问、统计/估算、重复扫描或执行热点三类代表性异常 SQL。
- 中文报告固定呈现：结论、影响、证据、建议、验证、回滚、不确定性。

M0 只注册 `/healthz`、`/api/v1/setup/status`、`/api/v1/setup/owner`、`/api/v1/auth/session`、`/api/v1/auth/login`、`/api/v1/auth/logout`、`/api/v1/m0/connection`、`/api/v1/m0/sql-candidates` 和 `/api/v1/m0/diagnoses` API families。

### 2.2 M0 明确延期

`GET /api/v1/setup/status`、`POST /api/v1/setup/owner`、`GET /api/v1/auth/session`、`POST /api/v1/auth/login`、`POST /api/v1/auth/logout` 是 M0 必需入口，不能被延期路由规则误伤。

以下能力既不能出现在 UI/OpenAPI，也不能以隐藏或未完成路由存在；冻结清单中的每个历史及新版路径都必须返回 `404`：

- legacy bootstrap、model/settings 和旧 `/cases/sql`/job 路线。
- 多 Source CRUD、持久化、轮换、删除、ledger、receipt 和恢复。
- PingKaiDB、Prometheus/TEM、告警入口和 release APIs。
- AI、模型配置和模型调用。
- Plan Replayer、Clinic/压缩包或手工资料入口。
- 跨平台制品、发布供应链、SBOM、签名和 provenance。

容器入口只允许默认命令或显式 `web-api`；`migrate`、`bootstrap-ingest`、
`bootstrap-reissue` 和任意其他参数必须在未导入旧恢复代码前退出 `64`。

Owner 认证状态可以保存在本地 SQLite；TiDB 凭据、Evidence、Diagnosis Case 和报告均为 M0 临时态。浏览器刷新可以丢失最后一份报告，进程重启必须丢失 TiDB 连接，QA 不把这些预期行为误报为持久化缺陷。

## 3. 需求追踪

| 标记 | 冻结要求 |
|---|---|
| `M0-G1` | Human 必须在运行前逐份接受三类中文样例报告的可理解性与可行动性；选择“方案 2”本身不等于报告验收。 |
| `M0-G2` | 一次运行只允许一个 SUT commit、一个应用 image digest、一个接口清单、一个规则包、一个环境清单和一组三场景清单。 |
| `M0-J1` | 一个真实 Chromium 主旅程覆盖一次性连接、选择或提交异常 SQL、只读采集和中文报告。 |
| `M0-D1` | 三个真实 TiDB v8.5.x 场景分别覆盖索引访问、统计/估算、重复扫描或执行热点，并保留独立原始证据与 ground truth。 |
| `M0-R1` | 报告以证据为上限，包含结论、影响、证据、建议、验证、回滚、不确定性；证据不足时降级或弃答。 |
| `M0-S1` | 只允许冻结 registry/binder 重建后的单条只读查询；握手前和每次 I/O 前都能证明多语句位为零；禁止 DML、DDL、`EXPLAIN ANALYZE`、任意 SQL 和自动执行建议。 |
| `M0-S2` | 数据库秘密不进入持久化、日志、URL、响应、报告、环境、浏览器存储或提交后的 DOM；驱动密码字段在 identity I/O 前清空；进程重启后必须丢失。 |
| `M0-S3` | 容器可在 Docker 内部监听，但宿主只发布 `127.0.0.1:18080`；非本机 Host/Origin 和非回环端口访问失败。 |
| `M0-S4` | 延期能力的前后端入口不存在，冻结的历史与新版代表路径全部返回 `404`。 |
| `M0-F1` | driver `connect_timeout/read_timeout=5` 并且 connect、execute/read、async close 各有 5 秒总 I/O deadline；诊断总计 30 秒；无自动重试或重连，超时/取消进入 `force_close` 并要求重新录入凭据。 |
| `T22-A1` | 结果只允许 `PASS`、`FAIL`、`BLOCKED`、`UNVERIFIED`，每项必须有可复核原始证据。 |
| `T22-A2` | 仅执行一次完整矩阵；最多一次、仅针对首轮失败项的有界复测。 |
| `T22-A3` | QA 不重复 Reviewer 的实现审查，也不执行 AI、多 Source、Plan Replayer、跨平台或供应链门禁。 |

## 4. 执行前硬门禁

下列字段全部写入一次运行的 `freeze-manifest.json` 后，QA 才能把运行状态从 `BLOCKED` 改为 `READY`：

1. M0 report/evidence core、runtime addendum 的完整 Git SHA 与本矩阵完整
   Git SHA；core 必须精确为
   `a39ba5584e5ed17cef2fe91e2dc8f4b788ca80db`，runtime addendum 必须精确为
   `fe1440b94405e113d64934865fae953e906e3669`。
2. 三份报告的不可变 SHA-256，以及 Human 对每份报告的明确接受消息引用。
3. SUT 完整 Git SHA、应用 OCI image digest 和逐字唯一启动命令；命令必须精确包含 loopback 端口、只读根文件系统、限权参数、`/tmp` tmpfs 与唯一 `/data` 卷。
4. 启用接口清单、延期路由清单与 CLI allowlist SHA-256；清单同时覆盖历史/新版 HTTP 路径、default/`web-api` 正例及延期 CLI 退出 `64` 负例。
5. Evidence/v2、规则包、报告 schema/renderer、服务端只读查询清单、连接/查询 deadline 与禁止自动重试/重连策略的版本及 SHA-256；两个 M0 Evidence 增量必须闭合且 `additionalProperties:false`；规则清单必须固定每条稳定 ID、TiDB v8.5.x 适用边界、最小证据和正/反/缺证据判据。同一候选还必须记录安装的 `asyncmy==0.2.14` distribution 文件名/SHA-256、镜像内兼容层行为探针证据 SHA-256 及精确 8 个安全字段投影。
6. TiDB v8.5.x 环境清单、脱敏 grants、三场景 seed/ground-truth 清单及 SHA-256。
7. 主机 OS/架构、Docker client/server、时钟、端口和执行前容器/卷清单。
8. 执行轮次为 `1`；若为唯一复测，必须同时记录首轮 run ID、失败用例 ID 和 mgr 批准范围。

任一字段缺失、工作树不 clean、digest 漂移或 Human 只接受了部分报告，整体均为 `BLOCKED`，不得先跑可用部分。正式产品执行次数当前固定为 `0`；文档 validator 不计入产品执行。

## 5. 环境与证据约束

| 环境 | 冻结要求 |
|---|---|
| `ENV-HOST` | 无旧 M0 容器/卷、端口空闲；只拉取冻结 image digest；记录 Docker inspect、socket 监听、启动日志、`/data` 卷布局、`/secrets` 不存在证据及镜像内 asyncmy distribution 指纹。 |
| `ENV-TIDB` | 一个隔离 TiDB v8.5.x 环境；测试管理员负责 seed，应用使用独立只读账号；三个场景与其他负载隔离。 |
| `ENV-BROWSER` | 一个新 Chromium profile；记录 Playwright/DevTools trace、console、network、storage 与关键截图。 |
| `ENV-FAULT` | 冻结的不可达连接、TLS 信任链/主机名失败、连接超时、查询超时、竞态、缺失或矛盾证据条件；不得临时增加故障种类。 |

原始数据库证据必须能关联到 TiDB 实例、版本、账号、时间窗、SQL digest、采集时间和查询模板。三场景不得只用 JSON fixture、mock、截图或作者自报替代真实 TiDB 观测。

## 6. 结果判定

- `PASS`：冻结对象上的实际行为完全满足预期，并有完整、脱敏且带 SHA-256 的原始证据。
- `FAIL`：观察到产品行为与预期不符。秘密泄漏、非只读查询、非回环暴露、延期路由非 404、伪造根因或报告缺少验证/回滚均直接阻断。
- `BLOCKED`：进入门禁、冻结对象或环境不完整，无法合法观察产品行为。它不是 PASS。
- `UNVERIFIED`：矩阵已定义但尚未执行或证据不足。它不能被转述为完成。

总体 PASS 要求 15 项全部 PASS、Human gate 可追踪、同一 commit/image digest 的 `#t23` 高风险定向审查无未关闭 Critical/High，且三份运行时报告的事实与原始证据一致。只允许一轮针对首轮失败项的复测；新增非阻断发现进入后续里程碑。

## 7. 冻结验收矩阵

| ID | 追踪 | 环境 | 步骤 | 预期 | 最低原始证据 | 初始结果 |
|---|---|---|---|---|---|---|
| `BOOT-001` | `M0-G2` `M0-S3` | `ENV-HOST` `ENV-BROWSER` | 按 freeze manifest 的唯一逐字命令以 digest 拉起应用；检查 `--read-only`、`no-new-privileges`、`cap-drop ALL`、`/tmp` tmpfs、唯一 `/data` 命名卷及镜像内无 `/secrets`；打开规范地址 `http://localhost:18080`；经 `setup/status` 创建唯一 Owner，并验证 session、logout、login；另以非规范 Host/Origin 与 Forwarded headers 尝试获取/使用 setup nonce；检查容器与宿主监听。 | 无源码构建、`.env`、Compose、默认密码、terminal bootstrap code 或第二条产品命令；只有精确 `Host: localhost:18080`、精确 Origin、无 forwarding headers 且 cookie/nonce 绑定的本机浏览器能创建唯一 Owner，第二次创建稳定拒绝；精确 digest 在只读根文件系统上启动，唯一持久挂载为 `/data`，宿主只发布 `127.0.0.1:18080`。 | 逐字命令及 SHA-256、pull/image/container inspect、mount 与文件系统 inventory、socket 监听、setup/auth 正反 HTTP 与浏览器 trace、Owner 计数、密码原文零匹配扫描。 | `UNVERIFIED` |
| `FLOW-001` | `M0-J1` `M0-R1` | `ENV-HOST` `ENV-TIDB` `ENV-BROWSER` | 以 Owner 登录，用全新 Chromium profile 输入一次性 TiDB 连接（优先 `verify_ca`；若冻结环境只允许 `disabled`，必须验证可见警告）；从 5–60 分钟窗口的候选中选择一个 SQL Digest，并提供对应的单条有界 SELECT 文本；完成索引场景的同步只读采集和报告阅读；在桌面和 `390px` 宽 viewport 各检查关键页面。 | 连接成功响应严格只有 `schema_version/connection_id/state/product/version/database/tls_mode/connected_at` 8 个安全字段；password 在连接提交 settle 后、SQL 在诊断 settle 后都从表单与 DOM 清空；候选最多 20 条且不返回 SQL/plan/literal/row/host/username；产品从不执行提交 SQL，本地解析后通过注册参数化只读函数查询核对 digest；UI 明示 rules-only/private preview，用户不拼接内部 ID 即完成主旅程；响应无 job/polling；`390px` 无全页横向溢出且关键动作可用。 | 全程 trace/录屏、console/network、脱敏请求响应与 8 字段精确集合 diff、表单 settle 前后 DOM diff、候选字段/预算核对、SQL 文本未执行证明、digest 核对与 TiDB 查询关联、桌面/390px 截图/layout 指标、最终报告 JSON。 | `UNVERIFIED` |
| `DX-001` | `M0-D1` `M0-R1` | `ENV-TIDB` | 对冻结的索引访问场景执行诊断并对照独立 ground truth。 | 只有同 case/subject 且角色级身份闭合的 `sql_structure + ordinary_plan + index + slow_query` 四角色同时 eligible，计划明确 `accessPath=table_full_scan`，索引覆盖、平均扫描行、scan/return 比与调用次数同时达到冻结阈值时，才命中 `TIDB85_INDEX_SCAN_RISK`；缺任一角色即输出 actionless `observe` 与未知/补证据。建议待 Human 批准并可验证/回滚，不自动建索引。 | seed/ground truth、目标 digest、SQL 结构、普通 EXPLAIN、索引原始响应、实测 scan/return、Evidence/v2、四角色关联校验、规则命中、报告 JSON。 | `UNVERIFIED` |
| `DX-002` | `M0-D1` `M0-R1` | `ENV-TIDB` | 对冻结的统计健康度场景执行诊断并对照独立 ground truth。 | 输出闭合 `statistics-health/v1`，仅含证据身份及 `tableName`、`healthyPercent`（0..100）；真实 `SHOW STATS_HEALTHY` 必须对目标数据库/非分区表恰好返回一行，且只有 `healthyPercent < 80` 才命中 `TIDB85_STATISTICS_HEALTH_RISK`。额外行、分区行、错表或空结果均为 gap/`observe`；不得出现 `planStats`、`estimatedRows`、`actualRows`，不得声称已证明估算偏差。 | seed/ground truth、目标 digest、`SHOW STATS_HEALTHY` 精确列集与单行原始响应、typed Evidence、角色级关联、规则命中、报告 JSON；查询审计证明未使用 `EXPLAIN ANALYZE`。 | `UNVERIFIED` |
| `DX-003` | `M0-D1` `M0-R1` | `ENV-TIDB` | 对冻结的重复扫描或执行热点场景执行诊断并对照独立 ground truth。 | 输出闭合 `statement-summary/v3`，以同一 digest/窗口的 `windowMinutes`、`executionCount`、`averageTotalKeys`、`averageProcessedKeys`、`weightedTotalKeys` 和 Slow Query 实测 scan/return 支撑；加权平均使用十进制 `ROUND_HALF_UP`，`weightedTotalKeys` 明示为聚合字段派生而非逐次原始精确总数。只有次数、加权扫描量、平均扫描行及 scan/return 比同时达到冻结阈值才命中 `TIDB85_REPEATED_HEAVY_SCAN`；`sqlStability` 复用两个最新、不重叠窗口的精确比率算法。 | seed/ground truth、目标 digest/时间窗、Statement Summary 与 Slow Query 原始列、typed Evidence、安全整数与 `weightedTotalKeys`/加权平均独立复算、窗口稳定性复算、规则命中、报告 JSON。 | `UNVERIFIED` |
| `RPT-001` | `M0-G1` `M0-R1` | `ENV-BROWSER` | 将三份运行时报告与 Human 已接受的三份 `fixture/review-only` 报告结构逐项比较，并由 QA 复核 Case、Evidence、页面事实、动作与语言。 | 全中文首屏依次回答结论、影响、证据、建议、验证、回滚、不确定性；移除固定英文废话和固定 `20%` 完整度展示；内部 ID 不主导；每个事实/动作可追到 eligible Evidence 或稳定规则 ID，缺证据不强断言。`businessEvidenceIds=[]` 时业务影响文案必须精确为“未提供业务影响证据，仅说明数据库技术影响”；正例默认 P2，仅同 digest/窗口的 eligible Slow Query `p95Ms>=5000` 且 Statement Summary `executionCount>=20` 才升 P1；completeness 按冻结 required-role 比率计算。所有报告记录 `configuredMode=rules`、`effectiveMode=rules`、`aiStatus=not_requested` 和空 AI pins。 | 三份 accepted artifact/hash/ref、三份运行时 Case/Evidence/报告 JSON 与截图、字段 diff、优先级/完整度复算、引用解析结果、QA 事实核对表。 | `UNVERIFIED` |
| `EVD-001` | `M0-D1` `M0-S1` | `ENV-TIDB` | 对三场景逐项追踪报告事实到 Evidence/v2 和实际 TiDB 观测；用冻结 schema 校验 typed payload；核对时间窗、freshness、coverage、身份和 digest。 | 所有用于结论的事实都来自本次单 TiDB 的可解析只读证据；SQL 级角色绑定 `sql:<digest>`/窗口，表级角色绑定 SQL 结构声明的表；typed projector 只返回闭合 payload，运行时必须经 registry/binder equality、预算/截断、raw/typed digest 和 context 校验的 managed-Evidence wrapper 才能形成 `CollectedEvidence`。`statistics-health/v1` 与 `statement-summary/v3` 闭合且拒绝额外字段；没有 `fixture/review-only` 冒充 runtime、跨场景串证据、过期证据或未披露截断。 | Evidence/v2 schema/digest 与校验输出、projector/managed-wrapper 边界证明、ServerQuery registry/binder equality、原始响应索引、角色级引用解析、时间线、完整性 digest、coverage/freshness 对照。 | `UNVERIFIED` |
| `SAFE-001` | `M0-S1` `T22-A3` | `ENV-TIDB` `ENV-HOST` | 用独立只读账号完成全部正/负场景，并把该账号实际发出的语句与冻结 registry/binder 清单逐条比对；向诊断面提交 missing/empty/oversize SQL、非 64 位小写 digest、DML、DDL、ADMIN/control、多语句、join/多表/仅派生表、locking read、`SELECT ... INTO OUTFILE`、用户 EXPLAIN 和 `EXPLAIN ANALYZE` payload；核对同一 image digest 的兼容层行为探针及 `#t23` 定向审查引用，QA 不重复私有字段代码审查。 | 镜像内安装精确 `asyncmy==0.2.14`，行为探针和 Reviewer 对同一候选证明握手前/每次 driver call 前多语句位为零；所有无效 SQL/digest 均在收集前返回 `422 VALIDATION_ERROR`；实际查询均是冻结 registry/binder 重建的单条只读语句；危险 payload 在本地 fail closed 且未发送到 TiDB；正常提交的 SELECT 也只作为 digest 函数参数及服务端 ordinary EXPLAIN 的已验证子句，不直接执行。 | 安装的 distribution 文件名/SHA-256、镜像内行为探针 digest、`#t23` 同候选证据引用、脱敏 grants、冻结查询清单、专用账号语句审计/summary、payload 与响应、提交 SELECT 未直接执行证明、零越界 diff。 | `UNVERIFIED` |
| `SAFE-002` | `M0-S2` | `ENV-HOST` `ENV-BROWSER` | 使用不同的唯一 Owner/TiDB canary 密码；提交完成后扫描 URL/响应/报告、HTTP/browser cache、浏览器 storage 与 DOM、容器 env/inspect/挂载/可写文件、`/data`、应用日志与错误路径；核对密码字段在 identity I/O 前清空的同候选 Reviewer/行为探针证据。 | 所有 API 响应带 `Cache-Control: no-store`；除提交前的 masked input 和各自瞬时请求外，两种 canary 原文及常见编码均不存在；Owner 只允许持久化不可逆 verifier；驱动 `_password=b""` 且 `_password_creator=None` 后才允许 identity I/O；TiDB 凭据不进入 `/data`、环境或证据，镜像无 `/secrets` 或文件 fallback；应用不返回凭据。 | canary 哈希、扫描命令/范围/零匹配结果、持久化字段类型证明、兼容层行为探针及 `#t23` 引用、脱敏 HTTP trace 与 cache headers、storage/cache dump、DOM snapshot、docker logs/inspect/diff。 | `UNVERIFIED` |
| `SAFE-003` | `M0-S2` `M0-F1` | `ENV-HOST` `ENV-BROWSER` `ENV-FAULT` | 建立 Owner 与 TiDB 连接后依次验证 idle 显式 disconnect、活动 probe/query 持有 normal lease 时的 logout、shutdown/容器停止及使用同一 `/data` 卷的重启；每次先验证 Owner login，再在未重新输入 TiDB 凭据时尝试诊断。 | Logout 先提交 session revocation，再走幂等 `force_close`，不返回 `M0_BUSY`；lifecycle generation 使旧操作无法在清理后安装连接；pending/installed sockets 均被等待关闭，graceful close 达 5 秒 deadline 则 abort transport；Owner 依然可凭原密码登录，但每个清理边界后 TiDB connection/凭据均丢失并要求重新输入，磁盘不能恢复。 | 各清理边界的单调时间线、auth/connection/diagnosis UI 与 HTTP、revocation-before-close 证据、task/cancel/socket/transport 终止证据、generation 竞态证据、Owner 重启登录及 connection disconnected 证据、storage/文件/日志 secret scan。 | `UNVERIFIED` |
| `SAFE-004` | `M0-S3` | `ENV-HOST` | 检查 Docker published ports 与宿主 socket；从非回环接口及 hostile Host/Origin 请求应用。 | 只有 `127.0.0.1:18080` 可达；`0.0.0.0`、`::`、LAN 地址及 hostile Host/Origin 不可使用产品接口。 | docker inspect、`ss`/等价输出、本机与隔离网络探测、脱敏 HTTP 响应。 | `UNVERIFIED` |
| `SAFE-005` | `M0-S4` `T22-A3` | `ENV-HOST` `ENV-BROWSER` | 先证明冻结 allowlist 的 method/path 可用，再对 legacy bootstrap、model/settings、持久化多 Source、Prometheus/TEM、Plan Replayer、PingKaiDB、旧 cases/jobs 和 release APIs 等延期清单逐一请求所有方法；同时请求 `/docs`、`/redoc`、`/openapi.json`，检查前端链接和运行期出网；对镜像分别执行默认/`web-api`、`migrate`、`bootstrap-ingest`、`bootstrap-reissue` 和未知 CLI 参数。 | M0 allowlist 不被误删；所有延期路径及 API 文档路径均不注册且返回 framework normal `404`，不以 `401/403/405/5xx` 伪装；只有默认/`web-api` 进入 Web，其余 CLI 在导入旧恢复逻辑前退出 `64`；UI 无延期入口；rules-only 旅程无模型/Prometheus/Plan Replayer 请求。 | allowlist/延期 route/CLI manifest SHA-256、method/path/status 机器可读结果、CLI exit/import trace、DOM/link inventory、network/egress trace；不依赖已禁用 OpenAPI 推断路由。 | `UNVERIFIED` |
| `FAIL-001` | `M0-F1` `M0-S2` | `ENV-FAULT` `ENV-BROWSER` | 在已有 ready 连接时，分别提交未知字段/超 4096 字节 body、malformed host/socket/URI、越界 port、database/username control character、超过 UTF-8 密码字节限制、非法 tls_mode、错误凭据、不可达/慢目标、TLS 信任链/主机名失败和非 TiDB 8.5.x 身份作为 replacement；计时并观察错误、清理及原连接。 | 闭合 DTO 输入均 fail closed 且返回稳定错误码；driver 仅设 `connect_timeout=5/read_timeout=5`，connect/probe/close 各受 5 秒外层 deadline 约束，不传虚假 `write_timeout` 且无自动重试/重连；`verify_ca` 必须使用 `ssl.create_default_context()`、`CERT_REQUIRED` 和 hostname check，不传 `ssl=True`、不降级明文；未知产品/版本/非 `@@autocommit=1` 不安装；中文 closed error 不含 password/SQL/driver/DSN/host/username/row；replacement 失败后原 ready 连接仍可用。 | fault ID、单调时钟时间线、脱敏请求/响应及错误码、连接尝试计数、SSLContext/不降级证据、日志/响应敏感值扫描、身份原始响应、原连接继续可用证据。 | `UNVERIFIED` |
| `FAIL-002` | `M0-F1` `M0-R1` | `ENV-FAULT` `ENV-TIDB` | 触发单查询 5 秒、候选 20 行/262144 字节、ordinary EXPLAIN 200 行/524288 字节、诊断最多 6 查询/1000 行/2 MiB/30 秒之一的冻结边界；在慢操作持有 normal lease 期间并发 PUT/DELETE/candidate/diagnosis；对查询超时/取消检查 socket/task 清理，再重新录入凭据恢复。 | 每个边界稳定终止且无自动重试/重连/挂起；正常并发请求单次立即获取 lease，失败就 `409 M0_BUSY` 而不排队；超时/取消返回脱敏错误、调用 `force_close`、不留后台查询并把 slot 变为 disconnected，必须重新输入凭据；证据 gap/截断不标为完整、不发布确定根因。 | fault/budget ID、查询审计、单调时间线、行/字节/查询计数、并发响应、取消/task/socket/transport cleanup、降级报告或错误、disconnected 与重新录入后恢复证据。 | `UNVERIFIED` |
| `FAIL-003` | `M0-R1` | `ENV-FAULT` `ENV-TIDB` | 按冻结规则清单对三类规则分别重放不满足判据的反例，以及 missing/stale/truncated/mismatched/unsupported/integrity-invalid 必需角色；与对应正常场景对照。 | 反例不误触发；任一必需角色异常都输出 actionless `observe`，明确未知和最小补采建议；不扩大结论，不伪造根因、指标、置信度或动作。 | 每条稳定规则 ID 的反例与六类 fault ID、正常/异常 Evidence diff、规则输出、报告 JSON/截图、引用解析结果。 | `UNVERIFIED` |

## 8. 一次执行与一次复测纪律

1. 首次运行前复制 [M0 QA 证据模板](m0-private-preview-evidence-template.md)，填满 freeze manifest 并由 QA 验证 digest；不在执行中改预期。
2. 首轮 runbook 冻结全部 15 项的顺序，先确认 localhost 与 404 边界；主旅程提交 canary 后立即做秘密扫描，再继续三类诊断。任一秘密泄漏、非只读语句、非回环暴露或延期路由非 404，立即停止并记 `FAIL`，不继续扩大暴露。
3. 候选 commit、image digest、规则包、接口、场景或环境发生任何变化，首轮证据不得拼接为 PASS。
4. 唯一复测只覆盖首轮失败用例及其直接回归依赖；发现新 Critical/High 时整体 FAIL，返回 RD，不开启第三轮。
5. QA 只验证冻结产品行为；Reviewer 只做候选的只读、秘密、超时、localhost、404 与 asyncmy 私有兼容层的高风险定向审查，二者不重复全量门禁。两者可在同一冻结候选上并行，但总体 PASS 必须等 `#t23` 结果。
