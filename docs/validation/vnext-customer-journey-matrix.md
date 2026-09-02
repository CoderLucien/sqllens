# vNext 客户旅程与诊断价值验收矩阵

状态：草案，禁止执行

负责人：`swat-qa` / `#t22`

适用范围：vNext M1 已管理数据源的异常 SQL 诊断

## 1. 目的

本矩阵把已批准的 Human 产品决策转成一次可执行、可追踪的验收批次。它判断客户能否从一个固定 Docker 命令走到有证据、可决策、可安全执行的中文诊断报告，而不是判断若干 API 是否返回 200。

`job completed、存在 hypothesis、容器可启动均不能单独构成 PASS`。任何严重产品价值缺陷都直接阻断 #t22 签字，即使单元测试、类型检查或容器健康检查通过。

## 2. 冻结清单

- Baseline commit: `746f55231cc4b059ab3f72126d20f6a4df104e48`
- Contract freeze ref: `UNASSIGNED`
- Freeze state: `PENDING`
- Human gate ref: `UNASSIGNED`
- SUT commit: `UNASSIGNED`
- Image digest: `UNASSIGNED`
- Fixture manifest SHA-256: `UNASSIGNED`
- Environment manifest SHA-256: `UNASSIGNED`
- Source revisions: `UNASSIGNED`
- Provider and model: `UNASSIGNED`
- Pinned policy revisions: `UNASSIGNED`
- Execution count: `0`

`746f552` 只冻结产品方向和初始草案。#t23 已在该提交发现契约 Critical/High，因此它不能作为运行时契约冻结提交。只有修复后的契约提交经定向复审、Human 接受实际客户旅程与报告、mgr 同时填满以上字段并把 `Freeze state` 改为 `READY` 后，QA 才能启动一次执行。

执行中不得更换 commit、image digest、来源修订、夹具或规则/模型修订。任何变化都使整批证据失效并回到 `PENDING`。

## 3. 需求追踪

| 标记 | 决策或验收要求 |
|---|---|
| `VNX-A1` | 一个固定、按 digest 引用的 Docker 命令启动本机产品，无源码构建、`.env`、平台选择或终端初始化码。 |
| `VNX-A2` | 空实例仅允许 localhost 创建唯一 Owner；首次创建原子关闭，恢复是独立且审计的本地流程。 |
| `VNX-A3` | 来源有内嵌获取指引、最小权限、能力测试、完整生命周期和不可变历史修订。 |
| `VNX-A4` | 用户明确选择规则模式或规则 + AI；配置模式、实际模式和降级原因始终可见。 |
| `VNX-B1` | 首条日常主路径为已管理数据源：集群与时间窗 → 异常 Statement/Slow Query → SQL Digest → 证据预览。 |
| `VNX-B2` | 采集、事实、规则、可选 AI、校验和发布各阶段显示状态、来源、耗时与降级原因。 |
| `VNX-B3` | 中文报告覆盖结论、优先级、影响、证据、推理、动作、验证、回滚、不确定性和官方引用。 |
| `T22-AC1` | 覆盖单命令安装、首次 Owner、来源生命周期、异常 SQL、规则/AI 透明度、中文报告及失败/降级。 |
| `T22-AC2` | 每项记录冻结对象、环境、步骤、预期、实际和原始证据。 |
| `T22-AC3` | 结果只允许 PASS、FAIL、BLOCKED、UNVERIFIED；严重产品价值缺陷阻断。 |
| `T22-AC4` | 只执行一次冻结矩阵；新增非阻断项进入后续迭代。 |
| `T22-R1` | 完成 job、存在 hypothesis 或容器启动都不是充分通过条件。 |
| `T22-R2` | 未冻结 artifact 或 digest 时禁止执行。 |
| `T22-R3` | QA 不重复 Reviewer 的实现审查和供应链全量门禁。 |

## 4. 本轮边界

包含：一个受控的已管理 TiDB 或平凯数据库来源、一条代表性异常 SQL、规则模式、规则 + AI 模式、三种受众投影及有界失败/降级夹具。

不包含：Plan Replayer 与手工资料入口、告警驱动入口、远程/LAN 部署、自定义端口和 Kubernetes。2C4G、跨平台 clean install、SBOM、签名、provenance 与正式 RC 均在 Human 产品门禁之后另立任务，不得借 #t22 自动扩项。

## 5. 执行环境标识

| 环境 | 冻结要求 |
|---|---|
| `ENV-LOCAL-FRESH` | 无产品容器和卷的主机；记录 OS、架构、Docker 版本、端口占用和时钟；只运行冻结 image digest。 |
| `ENV-MANAGED-SOURCE` | 一个隔离、可重放的 TiDB 8.5.x 或平凯数据库 7.1.x 来源；记录拓扑、版本、脱敏 grants、异常 SQL 数据集和关联指标。 |
| `ENV-VERSION-FIXTURES` | 两个受支持版本族及 unknown 版本的脱敏原始响应、能力矩阵和查询结果夹具，全部进入夹具清单。 |
| `ENV-PROVIDER` | 冻结 provider/model；能完成模型发现和一次真实结构化诊断请求；凭据仅在本地输入且证据脱敏。 |
| `ENV-FAULT` | 冻结的权限不足、陈旧/矛盾证据、超时、截断和模型错误夹具；不得临时增加故障种类。 |

## 6. 结果判定

- `PASS`：冻结对象上的实际结果完整满足预期，且原始证据可复核。
- `FAIL`：产品行为、报告价值或安全降级与预期不符。以下情况按 High 产品价值缺陷处理：只有英文/固定低置信度套话；没有业务影响或处置优先级；动作缺负责人、风险、验证或回滚；证据不足却给出确定根因；规则与 AI 贡献不可区分；声称使用 AI 但没有真实模型请求；三种受众的事实、优先级或动作状态互相矛盾；内部 ID 成为主要页面内容；用户离开产品才能完成主路径。
- `BLOCKED`：冻结对象不完整、Human gate 未完成或执行环境不可用，导致无法观察产品行为。BLOCKED 不等于产品失败，但不能签字。
- `UNVERIFIED`：草案、尚未执行或证据不足。它不能转述为通过。

总体只在 24 项全部 `PASS`、无未关闭 Critical/High、Human gate 有记录时签署 PASS。只允许一轮有界补证或复测，且仅覆盖失败项；任何新增非阻断发现进入后续迭代。

## 7. 冻结验收矩阵

表中“冻结对象”引用第 2 节全局清单；执行时必须再记录该用例实际使用的来源修订、夹具 ID 和策略修订。

| ID | 需求追踪 | 冻结对象 | 环境 | 步骤 | 价值预期 | 实际结果 | 原始证据 | 结果 |
|---|---|---|---|---|---|---|---|---|
| `INST-001` | `VNX-A1` `T22-AC1` `T22-R2` | SUT commit；image digest；唯一安装命令 | `ENV-LOCAL-FRESH` | 1. 在无旧卷主机复制发布页唯一命令<br>2. 不做额外准备直接启动<br>3. 打开 `http://localhost:18080` | 一条按 digest 固定的命令即可到达首次设置；Docker 自动选择架构；不要求源码、Compose、`.env`、迁移、平台选择、终端码或第二条产品命令。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：发布页截图、逐字命令、pull/run 输出、image inspect、首次页面截图。 | `UNVERIFIED` |
| `INST-002` | `VNX-A1` `VNX-A2` `T22-AC1` | image digest；容器配置；前后页面状态 | `ENV-LOCAL-FRESH` | 1. 检查实际容器配置<br>2. 完成初始化后重启<br>3. 再访问 `/setup` 与日常入口 | 容器为非 root、只读根、drop ALL、no-new-privileges、有界 noexec tmpfs、固定 data/secrets 卷、仅 `127.0.0.1:18080`；初始化壳与日常壳分离，完成后首次向导不再出现在日常导航。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：脱敏 inspect、端口监听、重启日志、初始化前后页面截图与导航录屏。 | `UNVERIFIED` |
| `OWN-001` | `VNX-A2` `T22-AC1` | SUT commit；空数据卷；Owner API/UI revision | `ENV-LOCAL-FRESH` | 1. 首次从本机打开页面<br>2. 由用户创建 Owner 密码<br>3. 检查响应、日志和存储 | 无默认密码、无终端 bootstrap code；密码只在本地 UI 输入且仅保存安全派生值；成功后进入下一初始化步骤，响应与日志不回显凭据。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：浏览器 trace、脱敏请求响应、日志 canary 搜索、数据库字段检查。 | `UNVERIFIED` |
| `OWN-002` | `VNX-A2` `T22-AC1` | SUT commit；Owner 并发夹具；来源判据修订 | `ENV-LOCAL-FRESH` `ENV-FAULT` | 1. 发送 hostile Origin/Host 与代理头请求<br>2. 并发提交两个不同密码<br>3. 重放失败请求 | 非本机/敌意来源不能创建 Owner；恰好一个合法并发请求成功，另一个稳定失败；重放不能覆盖凭据或产生第二 Owner。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：并发时间线、脱敏 HTTP trace、Owner 计数、审计事件；不复跑 Reviewer 的静态实现审查。 | `UNVERIFIED` |
| `OWN-003` | `VNX-A2` `VNX-B1` | SUT commit；已初始化卷；恢复策略修订 | `ENV-LOCAL-FRESH` | 1. 重启服务并登录<br>2. 再请求首次创建入口<br>3. 查看本地恢复入口说明 | 重启后唯一 Owner 可登录且首次创建永久关闭；恢复与首次创建分离、有审计、有明确用户说明，不重新暴露初始化向导。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：重启前后 Owner 状态、登录与首次入口响应、恢复说明截图、审计记录。 | `UNVERIFIED` |
| `SRC-001` | `VNX-A3` `T22-AC1` | Source contract freeze；来源向导 revision；credential policy | `ENV-LOCAL-FRESH` `ENV-MANAGED-SOURCE` | 1. 从初始化壳添加数据库来源<br>2. 按内嵌指引获取最小权限凭据<br>3. 仅在本地 UI 输入并保存草稿 | 页面明确责任角色、可复制步骤、必需与可选敏感权限、owner/expiry/rotation/revoke；凭据不进入 shell、URL、API 响应、日志或模型载荷。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：完整向导截图、脱敏表单 trace、credential canary 搜索、来源 JSON。 | `UNVERIFIED` |
| `SRC-002` | `VNX-A3` `T22-AC1` | Source contract freeze；version/capability fixture manifest；query policy | `ENV-MANAGED-SOURCE` `ENV-VERSION-FIXTURES` | 1. 分别重放 TiDB 8.5.x 与平凯数据库 7.1.x 预检<br>2. 对代表性来源执行有界测试<br>3. 查看能力明细 | 识别正确版本族并返回逐项 available/denied/missing/unknown 能力、最小权限差异、查询/行数/并发/速率预算；不是单一布尔“连接成功”。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：脱敏原始版本响应、能力矩阵、服务端查询清单、预算与测试结果。 | `UNVERIFIED` |
| `SRC-003` | `VNX-A3` `T22-AC1` | Source contract freeze；source revision；audit policy | `ENV-LOCAL-FRESH` `ENV-MANAGED-SOURCE` | 1. 完成 add/test/enable<br>2. edit 后验证新 revision<br>3. disable/enable<br>4. rotate credential<br>5. delete | 生命周期操作有 CSRF、乐观并发和审计原因；每次有效修改生成不可变新修订；轮换后旧凭据失效；删除不泄露 secret，状态和提示可理解。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：各阶段 source JSON、revision 序列、审计事件、旧凭据失效响应、页面截图。 | `UNVERIFIED` |
| `SRC-004` | `VNX-A3` `VNX-B2` | source revision；case fixture；credential lifecycle policy | `ENV-MANAGED-SOURCE` | 1. 启动诊断并记录 source revision<br>2. 编辑或删除来源<br>3. 读取旧报告并启动新诊断 | 旧 Case/Report 继续引用原来源修订与证据且不含可用凭据；修改只影响新 job；active-job 行为符合冻结的 lease/drain/cancel/tombstone 语义。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：前后 source/case/report JSON、修订引用、active-job 时间线、credentialRef 检查。 | `UNVERIFIED` |
| `SRC-005` | `VNX-A3` `VNX-B1` | permission fixtures；source revision；degradation policy | `ENV-VERSION-FIXTURES` `ENV-FAULT` | 1. 拒绝可选 PROCESS 权限<br>2. 以 schema-scoped 最小权限测试来源<br>3. 进入异常 SQL 发现页 | 产品不自动索取更高权限；清楚说明跨用户 Statement/Slow Query 发现受限、影响范围和获取方法；仍可使用安全可用能力，effective coverage 降低。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：脱敏 grants、能力矩阵、降级提示、实际允许查询清单、页面截图。 | `UNVERIFIED` |
| `DX-001` | `VNX-B1` `T22-AC1` | image digest；source revision；abnormal SQL fixture | `ENV-MANAGED-SOURCE` | 1. 在日常壳新建诊断<br>2. 选集群与有界时间窗<br>3. 浏览异常 Statement/Slow Query<br>4. 选择 SQL Digest | 用户不手工拼接内部 ID 或原始查询即可找到目标 SQL；时间窗、来源、数据库、Digest、业务症状清楚且可复核。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：逐步截图/录屏、选择结果、脱敏发现响应、固定 Digest 与时间窗。 | `UNVERIFIED` |
| `DX-002` | `VNX-B1` `VNX-B2` | query policy；evidence fixture；source revision | `ENV-MANAGED-SOURCE` | 1. 打开证据预检<br>2. 核对证据类别与有界查询<br>3. 启动采集并观察全部阶段 | 开始前可见将采集什么、为什么、权限和预算；只执行服务端白名单只读查询；normalize/acquire/features/rules/AI/validate/publish 各阶段显示状态、来源、耗时及降级。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：预检截图、服务端查询审计、阶段事件流、预算计数、取消/完成时间线。 | `UNVERIFIED` |
| `DX-003` | `VNX-B1` `VNX-B2` `T22-R1` | SUT commit；image digest；main case fixture；contract freeze | `ENV-LOCAL-FRESH` `ENV-MANAGED-SOURCE` | 1. 完整执行一次代表性异常 SQL<br>2. 打开发布的 Case 与报告<br>3. 核对来源、证据级别和修订 | 产生可行动的真实客户结果，而不只是 completed；Case 固定 source/evidence/rule/model/policy 修订，引用全部可解析，证据时间、freshness、coverage 和 digest 可查看。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：端到端录屏、Case/Report JSON、引用校验输出、来源查询审计、页面 trace。 | `UNVERIFIED` |
| `MODE-001` | `VNX-A4` `VNX-B3` | rules-only fixture；rule/document pack revisions | `ENV-MANAGED-SOURCE` | 1. 配置 Rules only<br>2. 执行主异常 SQL<br>3. 检查网络与报告 | configured/effective mode 均为 rules；无 provider 请求；确定性中文报告仍包含证据、结论、动作、验证、回滚和不确定性，不用英文套话替代。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：模式页面、网络/egress 记录、Case/Report JSON、rule/document refs。 | `UNVERIFIED` |
| `MODE-002` | `VNX-A4` `VNX-B2` | provider/model；prompt/payload/redaction revisions；AI fixture | `ENV-PROVIDER` `ENV-MANAGED-SOURCE` | 1. 配置 Rules + AI<br>2. 完成模型发现与最小真实结构化诊断预检<br>3. 执行主异常 SQL | 预检不只验证 `/models`；实际发生受预算约束的结构化诊断请求；报告显示 configured/effective mode、provider/model/prompt/redaction 修订和模型实际贡献。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：脱敏 provider 请求/响应、预算计数、模式截图、Case/Report JSON；API Key 永不入证据。 | `UNVERIFIED` |
| `MODE-003` | `VNX-A4` `VNX-B3` `T22-AC3` | AI boundary fixture；case/report contracts；action allowlist | `ENV-PROVIDER` `ENV-FAULT` | 1. 返回含未知 evidence/rule/action ID 或新测量值的模型结果<br>2. 观察校验与报告<br>3. 对照确定性 Case | 非法 AI 内容不能发布；AI 不能新增证据、对象、置信度、动作族或越过 evidence ceiling；页面明确校验失败和实际模式，确定性事实不被改写。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：脱敏恶意响应夹具、validator 输出、Case/Report diff、降级页面。 | `UNVERIFIED` |
| `MODE-004` | `VNX-A4` `VNX-B2` `T22-AC1` | timeout/invalid/oversize provider fixtures；degradation policy | `ENV-PROVIDER` `ENV-FAULT` | 1. 依冻结顺序注入 provider 不可用、超时或超限响应<br>2. 执行同一异常 SQL<br>3. 查看全局与报告状态 | 失败可见且有稳定原因码；effective mode 变为 rules；不丢确定性证据/动作，不伪称 AI 成功，也不因模型失败让整个诊断不可用。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：fault fixture ID、provider trace、全局/报告截图、Case/Report JSON、重试计数。 | `UNVERIFIED` |
| `RPT-001` | `VNX-B3` `T22-AC3` | main Case revision；DBA/SRE report projection | `ENV-MANAGED-SOURCE` | 1. 以 DBA/SRE 默认视图打开报告<br>2. 不展开 trace 阅读首屏<br>3. 复述问题和优先级 | 中文首屏能回答“是否现在处理、影响谁、为什么”；包含一句话结论、P0-P3/observe 优先级、集群/库/Digest/时间窗/业务影响和关键证据，而非内部 ID 或分析散文。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：首屏截图、可用性复述记录、Report JSON、与 Case 事实对照。 | `UNVERIFIED` |
| `RPT-002` | `VNX-B3` `T22-AC3` | main Case revision；action allowlist；report projection | `ENV-MANAGED-SOURCE` | 1. 阅读按序动作<br>2. 核对每个动作来源<br>3. 检查验证和回滚<br>4. 搜索自动执行入口 | 仅给 1-3 个有序动作；每项有 owner、风险、前置、步骤、预期收益、验证指标/阈值、回滚和 Human approval；产品不会自动执行生产变更。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：动作卡截图、Case/Report action JSON、引用校验、路由/页面可见入口清单。 | `UNVERIFIED` |
| `RPT-003` | `VNX-B3` `T22-AC3` | one Case revision；three report projections | `ENV-MANAGED-SOURCE` | 1. 切换 DBA/SRE、研发、事件负责人视图<br>2. 比较结论、优先级、事实和动作状态<br>3. 检查各自重点 | 三视图共享不可变 Case；仅表达重点不同。研发看到 SQL/schema 影响，事件负责人看到业务影响/决策状态；不得出现事实、数值、优先级或动作状态矛盾。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：三视图截图与 Report JSON、规范化字段 diff、同一 caseId/revision 证明。 | `UNVERIFIED` |
| `RPT-004` | `VNX-B3` `T22-AC3` | Case/Report contracts；pinned revisions；trace policy | `ENV-MANAGED-SOURCE` `ENV-PROVIDER` | 1. 展开证据与推理<br>2. 分别定位规则和 AI 内容<br>3. 最后打开 trace drawer | 证据卡显示来源、时间、freshness、coverage 和标识；规则命中、冲突、官方引用与 AI contribution 分开；configured/effective mode 和降级可见；内部 ID 仅在 trace drawer，不是主要体验。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：证据/推理/trace 截图、Report JSON、全部引用解析与 pinned revision 清单。 | `UNVERIFIED` |
| `DEG-001` | `VNX-A3` `VNX-B2` `T22-AC1` | unknown-version fixture；required-capability fixture；version policy | `ENV-VERSION-FIXTURES` `ENV-FAULT` | 1. 重放 unknown 版本<br>2. 重放必需能力 denied/missing<br>3. 尝试启用并诊断 | unknown 或缺必需能力的来源不能被当作可用版本；版本特定结论 fail closed；页面说明准确缺口和安全修复，不自动扩大权限。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：原始版本/权限响应、来源状态、错误 envelope、页面提示、查询审计。 | `UNVERIFIED` |
| `DEG-002` | `VNX-B2` `VNX-B3` `T22-AC3` | stale/missing/conflict fixtures；evidence ceiling policy | `ENV-FAULT` | 1. 分别重放 stale、missing 和 contradictory evidence<br>2. 生成报告<br>3. 对比正常主 Case | coverage/freshness 和冲突可见；结论上限下降并在必要时 abstain；列出最小下一证据；不把相关性写成根因，不给无证据的通用优化建议。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：三类 fixture ID、Case/Report JSON、正常/降级 diff、abstention 页面。 | `UNVERIFIED` |
| `DEG-003` | `VNX-B2` `T22-AC1` `T22-AC4` | timeout/truncation/cancel fixtures；collector budgets | `ENV-FAULT` `ENV-MANAGED-SOURCE` | 1. 依冻结夹具触发查询超时、maxRows 截断和用户取消<br>2. 观察阶段与终态<br>3. 再次执行正常主 Case | 精确预算和原因可见；部分数据不被标成完整证据；取消/超时后无无限重试或卡死；后续正常诊断可用。只验证客户可见结果，不扩成 2C4G 压测。 | 未执行：等待 mgr 冻结对象与 Human gate。 | 待采集：fixture/预算清单、查询审计、阶段事件、重试/取消时间线、后续正常 Case。 | `UNVERIFIED` |

## 8. 执行与变更纪律

1. mgr 发布完整冻结清单后，QA 复制本矩阵到一个 run 记录并填写实际结果与证据路径；不在执行中改预期。
2. 每项证据遵循 [vNext QA 证据模板](vnext-qa-evidence-template.md)，原始文件计算 SHA-256，公开回执只放脱敏摘要。
3. 若契约、客户旅程或报告字段漂移，停止执行并返回 #t17；不通过增加临时用例适配漂移。
4. Reviewer 负责高风险实现与契约审查；QA 只验证冻结对象的客户行为和产品价值，不重复供应链、SBOM、签名或全量安全扫描。
5. 首轮之后只允许一轮有界补证或复测。非阻断新发现记录到后续任务，不扩大当前矩阵。
