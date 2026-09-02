# vNext QA 执行证据模板

本模板只在 mgr 把矩阵 `Freeze state` 改为 `READY` 后使用。不要用实现方口头结论、截图摘要或聊天消息替代原始证据。

## 1. 执行身份

- Run ID：
- 开始/结束时间（UTC）：
- QA owner：
- 执行轮次：`1` 或唯一有界复测 `2`
- Human gate ref：
- Matrix commit：
- Contract freeze ref：
- SUT commit：
- 工作树：`clean`；否则停止
- Image digest：
- Fixture manifest SHA-256：
- Environment manifest SHA-256：
- Source revisions：
- Provider/model：
- Rule/document/parser/prompt/policy/redaction revisions：

以上任一项与冻结清单不一致时，整批结果为 `BLOCKED`，不得挑选局部证据签字。

## 2. 环境

- Host OS/kernel/architecture：
- CPU/RAM/disk：
- Docker client/server：
- 容器配置与端口 inspect SHA-256：
- TiDB 或平凯数据库版本/拓扑：
- 脱敏 grants SHA-256：
- 关联 Prometheus/TEM 版本（若冻结）：
- Provider endpoint identity（无 Key）：
- 时钟与时区：
- 执行前 SQLLens 容器/卷/端口清单：
- 执行后清理或保留策略：

## 3. 用例记录

每个矩阵 ID 单独复制一份：

### `<CASE-ID>`

- 冻结对象：
- 环境 ID：
- 精确步骤/命令：
- 预期结果：
- 实际结果：
- 结果：`PASS` / `FAIL` / `BLOCKED` / `UNVERIFIED`
- 缺陷 ID 与严重度（若失败）：
- 阻塞条件与 owner（若阻塞）：
- 原始证据相对路径与 SHA-256：
- 脱敏说明：

`PASS` 必须同时具备可复现步骤、可观察实际结果和原始证据。`job completed`、存在 hypothesis、容器健康或实现方测试通过都不是充分证据。

## 4. 建议证据目录

```text
evidence/<run-id>/
  freeze-manifest.json
  environment.json
  commands/
  browser/
  http/
  source-query-audit/
  cases/
  reports/
  provider-redacted/
  screenshots/
  logs-redacted/
  evidence-index.sha256
```

最低证据要求：

- 安装/Owner：逐字命令、脱敏 inspect、端口监听、浏览器 trace、Owner 计数与审计。
- Source：逐修订 Source JSON、能力矩阵、服务端查询审计、凭据 canary 搜索和生命周期时间线。
- 异常 SQL：集群/时间窗/Digest 选择、预检、阶段事件、Case/Report JSON 和端到端页面证据。
- Rules/AI：规则引用、configured/effective mode、脱敏 provider 真实请求/响应、预算和降级原因。
- 报告：三种 audience 投影、规范化字段 diff、证据/规则/claim/action 引用校验及关键页面。
- 失败/降级：固定 fault fixture、错误 envelope、终态、重试/取消记录和恢复后的正常 Case。

## 5. 脱敏与完整性

- API Key、密码、cookie、CSRF、SQL literal、行数据和机密原始证据不得进入聊天或公开附件。
- 脱敏前原始证据只保存在批准位置；公开副本必须保留失败可复现所需的状态、时间、ID 关系和摘要。
- 每个证据文件计算 SHA-256；`evidence-index.sha256` 自身进入任务 checkpoint。
- provider 证据必须证明发生真实结构化诊断请求，但不得保留 Authorization 值。
- 任何凭据暴露立即停止执行、轮换凭据，并将受影响用例标记 `FAIL`；不得用删除消息替代处置。

## 6. 批次结论

- 各结果计数：
- Critical/High 缺陷：
- 产品价值阻断：
- BLOCKED/UNVERIFIED 项：
- 唯一总体结论：`PASS` / `FAIL` / `BLOCKED` / `UNVERIFIED`
- 一轮补证或复测范围（如批准）：
- 新增非阻断 backlog（不进入本轮）：
- 残余风险与 owner：

只有 24 项全部 PASS、Human gate 可追踪、无未关闭 Critical/High 时，总体结论才能为 PASS。
