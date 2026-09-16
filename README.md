# SQLLens

TiDB SQL 诊断外挂工具：本地单容器运行，输入 SQL 证据，输出专业中文诊断报告，数据不出本机。

> **当前状态：M0（loopback 单机 MVP）**。支持离线 Plan Replayer zip 上传诊断 + 内置演示样例 + 可选 AI 增强；TiDB 在线直连为后续版本。

## 它做什么

1. **证据输入**：上传 TiDB `PLAN REPLAYER DUMP` 生成的 zip（离线模式，无需连库），或使用内置三份真实证据演示样例。解析层有界解压（单条目/总量上限）+ zip-bomb 与路径穿越防护。
2. **规则诊断（核心，确定性）**：索引访问、统计信息偏差、非 Sargable 谓词等规则；每条建议附四要素——变更操作（现成 DDL/SQL）、风险提示、成本预估、收益预估。规则结论可复现，不依赖 AI。
3. **可选 AI 增强**：配置任意 OpenAI 兼容 / Anthropic 兼容端点（DeepSeek、Qwen、GPT、vLLM 私有部署等）后，可对同一份证据按需生成第二份「AI 增强」报告。AI 只归纳与补充，不推翻规则结论；失败自动降级规则模式。不配置则零外部依赖、零出网。
4. **中文报告**：结论 → 证据 → 问题分析 → 变更建议 → 验证 → 回滚，六段结构；命令块一键复制。

## 快速开始（Docker，linux/arm64）

发布产物在 `feature/m0-v4-package` 分支 `release/` 目录：

```bash
git clone --depth 1 -b feature/m0-v4-package https://github.com/CoderLucien/sqllens.git
cd sqllens/release
shasum -a 256 -c sha256sum.txt   # 校验镜像完整性
docker load -i sqllens-v4-m0-arm64.tar
docker run -d --name sqllens \
  -p 127.0.0.1:18080:8080 \
  -v sqllens-data:/data \
  --restart unless-stopped \
  sqllens:v4-m0
open http://127.0.0.1:18080      # 健康检查: curl http://127.0.0.1:18080/healthz
```

linux/amd64 可从源码构建（`make build`，或直接使用 `apps/api/Dockerfile`）。

⚠️ **仅限本机使用**：固定绑定回环地址；端点无鉴权（TEST-ONLY / NOT-RC），不得映射到非回环地址。

## 开发

```bash
make bootstrap   # Python venv + 前端依赖
make dev         # API + Web 开发服务
make test        # pytest + 前端测试
make lint typecheck
```

技术栈：Python（`apps/api`，包名 `sqllens_api`）+ Vite 原生 Web 前端（`apps/web`）。

## 代码结构（当前活跃路径）

```
apps/api/src/sqllens_api/
  plan_replayer.py / plan_replayer_routes.py   # Plan Replayer zip 解析（有界、防护）
  v4_rules.py        # 规则引擎（确定性诊断 + 四要素）
  v4_diagnosis.py    # 诊断编排
  v4_routes.py       # API 路由（/api/v1/v4/diagnose、/ai/test、/ai/models）
  v4_ai.py           # 可选 AI 适配层（OpenAI/Anthropic 双协议、降级、缓存、token 预算）
apps/web/            # 三屏前端：输入 / AI 配置 / 报告
docs/contracts/      # 冻结数据契约（v4-diagnosis-input = evidence/v3；v4-diagnosis-report = report/v2）
docs/adr/            # 架构决策记录（ADR 0001–0011）
docs/threat-model.md # 威胁模型
tests/api/           # 回归测试（含契约字段冻结护栏测试）
release/             # 在 feature/m0-v4-package 分支：镜像 tar、sha256、启动说明、冒烟清单
```

注：仓库同时保留早期迭代的 vnext 阶段模块（`m0_*`、`evidence_connector/`、`setup.py` 等）及其契约（`docs/contracts/*-v1/v2`），当前活跃开发路径为上述 `v4_*` 与 `plan_replayer_*` 模块。

## 分支导览

| 分支 | 内容 |
|---|---|
| `main` | 集成主线（源码 + 文档） |
| `feature/m0-v4-prototype` | v4 源码开发分支 |
| `feature/m0-v4-package` | 交付打包分支（`release/` 内含 arm64 镜像与启动说明） |
| `qa/v4-smoke-checklist` | QA 验收清单 |
| 其余分支 | 早期迭代与交接基线，仅供参考 |

## 安全与隐私边界

- 只读诊断：不接受 DML/DDL，不执行任何生产变更
- 诊断数据（SQL / 证据 / 报告）仅会话内存，不落盘
- 连接与 AI 配置加密缓存于本机数据卷，可清除
- 规则模式零外部依赖、零出网；AI 模式仅向用户自配端点发送有界的结构化摘要（~2KB 上限），不含报告全文
