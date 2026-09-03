# SQLLens v4 启动说明（Mac M3 / linux/arm64）

> 目标包：`sqllens-v4-m0-arm64.tar`（linux/arm64 Docker 镜像）。
> 冒烟清单：`docs/validation/v4-m3-smoke-checklist.md`（随包交付，逐项执行）。

## 一键启动（照抄执行）

```bash
# 1. 加载镜像（仅一次）
docker load -i sqllens-v4-m0-arm64.tar

# 2. 一键启动（固定绑定本机回环 127.0.0.1:18080）
docker run -d \
  --name sqllens \
  -p 127.0.0.1:18080:8080 \
  -v sqllens-data:/data \
  --restart unless-stopped \
  sqllens:v4-m0

# 3. 打开浏览器
open http://127.0.0.1:18080
```

## 验证

```bash
curl -fsS http://127.0.0.1:18080/healthz   # 预期 200
docker logs -f sqllens                     # 查看日志
```

## ⚠️ 安全警示（重要）

- **仅限本机使用**：启动参数固定 `-p 127.0.0.1:18080:8080`，只监听回环地址。
  **不得**改为 `0.0.0.0` / `::` 或映射到局域网/公网地址，否则诊断数据与
  配置缓存将暴露给其他主机。
- 本版本为 loopback 单机 MVP，**端点无鉴权**（TEST-ONLY / NOT-RC），
  不适用于多用户或远程访问场景。
- 连接配置与 AI 配置加密缓存于本机数据卷 `sqllens-data`；诊断数据
  （SQL / 证据 / 报告）仅会话内存、不落盘，容器重启后不残留。

## 功能边界（如实说明）

- **在线模式（TiDB 直连）为后续版本**，当前 MVP 仅支持：
  离线「Plan Replayer」zip 上传 → 解析 → 规则诊断 → 中文六段报告，
  以及内置三份真实证据演示样例。
- AI 增强为可选配置；不配置时走纯规则模式（零外部依赖、零数据出本机）。
- 只读：不接受 DML/DDL/`EXPLAIN ANALYZE`，不自动执行任何生产变更。
- **验证边界（如实标注）**：Plan Replayer 解析的合成 zip 三类拒绝路径
  （空包/坏 zip/缺内容）已实测通过；**真实 `PLAN REPLAYER DUMP` zip 的
  evidence/v3 → diagnose 全链路为 M3 侧验证项**，本包未含真实 DUMP 包实测。
