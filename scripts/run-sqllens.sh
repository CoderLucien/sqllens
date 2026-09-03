#!/usr/bin/env bash
# SQLLens 一键启动（在已加载镜像的目标机上执行）。
#
# 用法： ./scripts/run-sqllens.sh [镜像名]
# 默认绑定 127.0.0.1:18080，数据卷 sqllens-data（仅 Owner 会话/SQLite，不含诊断数据）。
set -euo pipefail

IMAGE="${1:-sqllens:v4-m0}"
CONTAINER="sqllens"
PORT="${SQLLENS_PORT:-18080}"

if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
  echo "==> 已存在容器 ${CONTAINER}，先移除旧实例"
  docker rm -f "${CONTAINER}" >/dev/null
fi

echo "==> 启动 ${IMAGE} -> http://127.0.0.1:${PORT}"
docker run -d \
  --name "${CONTAINER}" \
  -p "127.0.0.1:${PORT}:8080" \
  -v sqllens-data:/data \
  --restart unless-stopped \
  "${IMAGE}"

echo "==> 已启动。打开 http://127.0.0.1:${PORT}"
echo "==> 查看日志： docker logs -f ${CONTAINER}"
echo "==> 停止： docker stop ${CONTAINER}"
