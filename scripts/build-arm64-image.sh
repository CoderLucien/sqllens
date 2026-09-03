#!/usr/bin/env bash
# 构建 SQLLens linux/arm64 Docker 镜像（交付给 Mac M3 的可测试包）。
#
# 用法： ./scripts/build-arm64-image.sh [镜像名] [输出目录]
# 产物： <输出目录>/sqllens-v4-m0-arm64.tar （docker load 后可运行）
set -euo pipefail

IMAGE="${1:-sqllens:v4-m0}"
OUT_DIR="${2:-dist}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${REPO_ROOT}/${OUT_DIR}"

echo "==> 构建 linux/arm64 镜像：${IMAGE}（本机 buildx 交叉构建）"
docker buildx build \
  --platform linux/arm64 \
  -f "${REPO_ROOT}/apps/api/Dockerfile" \
  -t "${IMAGE}" \
  --output "type=docker,dest=${REPO_ROOT}/${OUT_DIR}/sqllens-v4-m0-arm64.tar" \
  "${REPO_ROOT}"

echo "==> 完成：${REPO_ROOT}/${OUT_DIR}/sqllens-v4-m0-arm64.tar"
echo "==> 交付说明：在 Mac M3 上执行"
echo "    docker load -i sqllens-v4-m0-arm64.tar"
echo "    docker run -d --name sqllens -p 127.0.0.1:18080:8080 -v sqllens-data:/data ${IMAGE}"
