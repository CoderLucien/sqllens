#!/usr/bin/env bash
# 构建 SQLLens linux/arm64 Docker 镜像 + 交付包（Mac M3 可测）。
#
# 用法： ./scripts/build-arm64-image.sh [镜像名] [输出目录]
# 产物目录：
#   <out>/sqllens-v4-m0-arm64.tar      —— linux/arm64 镜像（docker load 后运行）
#   <out>/v4-m3-smoke-checklist.md     —— QA 冒烟清单（随包交付）
#   <out>/v4-m3-startup.md             —— 启动说明（含仅限本机使用警示）
set -euo pipefail

IMAGE="${1:-sqllens:v4-m0}"
OUT_DIR="${2:-dist}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/${OUT_DIR}"
mkdir -p "${OUT}"

echo "==> 构建 linux/arm64 镜像：${IMAGE}（本机 buildx 交叉构建，pip 重试已加固）"
docker buildx build \
  --platform linux/arm64 \
  -f "${REPO_ROOT}/apps/api/Dockerfile" \
  -t "${IMAGE}" \
  --output "type=docker,dest=${OUT}/sqllens-v4-m0-arm64.tar" \
  "${REPO_ROOT}"

echo "==> 随包交付文件"
cp -f "${REPO_ROOT}/docs/validation/v4-m3-smoke-checklist.md" "${OUT}/" 2>/dev/null || true
cp -f "${REPO_ROOT}/docs/v4-m3-startup.md" "${OUT}/" 2>/dev/null || true
# 在输出目录内生成 sha256sum，路径用相对文件名（M3 侧 cd 到该目录后可 -c 校验）。
( cd "${OUT}" && sha256sum sqllens-v4-m0-arm64.tar > sha256sum.txt )

echo "==> 完成：${OUT}/"
ls -la "${OUT}"
echo
echo "==> Mac M3 上执行："
echo "    docker load -i sqllens-v4-m0-arm64.tar"
echo "    docker run -d --name sqllens -p 127.0.0.1:18080:8080 -v sqllens-data:/data ${IMAGE}"
