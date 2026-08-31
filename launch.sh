#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="$ROOT/deploy/compose.json"
STATE_DIR=${SQLLENS_STATE_DIR:-"$HOME/.sqllens"}
BOOTSTRAP_FILE="$STATE_DIR/bootstrap-code"
PORT=${SQLLENS_PORT:-8080}
MODE=external
ACTION=start
PLATFORM=
ARCH=

usage() {
  cat <<'EOF'
Usage: ./launch.sh [start|check] [--mode external|local]

  start  Run preflight, migrate, and start the Web App (default).
  check  Run preflight without changing application state.

External-model mode is the Mac/Linux P0 path. Local GPU mode is accepted only
after the exact host and runtime combination has been qualified.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

compose() {
  docker compose --project-directory "$ROOT" -f "$COMPOSE_FILE" "$@"
}

cleanup_bootstrap() {
  if [ -f "$BOOTSTRAP_FILE" ]; then
    : > "$BOOTSTRAP_FILE"
    chmod 600 "$BOOTSTRAP_FILE"
  fi
}

parse_args() {
  if [ "$#" -gt 0 ]; then
    case "$1" in
      start|check)
        ACTION=$1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --*) ;;
      *) fail "unknown action: $1" ;;
    esac
  fi

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --mode)
        [ "$#" -ge 2 ] || fail "--mode requires external or local"
        MODE=$2
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *) fail "unknown option: $1" ;;
    esac
  done

  case "$MODE" in
    external|local) ;;
    *) fail "unsupported model mode: $MODE" ;;
  esac
}

detect_platform() {
  system=$(uname -s)
  machine=$(uname -m)

  case "$system" in
    Darwin) PLATFORM=macOS ;;
    Linux) PLATFORM=Linux ;;
    *) fail "unsupported operating system: $system" ;;
  esac

  case "$machine" in
    x86_64|amd64) ARCH=amd64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) fail "unsupported architecture: $machine" ;;
  esac
}

check_port() {
  case "$PORT" in
    ''|*[!0-9]*) fail "SQLLENS_PORT must be a number between 1024 and 65535" ;;
  esac
  [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] ||
    fail "SQLLENS_PORT must be a number between 1024 and 65535"

  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
      fail "port $PORT is already in use; set SQLLENS_PORT to a free local port and retry"
    fi
    return
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)$PORT$"; then
      fail "port $PORT is already in use; set SQLLENS_PORT to a free local port and retry"
    fi
    return
  fi

  fail "cannot verify port $PORT because neither lsof nor ss is installed"
}

check_disk() {
  available_kib=$(df -Pk "$ROOT" | awk 'NR == 2 {print $4}')
  case "$available_kib" in
    ''|*[!0-9]*) fail "could not determine free disk space for $ROOT" ;;
  esac
  [ "$available_kib" -ge 4194304 ] ||
    fail "at least 4 GiB free disk is required; free space and retry"
}

check_model_mode() {
  [ "$MODE" = external ] && return

  if [ "$PLATFORM" = macOS ]; then
    fail "local GPU mode is not qualified on macOS; retry with --mode external"
  fi

  fail "local GPU mode is not qualified for this release; retry with --mode external"
}

prepare_bootstrap_file() {
  umask 077
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  : > "$BOOTSTRAP_FILE"
  chmod 600 "$BOOTSTRAP_FILE"
  export SQLLENS_BOOTSTRAP_FILE="$BOOTSTRAP_FILE"
}

run_preflight() {
  detect_platform
  check_model_mode

  command -v docker >/dev/null 2>&1 ||
    fail "Docker is not installed; install Docker Desktop or Docker Engine with Compose"
  docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null) ||
    fail "Docker daemon is unavailable; start Docker and retry"
  compose_version=$(docker compose version --short 2>/dev/null) ||
    fail "Docker Compose v2 is unavailable; install the Compose plugin and retry"

  [ -f "$COMPOSE_FILE" ] || fail "release is incomplete: missing deploy/compose.json"
  check_port
  check_disk
  compose config -q >/dev/null 2>&1 ||
    fail "Compose configuration is invalid for this host"

  printf 'Platform: %s/%s\n' "$PLATFORM" "$ARCH"
  printf 'Docker: %s\n' "$docker_version"
  printf 'Compose: %s\n' "$compose_version"
  printf 'Model mode: external\n'
  printf 'Port: %s (loopback only)\n' "$PORT"
  printf 'Preflight passed\n'
}

wait_for_health() {
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    container_id=$(compose ps -q web-api 2>/dev/null || true)
    if [ -n "$container_id" ]; then
      health=$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)
      case "$health" in
        healthy) return 0 ;;
        unhealthy) fail "Web App health check failed; run ./launch.sh diagnostics" ;;
      esac
    fi
    attempt=$((attempt + 1))
    sleep 2
  done

  fail "Web App did not become healthy within 120 seconds; run ./launch.sh diagnostics"
}

start() {
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to create the one-time setup code"
  code=$(openssl rand -hex 16) || fail "could not create the one-time setup code"
  [ "${#code}" -eq 32 ] || fail "could not create a strong one-time setup code"
  printf '%s\n' "$code" > "$BOOTSTRAP_FILE"

  compose run --rm web-api migrate
  compose up -d --build
  wait_for_health

  printf '\nWeb App: http://127.0.0.1:%s\n' "$PORT"
  printf 'One-time initialization code: %s\n' "$code"
  printf 'The code is short-lived and is not written to application logs.\n'
}

parse_args "$@"
prepare_bootstrap_file
trap cleanup_bootstrap 0 1 2 3 15
run_preflight

case "$ACTION" in
  check) ;;
  start) start ;;
esac
