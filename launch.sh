#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="$ROOT/deploy/compose.json"
STATE_DIR=${SQLLENS_STATE_DIR:-"$HOME/.sqllens"}
BOOTSTRAP_FILE="$STATE_DIR/bootstrap-code"
HASH_MARKER="$STATE_DIR/bootstrap-hash-persisted"
LOCK_DIR="$STATE_DIR/start.lock"
PORT_EXPLICIT=0
if [ "${SQLLENS_PORT+x}" = x ]; then
  PORT_EXPLICIT=1
fi
PORT=${SQLLENS_PORT:-8080}
MODE=external
ACTION=start
PURGE_DATA=0
PLATFORM=
ARCH=
DOCKER_VERSION=
COMPOSE_VERSION=
CONTAINER_ID=
PUBLISHED_PORT=
ALREADY_RUNNING=0
LOCK_HELD=0
HASH_PERSISTED=0
TEMP_SECRET=
BOOTSTRAP_CODE=

usage() {
  cat <<'EOF'
Usage: ./launch.sh [action] [options]

Actions:
  start         Run preflight, migrate, and start the Web App (default).
  check         Run a read-only preflight without changing application state.
  stop          Stop the application and retain its data volume.
  uninstall     Remove application containers and retain data by default.
  diagnostics   Create a privacy-bounded diagnostic archive.

Options:
  --mode external|local  Select the model mode (default: external).
  --purge-data           With uninstall, also remove the named data volume.

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

parse_args() {
  if [ "$#" -gt 0 ]; then
    case "$1" in
      start|check|stop|uninstall|diagnostics)
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
      --purge-data)
        PURGE_DATA=1
        shift
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

  if [ "$PURGE_DATA" -eq 1 ] && [ "$ACTION" != uninstall ]; then
    fail "--purge-data is only valid with uninstall"
  fi
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

check_runtime() {
  command -v docker >/dev/null 2>&1 ||
    fail "Docker is not installed; install Docker Desktop or Docker Engine with Compose"
  DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null) ||
    fail "Docker daemon is unavailable; start Docker and retry"
  COMPOSE_VERSION=$(docker compose version --short 2>/dev/null) ||
    fail "Docker Compose v2 is unavailable; install the Compose plugin and retry"

  [ -f "$COMPOSE_FILE" ] || fail "release is incomplete: missing deploy/compose.json"
  compose config -q >/dev/null 2>&1 ||
    fail "Compose configuration is invalid for this host"
}

managed_web_running() {
  container_id=$(compose ps -q web-api 2>/dev/null | sed -n '1p')
  [ -n "$container_id" ] || return 1
  running=$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)
  [ "$running" = true ] || return 1
  CONTAINER_ID=$container_id
  return 0
}

read_managed_port() {
  published=$(docker port "$CONTAINER_ID" 8080/tcp 2>/dev/null | sed -n '1p') ||
    fail "could not read the managed Web App port; run ./launch.sh diagnostics"
  actual_port=${published##*:}
  case "$actual_port" in
    ''|*[!0-9]*)
      fail "managed Web App has no valid published port; run ./launch.sh diagnostics"
      ;;
  esac
  [ "$actual_port" -ge 1024 ] && [ "$actual_port" -le 65535 ] ||
    fail "managed Web App has an invalid published port; run ./launch.sh diagnostics"
  PUBLISHED_PORT=$actual_port
}

adopt_managed_port() {
  read_managed_port
  if [ "$PORT_EXPLICIT" -eq 1 ] && [ "$PORT" -ne "$PUBLISHED_PORT" ]; then
    fail "managed Web App is already running at http://127.0.0.1:$PUBLISHED_PORT; requested port $PORT differs; use the existing URL or run ./launch.sh stop before SQLLENS_PORT=$PORT ./launch.sh start"
  fi
  PORT=$PUBLISHED_PORT
}

check_port() {
  case "$PORT" in
    ''|*[!0-9]*) fail "SQLLENS_PORT must be a number between 1024 and 65535" ;;
  esac
  [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] ||
    fail "SQLLENS_PORT must be a number between 1024 and 65535"

  if managed_web_running; then
    adopt_managed_port
    ALREADY_RUNNING=1
    return
  fi

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

run_preflight() {
  detect_platform
  check_model_mode
  check_runtime
  check_port
  check_disk

  printf 'Platform: %s/%s\n' "$PLATFORM" "$ARCH"
  printf 'Docker: %s\n' "$DOCKER_VERSION"
  printf 'Compose: %s\n' "$COMPOSE_VERSION"
  printf 'Model mode: external\n'
  printf 'Port: %s (loopback only)\n' "$PORT"
  if [ "$ALREADY_RUNNING" -eq 1 ]; then
    printf 'Managed Web App: already running\n'
  fi
  printf 'Preflight passed\n'
}

release_start_lock() {
  [ "$LOCK_HELD" -eq 1 ] || return 0
  if [ -f "$LOCK_DIR/owner-pid" ]; then
    unlink "$LOCK_DIR/owner-pid" 2>/dev/null || true
  fi
  rmdir "$LOCK_DIR" 2>/dev/null || true
  LOCK_HELD=0
}

scrub_bootstrap_secret() {
  [ -f "$BOOTSTRAP_FILE" ] && [ ! -L "$BOOTSTRAP_FILE" ] || return 1
  : > "$BOOTSTRAP_FILE" || return 1
  chmod 600 "$BOOTSTRAP_FILE" || return 1
  [ ! -s "$BOOTSTRAP_FILE" ] || return 1
  return 0
}

on_exit() {
  status=$?
  trap - 0 1 2 3 15

  if [ "$HASH_PERSISTED" -eq 1 ]; then
    if ! scrub_bootstrap_secret; then
      printf 'ERROR: bootstrap hash is persisted but the mounted secret could not be scrubbed\n' >&2
      status=1
    fi
  fi
  if [ -n "$TEMP_SECRET" ] && [ -f "$TEMP_SECRET" ]; then
    unlink "$TEMP_SECRET" 2>/dev/null || true
  fi
  release_start_lock
  exit "$status"
}

install_start_traps() {
  trap on_exit 0
  trap 'exit 129' 1
  trap 'exit 130' 2
  trap 'exit 131' 3
  trap 'exit 143' 15
}

acquire_start_lock() {
  umask 077
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  if mkdir "$LOCK_DIR" 2>/dev/null; then
    LOCK_HELD=1
    printf '%s\n' "$$" > "$LOCK_DIR/owner-pid"
    chmod 600 "$LOCK_DIR/owner-pid"
    return
  fi

  owner_pid=
  attempts=0
  while [ "$attempts" -lt 10 ] && [ ! -f "$LOCK_DIR/owner-pid" ]; do
    attempts=$((attempts + 1))
    sleep 1
  done
  if [ -f "$LOCK_DIR/owner-pid" ]; then
    owner_pid=$(sed -n '1p' "$LOCK_DIR/owner-pid")
  fi

  case "$owner_pid" in
    ''|*[!0-9]*) ;;
    *)
      if kill -0 "$owner_pid" 2>/dev/null; then
        fail "startup is already in progress (pid $owner_pid); wait for it to finish or run ./launch.sh diagnostics"
      fi
      ;;
  esac

  if [ -f "$LOCK_DIR/owner-pid" ]; then
    unlink "$LOCK_DIR/owner-pid" 2>/dev/null ||
      fail "stale startup lock could not be cleared; run ./launch.sh diagnostics"
  fi
  rmdir "$LOCK_DIR" 2>/dev/null ||
    fail "stale startup lock contains unexpected files; run ./launch.sh diagnostics"

  mkdir "$LOCK_DIR" 2>/dev/null ||
    fail "startup is already in progress; wait for it to finish or run ./launch.sh diagnostics"
  LOCK_HELD=1
  printf '%s\n' "$$" > "$LOCK_DIR/owner-pid"
  chmod 600 "$LOCK_DIR/owner-pid"
}

start_lock_is_active() {
  [ -f "$LOCK_DIR/owner-pid" ] || return 1
  owner_pid=$(sed -n '1p' "$LOCK_DIR/owner-pid")
  case "$owner_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$owner_pid" 2>/dev/null
}

create_bootstrap_secret() {
  command -v openssl >/dev/null 2>&1 ||
    fail "openssl is required to create the one-time setup code"
  BOOTSTRAP_CODE=$(openssl rand -hex 16) ||
    fail "could not create the one-time setup code"
  [ "${#BOOTSTRAP_CODE}" -eq 32 ] ||
    fail "could not create a strong one-time setup code"

  TEMP_SECRET="$STATE_DIR/.bootstrap-code.$$"
  umask 077
  printf '%s\n' "$BOOTSTRAP_CODE" > "$TEMP_SECRET"
  chmod 600 "$TEMP_SECRET"
  mv -f "$TEMP_SECRET" "$BOOTSTRAP_FILE"
  TEMP_SECRET=
}

load_reusable_bootstrap_secret() {
  [ -f "$BOOTSTRAP_FILE" ] && [ ! -L "$BOOTSTRAP_FILE" ] ||
    fail "retained bootstrap secret is not a regular file; run ./launch.sh diagnostics"
  permissions=$(LC_ALL=C ls -ld "$BOOTSTRAP_FILE" | awk '{print $1}')
  case "$permissions" in
    -rw-------*) ;;
    *) fail "retained bootstrap secret must have mode 0600; run ./launch.sh diagnostics" ;;
  esac

  BOOTSTRAP_CODE=$(sed -n '1p' "$BOOTSTRAP_FILE")
  case "$BOOTSTRAP_CODE" in
    ''|*[!0-9a-f]*) fail "retained bootstrap secret has an invalid format; run ./launch.sh diagnostics" ;;
  esac
  [ "${#BOOTSTRAP_CODE}" -eq 32 ] ||
    fail "retained bootstrap secret has an invalid length; run ./launch.sh diagnostics"
}

create_or_reuse_bootstrap_secret() {
  if [ -e "$BOOTSTRAP_FILE" ] || [ -L "$BOOTSTRAP_FILE" ]; then
    if [ -s "$BOOTSTRAP_FILE" ]; then
      load_reusable_bootstrap_secret
      return
    fi
    if [ -f "$HASH_MARKER" ] && [ "$(sed -n '1p' "$HASH_MARKER")" = v1 ]; then
      return
    fi
    fail "existing bootstrap secret is empty without a persistence marker; run ./launch.sh diagnostics"
  fi

  if [ -f "$HASH_MARKER" ] && [ "$(sed -n '1p' "$HASH_MARKER")" = v1 ]; then
    TEMP_SECRET="$STATE_DIR/.bootstrap-code.$$"
    umask 077
    : > "$TEMP_SECRET"
    chmod 600 "$TEMP_SECRET"
    mv -f "$TEMP_SECRET" "$BOOTSTRAP_FILE"
    TEMP_SECRET=
    return
  fi

  create_bootstrap_secret
}

ingest_bootstrap_secret() {
  [ -n "$BOOTSTRAP_CODE" ] || return 0
  [ -f "$BOOTSTRAP_FILE" ] && [ ! -L "$BOOTSTRAP_FILE" ] && [ -s "$BOOTSTRAP_FILE" ] ||
    fail "bootstrap secret is unavailable for one-shot ingest; run ./launch.sh diagnostics"
  compose run --rm -T --no-deps web-api bootstrap-ingest < "$BOOTSTRAP_FILE" ||
    fail "runtime rejected bootstrap ingest; the 0600 secret was retained; run ./launch.sh diagnostics"
}

write_hash_marker() {
  marker_temp="$STATE_DIR/.bootstrap-hash-persisted.$$"
  umask 077
  printf 'v1\n' > "$marker_temp" || return 1
  chmod 600 "$marker_temp" || return 1
  mv -f "$marker_temp" "$HASH_MARKER" || return 1
  return 0
}

wait_for_health() {
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    if [ -z "$CONTAINER_ID" ]; then
      CONTAINER_ID=$(compose ps -q web-api 2>/dev/null | sed -n '1p')
    fi
    if [ -n "$CONTAINER_ID" ]; then
      health=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER_ID" 2>/dev/null || true)
      case "$health" in
        healthy) return 0 ;;
        unhealthy)
          fail "Web App health check failed; run ./launch.sh diagnostics, then ./launch.sh stop and ./launch.sh start"
          ;;
      esac
    fi
    attempt=$((attempt + 1))
    sleep 2
  done

  fail "Web App did not become healthy within 120 seconds; run ./launch.sh diagnostics, then ./launch.sh stop and ./launch.sh start"
}

bootstrap_hash_is_persisted() {
  docker exec "$CONTAINER_ID" python -c \
      "import json,sys,urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/v1/setup/status', timeout=2)); sys.exit(0 if data.get('bootstrap_hash_persisted') is True else 1)" \
      >/dev/null 2>&1
}

wait_for_bootstrap_hash() {
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    if bootstrap_hash_is_persisted; then
      write_hash_marker ||
        fail "runtime confirmed the bootstrap hash but the local persistence marker could not be written; the secret was retained"
      HASH_PERSISTED=1
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done

  fail "runtime did not confirm bootstrap hash persistence; the 0600 secret was retained; run ./launch.sh diagnostics"
}

print_running_url() {
  printf '\nWeb App is already running: http://127.0.0.1:%s\n' "$PORT"
  printf 'No new initialization code was generated.\n'
}

print_setup_url_and_code() {
  printf '\nWeb App: http://127.0.0.1:%s\n' "$PORT"
  printf 'One-time initialization code: %s\n' "$BOOTSTRAP_CODE"
  printf 'The code is short-lived and is not written to application logs.\n'
}

resume_running_start() {
  if start_lock_is_active; then
    fail "startup is already in progress; use the original launcher window or run ./launch.sh diagnostics"
  fi
  wait_for_health

  if [ -s "$BOOTSTRAP_FILE" ]; then
    install_start_traps
    acquire_start_lock
    load_reusable_bootstrap_secret
    wait_for_bootstrap_hash
    print_setup_url_and_code
    return
  fi

  if bootstrap_hash_is_persisted; then
    print_running_url
    return
  fi

  fail "running Web App has no persisted bootstrap hash or recoverable secret; run ./launch.sh diagnostics, then ./launch.sh stop and ./launch.sh start"
}

start_action() {
  if [ "$ALREADY_RUNNING" -eq 1 ]; then
    resume_running_start
    return
  fi

  install_start_traps
  acquire_start_lock

  if managed_web_running; then
    adopt_managed_port
    wait_for_health
    print_running_url
    return
  fi

  create_or_reuse_bootstrap_secret
  compose build web-api
  compose run --rm web-api migrate
  ingest_bootstrap_secret
  compose up -d --no-build
  wait_for_health
  wait_for_bootstrap_hash
  if [ -n "$BOOTSTRAP_CODE" ]; then
    print_setup_url_and_code
  else
    print_running_url
  fi
}

stop_action() {
  compose down --remove-orphans
  printf 'Application stopped. Data retained in Docker volume sqllens-data.\n'
}

uninstall_action() {
  if [ "$PURGE_DATA" -eq 1 ]; then
    if [ -L "$STATE_DIR" ]; then
      fail "local state directory is a symbolic link; run ./launch.sh diagnostics"
    fi
    install_start_traps
    acquire_start_lock
    validate_purge_local_state
    compose down --remove-orphans --volumes --rmi local
    clear_purge_local_state
    printf 'Application removed. Data volume removed by explicit request.\n'
    return
  fi

  compose down --remove-orphans --rmi local
  printf 'Application removed. Data retained in Docker volume sqllens-data.\n'
}

validate_purge_file() {
  path=$1
  label=$2
  if [ -e "$path" ] || [ -L "$path" ]; then
    [ -f "$path" ] && [ ! -L "$path" ] ||
      fail "$label is not a regular file; run ./launch.sh diagnostics"
  fi
}

validate_purge_local_state() {
  validate_purge_file "$BOOTSTRAP_FILE" "bootstrap secret"
  validate_purge_file "$HASH_MARKER" "bootstrap persistence marker"
}

clear_purge_local_state() {
  for path in "$BOOTSTRAP_FILE" "$HASH_MARKER"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      unlink "$path" || fail "data was removed but local bootstrap state could not be cleared"
    fi
  done
  release_start_lock
  rmdir "$STATE_DIR" 2>/dev/null || true
}

diagnostics_action() {
  command -v tar >/dev/null 2>&1 || fail "tar is required to create diagnostics"
  detect_platform
  check_runtime

  umask 077
  diagnostics_root="$STATE_DIR/diagnostics"
  timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
  bundle_name="diagnostics-$timestamp-$$"
  bundle_dir="$diagnostics_root/$bundle_name"
  archive="$diagnostics_root/$bundle_name.tar.gz"
  mkdir -p "$bundle_dir"
  chmod 700 "$STATE_DIR" "$diagnostics_root" "$bundle_dir"

  {
    printf 'platform=%s\n' "$PLATFORM"
    printf 'architecture=%s\n' "$ARCH"
    printf 'docker_version=%s\n' "$DOCKER_VERSION"
    printf 'compose_version=%s\n' "$COMPOSE_VERSION"
    printf 'port=%s\n' "$PORT"
  } > "$bundle_dir/system.txt"
  compose config > "$bundle_dir/compose.txt" 2>&1 || true
  compose ps --all > "$bundle_dir/containers.txt" 2>&1 || true

  container_id=$(compose ps -q web-api 2>/dev/null | sed -n '1p')
  if [ -n "$container_id" ]; then
    docker inspect --format \
      'name={{.Name}} image={{.Config.Image}} state={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{end}} exit_code={{.State.ExitCode}}' \
      "$container_id" > "$bundle_dir/web-api-state.txt" 2>&1 || true
  fi
  docker volume inspect --format 'name={{.Name}} driver={{.Driver}}' sqllens-data \
    > "$bundle_dir/volume.txt" 2>&1 || true

  chmod 600 "$bundle_dir"/*.txt
  tar -czf "$archive" -C "$diagnostics_root" "$bundle_name"
  chmod 600 "$archive"
  printf 'Diagnostics archive: %s\n' "$archive"
  printf 'Resolved Compose configuration is included. Application logs, container inspect environments, credentials, and user data were not collected.\n'
}

parse_args "$@"

case "$ACTION" in
  check)
    run_preflight
    ;;
  start)
    run_preflight
    start_action
    ;;
  stop)
    check_runtime
    stop_action
    ;;
  uninstall)
    check_runtime
    uninstall_action
    ;;
  diagnostics)
    diagnostics_action
    ;;
esac
