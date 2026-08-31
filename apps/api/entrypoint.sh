#!/bin/sh

set -eu

case "${1:-web-api}" in
  web-api)
    export SQLLENS_BIND_HOST=${SQLLENS_BIND_HOST:-0.0.0.0}
    export SQLLENS_PORT=${SQLLENS_PORT:-8080}
    exec python -m sqllens_api.main web-api
    ;;
  migrate)
    exec python -m sqllens_api.main migrate
    ;;
  *)
    printf 'unsupported runtime command: %s\n' "$1" >&2
    exit 64
    ;;
esac
