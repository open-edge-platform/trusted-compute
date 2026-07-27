#!/bin/bash
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# NPU telemetry agent for kata guests. Reads InfluxDB line protocol from the
# npu-reader binary and pushes it over HTTP to a configurable collector endpoint.
#
# Metrics emitted by npu-reader (one line per second):
#     npu,host=<h> power=<W>,frequency=<Hz>,temperature=<C>i,
#                  bandwidth=<MB/s>,tile_config=<n>i,utilization=<pct>i,
#                  memory_mb=<MB> <ts_ns>
#
# The collector endpoint is configured via Kata kernel_params annotation:
#   push_host=<ip>  push_port=<port>  push_path=<path>
# Any HTTP listener that accepts InfluxDB line protocol (Telegraf, Victoria
# Metrics, InfluxDB, etc.) can be used as the target.
#
# Implemented in bash + static npu-reader binary (no Python in VM).
#
# Guest install paths:
#   /usr/local/bin/npu-reader              (NPU stats tool — static Rust binary, musl target)
#   /usr/local/bin/npu-telemetry-agent.sh

set -euo pipefail

log() { echo "[npu-telemetry] $*" >&2; }

# ---------------------------------------------------------------------------
# Read kernel cmdline parameters injected by Kata
# ---------------------------------------------------------------------------
_cmdline_val() {
  local key="$1"
  local token
  for token in $(cat /proc/cmdline 2>/dev/null); do
    case "${token}" in "${key}="*) echo "${token#"${key}="}"; return;; esac
  done
}
PUSH_HOST="$(_cmdline_val push_host)"
PUSH_PORT="$(_cmdline_val push_port)"
PUSH_PATH="$(_cmdline_val push_path)"

if [ -z "${PUSH_HOST}" ]; then
  log "PUSH_HOST not configured; telemetry disabled."
  exit 0
fi
if [ -z "${PUSH_PORT}" ]; then
  log "PUSH_PORT not configured; telemetry disabled."
  exit 0
fi
if ! [[ "${PUSH_PORT}" =~ ^[0-9]+$ ]] || (( PUSH_PORT < 1 || PUSH_PORT > 65535 )); then
  log "PUSH_PORT is invalid (${PUSH_PORT}); telemetry disabled."
  exit 0
fi
if [ -z "${PUSH_PATH}" ]; then
  log "PUSH_PATH not configured; telemetry disabled."
  exit 0
fi
if [[ "${PUSH_PATH}" != /* ]] || [[ "${PUSH_PATH}" == *[[:space:]]* ]]; then
  log "PUSH_PATH must start with '/' and contain no whitespace: '${PUSH_PATH}'; telemetry disabled."
  exit 0
fi
if ! [[ "${PUSH_HOST}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  log "PUSH_HOST must be an IP/hostname with only [A-Za-z0-9.-]: '${PUSH_HOST}'; telemetry disabled."
  exit 0
fi

INTERVAL_MS="${COLLECT_INTERVAL_MS:-1000}"
if ! [[ "${INTERVAL_MS}" =~ ^[0-9]+$ ]] || (( INTERVAL_MS < 100 )); then
  log "COLLECT_INTERVAL_MS must be an integer >= 100 (got: ${INTERVAL_MS}); telemetry disabled."
  exit 0
fi

NPU_READER_BIN="${NPU_READER_BIN:-/usr/local/bin/npu-reader}"
[[ -x "$NPU_READER_BIN" ]] || { log "NPU_READER_BIN not executable: $NPU_READER_BIN"; exit 1; }

# The guest has no `hostname` binary; bash sets $HOSTNAME natively.
HOSTTAG="${METRICS_HOSTNAME:-${HOSTNAME:-$(cat /etc/hostname 2>/dev/null || echo kata-guest)}}"

# ---------------------------------------------------------------------------
# Wait up to 60 s for the NPU accel device (hot-plugged after boot)
# ---------------------------------------------------------------------------
for _ in {1..60}; do
  ls /dev/accel/accel* >/dev/null 2>&1 && break
  sleep 1
done
ls /dev/accel/accel* >/dev/null 2>&1 || { log "no NPU accel device present; exiting."; exit 0; }

# ---------------------------------------------------------------------------
# HTTP POST helper (pure bash /dev/tcp — no curl/wget in the VM)
# ---------------------------------------------------------------------------
post() {
  local body="$1"
  [ -n "$body" ] || return 0
  {
    printf 'POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
      "$PUSH_PATH" "$PUSH_HOST" "${#body}" "$body"
  } | timeout 10s bash -c 'cat >"/dev/tcp/$1/$2"' _ "$PUSH_HOST" "$PUSH_PORT" 2>/dev/null || {
    log "POST to ${PUSH_HOST}:${PUSH_PORT} failed or timed out"
    return 1
  }
}

log "NPU detected; pushing to http://${PUSH_HOST}:${PUSH_PORT}${PUSH_PATH} (InfluxDB line protocol)"

# ---------------------------------------------------------------------------
# Run npu-reader; read its stdout line by line and POST each metric line
# ---------------------------------------------------------------------------
METRICS_HOSTNAME="$HOSTTAG" NPU_INTERVAL_MS="$INTERVAL_MS" "$NPU_READER_BIN" | \
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    post "$line" || log "push failed; continuing"
  done

log "npu-reader exited; restarting via systemd."
exit 1
