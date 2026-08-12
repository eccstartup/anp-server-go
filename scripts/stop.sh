#!/usr/bin/env bash
#
# 停止 anp-server
#
# 用法: bash scripts/stop.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PIDFILE="$PROJECT_ROOT/anp-server.pid"

info()  { printf '\033[1;34m[anp-server]\033[0m %s\n' "$*"; }

if [ ! -f "$PIDFILE" ]; then
  info "没有找到 PID 文件（$PIDFILE），服务可能未通过 start.sh 启动。"
  info "如果是手动启动的，用 Ctrl-C 或 kill <pid> 停止。"
  exit 0
fi

PID=$(cat "$PIDFILE")
if kill -0 "$PID" 2>/dev/null; then
  info "停止 anp-server (pid=$PID) ..."
  kill "$PID" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.3
  done
  if kill -0 "$PID" 2>/dev/null; then
    info "进程未响应，强制终止..."
    kill -9 "$PID" 2>/dev/null || true
  fi
  info "已停止。"
else
  info "进程 $PID 已不存在，清理 PID 文件。"
fi

rm -f "$PIDFILE" "$PROJECT_ROOT/anp-server.url"
rm -f "$PROJECT_ROOT/anp-server.log" "$PROJECT_ROOT/anp-server.err.log"
