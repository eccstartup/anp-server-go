#!/usr/bin/env bash
#
# anp-server 安装启动脚本
#
# 用法:
#   ./scripts/install.sh              # 构建并安装到 PATH 上
#   ./scripts/start.sh                # 启动服务器（后台/前台可选）
#   ./scripts/start.sh --foreground   # 前台运行（Ctrl-C 停止）
#   ./scripts/start.sh --db ./mydata.db --port 8765
#
# 环境变量（也可用命令行参数）:
#   ANP_SERVER_DB     数据库文件（默认 ./data.db）
#   ANP_SERVER_HOST   监听地址（默认 127.0.0.1）
#   ANP_SERVER_PORT   监听端口（默认 0 = 随机）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEFAULT_DB="$PROJECT_ROOT/data.db"

info()  { printf '\033[1;34m[anp-server]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[anp-server]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 参数解析
FOREGROUND=""
DB="${ANP_SERVER_DB:-$DEFAULT_DB}"
HOST="${ANP_SERVER_HOST:-127.0.0.1}"
PORT="${ANP_SERVER_PORT:-0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --foreground|-f) FOREGROUND=1 ;;
    --db) DB="$2"; shift ;;
    --host) HOST="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --help|-h)
      echo "用法: bash scripts/start.sh [--foreground] [--db path] [--host h] [--port p]"
      echo ""
      echo "  --foreground, -f    前台运行（Ctrl-C 停止）"
      echo "  --db path           数据库文件（默认 ./data.db，留空用临时库）"
      echo "  --host h            监听地址（默认 127.0.0.1）"
      echo "  --port p            监听端口（默认随机）"
      echo ""
      echo "环境变量: ANP_SERVER_DB  ANP_SERVER_HOST  ANP_SERVER_PORT"
      exit 0
      ;;
    *) die "未知参数: $1（用 --help 看用法）" ;;
  esac
  shift
done

# ---------------------------------------------------------------- 构建
info "构建 anp-server ..."
( cd "$PROJECT_ROOT" && go build -o "$PROJECT_ROOT/anp-server" ./cmd/anp-server ) \
  || die "构建失败，请确认依赖可用（go mod tidy）。"

# ---------------------------------------------------------------- 启动
PORT_ARG=""
if [ "$PORT" != "0" ]; then
  PORT_ARG="--port $PORT"
fi

if [ -n "$FOREGROUND" ]; then
  info "前台启动（Ctrl-C 停止）"
  exec "$PROJECT_ROOT/anp-server" --db "$DB" --host "$HOST" ${PORT_ARG}
else
  LOGFILE="$PROJECT_ROOT/anp-server.log"
  PIDFILE="$PROJECT_ROOT/anp-server.pid"

  if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE")
    if kill -0 "$OLD_PID" 2>/dev/null && [ "$(ps -p "$OLD_PID" -o comm= 2>/dev/null)" = "anp-server" ]; then
      OLD_URL=$(cat "$PROJECT_ROOT/anp-server.url" 2>/dev/null || echo "?")
      info "服务已在运行（pid=$OLD_PID，$OLD_URL）。用 scripts/stop.sh 先停掉。"
      exit 0
    fi
    rm -f "$PIDFILE"
  fi

  "$PROJECT_ROOT/anp-server" --db "$DB" --host "$HOST" ${PORT_ARG} > "$PROJECT_ROOT/anp-server.url" 2>"$LOGFILE" &
  PID=$!
  echo "$PID" > "$PIDFILE"

  # 等它打印 URL
  for _ in $(seq 1 30); do
    [ -s "$PROJECT_ROOT/anp-server.url" ] && break
    sleep 0.2
  done

  URL=$(cat "$PROJECT_ROOT/anp-server.url" 2>/dev/null || echo "")
  if [ -z "$URL" ]; then
    info "后台启动中（pid=$PID）。日志: $LOGFILE"
    info "URL 还没出来，等一下再看 cat $PROJECT_ROOT/anp-server.url"
  else
    info "已启动 → $URL  (pid=$PID, db=$DB)"
    echo "  URL: $URL"
    echo "  日志: $LOGFILE"
    echo "  停止: bash scripts/stop.sh"
    echo "  状态: curl $URL/healthz"
  fi
fi
