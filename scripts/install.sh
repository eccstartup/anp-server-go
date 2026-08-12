#!/usr/bin/env bash
#
# 安装 anp-server 到 PATH
#
# 用法: bash scripts/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="anp-server"

info()  { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

# 选择安装目录：优先 PATH 上可写的
INSTALL_DIR="${ANP_INSTALL_DIR:-}"
if [ -z "$INSTALL_DIR" ]; then
  for d in "$HOME/.local/bin" "$HOME/bin" "/usr/local/bin"; do
    if [ -d "$d" ] && [ -w "$d" ]; then
      case ":$PATH:" in *":$d:"*) INSTALL_DIR="$d"; break ;; esac
    fi
  done
fi
[ -z "$INSTALL_DIR" ] && INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR" || die "无法创建 $INSTALL_DIR"

info "构建 anp-server ..."
( cd "$PROJECT_ROOT" && go build -o "$PROJECT_ROOT/anp-server" ./cmd/anp-server ) || die "构建失败"

cp "$PROJECT_ROOT/anp-server" "$INSTALL_DIR/$BINARY_NAME" || die "复制失败"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

info "已安装: $INSTALL_DIR/$BINARY_NAME"
"$INSTALL_DIR/$BINARY_NAME" --help 2>&1 | head -1 || true
