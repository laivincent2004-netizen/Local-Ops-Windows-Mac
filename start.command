#!/bin/bash
set -u
umask 077
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "错误：未找到 Python 3，请先安装 Python 3.12 或更高版本。" >&2
  exit 127
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
  echo "错误：总控台需要 Python 3.12 或更高版本。" >&2
  exit 126
fi
exec python3 server.py --launcher
