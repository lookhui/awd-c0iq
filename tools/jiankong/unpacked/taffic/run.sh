#!/usr/bin/env bash
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$BASE_DIR/lib:${LD_LIBRARY_PATH}"
chmod +x "$BASE_DIR/tafficc"
# 新增：运行程序
"$BASE_DIR/tafficc"
