#!/usr/bin/env bash
# C++ 在线判题 启动脚本
set -e

PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

# 如需自定义密码，取消下面两行注释并修改：
# export JUDGE_PASSWORD="你的访问密码"
# export ADMIN_PASSWORD="你的后台密码"

echo "▶ 启动 C++ 在线判题： http://${HOST}:${PORT}/"
echo "  主站：     http://${HOST}:${PORT}/"
echo "  管理后台： http://${HOST}:${PORT}/admin"

exec uvicorn app:app --host "${HOST}" --port "${PORT}"
