#!/bin/bash
# GatewayGuard 一键启动脚本

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"

echo "========================================="
echo "  GatewayGuard - 智能网关网络分析平台"
echo "========================================="

# 启动后端
echo "[1/2] 启动后端服务..."
cd "$BACKEND_DIR"

if [ ! -d "venv" ]; then
    echo "  创建虚拟环境..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -r requirements.txt -q -i https://pypi.tuna.tsinghua.edu.cn/simple --timeout 120

echo "  后端启动中 -> http://localhost:8000"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# 启动前端
echo "[2/2] 启动前端服务..."
cd "$FRONTEND_DIR"

if [ ! -d "node_modules" ]; then
    echo "  安装前端依赖..."
    npm install
fi

echo "  前端启动中 -> http://localhost:5173"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "========================================="
echo "  服务已启动:"
echo "  后端 API:  http://localhost:8000/docs"
echo "  前端界面:  http://localhost:5173"
echo "========================================="
echo "  按 Ctrl+C 停止所有服务"
echo ""

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
