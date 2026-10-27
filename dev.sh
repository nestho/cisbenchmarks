#!/usr/bin/env bash
# HardenX Live Development Server (Apple Silicon / M1 / M2 / M3 / macOS & Linux)
# Launches Go API Backend (:8080) + Vite Frontend with Instant HMR Hot-Reload (:5173)

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

cleanup() {
  echo ""
  echo "[*] Shutting down HardenX services..."
  kill $(jobs -p) 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM EXIT

echo "=========================================================="
echo "  🚀 Starting HardenX Enterprise Suite (Live Dev Mode)"
echo "=========================================================="

# 1. Start Go Backend
echo "[*] Launching Go Backend API server on :8080..."
(
  cd platform/backend
  go run ./cmd/server
) &
BACKEND_PID=$!

# Wait 1s for backend to initialize
sleep 1

# 2. Start Vite Frontend with Hot Module Reload
echo "[*] Launching Vite Frontend Dev Server with HMR on :5173..."
(
  cd platform/frontend
  npm run dev -- --host
) &
FRONTEND_PID=$!

echo ""
echo "=========================================================="
echo "  ✅ HardenX Live Services Active:"
echo "  • Dashboard UI (Live Hot-Reload): http://localhost:5173"
echo "  • Core API & Endpoints:           http://localhost:8080/api/v1/benchmarks"
echo "  • Health Status:                  http://localhost:8080/health"
echo "=========================================================="
echo "  Press Ctrl+C to stop all services."
echo ""

wait
