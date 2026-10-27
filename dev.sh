#!/usr/bin/env bash
# HardenX Live Development Server (Apple Silicon / M1 / M2 / M3 / macOS & Linux)
# Launches Go API Backend (:8080) + Vite Frontend with Instant HMR Hot-Reload (:5173)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Free ports 8080 and 5173 if already occupied
echo "[*] Checking and freeing ports 8080 and 5173..."
for port in 8080 5173; do
  pids=$(lsof -ti :$port 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "[*] Killing stale process on port $port (PID: $pids)..."
    kill -9 $pids 2>/dev/null || true
  fi
done

cleanup() {
  echo ""
  echo "[*] Stopping HardenX dev services..."
  if [ -n "$BACKEND_PID" ]; then kill -TERM "$BACKEND_PID" 2>/dev/null || true; fi
  if [ -n "$FRONTEND_PID" ]; then kill -TERM "$FRONTEND_PID" 2>/dev/null || true; fi
  exit 0
}
trap cleanup SIGINT SIGTERM

echo "=========================================================="
echo "  🚀 Starting HardenX Enterprise Suite (Live Dev Mode)"
echo "=========================================================="

# 1. Start Go Backend
echo "[*] Launching Go Backend API server on http://localhost:8080..."
(
  cd platform/backend
  exec go run ./cmd/server
) &
BACKEND_PID=$!

# Wait for backend to be ready
echo "[*] Waiting for backend API to be ready..."
for i in {1..15}; do
  if curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "[+] Backend API online and healthy!"
    break
  fi
  sleep 0.5
done

# 2. Start Vite Frontend with Hot Module Reload
echo "[*] Launching Vite Frontend Dev Server on http://localhost:5173..."
(
  cd platform/frontend
  exec npm run dev -- --host
) &
FRONTEND_PID=$!

echo ""
echo "=========================================================="
echo "  ✅ HardenX Live Services Active:"
echo "  • Dashboard UI (Live Hot-Reload): http://localhost:5173"
echo "  • Core API:                       http://localhost:8080"
echo "  • Health Check:                   http://localhost:8080/health"
echo "=========================================================="
echo "  Press Ctrl+C to stop."
echo ""

wait
