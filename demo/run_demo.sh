#!/bin/bash
# LogCentry Demo Runner
# Starts both the LogCentry API server and the VulnApp demo

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment if available
if [ -d "$PROJECT_DIR/.venv" ]; then
	source "$PROJECT_DIR/.venv/bin/activate"
fi

echo "=============================================="
echo " 🛡️  LogCentry Full Demo"
echo "=============================================="
echo ""

# Add src to PYTHONPATH
export PYTHONPATH="$PROJECT_DIR/src:$PYTHONPATH"

echo "📡 Starting LogCentry API Server on port 8000..."
python3 -c "
import sys
sys.path.insert(0, '$PROJECT_DIR/src')
from logcentry.api.server import run_server
run_server(host='0.0.0.0', port=8000)
" &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo ""
echo "🔓 Starting VulnApp Demo on port 5000..."
echo ""

python3 "$SCRIPT_DIR/vulnapp.py"

# Cleanup
kill $SERVER_PID 2>/dev/null || true
