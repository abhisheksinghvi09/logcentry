#!/bin/bash
#Nikhil Demo
# Start the LogCentry API server and demo application
# Kill any existing processes on ports 8000 and 5000
fuser -k 8000/tcp 2>/dev/null
fuser -k 5000/tcp 2>/dev/null

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Add src to PYTHONPATH
export PYTHONPATH=$(pwd)/src:$PYTHONPATH

# Start API Server
echo "Starting LogCentry API Server..."
python -m logcentry --serve --server-port 8000 > server.log 2>&1 &
SERVER_PID=$!
echo "API Server started with PID $SERVER_PID"

# Wait for API server to be ready
echo "Waiting for API server to be ready..."
sleep 5

# Start Demo Application
echo "Starting Demo Application..."
python demo/vulnapp.py > demo.log 2>&1 &
DEMO_PID=$!
echo "Demo Application started with PID $DEMO_PID"

echo "Services are running!"
echo "API Server: http://localhost:8000"
echo "Dashboard: http://localhost:8000/dashboard"
echo "Demo App: http://localhost:5000"

echo "Press Ctrl+C to stop all services"

# Wait for user to quit
trap "kill $SERVER_PID $DEMO_PID; exit" INT
wait
