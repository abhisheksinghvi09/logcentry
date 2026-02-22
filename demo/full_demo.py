#!/usr/bin/env python3
"""
LogCentry Full Demo - All-in-One

This script starts BOTH:
1. LogCentry API Server (port 8000)
2. VulnApp Demo (port 5000)

Usage: python demo/full_demo.py
"""

import os
import sys
import threading
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def start_api_server():
    """Start the LogCentry API server."""
    import uvicorn
    from logcentry.api.server import create_app
    
    uvicorn.run(
        create_app(),
        host="0.0.0.0",
        port=8000,
        log_level="warning",
    )

def start_vulnapp():
    """Start the VulnApp demo after a short delay."""
    time.sleep(3)  # Wait for API server to start
    
    # Add demo directory to path for import
    demo_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, demo_dir)
    
    # Import and run Flask app
    from vulnapp import app
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print(" 🛡️  LogCentry Full Demo")
    print("=" * 60)
    print("")
    print(" Starting services...")
    print("")
    print(" 📊 Dashboard:     http://localhost:8000/dashboard")
    print(" 📖 API Docs:      http://localhost:8000/api/docs")
    print(" 🔓 VulnApp Demo:  http://localhost:5000")
    print("")
    print("=" * 60)
    print(" Press Ctrl+C to stop")
    print("=" * 60 + "\n")
    
    # Start API server in background thread
    api_thread = threading.Thread(target=start_api_server, daemon=True)
    api_thread.start()
    
    # Start VulnApp in main thread
    try:
        start_vulnapp()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
