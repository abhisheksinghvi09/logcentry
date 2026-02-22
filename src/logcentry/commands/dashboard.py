"""
LogCentry CLI - Dashboard Command
"""

import threading
import time
import webbrowser

from rich.console import Console

from logcentry.api.server import run_server

console = Console()


def run_dashboard(args):
    """Run the web dashboard."""
    console.print(f"[green]Starting dashboard on port {args.port}...[/]")
    
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f"http://127.0.0.1:{args.port}")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    console.print("[bold green]Dashboard is running. Press Ctrl+C to exit.[/]")
    
    # Run server (this blocks)
    run_server(host="0.0.0.0", port=args.port)
