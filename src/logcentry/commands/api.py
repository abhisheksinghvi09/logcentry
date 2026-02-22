"""
LogCentry CLI - API Server Command
"""

from rich.console import Console
from rich.panel import Panel

console = Console()


def run_api_server(args):
    """Run the LogCentry API server."""
    from logcentry.api.server import run_server
    
    console.print(Panel(
        "[bold cyan]Starting LogCentry API Server[/]\n\n"
        f"Dashboard: [green]http://localhost:{args.server_port}/dashboard[/]\n"
        f"API Docs:  [green]http://localhost:{args.server_port}/api/docs[/]\n\n"
        "[dim]Developers can send logs using the SDK:[/]\n"
        "[yellow]from logcentry import LogCentry[/]\n"
        "[yellow]logger = LogCentry(api_key='lc_test')[/]\n"
        "[yellow]logger.info('Hello!')[/]",
        title="🛡️ LogCentry SaaS Mode",
        border_style="green",
    ))
    
    run_server(host=args.server_host, port=args.server_port)
