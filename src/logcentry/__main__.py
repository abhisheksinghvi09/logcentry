#!/usr/bin/env python3
"""
LogCentry AI - Main Entry Point

AI-Powered SIEM Framework with RAG-Enhanced Threat Intelligence
"""

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from logcentry.cli import create_parser
from logcentry.commands import (
    run_api_server,
    run_dashboard,
    run_direct_analysis,
    run_file_analysis,
    run_live_monitoring,
    run_webapp_monitoring,
    run_register_zk,
    run_login_zk,
)

console = Console()

BANNER_ASCII = r"""
██╗      ██████╗   ██████╗  ██████╗███████╗ ███╗   ██╗ ███████╗
██║     ██╔═══██╗ ██╔════╝ ██╔════╝██╔════╝ ████╗  ██║    ██╔══
██║     ██║   ██║ ██║  ███╗██║     █████╗   ██╔██╗ ██║    ██║   
██║     ██║   ██║ ██║   ██║██║     ██╔══╝   ██║╚██╗██║    ██║   
███████╗╚██████╔╝ ╚██████╔╝╚██████╗███████╗ ██║ ╚████║    ██║   
╚══════╝ ╚═════╝   ╚═════╝  ╚═════╝╚══════╝ ╚═╝  ╚═══╝    ╚═╝   
"""


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Show banner
    if not args.quiet:
        console.print(f"[bold cyan]{BANNER_ASCII}[/]")
        console.print("[dim]AI-Powered Threat Intelligence Framework v2.0[/]\n")

    # Serve API Mode (SaaS)
    if args.serve:
        run_api_server(args)
        return

    # Zero-Knowledge Auth
    if args.register:
        run_register_zk(args)
        return
    elif args.login:
        run_login_zk(args)
        return

    # Check for monitoring flags
    is_monitoring = any([
        args.siem, args.auth, args.firewall, args.kernel, args.service
    ])
    
    is_webapp = any([
        args.webapp, args.nginx, args.apache, args.docker
    ])

    # Initialize RAG if needed (for monitoring/analysis)
    rag_context = None
    if (args.rag or args.init_knowledge_base) and (is_monitoring or is_webapp):
        # Only import if needed to speed up startup
        try:
            from logcentry.rag import create_rag_pipeline
            
            console.print("[cyan]Initializing Knowledge Base...[/]")
            retriever = create_rag_pipeline(initialize_knowledge=args.init_knowledge_base)
            rag_context = retriever
            
            if args.init_knowledge_base:
                console.print("[bold green]✓ Knowledge base initialized successfully![/]")
                # If only init was requested, exit
                if not (is_monitoring or is_webapp):
                    return
                    
        except ImportError:
            console.print("[yellow]Warning: RAG dependencies not found. Running in standard mode.[/]")
        except Exception as e:
            console.print(f"[red]Error initializing RAG: {e}[/]")

    # Dispatch commands
    if is_webapp:
        run_webapp_monitoring(args, rag_context)
    elif is_monitoring:
        run_live_monitoring(args, rag_context)
    elif args.input_file:
        run_file_analysis(args)
    elif args.log:
        run_direct_analysis(args)
    elif args.init_knowledge_base:
        # Already done above
        console.print("[bold green]✓ Knowledge base initialized successfully![/]")
    elif args.dashboard:
        run_dashboard(args)
    else:
        # No action specified, show help
        parser.print_help()


if __name__ == "__main__":
    main()
