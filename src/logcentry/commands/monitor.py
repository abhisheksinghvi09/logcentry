"""
LogCentry CLI - Monitor Command
"""

import os
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from logcentry.core import LogBatch, ThreatAnalyzer
from logcentry.ingestion import JournaldStream, create_webapp_stream
from logcentry.utils.output import print_result

console = Console()


def run_live_monitoring(args, rag_retriever=None):
    """Run live log monitoring mode."""
    # Check for root privileges
    if os.getuid() != 0:
        console.print(Panel(
            "[bold yellow]Running in User Mode[/]\n"
            "`journalctl` will only show logs for the current user.\n"
            "For full system visibility, please run with 'sudo'.",
            title="Privilege Warning",
            border_style="yellow",
        ))
    
    # Determine categories
    categories = []
    if args.siem:
        categories.append("siem")
    if args.auth:
        categories.append("auth")
    if args.firewall:
        categories.append("firewall")
    if args.kernel:
        categories.append("kernel")
    if args.service:
        categories.append("service")
    
    console.print(Panel(
        f"Starting live monitoring for: [cyan]{', '.join(categories)}[/]\n"
        "Press [bold cyan]Ctrl+C[/] to stop and analyze collected logs.",
        border_style="green",
    ))
    
    # Start streaming
    stream = JournaldStream(categories=categories)
    
    def on_entry(entry):
        console.print(f"[dim]{entry.timestamp.strftime('%H:%M:%S')}[/] [{entry.source}] {entry.message[:100]}")
    
    stream.start(on_entry=on_entry)
    
    # Wait for Ctrl+C
    try:
        while stream.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitoring...[/]")
        stream.stop()
    
    # Analyze collected logs
    batch = stream.get_batch(max_size=1000)
    if batch.count > 0:
        console.print(f"[cyan]Analyzing {batch.count} collected log entries...[/]")
        
        analyzer = ThreatAnalyzer()
        rag_context = None
        
        if args.rag and rag_retriever:
            rag_context = rag_retriever.retrieve_for_logs(batch)
        
        result = analyzer.analyze(batch)
        print_result(result)
    else:
        console.print("[yellow]No logs were captured during the session.[/]")


def run_webapp_monitoring(args, rag_retriever=None):
    """Run web application log monitoring."""
    
    # Determine log source
    log_path = None
    docker_container = None
    source_name = "webapp"
    
    if args.webapp:
        log_path = args.webapp
        source_name = Path(args.webapp).name
    elif args.nginx:
        # Auto-detect nginx logs
        nginx_paths = [
            "/var/log/nginx/access.log",
            "/usr/local/nginx/logs/access.log",
        ]
        for p in nginx_paths:
            if Path(p).exists():
                log_path = p
                source_name = "nginx"
                break
        if not log_path:
            console.print("[red]Could not find nginx access log. Use --webapp PATH to specify.[/]")
            return
    elif args.apache:
        # Auto-detect Apache logs
        apache_paths = [
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
        ]
        for p in apache_paths:
            if Path(p).exists():
                log_path = p
                source_name = "apache"
                break
        if not log_path:
            console.print("[red]Could not find Apache access log. Use --webapp PATH to specify.[/]")
            return
    elif args.docker:
        docker_container = args.docker
        source_name = f"docker:{docker_container}"
    
    console.print(Panel(
        f"Starting web app monitoring: [cyan]{source_name}[/]\n"
        f"Format: [dim]{args.format}[/] (auto-detect)\n"
        "Press [bold cyan]Ctrl+C[/] to stop and analyze collected logs.",
        border_style="green",
    ))
    
    # Create stream
    stream = create_webapp_stream(
        log_path=log_path,
        docker_container=docker_container,
        log_format=args.format,
        follow=True,
    )
    stream.start()
    
    collected_entries = []
    
    # Display and collect logs
    try:
        while True:
            entries = stream.get_entries()
            for entry in entries:
                collected_entries.append(entry)
                # Format output based on log type
                ip = entry.metadata.get("ip", "")
                status = entry.metadata.get("status", "")
                path = entry.metadata.get("path", "")[:50] if entry.metadata.get("path") else ""
                
                # Color based on status code
                if status:
                    status_int = int(status) if status.isdigit() else 200
                    if status_int >= 500:
                        status_color = "red"
                    elif status_int >= 400:
                        status_color = "yellow"
                    else:
                        status_color = "green"
                else:
                    status_color = "dim"
                
                console.print(
                    f"[dim]{entry.timestamp.strftime('%H:%M:%S')}[/] "
                    f"[cyan]{ip}[/] "
                    f"[{status_color}]{status}[/] "
                    f"{path}"
                )
            
            time.sleep(0.1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitoring...[/]")
        stream.stop()
    
    # Analyze collected logs
    if collected_entries:
        console.print(f"[cyan]Analyzing {len(collected_entries)} web app log entries...[/]")
        
        batch = LogBatch(entries=collected_entries)
        analyzer = ThreatAnalyzer()
        rag_context = None
        
        if args.rag and rag_retriever:
            rag_context = rag_retriever.retrieve_for_logs(batch)
        
        result = analyzer.analyze(batch)
        print_result(result)
        
        # Generate report if requested
        if args.report:
            from logcentry.reporting import HTMLReportGenerator, JSONReportGenerator
            
            if args.report == "html":
                generator = HTMLReportGenerator()
            else:
                generator = JSONReportGenerator()
            
            report_path = generator.generate([result])
            console.print(Panel(
                f"✓ Report generated!\nLocation: [cyan]{report_path}[/]",
                title="Report Generation",
                border_style="green",
            ))
    else:
        console.print("[yellow]No logs were captured during the session.[/]")
