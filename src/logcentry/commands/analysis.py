"""
LogCentry CLI - Analysis Command
"""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from logcentry.utils.output import print_result

console = Console()


def run_file_analysis(args):
    """Run analysis on a file."""
    from logcentry.core import ThreatAnalyzer
    from logcentry.ingestion import PcapParser, StaticLogReader
    from logcentry.reporting import HTMLReportGenerator, JSONReportGenerator
    
    filepath = Path(args.input_file)
    
    console.print(Panel(f"📂 Analyzing: [cyan]{filepath}[/cyan]", border_style="green"))
    
    # Determine file type and parse
    suffix = filepath.suffix.lower()
    
    if suffix in {".pcap", ".pcapng", ".cap"}:
        # PCAP analysis
        pcap_parser = PcapParser()
        log_batch, summary = pcap_parser.parse(filepath)
        summary_text = pcap_parser.generate_summary_text(summary)
        console.print(Panel(summary_text, title="[yellow]PCAP Summary[/]", border_style="yellow"))
    else:
        # Text/JSON log analysis
        reader = StaticLogReader()
        log_batch = reader.read(filepath)
        summary = {"filename": filepath.name, "entry_count": log_batch.count}
        console.print(f"[green]✓ Loaded {log_batch.count} log entries[/]")
    
    # Get RAG context if enabled
    rag_context = None
    if args.rag:
        from logcentry.rag import create_rag_pipeline
        retriever = create_rag_pipeline()
        rag_context = retriever.retrieve_for_logs(log_batch)
        if rag_context:
            console.print(f"[cyan]📚 Retrieved {len(rag_context)} relevant knowledge items[/]")
    
    # Run analysis
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze(log_batch, rag_context=rag_context, summary_data=summary)
    
    # Output result
    if args.json:
        import json
        console.print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        print_result(result)
    
    # Generate report if requested
    if args.report == "html":
        generator = HTMLReportGenerator()
        report_path = generator.generate(result, filename=args.output)
        console.print(Panel(
            f"[bold green]✓ Report generated![/]\n[cyan]Location:[/] {report_path}",
            title="Report Generation",
        ))
    elif args.report == "json":
        generator = JSONReportGenerator()
        report_path = generator.generate(result, filename=args.output)
        console.print(f"[green]✓ JSON report saved to {report_path}[/]")


def run_direct_analysis(args):
    """Run analysis on direct text input."""
    from logcentry.core import ThreatAnalyzer
    
    console.print("[cyan]Analyzing provided log text...[/]")
    
    # Get RAG context if enabled
    rag_context = None
    if args.rag:
        from logcentry.rag import create_rag_pipeline
        retriever = create_rag_pipeline()
        rag_context = retriever.retrieve(args.log)
    
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze_text(args.log, rag_context=rag_context)
    
    if args.json:
        import json
        console.print(json.dumps(result.model_dump(), indent=2, default=str))
    else:
        print_result(result)
