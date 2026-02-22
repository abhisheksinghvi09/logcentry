"""
LogCentry Utils - Output Formatting
"""

from rich.console import Console
from rich.panel import Panel

console = Console()


def print_result(result):
    """Pretty print an analysis result."""
    analysis = result.analysis
    
    # Determine color based on severity
    score = analysis.severity_score
    if score >= 8:
        color = "red"
    elif score >= 6:
        color = "bright_red"
    elif score >= 4:
        color = "yellow"
    else:
        color = "green"
    
    # Build output
    output = (
        f"[bold]Severity:[/] [{color}]{score}/10 ({analysis.severity_level.value.upper()})[/{color}]\n"
        f"[bold]Confidence:[/] {analysis.confidence}\n\n"
        f"[bold cyan]Threat Assessment:[/]\n{analysis.threat_assessment}\n\n"
        f"[bold yellow]Explanation:[/]\n{analysis.detailed_explanation}\n\n"
        f"[bold green]Countermeasures:[/]\n"
    )
    
    for cm in analysis.countermeasures:
        output += f"  • {cm}\n"
    
    if analysis.mitre_attack_ttps:
        output += f"\n[bold magenta]MITRE ATT&CK:[/] {', '.join(analysis.mitre_attack_ttps)}"
    
    if analysis.cves:
        output += f"\n[bold magenta]CVEs:[/] {', '.join(analysis.cves)}"
    
    console.print(Panel(
        output,
        title="🛡️ LogCEntry AI SITREP",
        border_style="bright_magenta",
        padding=(1, 2),
        subtitle=f"[dim]Analysis ID: {result.id}[/]",
    ))
