"""
LogCentry CLI - Command Line Interface

Argument parsing and CLI command handling.
"""

import argparse
import textwrap


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with all CLI options."""
    parser = argparse.ArgumentParser(
        prog="logcentry",
        description="LogCEntry AI – AI-Powered SIEM with RAG-Enhanced Threat Intelligence",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          # --- Standalone Live Monitoring Modes ---
          sudo logcentry --siem              # Monitor all important logs
          sudo logcentry --auth              # Monitor ONLY authentication logs
          sudo logcentry --firewall          # Monitor ONLY firewall logs
          sudo logcentry --kernel            # Monitor ONLY kernel logs

          # --- Combine Monitors ---
          sudo logcentry --auth --firewall   # Monitor auth and firewall logs together

          # --- File Analysis ---
          logcentry mylog.log                # Analyze a log file
          logcentry mylog.log --report html  # Generate HTML report
          logcentry capture.pcap             # Analyze network capture

          # --- Run with the Web Dashboard ---
          sudo logcentry --siem --dashboard

          # --- RAG-Enhanced Analysis ---
          logcentry mylog.log --rag          # Use knowledge base for context
        """),
    )
    
    # === Live Monitoring ===
    monitor_group = parser.add_argument_group("Live Monitoring Modes (sudo recommended)")
    monitor_group.add_argument(
        "--siem",
        action="store_true",
        help="Monitor a broad range of general system logs in real-time.",
    )
    monitor_group.add_argument(
        "--auth",
        action="store_true",
        help="Monitor ONLY authentication logs (sshd, sudo, etc.).",
    )
    monitor_group.add_argument(
        "--firewall",
        action="store_true",
        help="Monitor ONLY firewall and network logs (ufw, etc.).",
    )
    monitor_group.add_argument(
        "--kernel",
        action="store_true",
        help="Monitor ONLY kernel-related logs.",
    )
    monitor_group.add_argument(
        "--service",
        action="store_true",
        help="Monitor ONLY system service logs (systemd, cron, etc.).",
    )
    
    # === API Server ===
    server_group = parser.add_argument_group("API Server (SaaS Mode)")
    server_group.add_argument(
        "--serve",
        action="store_true",
        help="Start the LogCentry API server for receiving logs from SDKs.",
    )
    server_group.add_argument(
        "--server-port",
        type=int,
        default=8000,
        help="Port for the API server (default: 8000).",
    )
    server_group.add_argument(
        "--server-host",
        type=str,
        default="0.0.0.0",
        help="Host for the API server (default: 0.0.0.0).",
    )
    
    # === Authentication ===
    auth_group = parser.add_argument_group("Zero-Knowledge Authentication")
    auth_group.add_argument(
        "--register",
        action="store_true",
        help="Register a new user using ZK Proofs (Argon2id).",
    )
    auth_group.add_argument(
        "--login",
        action="store_true",
        help="Login using ZK Proofs to obtain API token.",
    )
    
    # === Web App Monitoring ===
    webapp_group = parser.add_argument_group("Web Application Monitoring")
    webapp_group.add_argument(
        "--webapp",
        type=str,
        metavar="PATH",
        help="Monitor a web application log file (nginx, Apache, custom).",
    )
    webapp_group.add_argument(
        "--nginx",
        action="store_true",
        help="Auto-detect and monitor nginx access logs.",
    )
    webapp_group.add_argument(
        "--apache",
        action="store_true",
        help="Auto-detect and monitor Apache access logs.",
    )
    webapp_group.add_argument(
        "--docker",
        type=str,
        metavar="CONTAINER",
        help="Monitor logs from a Docker container.",
    )
    webapp_group.add_argument(
        "--format",
        type=str,
        choices=["auto", "common", "combined", "json"],
        default="auto",
        help="Log format for web app logs (default: auto-detect).",
    )
    
    # === File Analysis ===
    file_group = parser.add_argument_group("File Analysis & Other Options")
    file_group.add_argument(
        "input_file",
        nargs="?",
        default=None,
        help="Path to .log, .txt, .jsonl, .pcap, or .pcapng file for analysis.",
    )
    file_group.add_argument(
        "--log",
        type=str,
        metavar="TEXT",
        help="Security event text for a single, direct analysis.",
    )
    file_group.add_argument(
        "--report",
        type=str,
        choices=["html", "json", "batch"],
        help="Generate a report from analysis results.",
    )
    file_group.add_argument(
        "--output",
        "-o",
        type=str,
        metavar="PATH",
        help="Output path for generated report.",
    )
    
    # === RAG Options ===
    rag_group = parser.add_argument_group("RAG (Retrieval-Augmented Generation)")
    rag_group.add_argument(
        "--rag",
        action="store_true",
        help="Enable RAG for context-aware analysis using knowledge base.",
    )
    rag_group.add_argument(
        "--init-kb",
        action="store_true",
        dest="init_knowledge_base",
        help="Initialize/reload knowledge base (MITRE ATT&CK, CVEs, etc.).",
    )
    rag_group.add_argument(
        "--kb-path",
        type=str,
        metavar="PATH",
        help="Path to knowledge base files.",
    )
    
    # === Dashboard ===
    dash_group = parser.add_argument_group("Web Dashboard")
    dash_group.add_argument(
        "--dashboard",
        action="store_true",
        help="Run the web dashboard for live visualization.",
    )
    dash_group.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for the web dashboard (default: 8080).",
    )
    
    # === Output Options ===
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON to the console instead of formatted panels.",
    )
    output_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress banner and non-essential output.",
    )
    output_group.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase output verbosity (-v for INFO, -vv for DEBUG).",
    )
    
    # === Configuration ===
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--api-key",
        type=str,
        metavar="KEY",
        help="Gemini API key (overrides environment variable).",
    )
    config_group.add_argument(
        "--model",
        type=str,
        default="gemini-2.0-flash",
        help="Gemini model to use (default: gemini-2.0-flash).",
    )
    config_group.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Max API retries on failure (default: 5).",
    )
    
    return parser


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = create_parser()
    return parser.parse_args()


def get_log_level(verbose: int) -> str:
    """Convert verbosity level to log level string."""
    if verbose >= 2:
        return "DEBUG"
    elif verbose >= 1:
        return "INFO"
    else:
        return "WARNING"
