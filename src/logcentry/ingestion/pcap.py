"""
LogCentry Ingestion - PCAP Parser

Network packet capture file parsing and summarization using Scapy.
"""

import collections
from pathlib import Path
from typing import Any

from logcentry.core import LogBatch, LogEntry
from logcentry.utils import get_logger, validate_file_path

logger = get_logger(__name__)

# Optional Scapy import
try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    rdpcap = None


class PcapParser:
    """
    PCAP file parser for network traffic analysis.
    
    Extracts:
    - Top source/destination IPs
    - Port statistics
    - Protocol distribution
    - Packet metadata
    """
    
    SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
    
    def __init__(self):
        if not SCAPY_AVAILABLE:
            logger.warning("scapy_not_available", message="Install scapy for PCAP support")
    
    def parse(
        self,
        filepath: str | Path,
        max_packets: int | None = None,
    ) -> tuple[LogBatch, dict[str, Any]]:
        """
        Parse a PCAP file and extract statistics.
        
        Args:
            filepath: Path to PCAP file
            max_packets: Maximum packets to process
            
        Returns:
            Tuple of (LogBatch with packet entries, summary statistics dict)
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for PCAP parsing. Install with: pip install scapy"
            )
        
        path = validate_file_path(
            filepath,
            allowed_extensions=self.SUPPORTED_EXTENSIONS,
            must_exist=True,
        )
        
        logger.info("parsing_pcap", path=str(path))
        
        try:
            packets = rdpcap(str(path))
        except Exception as e:
            logger.error("pcap_read_failed", path=str(path), error=str(e))
            raise
        
        if max_packets:
            packets = packets[:max_packets]
        
        # Collect statistics
        top_src: collections.Counter = collections.Counter()
        top_dst: collections.Counter = collections.Counter()
        top_ports: collections.Counter = collections.Counter()
        top_protocols: collections.Counter = collections.Counter()
        
        entries = []
        
        for i, packet in enumerate(packets):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                top_src[src_ip] += 1
                top_dst[dst_ip] += 1
                
                protocol = "IP"
                port = None
                
                if TCP in packet:
                    protocol = "TCP"
                    port = packet[TCP].dport
                    top_ports[port] += 1
                elif UDP in packet:
                    protocol = "UDP"
                    port = packet[UDP].dport
                    top_ports[port] += 1
                
                top_protocols[protocol] += 1
                
                # Create a log entry for each packet (sampling for large captures)
                if i < 1000 or i % 100 == 0:  # Sample: first 1000 + every 100th
                    from datetime import datetime, timezone
                    
                    entries.append(LogEntry(
                        timestamp=datetime.now(timezone.utc),  # PCAP timestamp could be extracted
                        source=f"pcap:{src_ip}",
                        message=f"{protocol} {src_ip} -> {dst_ip}" + (f":{port}" if port else ""),
                        metadata={
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": protocol,
                            "port": port,
                        },
                    ))
        
        # Build summary
        summary = {
            "filename": path.name,
            "packet_count": len(packets),
            "top_sources": dict(top_src.most_common(10)),
            "top_destinations": dict(top_dst.most_common(10)),
            "top_ports": dict(top_ports.most_common(10)),
            "protocols": dict(top_protocols),
        }
        
        logger.info(
            "pcap_parsed",
            path=str(path),
            packet_count=len(packets),
            unique_sources=len(top_src),
        )
        
        return LogBatch(
            entries=entries,
            source_file=str(path),
            source_type="pcap",
        ), summary
    
    def generate_summary_text(self, summary: dict[str, Any]) -> str:
        """
        Generate human-readable summary text for LLM analysis.
        
        Args:
            summary: Summary dictionary from parse()
            
        Returns:
            Formatted summary string
        """
        lines = [
            f"PCAP Analysis for '{summary.get('filename', 'unknown')}' "
            f"({summary.get('packet_count', 0)} packets):",
            "",
            "Top 10 Source IPs (Talkers):",
        ]
        
        for ip, count in summary.get("top_sources", {}).items():
            lines.append(f"  • {ip}: {count} packets")
        
        lines.extend(["", "Top 10 Destination IPs:"])
        for ip, count in summary.get("top_destinations", {}).items():
            lines.append(f"  • {ip}: {count} packets")
        
        lines.extend(["", "Top 10 Destination Ports:"])
        for port, count in summary.get("top_ports", {}).items():
            lines.append(f"  • Port {port}: {count} connections")
        
        lines.extend(["", "Protocol Distribution:"])
        for proto, count in summary.get("protocols", {}).items():
            lines.append(f"  • {proto}: {count} packets")
        
        return "\n".join(lines)
