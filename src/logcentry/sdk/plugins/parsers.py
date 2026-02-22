"""
LogCentry SDK - Built-in Parsers

Default log parsers for common formats: JSON, Syslog, Apache, NGINX.
Extend BaseParser to add custom format support.
"""

import json
import re
from datetime import datetime
from typing import Any, Optional

from logcentry.sdk.plugins import BaseParser


class JSONParser(BaseParser):
    """Parser for JSON-formatted logs."""
    
    @property
    def name(self) -> str:
        return "json_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["json", "jsonl", "structured"]
    
    @property
    def description(self) -> str:
        return "Parses JSON and JSONL formatted log entries"
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if log looks like JSON."""
        stripped = raw_log.strip()
        return stripped.startswith("{") and stripped.endswith("}")
    
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Parse JSON log."""
        try:
            data = json.loads(raw_log)
            return {
                "message": data.get("message", data.get("msg", str(data))),
                "level": data.get("level", data.get("severity", "info")),
                "timestamp": data.get("timestamp", data.get("time", data.get("@timestamp"))),
                "source": data.get("source", data.get("logger", data.get("name"))),
                "metadata": {k: v for k, v in data.items() 
                           if k not in ("message", "msg", "level", "severity", "timestamp", "time", "@timestamp", "source", "logger", "name")},
                "raw": raw_log,
            }
        except json.JSONDecodeError:
            return {"message": raw_log, "level": "info", "raw": raw_log}


class SyslogParser(BaseParser):
    """Parser for RFC 5424 Syslog format."""
    
    # RFC 5424 pattern
    SYSLOG_PATTERN = re.compile(
        r"^<(\d+)>(\d+)?\s*"  # Priority and version
        r"(\S+)\s+"           # Timestamp
        r"(\S+)\s+"           # Hostname
        r"(\S+)\s+"           # App name
        r"(\S+)\s+"           # Proc ID
        r"(\S+)\s+"           # Msg ID
        r"(.*)$",             # Message
        re.DOTALL
    )
    
    # BSD Syslog pattern (RFC 3164)
    BSD_PATTERN = re.compile(
        r"^<(\d+)>"           # Priority
        r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"  # Timestamp
        r"(\S+)\s+"           # Hostname
        r"(.*)$",             # Message
        re.DOTALL
    )
    
    SEVERITY_MAP = {
        0: "critical",  # Emergency
        1: "critical",  # Alert
        2: "critical",  # Critical
        3: "error",     # Error
        4: "warning",   # Warning
        5: "info",      # Notice
        6: "info",      # Informational
        7: "debug",     # Debug
    }
    
    @property
    def name(self) -> str:
        return "syslog_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["syslog", "rfc5424", "rfc3164"]
    
    @property
    def description(self) -> str:
        return "Parses RFC 5424 and RFC 3164 (BSD) Syslog formats"
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if log looks like syslog."""
        return raw_log.strip().startswith("<")
    
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Parse syslog entry."""
        # Try RFC 5424 first
        match = self.SYSLOG_PATTERN.match(raw_log)
        if match:
            priority = int(match.group(1))
            severity = priority & 0x07
            facility = priority >> 3
            
            return {
                "message": match.group(8).strip(),
                "level": self.SEVERITY_MAP.get(severity, "info"),
                "timestamp": match.group(3),
                "source": match.group(5),  # App name
                "metadata": {
                    "priority": priority,
                    "facility": facility,
                    "severity": severity,
                    "hostname": match.group(4),
                    "proc_id": match.group(6),
                    "msg_id": match.group(7),
                },
                "raw": raw_log,
            }
        
        # Try BSD syslog
        match = self.BSD_PATTERN.match(raw_log)
        if match:
            priority = int(match.group(1))
            severity = priority & 0x07
            
            return {
                "message": match.group(4).strip(),
                "level": self.SEVERITY_MAP.get(severity, "info"),
                "timestamp": match.group(2),
                "source": match.group(3),
                "metadata": {
                    "priority": priority,
                    "severity": severity,
                },
                "raw": raw_log,
            }
        
        # Fallback
        return {"message": raw_log, "level": "info", "raw": raw_log}


class ApacheParser(BaseParser):
    """Parser for Apache Combined Log Format."""
    
    # Combined Log Format pattern
    COMBINED_PATTERN = re.compile(
        r'^(\S+)\s+'           # IP address
        r'(\S+)\s+'            # Identity
        r'(\S+)\s+'            # User
        r'\[([^\]]+)\]\s+'     # Timestamp
        r'"([^"]+)"\s+'        # Request
        r'(\d+)\s+'            # Status code
        r'(\S+)'               # Response size
        r'(?:\s+"([^"]*)")?'   # Referer (optional)
        r'(?:\s+"([^"]*)")?'   # User agent (optional)
    )
    
    @property
    def name(self) -> str:
        return "apache_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["apache", "combined", "common"]
    
    @property
    def description(self) -> str:
        return "Parses Apache Combined and Common Log formats"
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if log looks like Apache format."""
        return bool(self.COMBINED_PATTERN.match(raw_log))
    
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Parse Apache log entry."""
        match = self.COMBINED_PATTERN.match(raw_log)
        if not match:
            return {"message": raw_log, "level": "info", "raw": raw_log}
        
        ip = match.group(1)
        timestamp = match.group(4)
        request = match.group(5)
        status = int(match.group(6))
        size = match.group(7)
        referer = match.group(8) if match.lastindex >= 8 else None
        user_agent = match.group(9) if match.lastindex >= 9 else None
        
        # Parse request line
        request_parts = request.split(" ", 2)
        method = request_parts[0] if len(request_parts) > 0 else "-"
        path = request_parts[1] if len(request_parts) > 1 else "-"
        
        # Determine severity based on status code
        if status >= 500:
            level = "error"
        elif status >= 400:
            level = "warning"
        else:
            level = "info"
        
        return {
            "message": f"{method} {path} - {status}",
            "level": level,
            "timestamp": timestamp,
            "source": "apache",
            "metadata": {
                "ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "size": size if size != "-" else 0,
                "referer": referer,
                "user_agent": user_agent,
            },
            "raw": raw_log,
        }


class NginxParser(BaseParser):
    """Parser for NGINX access logs."""
    
    # NGINX combined format pattern
    NGINX_PATTERN = re.compile(
        r'^(\S+)\s+-\s+(\S+)\s+'     # IP and remote user
        r'\[([^\]]+)\]\s+'           # Timestamp
        r'"([^"]+)"\s+'              # Request
        r'(\d+)\s+'                  # Status code
        r'(\d+)\s+'                  # Body bytes sent
        r'"([^"]*)"\s+'              # Referer
        r'"([^"]*)"'                 # User agent
        r'(?:\s+"([^"]*)")?'         # Forwarded for (optional)
    )
    
    @property
    def name(self) -> str:
        return "nginx_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["nginx", "nginx_combined"]
    
    @property
    def description(self) -> str:
        return "Parses NGINX access log format"
    
    def can_parse(self, raw_log: str) -> bool:
        """Check if log looks like NGINX format."""
        return bool(self.NGINX_PATTERN.match(raw_log))
    
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Parse NGINX log entry."""
        match = self.NGINX_PATTERN.match(raw_log)
        if not match:
            return {"message": raw_log, "level": "info", "raw": raw_log}
        
        ip = match.group(1)
        timestamp = match.group(3)
        request = match.group(4)
        status = int(match.group(5))
        bytes_sent = int(match.group(6))
        referer = match.group(7)
        user_agent = match.group(8)
        
        # Parse request
        request_parts = request.split(" ", 2)
        method = request_parts[0] if len(request_parts) > 0 else "-"
        path = request_parts[1] if len(request_parts) > 1 else "-"
        
        # Severity from status
        if status >= 500:
            level = "error"
        elif status >= 400:
            level = "warning"
        else:
            level = "info"
        
        return {
            "message": f"{method} {path} - {status}",
            "level": level,
            "timestamp": timestamp,
            "source": "nginx",
            "metadata": {
                "ip": ip,
                "method": method,
                "path": path,
                "status": status,
                "bytes_sent": bytes_sent,
                "referer": referer,
                "user_agent": user_agent,
            },
            "raw": raw_log,
        }


class GenericParser(BaseParser):
    """
    Fallback parser for unrecognized log formats.
    
    Attempts basic pattern matching for common log elements.
    """
    
    # Common timestamp patterns
    TIMESTAMP_PATTERNS = [
        re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),  # ISO 8601
        re.compile(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'),    # Apache/NGINX
        re.compile(r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}'),        # Syslog
    ]
    
    # IP address pattern
    IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    
    # Log level detection
    LEVEL_PATTERN = re.compile(
        r'\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL|EMERG(?:ENCY)?)\b',
        re.IGNORECASE
    )
    
    LEVEL_MAP = {
        "debug": "debug",
        "info": "info",
        "notice": "info",
        "warn": "warning",
        "warning": "warning",
        "error": "error",
        "crit": "critical",
        "critical": "critical",
        "fatal": "critical",
        "emerg": "critical",
        "emergency": "critical",
    }
    
    @property
    def name(self) -> str:
        return "generic_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["generic", "text", "unknown"]
    
    @property
    def description(self) -> str:
        return "Generic parser for unrecognized log formats"
    
    def can_parse(self, raw_log: str) -> bool:
        """Always returns True as fallback parser."""
        return True
    
    def parse(self, raw_log: str) -> dict[str, Any]:
        """Parse log with best-effort extraction."""
        result: dict[str, Any] = {
            "message": raw_log,
            "level": "info",
            "timestamp": None,
            "source": None,
            "metadata": {},
            "raw": raw_log,
        }
        
        # Extract timestamp
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(raw_log)
            if match:
                result["timestamp"] = match.group(0)
                break
        
        # Extract log level
        level_match = self.LEVEL_PATTERN.search(raw_log)
        if level_match:
            level = level_match.group(1).lower()
            result["level"] = self.LEVEL_MAP.get(level, "info")
        
        # Extract IP addresses
        ips = self.IP_PATTERN.findall(raw_log)
        if ips:
            result["metadata"]["ips"] = ips
            result["metadata"]["source_ip"] = ips[0]
        
        return result


# Factory function to get all built-in parsers
def get_builtin_parsers() -> list[BaseParser]:
    """Get instances of all built-in parsers."""
    return [
        JSONParser(),
        SyslogParser(),
        ApacheParser(),
        NginxParser(),
        GenericParser(),
    ]
