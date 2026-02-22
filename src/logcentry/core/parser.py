"""
LogCentry Core - Log Parser

Unified log parsing and normalization for various log formats.
Converts heterogeneous log sources into standardized LogEntry objects.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from logcentry.core.models import LogBatch, LogEntry
from logcentry.utils import get_logger, sanitize_log_content, validate_file_path

logger = get_logger(__name__)


class LogParser:
    """
    Universal log parser that handles multiple formats.
    
    Supported formats:
    - Plain text logs (syslog-like)
    - JSON/JSONL logs
    - journalctl JSON output
    - Apache/Nginx access logs
    """
    
    # Common timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO 8601
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', "%Y-%m-%dT%H:%M:%S"),
        # Syslog format: Mar 10 12:34:56
        (r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', "%b %d %H:%M:%S"),
        # Apache/Nginx: [10/Mar/2024:12:34:56 +0000]
        (r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]', "%d/%b/%Y:%H:%M:%S %z"),
        # Simple date: 2024-03-10 12:34:56
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', "%Y-%m-%d %H:%M:%S"),
    ]
    
    # Syslog source pattern (after timestamp)
    SYSLOG_SOURCE_PATTERN = re.compile(
        r'^(?:\S+\s+)?'  # Optional hostname
        r'(\S+?):'       # Process name (captured)
    )
    
    def __init__(self):
        self._compiled_patterns = [
            (re.compile(pattern), fmt) 
            for pattern, fmt in self.TIMESTAMP_PATTERNS
        ]
    
    def parse_file(
        self, 
        filepath: str | Path,
        max_entries: int | None = None,
    ) -> LogBatch:
        """
        Parse a log file into a LogBatch.
        
        Args:
            filepath: Path to the log file
            max_entries: Maximum number of entries to parse (None for all)
            
        Returns:
            LogBatch containing parsed entries
        """
        path = validate_file_path(
            filepath, 
            allowed_extensions={".log", ".txt", ".jsonl", ".json"},
            must_exist=True,
        )
        
        logger.info("parsing_file", path=str(path))
        
        entries = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = sanitize_log_content(f.read())
        
        # Detect format and parse accordingly
        lines = content.strip().split("\n")
        is_jsonl = lines and lines[0].strip().startswith("{")
        
        for i, line in enumerate(lines):
            if max_entries and len(entries) >= max_entries:
                break
                
            if not line.strip():
                continue
                
            try:
                if is_jsonl:
                    entry = self._parse_json_line(line)
                else:
                    entry = self._parse_text_line(line)
                    
                if entry:
                    entries.append(entry)
            except Exception as e:
                logger.warning("parse_line_failed", line_num=i+1, error=str(e))
        
        logger.info("file_parsed", path=str(path), entry_count=len(entries))
        
        return LogBatch(
            entries=entries,
            source_file=str(path),
            source_type="jsonl" if is_jsonl else "text",
        )
    
    def parse_lines(self, lines: list[str], source: str = "stream") -> LogBatch:
        """Parse a list of log lines."""
        entries = []
        for line in lines:
            if not line.strip():
                continue
            try:
                if line.strip().startswith("{"):
                    entry = self._parse_json_line(line)
                else:
                    entry = self._parse_text_line(line)
                if entry:
                    entries.append(entry)
            except Exception:
                continue
        
        return LogBatch(entries=entries, source_type=source)
    
    def stream_file(
        self, 
        filepath: str | Path,
    ) -> Generator[LogEntry, None, None]:
        """
        Stream parse a log file, yielding entries one at a time.
        
        Useful for very large files to avoid loading all into memory.
        """
        path = validate_file_path(filepath, must_exist=True)
        
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    if line.startswith("{"):
                        entry = self._parse_json_line(line)
                    else:
                        entry = self._parse_text_line(line)
                    
                    if entry:
                        yield entry
                except Exception:
                    continue
    
    def _parse_json_line(self, line: str) -> LogEntry | None:
        """Parse a JSON/JSONL log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        
        # Handle journalctl JSON format
        if "__REALTIME_TIMESTAMP" in data:
            ts_usec = int(data.get("__REALTIME_TIMESTAMP", 0))
            timestamp = datetime.fromtimestamp(ts_usec / 1_000_000, tz=timezone.utc)
            source = data.get("SYSLOG_IDENTIFIER", data.get("_COMM", "unknown"))
            message = data.get("MESSAGE", "")
            
            return LogEntry(
                timestamp=timestamp,
                source=source,
                message=message if isinstance(message, str) else str(message),
                raw=line,
                metadata={
                    k: v for k, v in data.items() 
                    if not k.startswith("_") and k != "MESSAGE"
                },
            )
        
        # Handle generic JSON logs
        timestamp = self._extract_timestamp_from_dict(data)
        source = data.get("source", data.get("process", data.get("logger", "unknown")))
        message = data.get("message", data.get("msg", data.get("log", json.dumps(data))))
        
        return LogEntry(
            timestamp=timestamp,
            source=source,
            message=message,
            raw=line,
            metadata=data,
        )
    
    def _parse_text_line(self, line: str) -> LogEntry | None:
        """Parse a plain text log line."""
        timestamp = self._extract_timestamp(line)
        source, message = self._extract_source_and_message(line)
        
        return LogEntry(
            timestamp=timestamp,
            source=source,
            message=message,
            raw=line,
        )
    
    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from a log line."""
        for pattern, fmt in self._compiled_patterns:
            match = pattern.search(line)
            if match:
                ts_str = match.group(1)
                try:
                    # Handle ISO format with timezone
                    if "T" in ts_str and ("Z" in ts_str or "+" in ts_str or ts_str.count("-") > 2):
                        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    
                    dt = datetime.strptime(ts_str, fmt)
                    # Add current year for syslog format
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        
        # Fallback to current time
        return datetime.now(timezone.utc)
    
    def _extract_timestamp_from_dict(self, data: dict) -> datetime:
        """Extract timestamp from a JSON log dict."""
        for key in ["timestamp", "time", "@timestamp", "datetime", "ts"]:
            if key in data:
                val = data[key]
                if isinstance(val, str):
                    try:
                        return datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                elif isinstance(val, (int, float)):
                    # Unix timestamp
                    return datetime.fromtimestamp(val, tz=timezone.utc)
        
        return datetime.now(timezone.utc)
    
    def _extract_source_and_message(self, line: str) -> tuple[str, str]:
        """Extract source process and message from syslog-like line."""
        # Remove timestamp prefix
        for pattern, _ in self._compiled_patterns:
            line = pattern.sub("", line, count=1).strip()
        
        # Try to extract source from syslog format
        match = self.SYSLOG_SOURCE_PATTERN.match(line)
        if match:
            source = match.group(1)
            message = line[match.end():].strip()
            return source, message
        
        # Fallback: use "unknown" as source
        return "unknown", line
