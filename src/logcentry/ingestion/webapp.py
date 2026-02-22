"""
LogCentry - Web Application Log Ingestion

Provides dynamic log capture for web applications:
- File tail mode for nginx/Apache access logs
- Docker container log streaming
- Multiple log format parsers (Common, Combined, JSON)
"""

import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import Iterator

from logcentry.core.models import LogEntry
from logcentry.utils import get_logger, is_safe_command

logger = get_logger(__name__)


@dataclass
class WebAppLogConfig:
    """Configuration for web app log streaming."""
    
    # Log file paths
    log_path: str | None = None
    
    # Docker settings
    docker_container: str | None = None
    
    # Log format
    format: str = "auto"  # auto, common, combined, json, nginx_json, apache
    
    # Streaming settings
    follow: bool = True  # Tail mode
    from_beginning: bool = False  # Start from beginning of file


# Log format patterns
COMMON_LOG_PATTERN = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)'
)

COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


class WebAppLogParser:
    """Parses web application log entries into LogEntry objects."""
    
    def __init__(self, log_format: str = "auto"):
        self.format = log_format
        self._detected_format: str | None = None
    
    def parse(self, line: str, source: str = "webapp") -> LogEntry | None:
        """
        Parse a log line into a LogEntry.
        
        Args:
            line: Raw log line
            source: Source identifier
            
        Returns:
            LogEntry or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None
        
        # Auto-detect format
        if self.format == "auto":
            return self._parse_auto(line, source)
        elif self.format == "json" or self.format == "nginx_json":
            return self._parse_json(line, source)
        elif self.format == "combined":
            return self._parse_combined(line, source)
        elif self.format == "common":
            return self._parse_common(line, source)
        else:
            return self._parse_raw(line, source)
    
    def _parse_auto(self, line: str, source: str) -> LogEntry | None:
        """Auto-detect and parse log format."""
        # Try JSON first
        if line.startswith("{"):
            result = self._parse_json(line, source)
            if result:
                self._detected_format = "json"
                return result
        
        # Try Combined format
        result = self._parse_combined(line, source)
        if result:
            self._detected_format = "combined"
            return result
        
        # Try Common format
        result = self._parse_common(line, source)
        if result:
            self._detected_format = "common"
            return result
        
        # Fall back to raw
        return self._parse_raw(line, source)
    
    def _parse_json(self, line: str, source: str) -> LogEntry | None:
        """Parse JSON formatted log."""
        try:
            data = json.loads(line)
            
            # Extract common fields (nginx JSON, custom JSON)
            timestamp = data.get("time", data.get("timestamp", data.get("@timestamp", "")))
            ip = data.get("remote_addr", data.get("client_ip", data.get("ip", "")))
            method = data.get("request_method", data.get("method", ""))
            path = data.get("request_uri", data.get("uri", data.get("path", data.get("request", ""))))
            status = data.get("status", data.get("response_code", ""))
            user_agent = data.get("http_user_agent", data.get("user_agent", ""))
            
            # Build message
            message = f'{ip} "{method} {path}" {status}'
            if user_agent:
                message += f' "{user_agent[:50]}"'
            
            return LogEntry(
                timestamp=self._parse_timestamp(timestamp),
                source=source,
                message=message,
                level="INFO",
                raw_content=line,
                metadata={
                    "ip": ip,
                    "method": method,
                    "path": path,
                    "status": str(status),
                    "user_agent": user_agent,
                    "format": "json",
                    **{k: v for k, v in data.items() if k not in ["time", "timestamp", "@timestamp"]},
                },
            )
        except json.JSONDecodeError:
            return None
    
    def _parse_combined(self, line: str, source: str) -> LogEntry | None:
        """Parse Combined log format (nginx/Apache default)."""
        match = COMBINED_LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        status = data.get("status", "200")
        
        return LogEntry(
            timestamp=self._parse_access_timestamp(data.get("timestamp", "")),
            source=source,
            message=f'{data["ip"]} "{data["method"]} {data["path"]}" {status} "{data["user_agent"][:50]}"',
            level=self._status_to_level(status),
            raw_content=line,
            metadata={
                "ip": data["ip"],
                "method": data["method"],
                "path": data["path"],
                "status": status,
                "size": data["size"],
                "referer": data["referer"],
                "user_agent": data["user_agent"],
                "format": "combined",
            },
        )
    
    def _parse_common(self, line: str, source: str) -> LogEntry | None:
        """Parse Common log format."""
        match = COMMON_LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        status = data.get("status", "200")
        
        return LogEntry(
            timestamp=self._parse_access_timestamp(data.get("timestamp", "")),
            source=source,
            message=f'{data["ip"]} "{data["method"]} {data["path"]}" {status}',
            level=self._status_to_level(status),
            raw_content=line,
            metadata={
                "ip": data["ip"],
                "method": data["method"],
                "path": data["path"],
                "status": status,
                "size": data["size"],
                "format": "common",
            },
        )
    
    def _parse_raw(self, line: str, source: str) -> LogEntry:
        """Parse as raw log line."""
        return LogEntry(
            timestamp=datetime.now(),
            source=source,
            message=line[:500],  # Limit message length
            level="INFO",
            raw_content=line,
            metadata={"format": "raw"},
        )
    
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse various timestamp formats."""
        if not ts_str:
            return datetime.now()
        
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return datetime.now()
    
    def _parse_access_timestamp(self, ts_str: str) -> datetime:
        """Parse access log timestamp format: 06/Feb/2026:10:21:33 +0000"""
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return datetime.now()
    
    def _status_to_level(self, status: str) -> str:
        """Convert HTTP status code to log level."""
        try:
            code = int(status)
            if code < 400:
                return "INFO"
            elif code < 500:
                return "WARNING"
            else:
                return "ERROR"
        except (ValueError, TypeError):
            return "INFO"


class WebAppStream:
    """
    Streams web application logs from files or Docker.
    
    Supports:
    - File tailing (nginx, Apache, custom logs)
    - Docker container logs
    - Multiple log formats
    """
    
    def __init__(self, config: WebAppLogConfig):
        self.config = config
        self.parser = WebAppLogParser(config.format)
        self._queue: Queue[LogEntry] = Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None
    
    def start(self) -> None:
        """Start log streaming in background thread."""
        self._stop_event.clear()
        
        if self.config.docker_container:
            self._thread = threading.Thread(
                target=self._stream_docker,
                daemon=True,
            )
        elif self.config.log_path:
            self._thread = threading.Thread(
                target=self._stream_file,
                daemon=True,
            )
        else:
            raise ValueError("Must specify either log_path or docker_container")
        
        self._thread.start()
        logger.info("webapp_stream_started", 
                   source=self.config.docker_container or self.config.log_path)
    
    def stop(self) -> None:
        """Stop log streaming."""
        self._stop_event.set()
        
        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
        
        if self._thread:
            self._thread.join(timeout=2)
        
        logger.info("webapp_stream_stopped")
    
    def get_entries(self, timeout: float = 0.1) -> list[LogEntry]:
        """
        Get available log entries from the queue.
        
        Returns:
            List of LogEntry objects
        """
        entries = []
        try:
            while True:
                entry = self._queue.get_nowait()
                entries.append(entry)
        except Empty:
            pass
        return entries
    
    def iter_entries(self) -> Iterator[LogEntry]:
        """Iterate over log entries as they arrive."""
        while not self._stop_event.is_set():
            try:
                entry = self._queue.get(timeout=0.5)
                yield entry
            except Empty:
                continue
    
    def _stream_file(self) -> None:
        """Stream logs from a file using tail."""
        log_path = Path(self.config.log_path)
        
        if not log_path.exists():
            logger.error("log_file_not_found", path=str(log_path))
            return
        
        # Build tail command
        cmd = ["tail"]
        if self.config.follow:
            cmd.append("-f")
        if not self.config.from_beginning:
            cmd.extend(["-n", "100"])  # Start with last 100 lines
        else:
            cmd.extend(["-n", "+1"])
        cmd.append(str(log_path))
        
        # Validate command
        if not is_safe_command(cmd[0]):
            logger.error("unsafe_command", cmd=cmd[0])
            return
        
        source = log_path.name
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            
            logger.info("file_tail_started", path=str(log_path))
            
            for line in iter(self._process.stdout.readline, ''):
                if self._stop_event.is_set():
                    break
                
                entry = self.parser.parse(line, source=source)
                if entry:
                    self._queue.put(entry)
                    
        except Exception as e:
            logger.error("file_stream_error", error=str(e))
        finally:
            if self._process:
                self._process.terminate()
    
    def _stream_docker(self) -> None:
        """Stream logs from a Docker container."""
        container = self.config.docker_container
        
        # Build docker logs command
        cmd = ["docker", "logs"]
        if self.config.follow:
            cmd.append("-f")
        if not self.config.from_beginning:
            cmd.extend(["--tail", "100"])
        cmd.append(container)
        
        # Validate command
        if not is_safe_command("docker"):
            logger.error("docker_not_in_safelist")
            return
        
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Docker logs to stderr
                text=True,
                bufsize=1,
            )
            
            logger.info("docker_stream_started", container=container)
            
            for line in iter(self._process.stdout.readline, ''):
                if self._stop_event.is_set():
                    break
                
                entry = self.parser.parse(line, source=f"docker:{container}")
                if entry:
                    self._queue.put(entry)
                    
        except FileNotFoundError:
            logger.error("docker_not_found", msg="Docker CLI not installed")
        except Exception as e:
            logger.error("docker_stream_error", error=str(e))
        finally:
            if self._process:
                self._process.terminate()


def detect_log_files() -> list[Path]:
    """
    Auto-detect common web server log file locations.
    
    Returns:
        List of detected log file paths
    """
    common_paths = [
        # Nginx
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/usr/local/nginx/logs/access.log",
        # Apache
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        # Generic
        "/var/log/access.log",
    ]
    
    detected = []
    for path_str in common_paths:
        path = Path(path_str)
        if path.exists() and path.is_file():
            detected.append(path)
    
    return detected


def create_webapp_stream(
    log_path: str | None = None,
    docker_container: str | None = None,
    log_format: str = "auto",
    follow: bool = True,
) -> WebAppStream:
    """
    Factory function to create a WebAppStream.
    
    Args:
        log_path: Path to log file
        docker_container: Docker container name/ID
        log_format: Log format (auto, common, combined, json)
        follow: Whether to tail the file
        
    Returns:
        Configured WebAppStream
    """
    config = WebAppLogConfig(
        log_path=log_path,
        docker_container=docker_container,
        format=log_format,
        follow=follow,
    )
    return WebAppStream(config)
