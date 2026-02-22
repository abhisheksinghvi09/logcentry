"""
LogCentry Ingestion - Journald Stream

Real-time log streaming from systemd journald with event correlation.
"""

import json
import subprocess
import threading
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Callable, Generator

from logcentry.core import LogBatch, LogEntry
from logcentry.utils import get_logger, is_safe_command

logger = get_logger(__name__)


class JournaldStream:
    """
    Real-time log streaming from journalctl.
    
    Features:
    - Multiple category filters (auth, firewall, kernel, etc.)
    - Threaded collection for non-blocking operation
    - Batch accumulation for periodic analysis
    - Graceful shutdown handling
    """
    
    # Predefined category filters
    CATEGORIES = {
        "siem": {
            "name": "General SIEM",
            "filters": [],  # No additional filters, use base priority
        },
        "auth": {
            "name": "Authentication",
            "filters": ["-u", "sshd.service", "-u", "systemd-logind.service", "-u", "sudo"],
        },
        "firewall": {
            "name": "Firewall/Network",
            "filters": ["-k", "--grep=UFW"],
        },
        "kernel": {
            "name": "Kernel",
            "filters": ["-k"],
        },
        "service": {
            "name": "System Services",
            "filters": ["_SYSTEMD_UNIT=cron.service", "_SYSTEMD_UNIT=systemd-logind.service"],
        },
    }
    
    def __init__(
        self,
        categories: list[str] | None = None,
        priority_range: str = "0..4",  # Emergency to Warning
        since: str = "24 hours ago",
    ):
        """
        Initialize the journald stream.
        
        Args:
            categories: List of category names to monitor (default: ["siem"])
            priority_range: journalctl priority range (default: "0..4")
            since: Time range for logs (default: "24 hours ago")
        """
        self.categories = categories or ["siem"]
        self.priority_range = priority_range
        self.since = since
        
        self._queue: Queue[LogEntry] = Queue()
        self._running = False
        self._threads: list[threading.Thread] = []
        self._processes: list[subprocess.Popen] = []
    
    def _build_command(self, category: str) -> list[str]:
        """Build journalctl command for a category."""
        base_cmd = [
            "journalctl", "-f",
            "-p", self.priority_range,
            "-o", "json",
            "--no-pager",
            "--since", self.since,
        ]
        
        cat_config = self.CATEGORIES.get(category, {})
        filters = cat_config.get("filters", [])
        
        return base_cmd + filters
    
    def start(self, on_entry: Callable[[LogEntry], None] | None = None) -> None:
        """
        Start streaming logs.
        
        Args:
            on_entry: Optional callback for each log entry
        """
        self._running = True
        
        for category in self.categories:
            if category not in self.CATEGORIES:
                logger.warning("unknown_category", category=category)
                continue
            
            command = self._build_command(category)
            
            if not is_safe_command(command):
                logger.error("unsafe_command_blocked", command=command)
                continue
            
            thread = threading.Thread(
                target=self._stream_worker,
                args=(category, command, on_entry),
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()
            
            logger.info(
                "stream_started",
                category=category,
                name=self.CATEGORIES[category]["name"],
            )
    
    def _stream_worker(
        self,
        category: str,
        command: list[str],
        on_entry: Callable[[LogEntry], None] | None,
    ) -> None:
        """Worker thread that reads from journalctl."""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="ignore",
            )
            self._processes.append(process)
            
            for line in iter(process.stdout.readline, ""):
                if not self._running:
                    break
                
                if not line.strip():
                    continue
                
                entry = self._parse_journald_json(line, category)
                if entry:
                    self._queue.put(entry)
                    if on_entry:
                        on_entry(entry)
        
        except Exception as e:
            logger.error("stream_worker_error", category=category, error=str(e))
        finally:
            if process and process.poll() is None:
                process.terminate()
    
    def _parse_journald_json(self, line: str, category: str) -> LogEntry | None:
        """Parse a journalctl JSON line into a LogEntry."""
        try:
            data = json.loads(line)
            
            ts_usec = int(data.get("__REALTIME_TIMESTAMP", 0))
            timestamp = datetime.fromtimestamp(ts_usec / 1_000_000, tz=timezone.utc)
            
            source = data.get("SYSLOG_IDENTIFIER", data.get("_COMM", "unknown"))
            message = data.get("MESSAGE", "")
            
            # Handle array messages (journald can return message as array)
            if isinstance(message, list):
                message = " ".join(str(m) for m in message)
            
            return LogEntry(
                timestamp=timestamp,
                source=source,
                message=str(message),
                raw=line,
                metadata={"category": category},
            )
        
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug("parse_failed", line=line[:100], error=str(e))
            return None
    
    def stop(self) -> None:
        """Stop all streaming threads."""
        self._running = False
        
        for process in self._processes:
            if process.poll() is None:
                process.terminate()
        
        logger.info("stream_stopped")
    
    def get_batch(self, max_size: int = 100, timeout: float = 0.1) -> LogBatch:
        """
        Get accumulated log entries as a batch.
        
        Args:
            max_size: Maximum entries to return
            timeout: Timeout for waiting on empty queue
            
        Returns:
            LogBatch of accumulated entries
        """
        entries = []
        
        while len(entries) < max_size:
            try:
                entry = self._queue.get(timeout=timeout)
                entries.append(entry)
            except Empty:
                break
        
        return LogBatch(entries=entries, source_type="journald")
    
    def stream(self) -> Generator[LogEntry, None, None]:
        """
        Generator that yields log entries as they arrive.
        
        Must call start() before using this.
        """
        while self._running or not self._queue.empty():
            try:
                entry = self._queue.get(timeout=0.5)
                yield entry
            except Empty:
                continue
    
    @property
    def is_running(self) -> bool:
        return self._running
