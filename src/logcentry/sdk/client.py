"""
LogCentry SDK - Client (Agent)

Main SDK agent for sending logs to LogCentry API.
Implements the Singleton/Facade pattern backing agent.
"""

import atexit
import json
import queue
import threading
import time
from datetime import datetime
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

from logcentry.sdk.circuit_breaker import CircuitBreaker

class LogCentryAgent:
    """
    LogCentry SDK Agent.
    
    Handles log buffering, batching, and resilient transmission.
    Should detailed configuration be needed, use LogCentry instead.
    
    Architecture:
    - Queue: Buffers logs from application threads
    - Worker: Background thread consumes queue and batches logs
    - Resilience: Circuit Breaker prevents cascading failures
    """
    
    def __init__(
        self,
        api_key: str,
        endpoint: str = "http://localhost:8000",
        project: str | None = None,
        batch_size: int = 10,
        flush_interval: float = 5.0,
        sync_mode: bool = False,
    ):
        """
        Initialize the LogCentry agent.
        
        Args:
            api_key: Your LogCentry API key
            endpoint: API endpoint URL
            project: Project name (optional)
            batch_size: Batch size
            flush_interval: Flush interval
            sync_mode: Synchronous mode (blocking)
        """
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.project = project
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.sync_mode = sync_mode
        
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        
        # Resilience
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=30.0
        )
        
        if not sync_mode:
            self._start_background_thread()
            atexit.register(self.shutdown)
    
    def _start_background_thread(self) -> None:
        """Start the background sender thread."""
        if self._thread and self._thread.is_alive():
            return
            
        self._thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._thread.start()
    
    def _sender_loop(self) -> None:
        """Background loop to send batches."""
        batch = []
        last_flush = time.time()
        
        while not self._stop_event.is_set():
            try:
                # Wait for log or verify flush interval
                timeouts = max(0.1, self.flush_interval - (time.time() - last_flush))
                
                try:
                    log = self._queue.get(timeout=timeouts)
                    batch.append(log)
                except queue.Empty:
                    pass
                
                # Check conditions to send
                is_full = len(batch) >= self.batch_size
                is_time = (time.time() - last_flush) >= self.flush_interval
                
                if batch and (is_full or is_time):
                    # DEBUG PRINT
                    print(f"[SDK DEBUG] Sending batch (size={len(batch)})", flush=True)
                    self._send_batch(batch)
                    batch = []
                    last_flush = time.time()
                    
            except Exception as e:
                # Prevent thread death
                print(f"[LogCentry] Agent Error: {e}", flush=True)
                time.sleep(1)
        
        # Flush remaining on shutdown
        if batch:
            print(f"[SDK DEBUG] Flushing on shutdown (size={len(batch)})", flush=True)
            self._send_batch(batch)
    
    def _send_batch(self, batch: list[dict]) -> bool:
        """
        Send a batch of logs to the API with resilience.
        """
        if not batch:
            return True
        
        # Circuit Breaker Check
        if not self._circuit_breaker.allow_request():
            # Drop logs or fallback (could write to disk loop here)
            print(f"[LogCentry] Circuit OPEN. Dropping {len(batch)} logs.", flush=True)
            return False
        
        try:
            url = f"{self.endpoint}/api/v1/logs/batch"
            data = json.dumps({"logs": batch}).encode("utf-8")
            
            request = Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                },
                method="POST",
            )
            
            with urlopen(request, timeout=10) as response:
                if 200 <= response.status < 300:
                    print(f"[SDK DEBUG] Successfully sent batch to {url}", flush=True)
                    self._circuit_breaker.record_success()
                    return True
                else:
                    print(f"[SDK DEBUG] Failed to send batch (status {response.status})", flush=True)
                    self._circuit_breaker.record_failure()
                    return False
                
        except (URLError, Exception) as e:
            self._circuit_breaker.record_failure()
            # Silently fail - don't crash the app
            # Only print if debug enabled? For now, standard error.
            print(f"[LogCentry] Failed to send logs: {e}", flush=True)
            return False
    
    def _send_single(self, log: dict) -> bool:
        """Send a single log synchronously."""
        if not self._circuit_breaker.allow_request():
            return False

        try:
            url = f"{self.endpoint}/api/v1/logs"
            data = json.dumps(log).encode("utf-8")
            
            request = Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                },
                method="POST",
            )
            
            with urlopen(request, timeout=10) as response:
                if 200 <= response.status < 300:
                    self._circuit_breaker.record_success()
                    return True
                else:
                    self._circuit_breaker.record_failure()
                    return False
                
        except Exception as e:
            self._circuit_breaker.record_failure()
            print(f"[LogCentry] Failed to send log: {e}")
            return False
    
    def _log(self, level: str, message: str, **kwargs) -> None:
        """Internal log method."""
        log_entry = {
            "level": level,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "source": kwargs.pop("source", None),
            "metadata": kwargs,
        }
        
        if self.sync_mode:
            self._send_single(log_entry)
        else:
            try:
                # DEBUG PRINT
                print(f"[SDK DEBUG] Enqueueing log: {message[:20]}...", flush=True)
                self._queue.put(log_entry, block=False)
            except queue.Full:
                print("[SDK DEBUG] Queue FULL!", flush=True)
                pass
    
    # ==================== Public API ====================
    
    def debug(self, message: str, **kwargs) -> None:
        self._log("debug", message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        self._log("info", message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self._log("warning", message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self._log("error", message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log a critical message."""
        self._log("critical", message, **kwargs)
    
    def security(self, message: str, **kwargs) -> None:
        """Log a security event."""
        self._log("security", message, **kwargs)
    
    def log(self, level: str, message: str, **kwargs) -> None:
        """Log with custom level."""
        self._log(level.lower(), message, **kwargs)
    
    def flush(self) -> None:
        """Flush any pending logs."""
        if self.sync_mode:
            return
        
        # Wait for queue to empty (best effort)
        # In a real agent we might signal the thread
        pass 
        # For simplicity in this implementation, we can't easily force the thread to flush 
        # without complex signaling. 
        # But 'atexit' calls shutdown which sends remaining batch.
    
    def shutdown(self) -> None:
        """Shutdown the client gracefully."""
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

# Backward Compatibility
LogCentry = LogCentryAgent
