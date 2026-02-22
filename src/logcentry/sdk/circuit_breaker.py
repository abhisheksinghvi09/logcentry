"""
LogCentry SDK - Circuit Breaker

Implements the Circuit Breaker pattern to handle failures gracefully.
Prevents the SDK from overwhelming the API or crashing the host app during outages.
"""

import time
import threading
from enum import Enum
from typing import Callable, Any, TypeVar

T = TypeVar("T")

class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, requests blocked
    HALF_OPEN = "half_open" # Testing if service recovered


class CircuitBreaker:
    """
    Circuit Breaker implementation.
    
    Usage:
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
        
        if breaker.allow_request():
            try:
                do_something()
                breaker.record_success()
            except Exception:
                breaker.record_failure()
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exceptions: tuple[type[Exception], ...] | None = None,
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before testing recovery (Half-Open)
            expected_exceptions: Exceptions that count as failures (default: all)
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions or (Exception,)
        
        self._lock = threading.RLock()
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._last_failure_time = 0.0
    
    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state
    
    def allow_request(self) -> bool:
        """
        Check if request should be allowed.
        
        Returns:
            True if request matches circuit policy, False if blocked.
        """
        with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                now = time.time()
                if now - self._last_failure_time >= self.recovery_timeout:
                    self._transition_to(CircuitState.HALF_OPEN)
                    return True
                return False
            
            # HALF_OPEN: Allow one request to test recovery
            # In a real distributed system we might limit concurrent test requests,
            # but for this SDK, we let it pass. Simpler: if Half-Open, we treat as closed for this check
            # but monitor result closely.
            return True

    def record_success(self) -> None:
        """Record a successful operation."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.CLOSED)
            self._failures = 0

    def record_failure(self) -> None:
        """Record a failed operation."""
        with self._lock:
            self._failures += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                if self._failures >= self.failure_threshold:
                    self._transition_to(CircuitState.OPEN)
            
            elif self._state == CircuitState.HALF_OPEN:
                self._transition_to(CircuitState.OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        self._state = new_state
        # Reset failures on transition to Closed
        if new_state == CircuitState.CLOSED:
            self._failures = 0
