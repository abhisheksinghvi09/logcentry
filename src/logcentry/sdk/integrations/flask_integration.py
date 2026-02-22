"""
LogCentry SDK - Flask Integration

WSGI middleware for automatic request/response logging.

Usage:
    from flask import Flask
    from logcentry.sdk.integrations import flask_middleware
    
    app = Flask(__name__)
    app.wsgi_app = flask_middleware(app.wsgi_app, api_key="lc_xxx")
"""

import time
from typing import Any, Callable

from logcentry.sdk.client import LogCentry


class LogCentryFlaskMiddleware:
    """
    WSGI middleware for Flask that automatically logs requests.
    
    Captures:
    - Request method, path, IP
    - Response status code
    - Request duration
    - Errors and exceptions
    """
    
    def __init__(
        self,
        app: Callable,
        api_key: str,
        endpoint: str = "http://localhost:8000",
        log_request_body: bool = False,
        exclude_paths: list[str] | None = None,
    ):
        """
        Initialize the middleware.
        
        Args:
            app: WSGI application
            api_key: LogCentry API key
            endpoint: LogCentry API endpoint
            log_request_body: Whether to log request bodies
            exclude_paths: Paths to exclude from logging (e.g., ["/health"])
        """
        self.app = app
        self.logger = LogCentry(api_key=api_key, endpoint=endpoint)
        self.log_request_body = log_request_body
        self.exclude_paths = exclude_paths or ["/health", "/favicon.ico"]
    
    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """Handle WSGI request."""
        path = environ.get("PATH_INFO", "/")
        
        # Skip excluded paths
        if any(path.startswith(ex) for ex in self.exclude_paths):
            return self.app(environ, start_response)
        
        method = environ.get("REQUEST_METHOD", "GET")
        ip = environ.get("HTTP_X_FORWARDED_FOR", environ.get("REMOTE_ADDR", "unknown"))
        user_agent = environ.get("HTTP_USER_AGENT", "")
        
        start_time = time.time()
        status_code = "500"
        
        def custom_start_response(status, headers, exc_info=None):
            nonlocal status_code
            status_code = status.split(" ")[0]
            return start_response(status, headers, exc_info)
        
        try:
            response = self.app(environ, custom_start_response)
            duration_ms = (time.time() - start_time) * 1000
            
            # Determine log level based on status
            status_int = int(status_code)
            if status_int >= 500:
                level = "error"
            elif status_int >= 400:
                level = "warning"
            else:
                level = "info"
            
            self.logger.log(
                level,
                f"{method} {path} {status_code}",
                source="flask",
                ip=ip,
                method=method,
                path=path,
                status=status_code,
                duration_ms=round(duration_ms, 2),
                user_agent=user_agent[:100],
            )
            
            return response
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            self.logger.error(
                f"{method} {path} - Exception: {str(e)[:200]}",
                source="flask",
                ip=ip,
                method=method,
                path=path,
                duration_ms=round(duration_ms, 2),
                exception=type(e).__name__,
            )
            raise
