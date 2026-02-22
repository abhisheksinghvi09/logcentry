"""
LogCentry SDK - Django Integration

Django middleware for automatic request/response logging.

Usage:
    # settings.py
    MIDDLEWARE = [
        'logcentry.sdk.integrations.django_integration.LogCentryDjangoMiddleware',
        ...
    ]
    
    LOGCENTRY_API_KEY = "lc_xxx"
    LOGCENTRY_ENDPOINT = "http://localhost:8000"
"""

import time
from typing import Callable


class LogCentryDjangoMiddleware:
    """
    Django middleware for automatic request logging.
    
    Configure in settings.py:
        LOGCENTRY_API_KEY = "your_api_key"
        LOGCENTRY_ENDPOINT = "http://localhost:8000"  # optional
    """
    
    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self.logger = None
        self._initialized = False
    
    def _lazy_init(self):
        """Lazy initialization to avoid import issues."""
        if self._initialized:
            return
        
        from django.conf import settings
        from logcentry.sdk.client import LogCentry
        
        api_key = getattr(settings, "LOGCENTRY_API_KEY", None)
        endpoint = getattr(settings, "LOGCENTRY_ENDPOINT", "http://localhost:8000")
        
        if api_key:
            self.logger = LogCentry(api_key=api_key, endpoint=endpoint)
        
        self._initialized = True
    
    def __call__(self, request):
        self._lazy_init()
        
        if not self.logger:
            return self.get_response(request)
        
        # Skip health checks
        if request.path in ["/health", "/favicon.ico"]:
            return self.get_response(request)
        
        start_time = time.time()
        
        try:
            response = self.get_response(request)
            duration_ms = (time.time() - start_time) * 1000
            
            # Determine log level
            if response.status_code >= 500:
                level = "error"
            elif response.status_code >= 400:
                level = "warning"
            else:
                level = "info"
            
            ip = self._get_client_ip(request)
            
            self.logger.log(
                level,
                f"{request.method} {request.path} {response.status_code}",
                source="django",
                ip=ip,
                method=request.method,
                path=request.path,
                status=response.status_code,
                duration_ms=round(duration_ms, 2),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:100],
                user_id=getattr(request.user, "id", None) if hasattr(request, "user") else None,
            )
            
            return response
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            self.logger.error(
                f"{request.method} {request.path} - Exception: {str(e)[:200]}",
                source="django",
                ip=self._get_client_ip(request),
                method=request.method,
                path=request.path,
                duration_ms=round(duration_ms, 2),
                exception=type(e).__name__,
            )
            raise
    
    def _get_client_ip(self, request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")
