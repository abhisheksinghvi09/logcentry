"""
LogCentry SDK Quickstart

5 lines to capture and analyze security logs!
"""

# ==================== Basic Usage (5 lines) ====================

from logcentry.sdk import LogCentry

logger = LogCentry(api_key="lc_your_api_key")
logger.security("Failed login from 192.168.1.100", ip="192.168.1.100", user="admin")
logger.error("SQL injection detected", query="SELECT * FROM users WHERE id='1 OR 1=1'")

# ==================== Async Usage ====================

import asyncio
from logcentry.sdk import AsyncLogCentry


async def capture_logs():
    async with AsyncLogCentry(api_key="lc_your_api_key") as client:
        await client.security("Attack detected", severity="high")
        await client.info("Request processed", duration_ms=45)
        
        # Analyze logs with RAG context
        from logcentry.sdk import LogBatch, LogEntry
        batch = LogBatch()
        batch.add(LogEntry(message="Failed SSH login from 10.0.0.1"))
        batch.add(LogEntry(message="Brute force pattern detected"))
        
        result = await client.analyze_logs(batch, use_rag=True)
        print(f"Severity: {result.severity_level}")
        print(f"Recommendations: {result.countermeasures}")


# asyncio.run(capture_logs())

# ==================== Decorators ====================

from logcentry.sdk import log_capture, trace_operation


@log_capture(level="info", include_timing=True)
def process_request(user_id: int, action: str):
    """This function call is automatically logged."""
    return {"status": "ok", "user_id": user_id}


@trace_operation("db_query")
async def query_database(query: str):
    """This function is traced for distributed tracing."""
    return {"rows": 10}


# ==================== Custom Parsers ====================

from logcentry.sdk.plugins import PluginRegistry, BaseParser, register_parser

registry = PluginRegistry()


@register_parser(registry)
class MyAppParser(BaseParser):
    """Parse my app's custom log format."""
    
    @property
    def name(self) -> str:
        return "myapp_parser"
    
    @property
    def supported_formats(self) -> list[str]:
        return ["myapp"]
    
    def parse(self, raw_log: str) -> dict:
        # Parse: "[MyApp] LEVEL: message"
        if raw_log.startswith("[MyApp]"):
            parts = raw_log[7:].strip().split(": ", 1)
            return {
                "level": parts[0].lower() if parts else "info",
                "message": parts[1] if len(parts) > 1 else raw_log,
                "source": "myapp",
            }
        return {"message": raw_log}


# Test parser
log = "[MyApp] ERROR: Database connection failed"
parsed = registry.get_parser("myapp_parser").parse(log)
print(parsed)  # {'level': 'error', 'message': 'Database connection failed', 'source': 'myapp'}

# ==================== Security & Compliance ====================

from logcentry.sdk.security import PIIAnonymizer, AuditLogger

# Automatically anonymize PII in logs
anonymizer = PIIAnonymizer()
log_with_pii = "User email: john@example.com, IP: 192.168.1.1"
safe_log = anonymizer.anonymize(log_with_pii)
print(safe_log)  # User email: [EMAIL_REDACTED], IP: [IP_REDACTED]

# Audit all SDK actions
audit = AuditLogger()
audit.log("log_ingest", actor="sdk_user", resource="/api/v1/logs", count=100)

# ==================== Middleware Pipeline ====================

from logcentry.sdk.middleware import (
    MiddlewarePipeline,
    AuthMiddleware,
    RateLimitMiddleware,
    LoggingMiddleware,
)

pipeline = (
    MiddlewarePipeline()
    .add(LoggingMiddleware())
    .add(RateLimitMiddleware(requests_per_second=10))
    .add(AuthMiddleware(api_key="lc_xxx"))
)

# ==================== Flask Integration ====================

# from flask import Flask
# from logcentry.sdk import LogCentry, flask_middleware
#
# app = Flask(__name__)
# logger = LogCentry(api_key="lc_xxx")
# app.before_request(flask_middleware(logger))
#
# @app.route("/api/users")
# def get_users():
#     return {"users": []}

# ==================== Environment Variables ====================

# export LOGCENTRY_API_KEY=lc_your_api_key
# export LOGCENTRY_ENDPOINT=http://localhost:8000

# from logcentry.sdk.security import get_api_key
# api_key = get_api_key()  # Reads from LOGCENTRY_API_KEY

if __name__ == "__main__":
    print("LogCentry SDK Quickstart Examples")
    print("=" * 40)
    print(f"Parsed log: {parsed}")
    print(f"Anonymized: {safe_log}")
