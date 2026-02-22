# LogCentry Client SDK

**Lightweight Python SDK for LogCentry** - Zero heavy dependencies!

## Installation

```bash
# From PyPI (recommended for consumers)
pip install logcentry-client

# With async support
pip install logcentry-client[async]

# For local development of the client or to run examples against a local server,
# install in editable mode from the repository root (activate your venv first):
pip install -e .
```

Compare to **full SDK** which includes ML/RAG (~500MB):
```bash
pip install logcentry
```

## Quick Start

```python
from logcentry_client import LogCentry

# Initialize (point to local server during development)
logger = LogCentry(api_key="lc_your_api_key", endpoint="http://localhost:8000")

# Log events
logger.info("User logged in", user_id=123)
logger.error("Database failed", error="timeout")
logger.security("Attack detected", ip="10.0.0.1")

# Graceful shutdown
logger.shutdown()
```

## Features

| Feature | Client SDK | Full SDK |
|---------|------------|----------|
| Size | ~50KB | ~500MB |
| Dependencies | **None** | chromadb, torch, etc. |
| Log sending | ✅ | ✅ |
| Batching | ✅ | ✅ |
| Async support | ✅ (optional) | ✅ |
| Threat analysis | Via API | Local + API |
| RAG/ML | Via API | Local |

## Why Lightweight?

Like Stripe, Sentry, and DataDog SDKs:
- **Fast imports** - No heavy ML libraries
- **Small footprint** - Won't bloat your project
- **Backend processing** - Heavy work happens on LogCentry servers

## API

### LogCentry Client

```python
from logcentry_client import LogCentry

# Full configuration
logger = LogCentry(
    api_key="lc_xxx",           # Required (or set LOGCENTRY_API_KEY)
    endpoint="http://localhost:8000",
    batch_size=50,               # Logs per batch
    flush_interval=5.0,          # Seconds between auto-flush
    timeout=10,                  # HTTP timeout
    sync_mode=False,             # True = blocking sends
)

# Log methods
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
logger.critical("Critical message")
logger.security("Security event")

# With metadata
logger.info("User action", user_id=123, action="login", ip="10.0.0.1")

# Context for tracing
logger.set_context(trace_id="abc123", request_id="req-456")
logger.info("Request processed")  # Includes trace context
logger.clear_context()

# Request analysis from backend
result = logger.analyze(use_rag=True)
print(result["severity"], result["threats"])

# Cleanup
logger.shutdown()
```

### Async Client

```python
from logcentry_client import AsyncLogCentry  # Requires httpx

async with AsyncLogCentry(api_key="lc_xxx") as logger:
    await logger.info("Async log")
    await logger.security("Async security event")
```

### Decorator

```python
from logcentry_client import log_errors

@log_errors()
def risky_function():
    # Exceptions are automatically logged
    raise ValueError("Something failed")
```

## Environment Variables

```bash
export LOGCENTRY_API_KEY=lc_your_api_key
```

Then:
```python
logger = LogCentry()  # Uses env var
```

## License

MIT
