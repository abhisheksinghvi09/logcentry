# LogCentry AI v2.0

**AI-Powered SIEM Framework with RAG-Enhanced Threat Intelligence**

LogCentry AI is a comprehensive security log analysis platform that uses Large Language Models (Google Gemini) combined with Retrieval-Augmented Generation (RAG) to provide context-aware threat assessments and real-time log monitoring.

---

## ✨ Features

📘 Detailed ML/RAG documentation: see [ML_MODEL_USAGE.md](ML_MODEL_USAGE.md).

### Core Capabilities
- 🔍 **Multi-Source Log Ingestion**: Static files (.log, .txt, .jsonl), PCAP network captures, live journalctl streaming
- 🤖 **LLM-Powered Analysis**: Gemini 2.0 Flash for intelligent threat detection and severity scoring
- 📚 **RAG Pipeline**: ChromaDB vector store with MITRE ATT&CK, CVE, and custom rule knowledge
- 📊 **Professional Reports**: HTML and JSON output with detailed threat assessments
- 🖥️ **Live Dashboard**: Real-time web visualization with WebSocket support
- 🔒 **Enterprise Security**: JWT authentication, API key management, MFA support, audit logging

### SDK & Integration
- 🐍 **Python SDK**: Sync and async clients with automatic batching
- ⚡ **Circuit Breaker**: Resilient API calls with automatic retry and fallback
- 🎯 **Decorators**: `@log_capture`, `@trace_operation`, `@rag_query` for seamless integration
- 📦 **Zero-Config**: Facade pattern with global agent singleton

### API Features
- 🔐 **Authentication**: JWT tokens, API keys, refresh tokens, Zero-Knowledge auth
- 📈 **Real-time Streaming**: WebSocket endpoint for live log updates
- 🧠 **AI Analysis**: On-demand threat analysis with MITRE ATT&CK mapping
- 💾 **Redis Caching**: High-performance API key validation

---

## 🏗️ Architecture

```
LogCentry/
├── src/logcentry/
│   ├── api/                # FastAPI REST Server
│   │   ├── routes/         # Auth, Projects endpoints
│   │   ├── services/       # Cache, Audit, Logs services
│   │   ├── server.py       # Main application factory
│   │   ├── auth.py         # JWT & API key authentication
│   │   └── users.py        # User management & MFA
│   ├── sdk/                # Python Client SDK
│   │   ├── client.py       # Sync client with circuit breaker
│   │   ├── async_client.py # Async client
│   │   ├── decorators.py   # @log_capture, @trace_operation
│   │   └── circuit_breaker.py
│   ├── core/               # Log parsing & analysis
│   │   ├── analyzer.py     # ThreatAnalyzer with Gemini
│   │   ├── parser.py       # Multi-format log parser
│   │   └── models.py       # Pydantic data models
│   ├── ingestion/          # Log source handlers
│   │   ├── static.py       # File-based ingestion
│   │   ├── journald.py     # systemd journal
│   │   └── pcap.py         # Network captures
│   ├── rag/                # RAG Pipeline
│   │   ├── embeddings.py   # Gemini embeddings
│   │   ├── vectorstore.py  # ChromaDB integration
│   │   └── retriever.py    # Context retrieval
│   ├── dashboard/          # Web UI templates
│   └── reporting/          # HTML/JSON reports
├── knowledge_base/         # MITRE ATT&CK, CVEs, custom rules
├── demo/                   # Example vulnerable app
└── tests/                  # Unit & integration tests
```

---

## 🚀 Quick Start

### Installation (recommended)

Use a virtual environment and install runtime dependencies. The project provides both a requirements file and an editable install.

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install runtime deps (includes extras used during server startup)
pip install -r requirements.txt

# Install the package in editable/development mode so the `logcentry` module is importable
pip install -e .

# Copy example env and edit
cp .env.example .env
# Edit .env with your API keys and settings
```

### Environment Variables

```bash
# Required
GEMINI_API_KEY=your_gemini_api_key

# Optional
LOGCENTRY_MODEL=gemini-2.0-flash
LOGCENTRY_LOG_LEVEL=INFO
DEV_MODE=true
DATABASE_URL=sqlite:///./logcentry.db
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=your-secret-key
```

---

## 📖 Usage

### CLI Mode

```bash
# Analyze a log file
logcentry /var/log/auth.log

# With RAG-enhanced context
logcentry /var/log/auth.log --rag

# Generate HTML report
logcentry /var/log/auth.log --report html

# Live SIEM monitoring (requires sudo)
sudo logcentry --siem

# Initialize knowledge base
logcentry --init-kb
```

### API Server Mode

```bash
# Start the API server
logcentry --serve --server-port 8000

# Or using uvicorn directly
cd src
uvicorn "logcentry.api.server:create_app" --factory --reload
```

**Server Endpoints:**
- Dashboard: http://localhost:8000/
- API Docs: http://localhost:8000/api/docs
- Health: http://localhost:8000/api/v1/health

### SDK Usage

```python
import logcentry as lc

# Initialize (once at app startup)
lc.init(
    api_key="lc_dev_bypass_key",  # Or your project API key
    base_url="http://localhost:8000",
    sync_mode=True
)

# Send logs
lc.log("User login successful", level="INFO", source="auth")
lc.error("Database connection failed", source="db-service")
lc.warn("High latency detected", metadata={"latency_ms": 450})

# Use decorators
@lc.log_capture()
def process_payment(amount: float):
    print(f"Processing ${amount}")
    return {"status": "success"}

@lc.trace_operation()
def fetch_user_data(user_id: str):
    # Automatic timing and error capture
    return {"id": user_id, "name": "John"}

# Cleanup
lc.shutdown()
```

---

## 🔌 API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/signup` | POST | Register new user |
| `/api/v1/auth/login` | POST | Login (returns JWT) |
| `/api/v1/auth/refresh` | POST | Refresh access token |
| `/api/v1/auth/me` | GET | Get current user info |
| `/api/v1/auth/mfa/setup` | POST | Setup MFA |
| `/api/v1/auth/mfa/verify` | POST | Verify MFA code |

### Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/logs` | POST | Submit single log |
| `/api/v1/logs/batch` | POST | Submit multiple logs |
| `/api/v1/logs` | GET | Retrieve logs |
| `/api/v1/analyze` | POST | Run AI analysis |
| `/ws/logs` | WebSocket | Real-time log stream |

### System

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/demo-key` | GET | Get demo API key |

---

## 🛡️ Security Features

- **JWT Authentication**: Access and refresh tokens with configurable expiry
- **API Key Management**: Project-scoped API keys with Redis caching
- **MFA Support**: TOTP-based two-factor authentication
- **Zero-Knowledge Auth**: Optional ZK-proof based authentication
- **Audit Logging**: All security events are logged
- **Rate Limiting**: Configurable per-endpoint rate limits
- **CORS**: Configurable cross-origin resource sharing

---

## 🧪 Testing

```bash
# Run unit tests
pytest tests/

# With coverage
pytest --cov=src/logcentry tests/

# Run demo vulnerable app (for testing log capture)
python demo/vulnapp.py
```

---

## 📁 Demo Application

A demo vulnerable Flask app is included to test log ingestion. You can start the API server directly or use the provided `start_services.sh` helper which activates the venv (if present), adds `src` to `PYTHONPATH`, and launches both the API and the demo app.

```bash
# Using the CLI entry point (recommended)
python -m logcentry --serve --server-port 8000

# Or using the helper script (makes backgrounding easier)
./start_services.sh

# In another terminal, run the demo app if not already started
python demo/vulnapp.py
```

The demo app will generate various log types (INFO, WARN, ERROR) that are automatically captured and sent to LogCentry.

---

## 🔧 Configuration

See `.env.example` for all configuration options:

```bash
# Core
GEMINI_API_KEY=           # Required: Gemini API key
LOGCENTRY_MODEL=gemini-2.0-flash

# Database
DATABASE_URL=sqlite:///./logcentry.db

# Redis (optional, for caching)
REDIS_URL=redis://localhost:6379/0

# Security
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Development
DEV_MODE=true             # Enable demo user/key
```

---

## 📊 Project Status

| Component | Status | Notes |
|-----------|--------|-------|
| Core Parser | ✅ Complete | Multi-format support |
| LLM Analyzer | ✅ Complete | Gemini 2.0 Flash |
| RAG Pipeline | ✅ Complete | ChromaDB + MITRE ATT&CK |
| REST API | ✅ Complete | FastAPI with auth |
| Python SDK | ✅ Complete | Sync/Async with Circuit Breaker |
| WebSocket | ✅ Complete | Real-time streaming |
| Redis Cache | ✅ Complete | API key validation |
| MFA | ✅ Complete | TOTP support |
| CLI | ✅ Complete | Full feature set |
| Dashboard | ✅ Complete | Server-rendered HTML |

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**Built with ❤️ for Security Professionals**
