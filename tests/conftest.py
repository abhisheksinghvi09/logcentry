"""
LogCentry SDK Tests - Shared Fixtures

Pytest fixtures for unit and integration testing.
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# Ensure local src-layout package is importable when running `pytest` directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


# ==================== Event Loop ====================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ==================== SDK Fixtures ====================

@pytest.fixture
def api_key() -> str:
    """Test API key."""
    return "lc_test_api_key_12345678"


@pytest.fixture
def endpoint() -> str:
    """Test API endpoint."""
    return "http://localhost:8000"


@pytest.fixture
def sync_client(api_key: str, endpoint: str):
    """Create sync LogCentry client for testing."""
    from logcentry.sdk import LogCentry
    
    client = LogCentry(
        api_key=api_key,
        endpoint=endpoint,
        sync_mode=True,  # Sync for predictable testing
    )
    yield client
    client.shutdown()


@pytest.fixture
async def async_client(api_key: str, endpoint: str):
    """Create async LogCentry client for testing."""
    from logcentry.sdk import AsyncLogCentry
    
    async with AsyncLogCentry(
        api_key=api_key,
        endpoint=endpoint,
        flush_interval=0.1,
    ) as client:
        yield client


# ==================== Mock Fixtures ====================

@pytest.fixture
def mock_httpx_client():
    """Mock httpx client for network isolation."""
    with patch("httpx.AsyncClient") as mock:
        mock_instance = AsyncMock()
        mock_instance.post = AsyncMock(return_value=MagicMock(
            status_code=200,
            json=lambda: {"status": "ok"},
        ))
        mock_instance.get = AsyncMock(return_value=MagicMock(
            status_code=200,
            json=lambda: {"results": []},
        ))
        mock_instance.aclose = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=None)
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_vector_store():
    """Mock vector store for RAG tests."""
    with patch("logcentry.rag.vectorstore.VectorStore") as mock:
        mock_instance = MagicMock()
        mock_instance.search_by_text.return_value = [
            {
                "content": "MITRE ATT&CK T1059: Command and Scripting Interpreter",
                "metadata": {"source": "mitre_attack"},
                "distance": 0.2,
            },
            {
                "content": "CVE-2024-1234: Remote code execution vulnerability",
                "metadata": {"source": "cve"},
                "distance": 0.3,
            },
        ]
        mock_instance.count = 100
        mock.return_value = mock_instance
        yield mock_instance


# ==================== Test Data Fixtures ====================

@pytest.fixture
def sample_log_entry() -> dict:
    """Sample log entry for testing."""
    return {
        "message": "Failed login attempt from 192.168.1.100",
        "level": "warning",
        "timestamp": datetime.now().isoformat(),
        "source": "auth-service",
        "metadata": {
            "ip": "192.168.1.100",
            "user": "admin",
            "attempt": 3,
        },
    }


@pytest.fixture
def sample_log_batch(sample_log_entry: dict) -> list[dict]:
    """Sample batch of log entries."""
    entries = []
    for i in range(10):
        entry = sample_log_entry.copy()
        entry["message"] = f"Event {i}: {entry['message']}"
        entry["metadata"] = {**entry["metadata"], "index": i}
        entries.append(entry)
    return entries


@pytest.fixture
def sample_nginx_logs() -> list[str]:
    """Sample NGINX access logs."""
    return [
        '192.168.1.1 - - [07/Feb/2026:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '192.168.1.2 - - [07/Feb/2026:10:00:01 +0000] "POST /api/login HTTP/1.1" 401 56 "-" "curl/7.68.0"',
        '192.168.1.3 - - [07/Feb/2026:10:00:02 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 400 0 "-" "wget"',
        '192.168.1.1 - - [07/Feb/2026:10:00:03 +0000] "GET /api/data?id=1 OR 1=1 HTTP/1.1" 500 0 "-" "python-requests"',
    ]


@pytest.fixture
def sample_syslog_entries() -> list[str]:
    """Sample syslog entries."""
    return [
        '<34>1 2026-02-07T10:00:00Z server1 sshd 1234 - - Failed password for root from 10.0.0.1',
        '<38>1 2026-02-07T10:00:01Z server1 sshd 1234 - - Accepted publickey for admin from 10.0.0.2',
        '<29>1 2026-02-07T10:00:02Z firewall iptables 5678 - - Dropped packet from 192.168.1.100',
    ]


@pytest.fixture
def sample_json_logs() -> list[str]:
    """Sample JSON formatted logs."""
    logs = [
        {"level": "info", "message": "Application started", "timestamp": "2026-02-07T10:00:00Z"},
        {"level": "error", "message": "Database connection failed", "error": "timeout", "timestamp": "2026-02-07T10:00:01Z"},
        {"level": "warning", "message": "High memory usage", "value": "95%", "timestamp": "2026-02-07T10:00:02Z"},
    ]
    return [json.dumps(log) for log in logs]


@pytest.fixture
def malformed_logs() -> list[str]:
    """Malformed/corrupted log samples for edge case testing."""
    return [
        "",  # Empty
        "   ",  # Whitespace only
        "{invalid json",  # Broken JSON
        "Random text without structure",  # Unstructured
        "\x00\x01\x02",  # Binary data
        "A" * 100000,  # Very long line
    ]


# ==================== Analysis Fixtures ====================

@pytest.fixture
def sample_analysis_result() -> dict:
    """Sample analysis result."""
    return {
        "severity_score": 7,
        "severity_level": "high",
        "threat_assessment": "Possible SQL injection and path traversal attacks detected",
        "detailed_explanation": "Multiple suspicious patterns found in the logs...",
        "vulnerability_categories": ["injection", "exposure"],
        "countermeasures": [
            "Block source IP 192.168.1.3",
            "Review input validation",
            "Enable WAF rules",
        ],
    }


# ==================== Plugin Fixtures ====================

@pytest.fixture
def plugin_registry():
    """Fresh plugin registry for testing."""
    from logcentry.sdk.plugins import PluginRegistry
    return PluginRegistry()


@pytest.fixture
def sample_parser():
    """Sample custom parser for testing."""
    from logcentry.sdk.plugins import BaseParser
    
    class TestParser(BaseParser):
        @property
        def name(self) -> str:
            return "test_parser"
        
        @property
        def supported_formats(self) -> list[str]:
            return ["test"]
        
        def parse(self, raw_log: str) -> dict:
            return {"message": raw_log, "level": "info", "parsed_by": "test"}
    
    return TestParser()


# ==================== Utility Fixtures ====================

@pytest.fixture
def temp_knowledge_dir(tmp_path):
    """Temporary directory with sample knowledge files."""
    kb_dir = tmp_path / "knowledge_base"
    kb_dir.mkdir()
    
    # Create sample MITRE file
    mitre_dir = kb_dir / "mitre_attack"
    mitre_dir.mkdir()
    mitre_file = mitre_dir / "techniques.json"
    mitre_file.write_text(json.dumps([
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters",
            "tactics": ["execution"],
        },
    ]))
    
    # Create sample OWASP file
    owasp_dir = kb_dir / "owasp"
    owasp_dir.mkdir()
    owasp_file = owasp_dir / "owasp_top10.json"
    owasp_file.write_text(json.dumps([
        {
            "id": "A01:2021",
            "name": "Broken Access Control",
            "description": "Access control enforces policy...",
            "keywords": ["access", "control", "authorization"],
        },
    ]))
    
    return kb_dir
