"""
LogCentry SDK Tests - Plugin Tests

Unit tests for plugin architecture, parsers, and retrievers.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock


class TestPluginRegistry:
    """Tests for PluginRegistry."""
    
    def test_register_plugin(self, plugin_registry, sample_parser):
        """Test plugin registration."""
        plugin_registry.register_plugin(sample_parser)
        
        assert sample_parser.name in [p["name"] for p in plugin_registry.list_plugins()]
    
    def test_unregister_plugin(self, plugin_registry, sample_parser):
        """Test plugin unregistration."""
        plugin_registry.register_plugin(sample_parser)
        result = plugin_registry.unregister_plugin(sample_parser.name)
        
        assert result is True
        assert sample_parser.name not in [p["name"] for p in plugin_registry.list_plugins()]
    
    def test_duplicate_registration_fails(self, plugin_registry, sample_parser):
        """Test duplicate registration raises error."""
        plugin_registry.register_plugin(sample_parser)
        
        with pytest.raises(ValueError):
            plugin_registry.register_plugin(sample_parser)
    
    def test_get_plugin(self, plugin_registry, sample_parser):
        """Test getting plugin by name."""
        plugin_registry.register_plugin(sample_parser)
        
        retrieved = plugin_registry.get_plugin(sample_parser.name)
        assert retrieved is sample_parser
    
    def test_get_parser(self, plugin_registry, sample_parser):
        """Test getting parser by name."""
        plugin_registry.register_plugin(sample_parser)
        
        parser = plugin_registry.get_parser(sample_parser.name)
        assert parser is sample_parser


class TestEventHooks:
    """Tests for event hook system."""
    
    def test_add_hook(self, plugin_registry):
        """Test adding event hook."""
        from logcentry.sdk.plugins import EventType
        
        called = []
        
        def handler(ctx):
            called.append(ctx.data)
        
        plugin_registry.add_hook(EventType.ON_LOG_INGEST, handler)
        plugin_registry.emit_sync(EventType.ON_LOG_INGEST, "test_data")
        
        assert "test_data" in called
    
    def test_remove_hook(self, plugin_registry):
        """Test removing event hook."""
        from logcentry.sdk.plugins import EventType
        
        def handler(ctx):
            pass
        
        plugin_registry.add_hook(EventType.ON_LOG_INGEST, handler)
        result = plugin_registry.remove_hook(EventType.ON_LOG_INGEST, handler)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_async_emit(self, plugin_registry):
        """Test async event emission."""
        from logcentry.sdk.plugins import EventType
        
        results = []
        
        async def async_handler(ctx):
            results.append(ctx.data)
            return "async_result"
        
        plugin_registry.add_hook(EventType.ON_RAG_QUERY, async_handler)
        emit_results = await plugin_registry.emit(EventType.ON_RAG_QUERY, "query_data")
        
        assert "query_data" in results
        assert "async_result" in emit_results


class TestBuiltinParsers:
    """Tests for built-in log parsers."""
    
    def test_json_parser(self):
        """Test JSON parser."""
        from logcentry.sdk.plugins.parsers import JSONParser
        
        parser = JSONParser()
        log = '{"level": "error", "message": "Database failed", "code": 500}'
        
        assert parser.can_parse(log)
        
        result = parser.parse(log)
        assert result["message"] == "Database failed"
        assert result["level"] == "error"
        assert result["metadata"]["code"] == 500
    
    def test_json_parser_invalid(self):
        """Test JSON parser with invalid input."""
        from logcentry.sdk.plugins.parsers import JSONParser
        
        parser = JSONParser()
        log = "not json at all"
        
        assert not parser.can_parse(log)
        
        result = parser.parse(log)
        assert result["message"] == log
    
    def test_syslog_parser(self):
        """Test syslog parser."""
        from logcentry.sdk.plugins.parsers import SyslogParser
        
        parser = SyslogParser()
        log = '<34>1 2026-02-07T10:00:00Z server1 sshd 1234 - - Failed password for root'
        
        assert parser.can_parse(log)
        
        result = parser.parse(log)
        assert "Failed password" in result["message"]
        assert result["metadata"]["hostname"] == "server1"
    
    def test_apache_parser(self, sample_nginx_logs):
        """Test Apache/NGINX parser."""
        from logcentry.sdk.plugins.parsers import NginxParser
        
        parser = NginxParser()
        log = sample_nginx_logs[0]
        
        if parser.can_parse(log):
            result = parser.parse(log)
            assert result["metadata"]["method"] == "GET"
            assert result["metadata"]["status"] == 200
    
    def test_generic_parser(self):
        """Test generic fallback parser."""
        from logcentry.sdk.plugins.parsers import GenericParser
        
        parser = GenericParser()
        log = "2026-02-07T10:00:00 ERROR Something went wrong from 192.168.1.1"
        
        assert parser.can_parse(log)  # Always true
        
        result = parser.parse(log)
        assert result["level"] == "error"
        assert "192.168.1.1" in result["metadata"].get("ips", [])


class TestMalformedLogs:
    """Tests for handling malformed/corrupted logs."""
    
    def test_empty_log(self, malformed_logs):
        """Test handling empty log."""
        from logcentry.sdk.plugins.parsers import GenericParser
        
        parser = GenericParser()
        result = parser.parse(malformed_logs[0])  # Empty string
        
        assert result["message"] == ""
    
    def test_broken_json(self, malformed_logs):
        """Test handling broken JSON."""
        from logcentry.sdk.plugins.parsers import JSONParser
        
        parser = JSONParser()
        result = parser.parse(malformed_logs[2])  # "{invalid json"
        
        # Should not raise, return raw as message
        assert result["raw"] == malformed_logs[2]
    
    def test_very_long_log(self, malformed_logs):
        """Test handling very long log line."""
        from logcentry.sdk.plugins.parsers import GenericParser
        
        parser = GenericParser()
        result = parser.parse(malformed_logs[5])  # "A" * 100000
        
        assert len(result["message"]) == 100000


class TestRetrievers:
    """Tests for RAG retrievers."""
    
    @pytest.mark.asyncio
    async def test_local_retriever(self):
        """Test local/offline retriever."""
        from logcentry.sdk.plugins.retrievers import LocalRetriever
        
        retriever = LocalRetriever()
        retriever.load_documents([
            {"content": "SQL injection attack pattern", "source": "rules"},
            {"content": "XSS cross-site scripting attack", "source": "rules"},
            {"content": "Normal user login activity", "source": "baseline"},
        ])
        
        results = await retriever.retrieve("injection attack", top_k=2)
        
        assert len(results) <= 2
        assert results[0]["score"] > 0
    
    @pytest.mark.asyncio
    async def test_explainable_retriever(self, mock_vector_store):
        """Test explainable retriever wrapper."""
        from logcentry.sdk.plugins.retrievers import LocalRetriever, ExplainableRetriever
        
        base = LocalRetriever()
        base.load_documents([
            {"content": "Test security content", "source": "test"},
        ])
        
        explainable = ExplainableRetriever(base, include_chunks=True, include_scores=True)
        results = await explainable.retrieve("security", top_k=1)
        
        if results:
            assert "explanation" in results[0]
            assert "relevance_score" in results[0]["explanation"]
            assert "score_explanation" in results[0]["explanation"]


class TestParserRegistration:
    """Tests for parser registration decorators."""
    
    def test_register_parser_decorator(self, plugin_registry):
        """Test @register_parser decorator."""
        from logcentry.sdk.plugins import BaseParser, register_parser
        
        @register_parser(plugin_registry)
        class CustomParser(BaseParser):
            @property
            def name(self) -> str:
                return "custom_parser"
            
            @property
            def supported_formats(self) -> list[str]:
                return ["custom"]
            
            def parse(self, raw_log: str) -> dict:
                return {"message": raw_log, "parsed": True}
        
        assert plugin_registry.get_parser("custom_parser") is not None
    
    def test_find_parser_for_log(self, plugin_registry):
        """Test finding appropriate parser for log."""
        from logcentry.sdk.plugins.parsers import JSONParser, SyslogParser
        
        plugin_registry.register_plugin(JSONParser())
        plugin_registry.register_plugin(SyslogParser())
        
        # JSON log should find JSON parser
        json_log = '{"message": "test"}'
        parser = plugin_registry.find_parser_for(json_log)
        assert parser is not None
        assert parser.name == "json_parser"
        
        # Syslog should find syslog parser
        syslog = '<34>1 2026-02-07T10:00:00Z host app - - test'
        parser = plugin_registry.find_parser_for(syslog)
        assert parser is not None
        assert parser.name == "syslog_parser"
