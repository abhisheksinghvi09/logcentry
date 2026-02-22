"""
LogCentry API - Cache Service

Provides application-level caching using Redis.
Supports JSON serialization and robust error handling.
"""

import json
import os
from typing import Any, Optional
import redis
from datetime import datetime, date

from logcentry.utils import get_logger

logger = get_logger(__name__)

class RedisCacheService:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisCacheService, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        
        try:
            self.redis = redis.from_url(redis_url, decode_responses=True)
            # Test connection
            self.redis.ping()
            self.enabled = True
            logger.info("redis_connected", url=redis_url)
        except redis.ConnectionError:
            logger.warning("redis_connection_failed", url=redis_url)
            self.redis = None
            self.enabled = False
        except Exception as e:
            logger.error("redis_init_error", error=str(e))
            self.redis = None
            self.enabled = False

    def _serialize(self, value: Any) -> str:
        """Serialize value to JSON string."""
        if value is None:
            return None
        
        def json_serial(obj):
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            if hasattr(obj, "to_dict"):
                return obj.to_dict()
            raise TypeError(f"Type {type(obj)} not serializable")
            
        return json.dumps(value, default=json_serial)

    def _deserialize(self, value: str) -> Any:
        """Deserialize JSON string to object."""
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set a value in cache with TTL (seconds)."""
        if not self.enabled:
            return False
        
        try:
            serialized = self._serialize(value)
            return self.redis.setex(key, ttl, serialized)
        except Exception as e:
            logger.error("cache_set_error", key=key, error=str(e))
            return False

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache."""
        if not self.enabled:
            return None
            
        try:
            value = self.redis.get(key)
            return self._deserialize(value)
        except Exception as e:
            logger.error("cache_get_error", key=key, error=str(e))
            return None

    def delete(self, key: str) -> bool:
        """Delete a value from cache."""
        if not self.enabled:
            return False
            
        try:
            return bool(self.redis.delete(key))
        except Exception as e:
            logger.error("cache_delete_error", key=key, error=str(e))
            return False
