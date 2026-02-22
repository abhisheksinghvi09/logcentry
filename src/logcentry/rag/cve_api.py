"""
LogCentry RAG - CVE Database API Client

Fetches vulnerability data from NVD (National Vulnerability Database) API.
Provides real-time CVE lookups for enhanced RAG context.
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from logcentry.config import get_cached_settings
from logcentry.utils import get_logger

logger = get_logger(__name__)

# NVD API endpoints
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Cache settings
CACHE_TTL_HOURS = 24
MAX_CACHE_SIZE = 500  # Maximum number of cached queries


class CVECache:
    """Simple file-based cache for CVE API responses."""
    
    def __init__(self, cache_dir: Path | None = None):
        """Initialize cache."""
        settings = get_cached_settings()
        self.cache_dir = cache_dir or Path(settings.data_dir) / "cve_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.cache_dir / "index.json"
        self._load_index()
    
    def _load_index(self) -> None:
        """Load cache index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file, "r") as f:
                    self.index = json.load(f)
            except Exception:
                self.index = {}
        else:
            self.index = {}
    
    def _save_index(self) -> None:
        """Save cache index to disk."""
        with open(self.index_file, "w") as f:
            json.dump(self.index, f)
    
    def _get_cache_key(self, query: str) -> str:
        """Generate cache key from query."""
        return hashlib.md5(query.encode()).hexdigest()[:16]
    
    def get(self, query: str) -> list[dict] | None:
        """Get cached results for a query."""
        key = self._get_cache_key(query)
        
        if key not in self.index:
            return None
        
        entry = self.index[key]
        cached_at = datetime.fromisoformat(entry["cached_at"])
        
        # Check if cache is expired
        if datetime.now() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
            self._remove_entry(key)
            return None
        
        # Load cached data
        cache_file = self.cache_dir / f"{key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    return json.load(f)
            except Exception:
                self._remove_entry(key)
                return None
        
        return None
    
    def set(self, query: str, results: list[dict]) -> None:
        """Cache query results."""
        key = self._get_cache_key(query)
        
        # Enforce max cache size
        if len(self.index) >= MAX_CACHE_SIZE:
            self._cleanup_old_entries()
        
        # Save data
        cache_file = self.cache_dir / f"{key}.json"
        with open(cache_file, "w") as f:
            json.dump(results, f)
        
        # Update index
        self.index[key] = {
            "query": query,
            "cached_at": datetime.now().isoformat(),
            "count": len(results),
        }
        self._save_index()
    
    def _remove_entry(self, key: str) -> None:
        """Remove a cache entry."""
        if key in self.index:
            del self.index[key]
            cache_file = self.cache_dir / f"{key}.json"
            if cache_file.exists():
                cache_file.unlink()
            self._save_index()
    
    def _cleanup_old_entries(self) -> None:
        """Remove oldest entries to make room."""
        # Sort by cached_at and remove oldest 10%
        sorted_keys = sorted(
            self.index.keys(),
            key=lambda k: self.index[k]["cached_at"]
        )
        to_remove = sorted_keys[:max(1, len(sorted_keys) // 10)]
        for key in to_remove:
            self._remove_entry(key)


class CVEApiClient:
    """
    Client for fetching CVE data from NVD API.
    
    Features:
    - Search CVEs by keyword
    - Get specific CVE by ID
    - Fetch recent CVEs
    - Automatic caching with 24-hour TTL
    - Rate limiting protection
    """
    
    def __init__(self, api_key: str | None = None):
        """
        Initialize the CVE API client.
        
        Args:
            api_key: Optional NVD API key for higher rate limits (50/min vs 6/min)
        """
        self.api_key = api_key
        self.cache = CVECache()
        self.last_request_time = 0.0
        
        # Rate limit: 6 requests/min without key, 50/min with key
        self.min_request_interval = 10.0 if not api_key else 1.2
        
        logger.info(
            "cve_api_client_initialized",
            has_api_key=bool(api_key),
            rate_limit=f"{60 / self.min_request_interval:.0f}/min",
        )
    
    async def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    async def _make_request(self, params: dict[str, Any]) -> dict:
        """Make a rate-limited request to the NVD API."""
        await self._rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(
                    NVD_API_BASE,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as e:
                logger.error(
                    "nvd_api_error",
                    status_code=e.response.status_code,
                    detail=str(e),
                )
                raise
            except httpx.RequestError as e:
                logger.error("nvd_api_request_error", error=str(e))
                raise
    
    def _parse_cve_item(self, item: dict) -> dict:
        """Parse a CVE item from NVD API response."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Get description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")
        
        # Get CVSS score (prefer v3.1, then v3.0, then v2)
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_version = None
        
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_version = version.replace("cvssMetric", "CVSS ")
                break
        
        # Get affected products (CPE)
        configurations = cve.get("configurations", [])
        affected = []
        for config in configurations[:3]:  # Limit to first 3
            nodes = config.get("nodes", [])
            for node in nodes[:3]:
                for cpe_match in node.get("cpeMatch", [])[:3]:
                    if cpe_match.get("vulnerable"):
                        criteria = cpe_match.get("criteria", "")
                        # Extract product name from CPE
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            affected.append(f"{parts[3]} {parts[4]} {parts[5]}".strip())
        
        # Get references
        references = [
            ref.get("url", "")
            for ref in cve.get("references", [])[:5]
            if ref.get("url")
        ]
        
        # Get weaknesses (CWE)
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    weaknesses.append(desc["value"])
        
        return {
            "id": cve_id,
            "description": description,
            "cvss": cvss_score,
            "cvss_version": cvss_version,
            "affected": affected[:5],
            "references": references,
            "weaknesses": weaknesses,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        }
    
    async def search_cves(
        self,
        keyword: str,
        limit: int = 10,
        use_cache: bool = True,
    ) -> list[dict]:
        """
        Search for CVEs by keyword.
        
        Args:
            keyword: Search term (e.g., "log4j", "ssh", "buffer overflow")
            limit: Maximum number of results
            use_cache: Whether to use cached results
            
        Returns:
            List of CVE dictionaries
        """
        cache_key = f"search:{keyword}:{limit}"
        
        # Check cache first
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("cve_cache_hit", query=keyword)
                return cached
        
        try:
            response = await self._make_request({
                "keywordSearch": keyword,
                "resultsPerPage": min(limit, 100),
            })
            
            results = []
            for item in response.get("vulnerabilities", []):
                results.append(self._parse_cve_item(item))
            
            # Cache the results
            if use_cache:
                self.cache.set(cache_key, results)
            
            logger.info(
                "cve_search_complete",
                keyword=keyword,
                results_count=len(results),
            )
            
            return results
            
        except Exception as e:
            logger.warning("cve_search_failed", keyword=keyword, error=str(e))
            return []
    
    async def get_cve_by_id(self, cve_id: str, use_cache: bool = True) -> dict | None:
        """
        Get a specific CVE by its ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-6387")
            use_cache: Whether to use cached results
            
        Returns:
            CVE dictionary or None if not found
        """
        cache_key = f"id:{cve_id}"
        
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("cve_cache_hit", cve_id=cve_id)
                return cached[0] if cached else None
        
        try:
            response = await self._make_request({"cveId": cve_id})
            
            vulnerabilities = response.get("vulnerabilities", [])
            if vulnerabilities:
                result = self._parse_cve_item(vulnerabilities[0])
                if use_cache:
                    self.cache.set(cache_key, [result])
                return result
            
            return None
            
        except Exception as e:
            logger.warning("cve_lookup_failed", cve_id=cve_id, error=str(e))
            return None
    
    async def get_recent_cves(
        self,
        days: int = 30,
        limit: int = 50,
        use_cache: bool = True,
    ) -> list[dict]:
        """
        Get recently published CVEs.
        
        Args:
            days: Number of days to look back
            limit: Maximum number of results
            use_cache: Whether to use cached results
            
        Returns:
            List of recent CVE dictionaries
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        cache_key = f"recent:{days}:{limit}"
        
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug("cve_cache_hit", query="recent")
                return cached
        
        try:
            response = await self._make_request({
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": min(limit, 100),
            })
            
            results = []
            for item in response.get("vulnerabilities", []):
                results.append(self._parse_cve_item(item))
            
            if use_cache:
                self.cache.set(cache_key, results)
            
            logger.info(
                "recent_cves_fetched",
                days=days,
                results_count=len(results),
            )
            
            return results
            
        except Exception as e:
            logger.warning("recent_cves_failed", days=days, error=str(e))
            return []
    
    async def enrich_cve_ids(self, cve_ids: list[str]) -> list[dict]:
        """
        Fetch full details for a list of CVE IDs.
        
        Useful for enriching CVE IDs found in log analysis.
        
        Args:
            cve_ids: List of CVE identifiers
            
        Returns:
            List of CVE dictionaries with full details
        """
        results = []
        
        for cve_id in cve_ids[:10]:  # Limit to 10 to respect rate limits
            cve_data = await self.get_cve_by_id(cve_id)
            if cve_data:
                results.append(cve_data)
        
        return results


# Convenience function for synchronous code
def search_cves_sync(keyword: str, limit: int = 10) -> list[dict]:
    """Synchronous wrapper for CVE search."""
    client = CVEApiClient()
    return asyncio.run(client.search_cves(keyword, limit))


def get_cve_sync(cve_id: str) -> dict | None:
    """Synchronous wrapper for CVE lookup."""
    client = CVEApiClient()
    return asyncio.run(client.get_cve_by_id(cve_id))
