"""
LogCentry RAG - Knowledge Base

Manages security knowledge sources (MITRE ATT&CK, CVEs, custom rules, historical analyses).
Handles loading, indexing, and updating of knowledge documents.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from logcentry.config import get_cached_settings
from logcentry.core.models import RAGDocument
from logcentry.rag.embeddings import embed_texts
from logcentry.rag.vectorstore import VectorStore
from logcentry.utils import get_logger

logger = get_logger(__name__)


class KnowledgeBase:
    """
    Security knowledge base manager.
    
    Sources:
    - MITRE ATT&CK techniques
    - CVE descriptions
    - Custom security rules
    - Historical analysis results
    """
    
    def __init__(
        self,
        vector_store: VectorStore | None = None,
        knowledge_path: str | Path | None = None,
    ):
        """
        Initialize the knowledge base.
        
        Args:
            vector_store: Optional pre-configured VectorStore
            knowledge_path: Path to knowledge base files
        """
        settings = get_cached_settings()
        
        self.vector_store = vector_store or VectorStore()
        self.knowledge_path = Path(knowledge_path or settings.knowledge_base_path)
        
        logger.info(
            "knowledge_base_initialized",
            path=str(self.knowledge_path),
            document_count=self.vector_store.count,
        )
    
    def load_mitre_attack(self, filepath: str | Path | None = None) -> int:
        """
        Load MITRE ATT&CK techniques from JSON file.
        
        Expected format: List of objects with 'id', 'name', 'description', 'tactics'
        
        Args:
            filepath: Path to MITRE ATT&CK JSON (default: knowledge_base/mitre_attack/techniques.json)
            
        Returns:
            Number of techniques loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "mitre_attack" / "techniques.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("mitre_file_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            techniques = json.load(f)
        
        documents = []
        for tech in techniques:
            tech_id = tech.get("id", tech.get("external_id", ""))
            name = tech.get("name", "")
            description = tech.get("description", "")
            tactics = tech.get("tactics", [])
            
            if not tech_id or not description:
                continue
            
            content = f"MITRE ATT&CK {tech_id}: {name}\n\nTactics: {', '.join(tactics)}\n\n{description}"
            
            documents.append(RAGDocument(
                id=f"mitre_{tech_id}",
                content=content,
                source="mitre_attack",
                metadata={
                    "technique_id": tech_id,
                    "name": name,
                    "tactics": ", ".join(tactics) if tactics else "",  # ChromaDB requires strings
                },
            ))
        
        # Generate embeddings in batch
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            
            self.vector_store.add_documents(documents)
        
        logger.info("mitre_attack_loaded", count=len(documents))
        return len(documents)
    
    def load_cve_database(self, filepath: str | Path | None = None) -> int:
        """
        Load CVE descriptions from JSON file.
        
        Expected format: List of objects with 'id', 'description', 'cvss', 'references'
        
        Args:
            filepath: Path to CVE JSON file
            
        Returns:
            Number of CVEs loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "cve_database" / "cves.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("cve_file_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            cves = json.load(f)
        
        documents = []
        for cve in cves:
            cve_id = cve.get("id", cve.get("cve_id", ""))
            description = cve.get("description", "")
            cvss = cve.get("cvss", cve.get("cvss_score", "N/A"))
            
            if not cve_id or not description:
                continue
            
            content = f"{cve_id} (CVSS: {cvss})\n\n{description}"
            
            documents.append(RAGDocument(
                id=f"cve_{cve_id}",
                content=content,
                source="cve",
                metadata={
                    "cve_id": cve_id,
                    "cvss": cvss,
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            
            self.vector_store.add_documents(documents)
        
        logger.info("cve_database_loaded", count=len(documents))
        return len(documents)
    
    async def load_cve_from_api(
        self,
        keywords: list[str] | None = None,
        days: int = 30,
        limit_per_keyword: int = 10,
    ) -> int:
        """
        Load CVEs from NVD API.
        
        Fetches recent CVEs and optionally searches by keywords.
        Results are cached for 24 hours.
        
        Args:
            keywords: Optional keywords to search (e.g., ["ssh", "nginx", "apache"])
            days: Number of days back for recent CVEs
            limit_per_keyword: Max results per keyword search
            
        Returns:
            Number of CVEs loaded
        """
        from logcentry.rag.cve_api import CVEApiClient
        
        client = CVEApiClient()
        all_cves = []
        
        # Fetch recent CVEs
        try:
            recent = await client.get_recent_cves(days=days, limit=limit_per_keyword)
            all_cves.extend(recent)
            logger.info("recent_cves_fetched", count=len(recent))
        except Exception as e:
            logger.warning("recent_cves_fetch_failed", error=str(e))
        
        # Search by keywords if provided
        if keywords:
            for keyword in keywords[:5]:  # Limit to 5 keywords
                try:
                    results = await client.search_cves(keyword, limit=limit_per_keyword)
                    all_cves.extend(results)
                    logger.info("keyword_cves_fetched", keyword=keyword, count=len(results))
                except Exception as e:
                    logger.warning("keyword_cve_fetch_failed", keyword=keyword, error=str(e))
        
        # Deduplicate by CVE ID
        seen_ids = set()
        unique_cves = []
        for cve in all_cves:
            cve_id = cve.get("id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique_cves.append(cve)
        
        # Add to vector store
        documents = []
        for cve in unique_cves:
            cve_id = cve.get("id", "")
            description = cve.get("description", "")
            cvss = cve.get("cvss", "N/A")
            affected = cve.get("affected", [])
            weaknesses = cve.get("weaknesses", [])
            
            if not cve_id or not description:
                continue
            
            # Build rich content for embedding
            content_parts = [
                f"{cve_id} (CVSS: {cvss})",
                f"\nDescription: {description}",
            ]
            
            if affected:
                content_parts.append(f"\nAffected: {', '.join(affected[:5])}")
            
            if weaknesses:
                content_parts.append(f"\nWeaknesses: {', '.join(weaknesses)}")
            
            content = "\n".join(content_parts)
            
            documents.append(RAGDocument(
                id=f"cve_api_{cve_id}",
                content=content,
                source="cve_api",
                metadata={
                    "cve_id": cve_id,
                    "cvss": str(cvss) if cvss else "N/A",
                    "source_type": "nvd_api",
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            
            self.vector_store.add_documents(documents)
        
        logger.info("cve_api_loaded", count=len(documents))
        return len(documents)
    
    async def search_cve_realtime(self, keyword: str, limit: int = 5) -> list[str]:
        """
        Search CVEs in real-time for on-demand enrichment.
        
        Use this during analysis to get relevant CVE context.
        
        Args:
            keyword: Search term
            limit: Maximum results
            
        Returns:
            List of formatted CVE context strings
        """
        from logcentry.rag.cve_api import CVEApiClient
        
        client = CVEApiClient()
        
        try:
            results = await client.search_cves(keyword, limit=limit)
            
            contexts = []
            for cve in results:
                cve_id = cve.get("id", "")
                description = cve.get("description", "")
                cvss = cve.get("cvss", "N/A")
                
                context = f"{cve_id} (CVSS: {cvss}): {description[:500]}"
                contexts.append(context)
            
            return contexts
            
        except Exception as e:
            logger.warning("realtime_cve_search_failed", keyword=keyword, error=str(e))
            return []
    
    def load_custom_rules(self, filepath: str | Path | None = None) -> int:
        """
        Load custom security rules from JSON file.
        
        Expected format: List of objects with 'id', 'name', 'description', 'severity', 'patterns'
        
        Returns:
            Number of rules loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "custom_rules" / "rules.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("custom_rules_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        
        documents = []
        for rule in rules:
            rule_id = rule.get("id", "")
            name = rule.get("name", "")
            description = rule.get("description", "")
            severity = rule.get("severity", "medium")
            
            if not rule_id or not description:
                continue
            
            content = f"Security Rule: {name}\nSeverity: {severity}\n\n{description}"
            
            documents.append(RAGDocument(
                id=f"rule_{rule_id}",
                content=content,
                source="custom_rule",
                metadata={
                    "rule_id": rule_id,
                    "name": name,
                    "severity": severity,
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            
            self.vector_store.add_documents(documents)
        
        logger.info("custom_rules_loaded", count=len(documents))
        return len(documents)
    
    def add_historical_analysis(
        self,
        analysis_result: dict[str, Any],
    ) -> None:
        """
        Add a historical analysis result to the knowledge base.
        
        This allows the system to learn from past analyses.
        
        Args:
            analysis_result: Analysis result dictionary
        """
        # Create a summary for embedding
        analysis = analysis_result.get("analysis", {})
        
        content = (
            f"Historical Security Analysis\n"
            f"Severity: {analysis.get('severity_score', 'N/A')}/10\n"
            f"Assessment: {analysis.get('threat_assessment', 'N/A')}\n"
            f"Explanation: {analysis.get('detailed_explanation', 'N/A')}"
        )
        
        # Generate unique ID based on content hash
        doc_id = f"hist_{hashlib.md5(content.encode()).hexdigest()[:12]}"
        
        from logcentry.rag.embeddings import embed_text
        embedding = embed_text(content)
        
        doc = RAGDocument(
            id=doc_id,
            content=content,
            source="historical",
            metadata={
                "timestamp": analysis_result.get("timestamp", ""),
                "severity_score": analysis.get("severity_score"),
            },
            embedding=embedding,
        )
        
        self.vector_store.add_documents([doc])
        logger.debug("historical_analysis_added", doc_id=doc_id)
    
    def load_owasp(self, filepath: str | Path | None = None) -> int:
        """
        Load OWASP Top 10 vulnerabilities from JSON.
        
        Returns:
            Number of OWASP entries loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "owasp" / "owasp_top10.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("owasp_file_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            owasp_items = json.load(f)
        
        documents = []
        for item in owasp_items:
            owasp_id = item.get("id", "")
            name = item.get("name", "")
            description = item.get("description", "")
            keywords = item.get("keywords", [])
            log_indicators = item.get("log_indicators", [])
            
            if not owasp_id or not description:
                continue
            
            content = (
                f"OWASP {owasp_id}: {name}\n\n"
                f"Description: {description}\n\n"
                f"Log Indicators: {', '.join(log_indicators)}\n"
                f"Keywords: {', '.join(keywords)}"
            )
            
            documents.append(RAGDocument(
                id=f"owasp_{owasp_id}",
                content=content,
                source="owasp",
                metadata={
                    "owasp_id": owasp_id,
                    "name": name,
                    "severity": item.get("severity", "high"),
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            self.vector_store.add_documents(documents)
        
        logger.info("owasp_loaded", count=len(documents))
        return len(documents)
    
    def load_sigma_rules(self, filepath: str | Path | None = None) -> int:
        """
        Load Sigma detection rules from JSON.
        
        Returns:
            Number of Sigma rules loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "sigma_rules" / "rules.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("sigma_rules_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        
        documents = []
        for rule in rules:
            rule_id = rule.get("id", "")
            title = rule.get("title", "")
            description = rule.get("description", "")
            patterns = rule.get("patterns", [])
            
            if not rule_id or not description:
                continue
            
            content = (
                f"Sigma Rule: {title}\n\n"
                f"Description: {description}\n\n"
                f"Detection Patterns: {', '.join(patterns[:10])}\n"
                f"Severity: {rule.get('severity', 'medium')}\n"
                f"False Positive Risk: {rule.get('false_positive_risk', 'unknown')}"
            )
            
            documents.append(RAGDocument(
                id=f"sigma_{rule_id}",
                content=content,
                source="sigma",
                metadata={
                    "rule_id": rule_id,
                    "title": title,
                    "severity": rule.get("severity", "medium"),
                    "log_source": rule.get("log_source", "any"),
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            self.vector_store.add_documents(documents)
        
        logger.info("sigma_rules_loaded", count=len(documents))
        return len(documents)
    
    def load_threat_intel(self, filepath: str | Path | None = None) -> int:
        """
        Load threat intelligence (IOCs) from JSON.
        
        Returns:
            Number of threat intel entries loaded
        """
        if filepath is None:
            filepath = self.knowledge_path / "threat_intel" / "iocs.json"
        
        path = Path(filepath)
        if not path.exists():
            logger.warning("threat_intel_not_found", path=str(path))
            return 0
        
        with open(path, "r", encoding="utf-8") as f:
            intel_items = json.load(f)
        
        documents = []
        for item in intel_items:
            intel_id = item.get("id", "")
            intel_type = item.get("type", "")
            category = item.get("category", "")
            description = item.get("description", "")
            indicators = item.get("indicators", [])
            
            if not intel_id or not description:
                continue
            
            # Build indicator list
            indicator_texts = []
            for ind in indicators[:10]:  # Limit to 10
                if "value" in ind:
                    indicator_texts.append(f"{ind.get('value')} ({ind.get('threat', 'unknown')})")
                elif "pattern" in ind:
                    indicator_texts.append(f"Pattern: {ind.get('pattern')} ({ind.get('threat', 'unknown')})")
            
            content = (
                f"Threat Intelligence: {category.upper()}\n"
                f"Type: {intel_type}\n\n"
                f"Description: {description}\n\n"
                f"Indicators:\n" + "\n".join(f"  - {i}" for i in indicator_texts)
            )
            
            documents.append(RAGDocument(
                id=f"intel_{intel_id}",
                content=content,
                source="threat_intel",
                metadata={
                    "intel_id": intel_id,
                    "type": intel_type,
                    "category": category,
                    "severity": item.get("severity", "high"),
                },
            ))
        
        if documents:
            contents = [doc.content for doc in documents]
            embeddings = embed_texts(contents)
            for doc, embedding in zip(documents, embeddings):
                doc.embedding = embedding
            self.vector_store.add_documents(documents)
        
        logger.info("threat_intel_loaded", count=len(documents))
        return len(documents)
    
    def load_all(self) -> dict[str, int]:
        """
        Load all available knowledge sources.
        
        Returns:
            Dictionary with counts for each source
        """
        counts = {
            "mitre_attack": self.load_mitre_attack(),
            "cve": self.load_cve_database(),
            "custom_rules": self.load_custom_rules(),
            "owasp": self.load_owasp(),
            "sigma_rules": self.load_sigma_rules(),
            "threat_intel": self.load_threat_intel(),
        }
        
        total = sum(counts.values())
        logger.info("knowledge_base_loaded", total=total, **counts)
        return counts
    
    @property
    def document_count(self) -> int:
        """Get total document count."""
        return self.vector_store.count
