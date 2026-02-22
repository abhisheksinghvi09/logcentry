"""
LogCentry Core - Data Models

Pydantic models for type-safe data structures throughout the application.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_score(cls, score: int) -> "Severity":
        """Convert numeric score (0-10) to severity level."""
        if score >= 8:
            return cls.CRITICAL
        elif score >= 6:
            return cls.HIGH
        elif score >= 4:
            return cls.MEDIUM
        elif score >= 2:
            return cls.LOW
        else:
            return cls.INFO


class VulnerabilityCategory(str, Enum):
    """Vulnerability categorization for grouping similar threats."""
    INJECTION = "injection"           # SQL, XSS, Command injection
    AUTH_FAILURE = "auth_failure"     # Authentication/Authorization failures
    EXPOSURE = "exposure"             # Data exposure, misconfiguration
    DOS = "dos"                       # Denial of service
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    RECONNAISSANCE = "reconnaissance"
    BRUTE_FORCE = "brute_force"
    OTHER = "other"
    
    @classmethod
    def from_keywords(cls, text: str) -> "VulnerabilityCategory":
        """Infer category from text keywords."""
        text_lower = text.lower()
        
        if any(kw in text_lower for kw in ["sql", "xss", "injection", "command"]):
            return cls.INJECTION
        elif any(kw in text_lower for kw in ["auth", "login", "password", "credential", "session"]):
            return cls.AUTH_FAILURE
        elif any(kw in text_lower for kw in ["exposure", "leak", "disclosure", "misconfigur"]):
            return cls.EXPOSURE
        elif any(kw in text_lower for kw in ["dos", "denial", "flood", "exhaust"]):
            return cls.DOS
        elif any(kw in text_lower for kw in ["privilege", "escalat", "root", "admin"]):
            return cls.PRIVILEGE_ESCALATION
        elif any(kw in text_lower for kw in ["malware", "virus", "trojan", "ransomware"]):
            return cls.MALWARE
        elif any(kw in text_lower for kw in ["scan", "probe", "recon", "enum"]):
            return cls.RECONNAISSANCE
        elif any(kw in text_lower for kw in ["brute", "force", "attempt", "failed login"]):
            return cls.BRUTE_FORCE
        else:
            return cls.OTHER


class PatchSuggestion(BaseModel):
    """Structured patch/remediation suggestion."""
    category: VulnerabilityCategory = VulnerabilityCategory.OTHER
    title: str = Field(description="Short title for the patch")
    description: str = Field(description="Detailed explanation of what to patch and why")
    priority: str = Field(default="medium", description="high/medium/low priority")
    related_cves: list[str] = Field(default_factory=list, description="Related CVE IDs")
    commands: list[str] = Field(default_factory=list, description="Specific commands to run")
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class LogEntry(BaseModel):
    """Normalized log entry structure."""
    timestamp: datetime
    source: str = Field(description="Source of the log (process name, file, etc.)")
    message: str
    raw: str | None = Field(default=None, description="Original raw log line")
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class LogBatch(BaseModel):
    """Collection of log entries for batch processing."""
    entries: list[LogEntry]
    source_file: str | None = None
    source_type: str = "unknown"  # journald, file, pcap, etc.
    
    @property
    def count(self) -> int:
        return len(self.entries)
    
    def to_text(self) -> str:
        """Convert batch to text format for LLM analysis."""
        lines = []
        for entry in self.entries:
            lines.append(f"[{entry.timestamp.isoformat()}] [{entry.source}] {entry.message}")
        return "\n".join(lines)


class ThreatAnalysis(BaseModel):
    """Structured threat analysis result from LLM."""
    severity_score: int = Field(ge=0, le=10, description="Threat severity 0-10")
    severity_level: Severity = Severity.UNKNOWN
    confidence: str = Field(default="Medium", description="Low/Medium/High")
    threat_assessment: str
    detailed_explanation: str
    countermeasures: list[str] = Field(default_factory=list)
    mitre_attack_ttps: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    patch_suggestions: list[PatchSuggestion] = Field(default_factory=list, description="Remediation suggestions")
    vulnerability_categories: list[VulnerabilityCategory] = Field(default_factory=list, description="Categories of vulnerabilities detected")
    
    @classmethod
    def from_raw_sections(cls, sections: dict[str, str]) -> "ThreatAnalysis":
        """Create from raw parsed sections."""
        import re
        
        # Parse severity score
        severity_text = sections.get("Severity Score", "0")
        score_match = re.search(r'\d+', severity_text)
        score = int(score_match.group()) if score_match else 0
        
        # Parse confidence
        confidence = "Medium"
        if "high" in severity_text.lower():
            confidence = "High"
        elif "low" in severity_text.lower():
            confidence = "Low"
        
        # Parse countermeasures into list
        countermeasures_text = sections.get("Immediate Countermeasures", "")
        countermeasures = [
            line.strip().lstrip("•-*").strip()
            for line in countermeasures_text.split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        
        # Extract MITRE ATT&CK TTPs
        all_text = " ".join(sections.values())
        ttp_pattern = r'T\d{4}(?:\.\d{3})?'
        ttps = list(set(re.findall(ttp_pattern, all_text)))
        
        # Extract CVEs
        cve_pattern = r'CVE-\d{4}-\d+'
        cves = list(set(re.findall(cve_pattern, all_text, re.IGNORECASE)))
        
        # Parse vulnerability categories
        categories_text = sections.get("Vulnerability Categories", "")
        categories = []
        for cat in VulnerabilityCategory:
            if cat.value in categories_text.lower():
                categories.append(cat)
        
        # If no explicit categories, infer from text
        if not categories:
            inferred = VulnerabilityCategory.from_keywords(all_text)
            if inferred != VulnerabilityCategory.OTHER:
                categories.append(inferred)
        
        # Parse patch suggestions
        patch_suggestions = []
        patch_text = sections.get("Patch Suggestions", "")
        
        # Try to parse structured patch suggestions
        patch_blocks = re.split(r'\n(?=Category:|Title:|- Category:)', patch_text)
        for block in patch_blocks:
            if not block.strip():
                continue
            
            # Extract fields from block
            category_match = re.search(r'Category:\s*(\w+)', block, re.IGNORECASE)
            title_match = re.search(r'Title:\s*(.+?)(?:\n|$)', block, re.IGNORECASE)
            desc_match = re.search(r'Description:\s*(.+?)(?:\n(?=\w+:)|$)', block, re.IGNORECASE | re.DOTALL)
            priority_match = re.search(r'Priority:\s*(\w+)', block, re.IGNORECASE)
            commands_match = re.search(r'Commands?:\s*(.+?)(?:\n(?=\w+:)|$)', block, re.IGNORECASE | re.DOTALL)
            
            if title_match or desc_match:
                # Determine category
                cat = VulnerabilityCategory.OTHER
                if category_match:
                    cat_str = category_match.group(1).lower()
                    for c in VulnerabilityCategory:
                        if c.value == cat_str or cat_str in c.value:
                            cat = c
                            break
                
                # Extract commands as list
                commands = []
                if commands_match:
                    cmd_text = commands_match.group(1).strip()
                    commands = [c.strip().lstrip("`").rstrip("`") for c in cmd_text.split("\n") if c.strip()]
                
                patch_suggestions.append(PatchSuggestion(
                    category=cat,
                    title=title_match.group(1).strip() if title_match else "Security Fix",
                    description=desc_match.group(1).strip() if desc_match else block.strip()[:200],
                    priority=priority_match.group(1).lower() if priority_match else "medium",
                    commands=commands[:5],  # Limit to 5 commands
                    related_cves=[c for c in cves if c.upper() in block.upper()],
                ))
        
        # If no structured patches found but countermeasures exist, create suggestions from them
        if not patch_suggestions and countermeasures:
            for i, cm in enumerate(countermeasures[:3]):  # Max 3
                cat = VulnerabilityCategory.from_keywords(cm)
                patch_suggestions.append(PatchSuggestion(
                    category=cat,
                    title=f"Countermeasure {i+1}",
                    description=cm,
                    priority="high" if score >= 7 else "medium" if score >= 4 else "low",
                ))
        
        return cls(
            severity_score=score,
            severity_level=Severity.from_score(score),
            confidence=confidence,
            threat_assessment=sections.get("Threat Assessment", "No assessment available"),
            detailed_explanation=sections.get("Detailed Explanation", "No explanation available"),
            countermeasures=countermeasures,
            mitre_attack_ttps=ttps,
            cves=cves,
            patch_suggestions=patch_suggestions,
            vulnerability_categories=categories if categories else [VulnerabilityCategory.OTHER],
        )


class AnalysisResult(BaseModel):
    """Complete analysis result with input and output."""
    id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    timestamp: datetime = Field(default_factory=datetime.now)
    input_text: str
    input_summary: dict[str, Any] = Field(default_factory=dict)
    analysis: ThreatAnalysis
    rag_context_used: list[str] = Field(default_factory=list, description="Retrieved documents used")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class RAGDocument(BaseModel):
    """Document in the RAG knowledge base."""
    id: str
    content: str
    source: str  # mitre, cve, custom, historical
    metadata: dict[str, Any] = Field(default_factory=dict)
    embedding: list[float] | None = None
