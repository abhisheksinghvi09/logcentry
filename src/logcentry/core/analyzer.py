"""
LogCentry Core - LLM Analyzer

The threat analysis engine that interfaces with LLM APIs (Gemini or OpenAI).
Handles prompt construction, API calls, and response parsing.
"""

import os
import re
from typing import Any

from logcentry.config import get_cached_settings
from logcentry.core.models import AnalysisResult, LogBatch, ThreatAnalysis
from logcentry.utils import get_logger

logger = get_logger(__name__)


SYSTEM_PROMPT = """You are LogCEntry AI, a world-class Threat Intelligence Analyst. Your analysis must be sharp, concise, and grounded in evidence.

**CRITICAL DIRECTIVE: AVOID FALSE POSITIVES.**
Before assigning a high severity, you MUST consider potential benign explanations for the activity.

Your report (SITREP) must follow this exact structure:
- **Severity Score:** (0-10 with confidence level [Low/Medium/High].)
- **Threat Assessment:** (Brief analysis of the likely attack scenario. Reference MITRE ATT&CK TTPs or CVEs if confident.)
- **Vulnerability Categories:** (List the detected vulnerability types from: injection, auth_failure, exposure, dos, privilege_escalation, malware, reconnaissance, brute_force, other)
- **Detailed Explanation:** (A paragraph explaining the reasoning behind the assessment and severity.)
- **Immediate Countermeasures:** (2-3 direct, actionable steps in bullet points.)
- **Patch Suggestions:** (For each detected vulnerability, provide structured remediation:)
  - Category: [category_name from list above]
  - Title: [short descriptive title]
  - Description: [what to patch/fix and why]
  - Priority: [high/medium/low]
  - Commands: [specific commands to run if applicable, one per line]

When provided with CONTEXT from the knowledge base, use it to inform your analysis. Reference specific TTPs, CVEs, or similar past incidents when relevant.
"""


class ThreatAnalyzer:
    """
    LLM-powered threat analysis engine.
    
    Supports:
    - Google Gemini API
    - OpenAI API (GPT-4o-mini, GPT-4, etc.)
    
    Handles:
    - Prompt construction with optional RAG context
    - Response parsing into structured format
    - Retry logic for API failures
    """
    
    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model_name: str | None = None,
    ):
        """
        Initialize the analyzer.
        
        Args:
            provider: "openai" or "gemini" (auto-detected from settings if not specified)
            api_key: API key (defaults to settings)
            model_name: Model to use (defaults based on provider)
        """
        settings = get_cached_settings()
        self.max_retries = settings.max_retries
        
        # Auto-detect provider based on available API keys from settings
        if provider is None:
            # Check settings first (which reads from .env), then env vars
            has_openai = bool(settings.openai_api_key) or bool(os.getenv("OPENAI_API_KEY"))
            has_gemini = bool(settings.gemini_api_key) or bool(os.getenv("GEMINI_API_KEY"))
            
            # Prefer OpenAI if available, or if key starts with sk-
            if has_openai or (api_key and api_key.startswith("sk-")):
                provider = "openai"
            elif has_gemini:
                provider = "gemini"
            else:
                provider = "openai"  # Default to OpenAI
        
        self.provider = provider.lower()
        
        if self.provider == "openai":
            self._init_openai(api_key, model_name, settings)
        else:
            self._init_gemini(api_key, model_name, settings)
        
        logger.info("analyzer_initialized", provider=self.provider, model=self.model_name)
    
    def _init_openai(self, api_key: str | None, model_name: str | None, settings):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("OpenAI not installed. Run: pip install openai")
        
        # Get API key from argument, settings, or env
        self.api_key = api_key or settings.openai_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY in .env or environment.")
        
        self.model_name = model_name or "gpt-4o-mini"
        self.client = OpenAI(api_key=self.api_key)
    
    def _init_gemini(self, api_key: str | None, model_name: str | None, settings):
        """Initialize Gemini client."""
        try:
            import google.generativeai as genai
        except ImportError:
            raise RuntimeError("Gemini not installed. Run: pip install google-generativeai")
        
        self.api_key = api_key or settings.api_key
        self.model_name = model_name or settings.model
        
        genai.configure(api_key=self.api_key)
        self.client = genai.GenerativeModel(
            model_name=self.model_name,
            system_instruction=SYSTEM_PROMPT,
        )
    
    def analyze(
        self,
        log_batch: LogBatch,
        rag_context: list[str] | None = None,
        summary_data: dict[str, Any] | None = None,
    ) -> AnalysisResult:
        """
        Analyze a batch of logs for security threats.
        
        Args:
            log_batch: Batch of parsed log entries
            rag_context: Optional retrieved context from knowledge base
            summary_data: Optional pre-computed summary (e.g., from PCAP analysis)
            
        Returns:
            Complete analysis result
        """
        # Build the prompt
        prompt = self._build_prompt(log_batch, rag_context, summary_data)
        
        logger.info(
            "analyzing_logs",
            entry_count=log_batch.count,
            has_rag_context=bool(rag_context),
            provider=self.provider,
        )
        
        # Call the API with retry logic
        response_text = self._call_api(prompt)
        
        # Parse the response
        sections = self._parse_response(response_text)
        threat_analysis = ThreatAnalysis.from_raw_sections(sections)
        
        # Build the result
        result = AnalysisResult(
            input_text=log_batch.to_text()[:5000],  # Truncate for storage
            input_summary=summary_data or {},
            analysis=threat_analysis,
            rag_context_used=rag_context[:3] if rag_context else [],  # Store top 3
        )
        
        logger.info(
            "analysis_complete",
            severity=threat_analysis.severity_level.value,
            score=threat_analysis.severity_score,
        )
        
        return result
    
    def analyze_text(
        self,
        text: str,
        rag_context: list[str] | None = None,
    ) -> AnalysisResult:
        """
        Analyze raw text (for direct input mode).
        
        Args:
            text: Raw log text
            rag_context: Optional RAG context
            
        Returns:
            Analysis result
        """
        from logcentry.core.parser import LogParser
        
        parser = LogParser()
        lines = text.strip().split("\n")
        log_batch = parser.parse_lines(lines, source="direct_input")
        
        return self.analyze(log_batch, rag_context)
    
    def _build_prompt(
        self,
        log_batch: LogBatch,
        rag_context: list[str] | None = None,
        summary_data: dict[str, Any] | None = None,
    ) -> str:
        """Build the analysis prompt with optional RAG context."""
        parts = []
        
        # Add RAG context if available
        if rag_context:
            parts.append("=== RELEVANT CONTEXT FROM KNOWLEDGE BASE ===")
            for i, ctx in enumerate(rag_context[:5], 1):  # Max 5 context items
                parts.append(f"\n[Context {i}]\n{ctx[:1000]}")  # Truncate each
            parts.append("\n" + "=" * 50 + "\n")
        
        # Add summary if available (e.g., PCAP stats)
        if summary_data:
            parts.append("=== LOG SUMMARY ===")
            for key, value in summary_data.items():
                parts.append(f"- {key}: {value}")
            parts.append("")
        
        # Add the main log content
        parts.append("=== LOGS TO ANALYZE ===")
        parts.append("The logs are provided below. Analyze them for security threats:\n")
        parts.append(log_batch.to_text())
        
        return "\n".join(parts)
    
    def _call_api(self, prompt: str) -> str:
        """Call the LLM API with retry logic."""
        import time
        
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                if self.provider == "openai":
                    return self._call_openai(prompt)
                else:
                    return self._call_gemini(prompt)
            except Exception as e:
                last_error = e
                logger.warning(
                    "api_call_failed",
                    attempt=attempt + 1,
                    max_retries=self.max_retries,
                    error=str(e),
                )
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        raise RuntimeError(f"API call failed after {self.max_retries} attempts: {last_error}")
    
    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        return response.choices[0].message.content
    
    def _call_gemini(self, prompt: str) -> str:
        """Call Gemini API."""
        response = self.client.generate_content(prompt)
        return response.text
    
    def _parse_response(self, text: str) -> dict[str, str]:
        """Parse LLM response into structured sections."""
        sections = {
            "Severity Score": "N/A",
            "Threat Assessment": "N/A",
            "Vulnerability Categories": "",
            "Detailed Explanation": "N/A",
            "Immediate Countermeasures": "N/A",
            "Patch Suggestions": "",
        }
        
        patterns = {
            "Severity Score": r"\*?\*?Severity Score:?\*?\*?\s*(.*?)(?=\n\*?\*?Threat|$)",
            "Threat Assessment": r"\*?\*?Threat Assessment:?\*?\*?\s*(.*?)(?=\n\*?\*?(?:Vulnerability|Detailed)|$)",
            "Vulnerability Categories": r"\*?\*?Vulnerability Categor(?:y|ies):?\*?\*?\s*(.*?)(?=\n\*?\*?Detailed|$)",
            "Detailed Explanation": r"\*?\*?Detailed Explanation:?\*?\*?\s*(.*?)(?=\n\*?\*?Immediate|$)",
            "Immediate Countermeasures": r"\*?\*?Immediate Countermeasures:?\*?\*?\s*(.*?)(?=\n\*?\*?Patch|$)",
            "Patch Suggestions": r"\*?\*?Patch Suggestions?:?\*?\*?\s*(.*?)$",
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                sections[key] = match.group(1).strip()
        
        return sections
