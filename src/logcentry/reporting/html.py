"""
LogCentry Reporting - HTML Report Generator

Professional HTML report generation for security analysis results.
"""

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from logcentry.config import get_cached_settings
from logcentry.core.models import AnalysisResult, Severity
from logcentry.utils import get_logger, sanitize_html

logger = get_logger(__name__)


class HTMLReportGenerator:
    """Generate professional HTML security reports."""
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: ("#ef4444", "white"),
        Severity.HIGH: ("#f97316", "white"),
        Severity.MEDIUM: ("#facc15", "#422006"),
        Severity.LOW: ("#22c55e", "white"),
        Severity.INFO: ("#3b82f6", "white"),
        Severity.UNKNOWN: ("#64748b", "white"),
    }
    
    def __init__(self, output_dir: str | Path | None = None):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory for generated reports
        """
        settings = get_cached_settings()
        self.output_dir = Path(output_dir or settings.reports_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(
        self,
        result: AnalysisResult,
        filename: str | None = None,
    ) -> Path:
        """
        Generate an HTML report for an analysis result.
        
        Args:
            result: Analysis result to report
            filename: Optional output filename
            
        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_report_{timestamp}.html"
        
        filepath = self.output_dir / filename
        
        html_content = self._render_report(result)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info("report_generated", path=str(filepath))
        return filepath
    
    def _render_report(self, result: AnalysisResult) -> str:
        """Render the HTML report content."""
        analysis = result.analysis
        
        # Get severity styling
        bg_color, text_color = self.SEVERITY_COLORS.get(
            analysis.severity_level,
            self.SEVERITY_COLORS[Severity.UNKNOWN],
        )
        
        # Format countermeasures as list
        countermeasures_html = "<ul>"
        for cm in analysis.countermeasures:
            countermeasures_html += f"<li>{sanitize_html(cm)}</li>"
        countermeasures_html += "</ul>"
        
        # Format MITRE TTPs if present
        ttps_html = ""
        if analysis.mitre_attack_ttps:
            ttps_html = (
                '<div class="ttps">'
                '<strong>MITRE ATT&CK:</strong> '
                + ", ".join(f'<code>{ttp}</code>' for ttp in analysis.mitre_attack_ttps)
                + "</div>"
            )
        
        # Format CVEs if present
        cves_html = ""
        if analysis.cves:
            cves_html = (
                '<div class="cves">'
                '<strong>Related CVEs:</strong> '
                + ", ".join(f'<code>{cve}</code>' for cve in analysis.cves)
                + "</div>"
            )
        
        # Format RAG context if used
        rag_html = ""
        if result.rag_context_used:
            rag_html = """
            <div class="section">
                <div class="section-title">📚 Knowledge Base Context Used</div>
                <div class="content-box rag-context">
            """
            for i, ctx in enumerate(result.rag_context_used, 1):
                rag_html += f"""
                    <div class="context-item">
                        <strong>Context {i}:</strong>
                        <p>{sanitize_html(ctx[:300])}...</p>
                    </div>
                """
            rag_html += "</div></div>"
        
        # Input preview
        input_preview = result.input_text[:500]
        if len(result.input_text) > 500:
            input_preview += "..."
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogCEntry AI Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            background: #f1f5f9; 
            font-family: 'Inter', -apple-system, sans-serif; 
            padding: 2rem; 
            color: #334155;
            line-height: 1.6;
        }}
        .container {{ 
            max-width: 900px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 16px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{ 
            background: linear-gradient(135deg, #4f46e5, #7c3aed); 
            color: white; 
            padding: 2.5rem; 
            text-align: center;
        }}
        .header h1 {{ font-size: 1.875rem; font-weight: 700; }}
        .header p {{ opacity: 0.9; margin-top: 0.5rem; }}
        .section {{ padding: 2rem; border-bottom: 1px solid #e2e8f0; }}
        .section:last-child {{ border-bottom: none; }}
        .section-title {{ 
            font-size: 1.25rem; 
            font-weight: 600; 
            margin-bottom: 1rem; 
            color: #1e293b;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .severity-badge {{ 
            display: inline-block; 
            padding: 0.5rem 1rem; 
            border-radius: 8px; 
            font-weight: 600;
            background-color: {bg_color};
            color: {text_color};
        }}
        .content-box {{ 
            background: #f8fafc; 
            border-left: 4px solid #6366f1; 
            padding: 1.5rem; 
            border-radius: 8px; 
            margin-top: 1rem;
        }}
        .ttps, .cves {{ margin-top: 1rem; }}
        code {{ 
            background: #e0e7ff; 
            padding: 0.125rem 0.375rem; 
            border-radius: 4px;
            font-size: 0.875rem;
        }}
        ul {{ margin-left: 1.5rem; margin-top: 0.5rem; }}
        li {{ margin-bottom: 0.5rem; }}
        pre {{ 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            font-family: 'Fira Code', monospace;
            font-size: 0.875rem;
            background: #1e293b;
            color: #e2e8f0;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
        }}
        .meta {{ color: #64748b; font-size: 0.875rem; }}
        .footer {{ 
            text-align: center; 
            padding: 1.5rem; 
            color: #64748b; 
            font-size: 0.875rem;
            background: #f8fafc;
        }}
        .rag-context .context-item {{
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 1px dashed #cbd5e1;
        }}
        .rag-context .context-item:last-child {{ border-bottom: none; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ LogCEntry AI Security Report</h1>
            <p>AI-Powered Threat Intelligence Analysis</p>
        </div>
        
        <div class="section">
            <div class="section-title">📅 Report Information</div>
            <p class="meta"><strong>Generated:</strong> {result.timestamp.strftime("%B %d, %Y at %I:%M:%S %p")}</p>
            <p class="meta"><strong>Analysis ID:</strong> {result.id}</p>
            <p class="meta"><strong>Confidence:</strong> {analysis.confidence}</p>
        </div>
        
        <div class="section">
            <div class="section-title">⚠️ Severity Assessment</div>
            <span class="severity-badge">{analysis.severity_score}/10 - {analysis.severity_level.value.upper()}</span>
            {ttps_html}
            {cves_html}
        </div>
        
        <div class="section">
            <div class="section-title">🎯 Threat Assessment</div>
            <div class="content-box">
                <p>{sanitize_html(analysis.threat_assessment)}</p>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">📖 Detailed Explanation</div>
            <div class="content-box">
                <p>{sanitize_html(analysis.detailed_explanation)}</p>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">🔧 Immediate Countermeasures</div>
            <div class="content-box">
                {countermeasures_html}
            </div>
        </div>
        
        {rag_html}
        
        <div class="section">
            <div class="section-title">📝 Analyzed Input</div>
            <pre>{sanitize_html(input_preview)}</pre>
        </div>
        
        <div class="footer">
            <p>Generated by LogCEntry AI v2.0 | RAG-Enhanced Threat Intelligence</p>
        </div>
    </div>
</body>
</html>"""


class JSONReportGenerator:
    """Generate JSON reports for machine processing."""
    
    def __init__(self, output_dir: str | Path | None = None):
        settings = get_cached_settings()
        self.output_dir = Path(output_dir or settings.reports_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(
        self,
        result: AnalysisResult,
        filename: str | None = None,
    ) -> Path:
        """Generate a JSON report."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_report_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        # Convert to dict for JSON serialization
        data = {
            "id": result.id,
            "timestamp": result.timestamp.isoformat(),
            "analysis": {
                "severity_score": result.analysis.severity_score,
                "severity_level": result.analysis.severity_level.value,
                "confidence": result.analysis.confidence,
                "threat_assessment": result.analysis.threat_assessment,
                "detailed_explanation": result.analysis.detailed_explanation,
                "countermeasures": result.analysis.countermeasures,
                "mitre_attack_ttps": result.analysis.mitre_attack_ttps,
                "cves": result.analysis.cves,
            },
            "input_summary": result.input_summary,
            "rag_context_used": result.rag_context_used,
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info("json_report_generated", path=str(filepath))
        return filepath
