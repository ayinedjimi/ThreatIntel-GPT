"""
Threat Intelligence Analyzer

Author: Ayi NEDJIMI
"""

import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .llm_engine import LLMEngine
from .mitre import MITREMapper
from .cache import CacheManager
from .correlator import ThreatCorrelator


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatAnalysisResult:
    """Container for threat analysis results"""
    ioc: str
    ioc_type: str
    threat_score: float
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    description: str
    recommendations: List[str]
    sources: List[str]
    timestamp: str
    confidence: float
    related_threats: List[Dict[str, Any]]


class ThreatAnalyzer:
    """
    Main threat intelligence analyzer using LLM and MITRE ATT&CK
    """

    IOC_PATTERNS = {
        "ip": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "domain": r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$",
        "url": r"^https?://",
        "hash_md5": r"^[a-fA-F0-9]{32}$",
        "hash_sha1": r"^[a-fA-F0-9]{40}$",
        "hash_sha256": r"^[a-fA-F0-9]{64}$",
        "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    }

    def __init__(
        self,
        model_name: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
        use_cache: bool = True,
        redis_host: str = "localhost",
        redis_port: int = 6379
    ):
        """
        Initialize the ThreatAnalyzer

        Args:
            model_name: LLM model to use
            api_key: API key for LLM service
            use_cache: Whether to use Redis caching
            redis_host: Redis host address
            redis_port: Redis port
        """
        self.llm = LLMEngine(model_name=model_name, api_key=api_key)
        self.mitre = MITREMapper()
        self.correlator = ThreatCorrelator()

        if use_cache:
            try:
                self.cache = CacheManager(host=redis_host, port=redis_port)
            except Exception as e:
                logger.warning(f"Failed to initialize cache: {e}. Running without cache.")
                self.cache = None
        else:
            self.cache = None

    def detect_ioc_type(self, ioc: str) -> Optional[str]:
        """
        Auto-detect IOC type based on pattern matching

        Args:
            ioc: Indicator of Compromise

        Returns:
            Detected IOC type or None
        """
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            if re.match(pattern, ioc):
                return ioc_type
        return None

    def analyze_ioc(
        self,
        ioc: str,
        ioc_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ThreatAnalysisResult:
        """
        Analyze an Indicator of Compromise

        Args:
            ioc: The indicator to analyze
            ioc_type: Type of IOC (ip, domain, hash, etc.)
            context: Additional context for analysis

        Returns:
            ThreatAnalysisResult object
        """
        # Auto-detect IOC type if not provided
        if not ioc_type:
            ioc_type = self.detect_ioc_type(ioc)
            if not ioc_type:
                ioc_type = "unknown"

        logger.info(f"Analyzing IOC: {ioc} (type: {ioc_type})")

        # Check cache
        if self.cache:
            cached_result = self.cache.get(f"ioc:{ioc}")
            if cached_result:
                logger.info("Retrieved from cache")
                return cached_result

        # Build analysis prompt
        prompt = self._build_analysis_prompt(ioc, ioc_type, context)

        # Get LLM analysis
        llm_response = self.llm.analyze(prompt)

        # Parse LLM response
        parsed_data = self._parse_llm_response(llm_response)

        # Map to MITRE ATT&CK
        mitre_mapping = self.mitre.map_to_mitre(parsed_data.get("description", ""))

        # Calculate threat score
        threat_score = self._calculate_threat_score(parsed_data, mitre_mapping)

        # Get related threats
        related_threats = self.correlator.find_related(ioc, ioc_type)

        # Create result
        result = ThreatAnalysisResult(
            ioc=ioc,
            ioc_type=ioc_type,
            threat_score=threat_score,
            severity=self._get_severity(threat_score),
            mitre_tactics=mitre_mapping.get("tactics", []),
            mitre_techniques=mitre_mapping.get("techniques", []),
            description=parsed_data.get("description", ""),
            recommendations=parsed_data.get("recommendations", []),
            sources=parsed_data.get("sources", []),
            timestamp=datetime.utcnow().isoformat(),
            confidence=parsed_data.get("confidence", 0.5),
            related_threats=related_threats
        )

        # Cache result
        if self.cache:
            self.cache.set(f"ioc:{ioc}", result, ttl=3600)

        return result

    def _build_analysis_prompt(
        self,
        ioc: str,
        ioc_type: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build the analysis prompt for LLM"""
        prompt = f"""Analyze the following security indicator:

IOC: {ioc}
Type: {ioc_type}
"""
        if context:
            prompt += f"\nAdditional Context:\n{context}\n"

        prompt += """
Provide a comprehensive threat intelligence analysis including:
1. Threat description and potential impact
2. Known attack patterns or campaigns
3. Recommended mitigation actions
4. Confidence level (0-1)
5. Related IOCs or threat actors if known

Format the response as structured data.
"""
        return prompt

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured data"""
        # Simple parsing - in production, use more robust parsing
        return {
            "description": response[:500] if response else "No description available",
            "recommendations": [
                "Monitor network traffic for suspicious activity",
                "Block the indicator at perimeter defenses",
                "Review logs for related indicators",
                "Update threat intelligence feeds"
            ],
            "sources": ["LLM Analysis"],
            "confidence": 0.7
        }

    def _calculate_threat_score(
        self,
        parsed_data: Dict[str, Any],
        mitre_mapping: Dict[str, Any]
    ) -> float:
        """Calculate threat score (0-100)"""
        base_score = 50.0

        # Adjust based on MITRE techniques
        technique_count = len(mitre_mapping.get("techniques", []))
        base_score += min(technique_count * 5, 30)

        # Adjust based on confidence
        confidence = parsed_data.get("confidence", 0.5)
        base_score *= confidence

        return min(base_score, 100.0)

    def _get_severity(self, threat_score: float) -> str:
        """Convert threat score to severity level"""
        if threat_score >= 80:
            return "CRITICAL"
        elif threat_score >= 60:
            return "HIGH"
        elif threat_score >= 40:
            return "MEDIUM"
        elif threat_score >= 20:
            return "LOW"
        else:
            return "INFO"

    def batch_analyze(
        self,
        iocs: List[str],
        ioc_type: Optional[str] = None
    ) -> List[ThreatAnalysisResult]:
        """
        Analyze multiple IOCs in batch

        Args:
            iocs: List of indicators
            ioc_type: Type of IOCs (if all same type)

        Returns:
            List of ThreatAnalysisResult objects
        """
        results = []
        for ioc in iocs:
            try:
                result = self.analyze_ioc(ioc, ioc_type)
                results.append(result)
            except Exception as e:
                logger.error(f"Error analyzing {ioc}: {e}")
        return results
