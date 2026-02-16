"""
Tests for ThreatIntel-GPT Analyzer

Author: Ayi NEDJIMI
"""

import pytest
from threatintel_gpt import ThreatAnalyzer


def test_analyzer_initialization():
    """Test analyzer initialization"""
    analyzer = ThreatAnalyzer(use_cache=False)
    assert analyzer is not None
    assert analyzer.llm is not None
    assert analyzer.mitre is not None


def test_ioc_type_detection():
    """Test IOC type detection"""
    analyzer = ThreatAnalyzer(use_cache=False)

    assert analyzer.detect_ioc_type("192.168.1.1") == "ip"
    assert analyzer.detect_ioc_type("example.com") == "domain"
    assert analyzer.detect_ioc_type("https://example.com") == "url"
    assert analyzer.detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"
    assert analyzer.detect_ioc_type("test@example.com") == "email"


def test_analyze_ioc():
    """Test IOC analysis"""
    analyzer = ThreatAnalyzer(use_cache=False)

    result = analyzer.analyze_ioc("192.168.1.100", "ip")

    assert result is not None
    assert result.ioc == "192.168.1.100"
    assert result.ioc_type == "ip"
    assert 0 <= result.threat_score <= 100
    assert result.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert isinstance(result.recommendations, list)


def test_batch_analyze():
    """Test batch analysis"""
    analyzer = ThreatAnalyzer(use_cache=False)

    iocs = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    results = analyzer.batch_analyze(iocs, "ip")

    assert len(results) == 3
    assert all(r.ioc_type == "ip" for r in results)
