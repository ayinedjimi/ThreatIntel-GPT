"""
ThreatIntel-GPT: AI-Powered Threat Intelligence Analysis Platform

Author: Ayi NEDJIMI
Website: https://ayinedjimi-consultants.fr
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Ayi NEDJIMI"
__email__ = "contact@ayinedjimi-consultants.fr"

from .analyzer import ThreatAnalyzer
from .mitre import MITREMapper
from .llm_engine import LLMEngine
from .correlator import ThreatCorrelator

__all__ = [
    "ThreatAnalyzer",
    "MITREMapper",
    "LLMEngine",
    "ThreatCorrelator",
]
