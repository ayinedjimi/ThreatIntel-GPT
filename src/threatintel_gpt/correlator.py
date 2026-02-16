"""
Threat Correlator for identifying related threats

Author: Ayi NEDJIMI
"""

import logging
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatCorrelator:
    """
    Correlates threats across multiple sources and time periods
    """

    def __init__(self):
        """Initialize the threat correlator"""
        self.threat_database = defaultdict(list)
        self.correlation_rules = self._initialize_rules()

    def _initialize_rules(self) -> Dict[str, Any]:
        """Initialize correlation rules"""
        return {
            "ip_to_domain": {
                "enabled": True,
                "confidence": 0.8
            },
            "hash_to_campaign": {
                "enabled": True,
                "confidence": 0.9
            },
            "temporal_clustering": {
                "enabled": True,
                "time_window": timedelta(hours=24),
                "confidence": 0.7
            }
        }

    def add_threat(self, ioc: str, ioc_type: str, metadata: Dict[str, Any]):
        """
        Add threat to correlation database

        Args:
            ioc: Indicator of Compromise
            ioc_type: Type of IOC
            metadata: Additional threat metadata
        """
        threat_entry = {
            "ioc": ioc,
            "type": ioc_type,
            "metadata": metadata,
            "timestamp": datetime.utcnow()
        }
        self.threat_database[ioc_type].append(threat_entry)

    def find_related(
        self,
        ioc: str,
        ioc_type: str,
        max_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Find threats related to given IOC

        Args:
            ioc: Indicator to find relations for
            ioc_type: Type of IOC
            max_results: Maximum number of results

        Returns:
            List of related threats
        """
        related_threats = []

        # Find by same type
        for threat in self.threat_database.get(ioc_type, []):
            if threat["ioc"] != ioc:
                similarity = self._calculate_similarity(ioc, threat["ioc"], ioc_type)
                if similarity > 0.5:
                    related_threats.append({
                        "ioc": threat["ioc"],
                        "type": threat["type"],
                        "similarity": similarity,
                        "relationship": "same_type",
                        "metadata": threat["metadata"]
                    })

        # Find cross-type correlations
        cross_type_related = self._find_cross_type_correlations(ioc, ioc_type)
        related_threats.extend(cross_type_related)

        # Sort by similarity and limit results
        related_threats.sort(key=lambda x: x["similarity"], reverse=True)
        return related_threats[:max_results]

    def _calculate_similarity(self, ioc1: str, ioc2: str, ioc_type: str) -> float:
        """
        Calculate similarity between two IOCs

        Args:
            ioc1: First IOC
            ioc2: Second IOC
            ioc_type: Type of IOCs

        Returns:
            Similarity score (0-1)
        """
        if ioc_type == "ip":
            # Check if IPs are in same subnet
            try:
                parts1 = ioc1.split(".")
                parts2 = ioc2.split(".")
                if parts1[:3] == parts2[:3]:  # Same /24 subnet
                    return 0.8
                elif parts1[:2] == parts2[:2]:  # Same /16 subnet
                    return 0.6
            except:
                pass

        elif ioc_type == "domain":
            # Check if domains share TLD or structure
            if ioc1.split(".")[-1] == ioc2.split(".")[-1]:
                return 0.6

        elif ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            # Exact match only for hashes
            return 1.0 if ioc1 == ioc2 else 0.0

        return 0.3  # Default low similarity

    def _find_cross_type_correlations(
        self,
        ioc: str,
        ioc_type: str
    ) -> List[Dict[str, Any]]:
        """
        Find correlations across different IOC types

        Args:
            ioc: Source IOC
            ioc_type: Source IOC type

        Returns:
            List of cross-type correlations
        """
        correlations = []

        # Example: IP to domain correlations
        if ioc_type == "ip":
            for domain_threat in self.threat_database.get("domain", []):
                # In real implementation, check DNS records
                correlations.append({
                    "ioc": domain_threat["ioc"],
                    "type": "domain",
                    "similarity": 0.7,
                    "relationship": "dns_resolution",
                    "metadata": domain_threat["metadata"]
                })

        return correlations

    def cluster_threats(
        self,
        time_window: timedelta = timedelta(hours=24)
    ) -> List[Dict[str, Any]]:
        """
        Cluster threats based on temporal and pattern similarities

        Args:
            time_window: Time window for clustering

        Returns:
            List of threat clusters
        """
        clusters = []
        now = datetime.utcnow()

        # Simple temporal clustering
        recent_threats = []
        for ioc_type, threats in self.threat_database.items():
            for threat in threats:
                if now - threat["timestamp"] <= time_window:
                    recent_threats.append(threat)

        if recent_threats:
            clusters.append({
                "cluster_id": 1,
                "threat_count": len(recent_threats),
                "time_window": str(time_window),
                "threats": recent_threats[:10]  # Limit to 10 for display
            })

        return clusters

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get correlation statistics

        Returns:
            Dictionary of statistics
        """
        total_threats = sum(len(threats) for threats in self.threat_database.values())

        return {
            "total_threats": total_threats,
            "by_type": {
                ioc_type: len(threats)
                for ioc_type, threats in self.threat_database.items()
            },
            "correlation_rules_active": sum(
                1 for rule in self.correlation_rules.values()
                if rule.get("enabled", False)
            )
        }
