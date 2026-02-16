"""
MITRE ATT&CK Framework Integration

Author: Ayi NEDJIMI
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import requests

logger = logging.getLogger(__name__)


class MITREMapper:
    """
    Maps threat intelligence to MITRE ATT&CK framework
    """

    MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # Common technique mappings (simplified version)
    TECHNIQUE_KEYWORDS = {
        "T1566": ["phishing", "spearphishing", "email attack"],
        "T1059": ["command", "script", "powershell", "cmd", "bash"],
        "T1105": ["download", "ingress tool transfer", "file transfer"],
        "T1071": ["http", "https", "web protocol", "application layer"],
        "T1090": ["proxy", "vpn", "tunnel"],
        "T1189": ["drive-by", "watering hole", "compromised website"],
        "T1190": ["exploit", "vulnerability", "cve"],
        "T1133": ["vpn", "remote access", "external remote services"],
        "T1078": ["valid account", "credential", "stolen credentials"],
        "T1110": ["brute force", "password spray", "credential stuffing"],
        "T1486": ["ransomware", "encryption", "data encrypted"],
        "T1485": ["data destruction", "delete", "wipe"],
        "T1567": ["exfiltration", "data theft", "upload"],
        "T1021": ["rdp", "remote desktop", "remote services"],
        "T1003": ["credential dump", "lsass", "mimikatz"],
    }

    TACTIC_MAPPING = {
        "T1566": "Initial Access",
        "T1059": "Execution",
        "T1105": "Command and Control",
        "T1071": "Command and Control",
        "T1090": "Command and Control",
        "T1189": "Initial Access",
        "T1190": "Initial Access",
        "T1133": "Persistence",
        "T1078": "Defense Evasion",
        "T1110": "Credential Access",
        "T1486": "Impact",
        "T1485": "Impact",
        "T1567": "Exfiltration",
        "T1021": "Lateral Movement",
        "T1003": "Credential Access",
    }

    def __init__(self, update_on_init: bool = False):
        """
        Initialize MITRE ATT&CK mapper

        Args:
            update_on_init: Whether to update MITRE data on initialization
        """
        self.data_path = Path.home() / ".threatintel_gpt" / "mitre_attack.json"
        self.data_path.parent.mkdir(parents=True, exist_ok=True)

        if update_on_init or not self.data_path.exists():
            self.update_mitre_data()

    def update_mitre_data(self) -> bool:
        """
        Download latest MITRE ATT&CK data

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info("Downloading MITRE ATT&CK data...")
            response = requests.get(self.MITRE_ATTACK_URL, timeout=30)
            response.raise_for_status()

            with open(self.data_path, "w") as f:
                json.dump(response.json(), f)

            logger.info("MITRE ATT&CK data updated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to update MITRE data: {e}")
            return False

    def map_to_mitre(self, description: str) -> Dict[str, List[str]]:
        """
        Map threat description to MITRE ATT&CK techniques and tactics

        Args:
            description: Threat description text

        Returns:
            Dictionary with tactics and techniques
        """
        description_lower = description.lower()
        matched_techniques = []
        matched_tactics = []

        # Match techniques based on keywords
        for technique_id, keywords in self.TECHNIQUE_KEYWORDS.items():
            for keyword in keywords:
                if keyword in description_lower:
                    if technique_id not in matched_techniques:
                        matched_techniques.append(technique_id)
                        # Add corresponding tactic
                        tactic = self.TACTIC_MAPPING.get(technique_id)
                        if tactic and tactic not in matched_tactics:
                            matched_tactics.append(tactic)
                    break

        return {
            "techniques": matched_techniques,
            "tactics": matched_tactics,
            "details": self._get_technique_details(matched_techniques)
        }

    def _get_technique_details(self, technique_ids: List[str]) -> List[Dict[str, str]]:
        """
        Get detailed information about techniques

        Args:
            technique_ids: List of MITRE technique IDs

        Returns:
            List of technique details
        """
        details = []
        for tech_id in technique_ids:
            details.append({
                "id": tech_id,
                "name": self._get_technique_name(tech_id),
                "tactic": self.TACTIC_MAPPING.get(tech_id, "Unknown"),
                "url": f"https://attack.mitre.org/techniques/{tech_id}/"
            })
        return details

    def _get_technique_name(self, technique_id: str) -> str:
        """Get human-readable name for technique"""
        technique_names = {
            "T1566": "Phishing",
            "T1059": "Command and Scripting Interpreter",
            "T1105": "Ingress Tool Transfer",
            "T1071": "Application Layer Protocol",
            "T1090": "Proxy",
            "T1189": "Drive-by Compromise",
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1078": "Valid Accounts",
            "T1110": "Brute Force",
            "T1486": "Data Encrypted for Impact",
            "T1485": "Data Destruction",
            "T1567": "Exfiltration Over Web Service",
            "T1021": "Remote Services",
            "T1003": "OS Credential Dumping",
        }
        return technique_names.get(technique_id, "Unknown Technique")

    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for MITRE techniques by query

        Args:
            query: Search query

        Returns:
            List of matching techniques
        """
        results = []
        query_lower = query.lower()

        for tech_id, keywords in self.TECHNIQUE_KEYWORDS.items():
            for keyword in keywords:
                if query_lower in keyword or keyword in query_lower:
                    results.append({
                        "id": tech_id,
                        "name": self._get_technique_name(tech_id),
                        "tactic": self.TACTIC_MAPPING.get(tech_id),
                        "keywords": keywords,
                        "url": f"https://attack.mitre.org/techniques/{tech_id}/"
                    })
                    break

        return results

    def get_tactics(self) -> List[str]:
        """Get list of all MITRE ATT&CK tactics"""
        return list(set(self.TACTIC_MAPPING.values()))

    def get_techniques_by_tactic(self, tactic: str) -> List[str]:
        """
        Get techniques for a specific tactic

        Args:
            tactic: MITRE tactic name

        Returns:
            List of technique IDs
        """
        return [
            tech_id for tech_id, t in self.TACTIC_MAPPING.items()
            if t == tactic
        ]
