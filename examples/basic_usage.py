"""
Basic usage examples for ThreatIntel-GPT

Author: Ayi NEDJIMI
"""

from threatintel_gpt import ThreatAnalyzer


def main():
    # Initialize analyzer
    analyzer = ThreatAnalyzer(
        model_name="gpt-3.5-turbo",
        use_cache=True
    )

    # Example 1: Analyze a single IP
    print("=== Example 1: Analyze IP Address ===")
    result = analyzer.analyze_ioc("192.168.1.100", "ip")
    print(f"IOC: {result.ioc}")
    print(f"Threat Score: {result.threat_score}")
    print(f"Severity: {result.severity}")
    print(f"MITRE Tactics: {', '.join(result.mitre_tactics)}")
    print(f"Recommendations: {result.recommendations[:2]}")
    print()

    # Example 2: Auto-detect IOC type
    print("=== Example 2: Auto-detect IOC Type ===")
    result = analyzer.analyze_ioc("malicious.example.com")
    print(f"Detected Type: {result.ioc_type}")
    print(f"Threat Score: {result.threat_score}")
    print()

    # Example 3: Batch analysis
    print("=== Example 3: Batch Analysis ===")
    iocs = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1"
    ]
    results = analyzer.batch_analyze(iocs, "ip")
    for r in results:
        print(f"{r.ioc}: {r.severity} (Score: {r.threat_score:.2f})")
    print()

    # Example 4: MITRE ATT&CK mapping
    print("=== Example 4: MITRE ATT&CK ===")
    tactics = analyzer.mitre.get_tactics()
    print(f"Available Tactics: {', '.join(tactics[:5])}...")


if __name__ == "__main__":
    main()
