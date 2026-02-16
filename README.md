# 🔍 ThreatIntel-GPT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![HuggingFace](https://img.shields.io/badge/🤗-HuggingFace-yellow)](https://huggingface.co/AYI-NEDJIMI)

[English](#english) | [Français](#français)

---

## English

### 🎯 Overview

**ThreatIntel-GPT** is an advanced AI-powered threat intelligence analysis platform that leverages Large Language Models (LLMs) and the MITRE ATT&CK framework to provide comprehensive security threat analysis, correlation, and actionable insights.

### ✨ Key Features

- **🤖 LLM-Powered Analysis**: Uses state-of-the-art language models for threat intelligence processing
- **🎯 MITRE ATT&CK Integration**: Automatic mapping to tactics, techniques, and procedures (TTPs)
- **📊 Real-time Correlation**: Cross-reference threats across multiple intelligence sources
- **💾 Redis Caching**: High-performance caching for rapid threat lookups
- **🔗 Multi-Source Integration**: Aggregates data from OSINT, feeds, and custom sources
- **📈 Threat Scoring**: AI-based severity assessment and prioritization
- **🌐 RESTful API**: Easy integration with existing security infrastructure
- **📝 Detailed Reports**: Generate comprehensive threat intelligence reports

### 🚀 Quick Start

#### Installation

```bash
# Clone the repository
git clone https://github.com/AYI-NEDJIMI/ThreatIntel-GPT.git
cd ThreatIntel-GPT

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

#### Basic Usage

```python
from threatintel_gpt import ThreatAnalyzer

# Initialize the analyzer
analyzer = ThreatAnalyzer(
    model_name="gpt-3.5-turbo",
    api_key="your-api-key"
)

# Analyze a threat indicator
result = analyzer.analyze_ioc(
    ioc="192.168.1.100",
    ioc_type="ip"
)

print(result.threat_score)
print(result.mitre_tactics)
print(result.recommendations)
```

#### API Server

```bash
# Start the API server
python -m threatintel_gpt.api

# Access at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### 📋 Requirements

- Python 3.8+
- Redis (optional, for caching)
- OpenAI API key or compatible LLM endpoint
- 4GB+ RAM recommended

### 🏗️ Architecture

```
ThreatIntel-GPT/
├── src/
│   └── threatintel_gpt/
│       ├── __init__.py
│       ├── analyzer.py          # Core threat analysis
│       ├── mitre.py              # MITRE ATT&CK integration
│       ├── llm_engine.py         # LLM interaction layer
│       ├── cache.py              # Redis caching
│       ├── correlator.py         # Threat correlation
│       └── api.py                # FastAPI application
├── tests/
├── docs/
└── examples/
```

### 🔧 Configuration

Create a `.env` file:

```env
OPENAI_API_KEY=your-api-key
REDIS_HOST=localhost
REDIS_PORT=6379
MITRE_UPDATE_INTERVAL=86400
LOG_LEVEL=INFO
```

### 📖 Documentation

Full documentation available in the [docs/](docs/) directory:
- [Installation Guide](docs/installation.md)
- [API Reference](docs/api_reference.md)
- [MITRE Integration](docs/mitre_integration.md)
- [Advanced Usage](docs/advanced_usage.md)

### 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### 🔒 Security

For security concerns, please review our [Security Policy](SECURITY.md).

### 👤 Author

**Ayi NEDJIMI**

- Website: [ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)
- HuggingFace: [@AYI-NEDJIMI](https://huggingface.co/AYI-NEDJIMI)
- LinkedIn: [Ayi NEDJIMI](https://linkedin.com/in/ayi-nedjimi)
- GitHub: [@AYI-NEDJIMI](https://github.com/AYI-NEDJIMI)

### 🔗 Related Projects

- [KVortex](https://github.com/AYI-NEDJIMI/kvortex) - Advanced RAG system for knowledge management
- [BamDamForensics](https://github.com/AYI-NEDJIMI/BamDamForensics) - Digital forensics toolkit
- [ComplianceBot](https://github.com/AYI-NEDJIMI/ComplianceBot) - AI compliance assistant
- [VulnScanner-LLM](https://github.com/AYI-NEDJIMI/VulnScanner-LLM) - AI-powered vulnerability scanner

### 📚 Citation

If you use ThreatIntel-GPT in your research or project, please cite:

```bibtex
@software{nedjimi2025threatintel,
  author = {NEDJIMI, Ayi},
  title = {ThreatIntel-GPT: AI-Powered Threat Intelligence Analysis},
  year = {2025},
  url = {https://github.com/AYI-NEDJIMI/ThreatIntel-GPT}
}
```

### ⭐ Star History

If you find this project useful, please consider giving it a star!

---

## Français

### 🎯 Aperçu

**ThreatIntel-GPT** est une plateforme d'analyse de renseignements sur les menaces alimentée par l'IA qui exploite les grands modèles de langage (LLM) et le framework MITRE ATT&CK pour fournir une analyse complète des menaces de sécurité, une corrélation et des informations exploitables.

### ✨ Fonctionnalités Clés

- **🤖 Analyse Alimentée par LLM**: Utilise des modèles de langage de pointe pour le traitement des renseignements sur les menaces
- **🎯 Intégration MITRE ATT&CK**: Cartographie automatique vers les tactiques, techniques et procédures (TTP)
- **📊 Corrélation en Temps Réel**: Référencement croisé des menaces sur plusieurs sources de renseignements
- **💾 Cache Redis**: Cache haute performance pour des recherches rapides de menaces
- **🔗 Intégration Multi-Sources**: Agrège les données d'OSINT, de flux et de sources personnalisées
- **📈 Scoring des Menaces**: Évaluation et priorisation de la gravité basées sur l'IA
- **🌐 API RESTful**: Intégration facile avec l'infrastructure de sécurité existante
- **📝 Rapports Détaillés**: Génération de rapports complets de renseignements sur les menaces

### 🚀 Démarrage Rapide

#### Installation

```bash
# Cloner le dépôt
git clone https://github.com/AYI-NEDJIMI/ThreatIntel-GPT.git
cd ThreatIntel-GPT

# Installer les dépendances
pip install -r requirements.txt

# Installer le package
pip install -e .
```

#### Utilisation de Base

```python
from threatintel_gpt import ThreatAnalyzer

# Initialiser l'analyseur
analyzer = ThreatAnalyzer(
    model_name="gpt-3.5-turbo",
    api_key="votre-clé-api"
)

# Analyser un indicateur de menace
result = analyzer.analyze_ioc(
    ioc="192.168.1.100",
    ioc_type="ip"
)

print(result.threat_score)
print(result.mitre_tactics)
print(result.recommendations)
```

#### Serveur API

```bash
# Démarrer le serveur API
python -m threatintel_gpt.api

# Accès à http://localhost:8000
# Documentation API à http://localhost:8000/docs
```

### 📋 Prérequis

- Python 3.8+
- Redis (optionnel, pour le cache)
- Clé API OpenAI ou endpoint LLM compatible
- 4GB+ RAM recommandé

### 🤝 Contribution

Les contributions sont les bienvenues! Veuillez d'abord lire nos [Directives de Contribution](CONTRIBUTING.md).

### 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

### 👤 Auteur

**Ayi NEDJIMI**

- Site Web: [ayinedjimi-consultants.fr](https://ayinedjimi-consultants.fr)
- HuggingFace: [@AYI-NEDJIMI](https://huggingface.co/AYI-NEDJIMI)
- LinkedIn: [Ayi NEDJIMI](https://linkedin.com/in/ayi-nedjimi)
- GitHub: [@AYI-NEDJIMI](https://github.com/AYI-NEDJIMI)

### 🔗 Projets Connexes

- [KVortex](https://github.com/AYI-NEDJIMI/kvortex) - Système RAG avancé pour la gestion des connaissances
- [BamDamForensics](https://github.com/AYI-NEDJIMI/BamDamForensics) - Boîte à outils d'investigation numérique
- [ComplianceBot](https://github.com/AYI-NEDJIMI/ComplianceBot) - Assistant de conformité IA
- [VulnScanner-LLM](https://github.com/AYI-NEDJIMI/VulnScanner-LLM) - Scanner de vulnérabilités alimenté par l'IA

---

**Made with ❤️ for the cybersecurity community**
