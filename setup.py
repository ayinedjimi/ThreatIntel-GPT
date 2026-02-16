"""
ThreatIntel-GPT Setup Configuration

Author: Ayi NEDJIMI
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="threatintel-gpt",
    version="1.0.0",
    author="Ayi NEDJIMI",
    author_email="contact@ayinedjimi-consultants.fr",
    description="AI-Powered Threat Intelligence Analysis Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AYI-NEDJIMI/ThreatIntel-GPT",
    project_urls={
        "Bug Tracker": "https://github.com/AYI-NEDJIMI/ThreatIntel-GPT/issues",
        "Documentation": "https://github.com/AYI-NEDJIMI/ThreatIntel-GPT/tree/main/docs",
        "Source Code": "https://github.com/AYI-NEDJIMI/ThreatIntel-GPT",
        "Website": "https://ayinedjimi-consultants.fr",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "langchain>=0.1.0",
        "openai>=1.3.0",
        "redis>=5.0.0",
        "requests>=2.31.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threatintel-gpt=threatintel_gpt.api:main",
        ],
    },
)
