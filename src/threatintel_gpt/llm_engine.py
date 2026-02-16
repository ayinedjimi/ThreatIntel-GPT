"""
LLM Engine for threat intelligence analysis

Author: Ayi NEDJIMI
"""

import os
import logging
from typing import Optional, Dict, Any
from langchain.llms import OpenAI
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

logger = logging.getLogger(__name__)


class LLMEngine:
    """
    LLM interaction engine using LangChain
    """

    def __init__(
        self,
        model_name: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
        temperature: float = 0.3,
        max_tokens: int = 1000
    ):
        """
        Initialize the LLM engine

        Args:
            model_name: Name of the LLM model
            api_key: API key for the LLM service
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens in response
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens

        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")

        if not self.api_key:
            logger.warning("No API key provided. LLM functionality will be limited.")

        # Initialize the model
        self._initialize_model()

    def _initialize_model(self):
        """Initialize the LLM model"""
        try:
            if self.api_key:
                self.llm = ChatOpenAI(
                    model_name=self.model_name,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    openai_api_key=self.api_key
                )
                logger.info(f"Initialized LLM: {self.model_name}")
            else:
                # Fallback to mock mode for testing
                self.llm = None
                logger.warning("Running in mock mode without LLM")
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {e}")
            self.llm = None

    def analyze(self, prompt: str) -> str:
        """
        Analyze a prompt using the LLM

        Args:
            prompt: Input prompt for analysis

        Returns:
            LLM response text
        """
        if not self.llm:
            return self._mock_response(prompt)

        try:
            response = self.llm.predict(prompt)
            return response
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._mock_response(prompt)

    def analyze_with_template(
        self,
        template: str,
        variables: Dict[str, Any]
    ) -> str:
        """
        Analyze using a prompt template

        Args:
            template: Prompt template string
            variables: Variables to fill in template

        Returns:
            LLM response text
        """
        if not self.llm:
            return self._mock_response(str(variables))

        try:
            prompt = PromptTemplate(
                template=template,
                input_variables=list(variables.keys())
            )
            chain = LLMChain(llm=self.llm, prompt=prompt)
            response = chain.run(**variables)
            return response
        except Exception as e:
            logger.error(f"Template analysis failed: {e}")
            return self._mock_response(str(variables))

    def _mock_response(self, prompt: str) -> str:
        """
        Generate a mock response for testing without API key

        Args:
            prompt: Input prompt

        Returns:
            Mock response
        """
        return f"""
THREAT ANALYSIS (Mock Mode):

The analyzed indicator appears to be potentially malicious based on pattern analysis.

Key Findings:
- Indicator shows characteristics associated with known threat patterns
- Recommended blocking at network perimeter
- Monitor for related indicators
- Review historical logs for similar patterns

MITRE ATT&CK Mapping:
- Tactic: Initial Access, Execution
- Technique: T1566 (Phishing), T1059 (Command and Scripting Interpreter)

Confidence Level: Medium (0.6)

Recommendations:
1. Implement network-level blocking
2. Enhance monitoring and detection rules
3. Conduct threat hunting activities
4. Update threat intelligence feeds

Note: This is a mock response. Configure OpenAI API key for full functionality.
"""

    def summarize(self, text: str, max_length: int = 200) -> str:
        """
        Summarize text using LLM

        Args:
            text: Text to summarize
            max_length: Maximum summary length

        Returns:
            Summarized text
        """
        prompt = f"""Summarize the following threat intelligence in {max_length} characters or less:

{text}

Summary:"""

        return self.analyze(prompt)

    def extract_iocs(self, text: str) -> Dict[str, list]:
        """
        Extract IOCs from unstructured text

        Args:
            text: Text containing potential IOCs

        Returns:
            Dictionary of extracted IOCs by type
        """
        prompt = f"""Extract all indicators of compromise (IOCs) from the following text.
Categorize them as IP addresses, domains, URLs, file hashes, or email addresses.

Text: {text}

Respond in structured format:
IPs: [list]
Domains: [list]
URLs: [list]
Hashes: [list]
Emails: [list]
"""

        response = self.analyze(prompt)

        # Parse response (simplified - enhance for production)
        return {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": []
        }
