"""
Module for invoking the Gemini AI model and returning structured
Diamond Model analysis results via LangChain.
"""

from typing import Any

from langchain_google_genai import ChatGoogleGenerativeAI

from .prompt_manager import PromptManager
from .response_parser import ResponseParser


class AIAnalyzer:
    """
    Handles AI model invocation for Diamond Model intrusion analysis,
    delegating prompt construction to PromptManager and response parsing
    to ResponseParser. Responsible only for AI interaction, not UI or
    business logic.
    """

    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-flash",
        temperature: float = 0.2,
    ) -> None:
        """
        Initialize the AIAnalyzer with API credentials and model settings.

        Args:
            api_key:     Google Generative AI API key.
            model_name:  Gemini model identifier.
            temperature: Sampling temperature for response generation.
        """
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        self.prompt_manager = PromptManager()
        self.response_parser = ResponseParser()

    def build_messages(
        self, scenario_text: str, evidence: dict[str, Any]
    ) -> list[dict[str, str]]:
        """
        Construct the chat message list for the AI model.

        Args:
            scenario_text: Normalized incident scenario string.
            evidence:      Pre-extracted IOC and keyword dictionary.

        Returns:
            List of role/content message dictionaries.
        """
        return self.prompt_manager.build_messages(scenario_text, evidence)

    def invoke_raw(
        self, scenario_text: str, evidence: dict[str, Any]
    ) -> str:
        """
        Invoke the Gemini model and return the raw response text.

        Args:
            scenario_text: Normalized incident scenario string.
            evidence:      Pre-extracted IOC and keyword dictionary.

        Returns:
            Raw string content from the AI response.
        """
        messages = self.build_messages(scenario_text, evidence)
        llm = ChatGoogleGenerativeAI(
            model=self.model_name,
            google_api_key=self.api_key,
            temperature=self.temperature,
        )
        response = llm.invoke(messages)

        if hasattr(response, "content"):
            return str(response.content)
        if isinstance(response, dict):
            return str(response.get("content", ""))
        return str(response)

    def analyze(
        self, scenario_text: str, evidence: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Run the full AI analysis pipeline: invoke the model, parse,
        and validate the structured JSON response.

        Args:
            scenario_text: Normalized incident scenario string.
            evidence:      Pre-extracted IOC and keyword dictionary.

        Returns:
            Validated Diamond Model dictionary with all required vertex keys.

        Raises:
            ValueError: If the AI response cannot be parsed as valid JSON.
        """
        raw = self.invoke_raw(scenario_text, evidence)
        return self.response_parser.parse_and_validate(raw)