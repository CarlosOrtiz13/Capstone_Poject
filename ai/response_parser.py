"""
Module for parsing and validating raw AI JSON responses
for the Diamond Model of Intrusion Analysis pipeline.
"""

import json
import re
from typing import Any


class ResponseParser:
    """
    Cleans, parses, and validates raw AI output into structured
    Diamond Model dictionaries, ensuring all required vertex keys
    are present before downstream processing.
    """

    _REQUIRED_KEYS: list[str] = [
        "adversary",
        "victim",
        "capability",
        "infrastructure",
        "meta",
    ]

    def clean_json_text(self, raw_text: str) -> str:
        """
        Strip markdown code fences and surrounding whitespace from
        a raw AI response string.

        Args:
            raw_text: Raw string returned by the AI model.

        Returns:
            Cleaned string ready for JSON parsing.
        """
        cleaned = re.sub(r"```(?:json)?\s*", "", raw_text)
        cleaned = cleaned.replace("```", "")
        return cleaned.strip()

    def parse_json_response(self, raw_text: str) -> dict[str, Any]:
        """
        Clean and parse a raw AI response string into a Python dictionary.

        Args:
            raw_text: Raw string returned by the AI model.

        Returns:
            Parsed dictionary from the JSON response.

        Raises:
            ValueError: If the cleaned text cannot be decoded as valid JSON.
        """
        cleaned = self.clean_json_text(raw_text)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Failed to parse AI response as JSON: {e}\n"
                f"Cleaned text received:\n{cleaned}"
            ) from e

    def ensure_required_keys(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Ensure all required Diamond Model vertex keys are present
        in the parsed dictionary, inserting empty dicts for any that
        are missing.

        Args:
            data: Parsed response dictionary.

        Returns:
            Dictionary guaranteed to contain all required top-level keys.
        """
        for key in self._REQUIRED_KEYS:
            if key not in data:
                data[key] = {}
        return data

    def parse_and_validate(self, raw_text: str) -> dict[str, Any]:
        """
        Parse a raw AI response and enforce the presence of all
        required Diamond Model keys in a single step.

        Args:
            raw_text: Raw string returned by the AI model.

        Returns:
            Validated dictionary with all required vertex keys present.

        Raises:
            ValueError: If the response cannot be parsed as valid JSON.
        """
        data = self.parse_json_response(raw_text)
        return self.ensure_required_keys(data)