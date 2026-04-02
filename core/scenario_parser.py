"""
Module for parsing, normalizing, and structuring raw scenario text
for use in the Diamond Model of Intrusion Analysis pipeline.
"""

import re


class ScenarioParser:
    """
    Provides utilities for normalizing free-form incident text,
    splitting it into sentences, and assembling structured scenario
    strings for AI analysis.
    """

    def normalize(self, text: str) -> str:
        """
        Normalize raw input text by standardizing line endings,
        removing excess whitespace, and collapsing blank lines.

        Args:
            text: Raw scenario input string.

        Returns:
            Cleaned and normalized string, or empty string if input is blank.
        """
        if not text or not text.strip():
            return ""

        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        return text.strip()

    def split_sentences(self, text: str) -> list[str]:
        """
        Split normalized text into individual sentences on
        common terminal punctuation marks.

        Args:
            text: Normalized input string.

        Returns:
            List of non-empty, stripped sentence strings.
        """
        parts = re.split(r"(?<=[.!?])\s+", text)
        return [s.strip() for s in parts if s.strip()]

    def build_scenario_text(
        self,
        adversary: str = "",
        victim: str = "",
        extra: str = "",
    ) -> str:
        """
        Assemble a structured scenario string from discrete input sections.

        Args:
            adversary: Text describing the adversary.
            victim:    Text describing the victim.
            extra:     Any additional contextual information.

        Returns:
            A formatted multi-section scenario string.
        """
        sections = [
            f"ADVERSARY:\n{adversary.strip()}",
            f"VICTIM:\n{victim.strip()}",
            f"ADDITIONAL INFORMATION:\n{extra.strip()}",
        ]
        return "\n\n".join(sections)