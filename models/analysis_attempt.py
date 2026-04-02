"""
Module for representing a single AI-assisted analysis attempt within the Diamond Model system.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisAttempt:
    """
    Represents one complete analysis attempt, capturing the input scenario,
    raw AI output, extracted evidence, the final Diamond Model state,
    validation results, and any subsequent human edits made during review.
    """

    attempt_id: str
    timestamp: str
    scenario_text: str
    extracted_evidence: dict[str, Any]
    ai_raw_output: dict[str, Any] | str
    final_model: dict[str, Any]
    validation_results: dict[str, Any]
    human_edits: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Returns a serializable dictionary of all analysis attempt fields."""
        return {
            "attempt_id": self.attempt_id,
            "timestamp": self.timestamp,
            "scenario_text": self.scenario_text,
            "extracted_evidence": self.extracted_evidence,
            "ai_raw_output": self.ai_raw_output,
            "final_model": self.final_model,
            "validation_results": self.validation_results,
            "human_edits": self.human_edits,
        }