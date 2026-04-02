"""
Module for orchestrating a complete end-to-end Diamond Model
intrusion analysis session from raw scenario text to validated output.
"""

import uuid
from datetime import datetime
from typing import Any

from ai.ai_analyzer import AIAnalyzer

from .diamond_builder import DiamondModelBuilder
from .evidence_extractor import EvidenceExtractor
from .scenario_parser import ScenarioParser
from .validator import Validator


class AnalysisSession:
    """
    Orchestrates a single end-to-end analysis run, coordinating scenario
    normalization, evidence extraction, AI invocation, Diamond Model
    construction, and validation. Business logic lives here, not in the UI.
    """

    def __init__(self, api_key: str) -> None:
        """
        Initialize the session with all required pipeline components.

        Args:
            api_key: Google Generative AI API key for the AI analyzer.
        """
        self.parser = ScenarioParser()
        self.extractor = EvidenceExtractor()
        self.builder = DiamondModelBuilder()
        self.validator = Validator()
        self.ai_analyzer = AIAnalyzer(api_key=api_key)

    def run(self, scenario_text: str) -> dict[str, Any]:
        """
        Execute a complete analysis pipeline on the provided scenario text.

        Steps:
            1. Normalize the raw scenario text.
            2. Extract structured evidence indicators.
            3. Invoke the AI model for Diamond Model analysis.
            4. Build a DiamondModel from AI output and evidence.
            5. Validate the resulting model.
            6. Return a structured result dictionary.

        Args:
            scenario_text: Raw incident scenario text provided by the user.

        Returns:
            Dictionary containing:
                - attempt_id (str):         Unique identifier for this run.
                - timestamp (str):          UTC ISO-format timestamp.
                - clean_text (str):         Normalized scenario text.
                - evidence (dict):          Extracted IOCs and keywords.
                - parsed_ai (dict):         Raw validated AI response.
                - model (DiamondModel):     Populated DiamondModel instance.
                - model_dict (dict):        Serializable form of the model.
                - validation (dict):        Validation report with warnings and score.
        """
        clean_text = self.parser.normalize(scenario_text)
        evidence = self.extractor.extract_all(clean_text)
        parsed_ai = self.ai_analyzer.analyze(clean_text, evidence)
        model = self.builder.build(parsed_ai, evidence)
        validation = self.validator.validate(model)

        return {
            "attempt_id": str(uuid.uuid4()),
            "timestamp":  datetime.utcnow().isoformat(),
            "clean_text": clean_text,
            "evidence":   evidence,
            "parsed_ai":  parsed_ai,
            "model":      model,
            "model_dict": model.to_dict(),
            "validation": validation,
        }