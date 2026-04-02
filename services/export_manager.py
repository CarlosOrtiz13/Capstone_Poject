"""
Module for preparing and encoding Diamond Model analysis exports
in JSON, STIX, and PDF formats from a single unified interface.
"""

import json
from typing import Any

from models import DiamondModel
from .report_generator import ReportGenerator
from .stix_mapper import StixMapper


class ExportManager:
    """
    Provides a unified interface for exporting a DiamondModel analysis
    in three formats: plain JSON, STIX-like bundle, and PDF report.
    Delegates format-specific logic to ReportGenerator and StixMapper.
    """

    def __init__(self) -> None:
        """Initialize with instances of ReportGenerator and StixMapper."""
        self.report_generator = ReportGenerator()
        self.stix_mapper      = StixMapper()

    def export_json(
        self,
        model: DiamondModel,
        evidence: dict[str, Any],
        validation: dict[str, Any],
        scenario_text: str,
        attempt_id: str = "",
        timestamp: str = "",
    ) -> bytes:
        """
        Serialize the full analysis result as pretty-printed JSON bytes.

        Args:
            model:         Populated DiamondModel instance.
            evidence:      Dictionary of extracted IOCs and keywords.
            validation:    Validation report dictionary.
            scenario_text: Normalized scenario text.
            attempt_id:    Optional unique attempt identifier.
            timestamp:     Optional ISO timestamp string.

        Returns:
            UTF-8 encoded JSON bytes.
        """
        payload = {
            "attempt_id":    attempt_id,
            "timestamp":     timestamp,
            "scenario_text": scenario_text,
            "evidence":      evidence,
            "final_model":   model.to_dict(),
            "validation":    validation,
        }
        return json.dumps(payload, indent=2).encode("utf-8")

    def export_stix(self, model: DiamondModel) -> bytes:
        """
        Convert the DiamondModel to a STIX-like bundle and encode as JSON bytes.

        Args:
            model: Populated DiamondModel instance.

        Returns:
            UTF-8 encoded JSON bytes representing the STIX bundle.
        """
        bundle = self.stix_mapper.to_bundle(model)
        return json.dumps(bundle, indent=2).encode("utf-8")

    def export_pdf(
        self,
        model: DiamondModel,
        evidence: dict[str, Any],
        validation: dict[str, Any],
        scenario_text: str,
        attempt_id: str = "",
        timestamp: str = "",
    ) -> bytes:
        """
        Generate a PDF report from the DiamondModel analysis.

        Args:
            model:         Populated DiamondModel instance.
            evidence:      Dictionary of extracted IOCs and keywords.
            validation:    Validation report dictionary.
            scenario_text: Normalized scenario text.
            attempt_id:    Optional unique attempt identifier.
            timestamp:     Optional ISO timestamp string.

        Returns:
            Raw PDF bytes suitable for download or storage.
        """
        return self.report_generator.generate_pdf(
            model=model,
            evidence=evidence,
            validation=validation,
            scenario_text=scenario_text,
            attempt_id=attempt_id,
            timestamp=timestamp,
        )