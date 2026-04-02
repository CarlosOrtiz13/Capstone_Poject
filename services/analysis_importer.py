"""
Module for importing analysis results into the Diamond Model application
from native JSON exports or STIX-like bundle files.
"""

import json
from typing import Any

from models import DiamondModel
from .stix_importer import StixImporter


class AnalysisImporter:
    """
    Detects and loads Diamond Model analysis data from two supported
    input formats: native app JSON exports and STIX-like bundle files.
    Returns a normalized result dictionary compatible with the app's
    session state structure.
    """

    def __init__(self) -> None:
        """Initialize with a StixImporter instance for bundle handling."""
        self.stix_importer = StixImporter()

    def parse_uploaded_text(self, text: str) -> dict[str, Any]:
        """
        Parse a raw JSON string into a dictionary.

        Args:
            text: Raw JSON string from an uploaded file or text input.

        Returns:
            Parsed dictionary.

        Raises:
            ValueError: If the text is not valid JSON.
        """
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Could not parse uploaded file as JSON: {e}"
            ) from e

    def is_native_analysis_export(self, data: dict[str, Any]) -> bool:
        """
        Detect whether the data looks like a native app JSON export.

        Args:
            data: Parsed dictionary to inspect.

        Returns:
            True if the data contains native export keys.
        """
        native_keys = {"scenario_text", "final_model", "validation"}
        return isinstance(data, dict) and native_keys.issubset(data.keys())

    def is_stix_bundle(self, data: dict[str, Any]) -> bool:
        """
        Detect whether the data is a STIX-like bundle.

        Args:
            data: Parsed dictionary to inspect.

        Returns:
            True if the data has type 'bundle' and an objects list.
        """
        return (
            isinstance(data, dict)
            and data.get("type") == "bundle"
            and "objects" in data
        )

    def load_native_analysis(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize a native app JSON export into a session-compatible dictionary.

        Args:
            data: Parsed native export dictionary.

        Returns:
            Normalized dictionary with attempt_id, timestamp, scenario_text,
            evidence, model_dict, and validation keys.
        """
        model_dict = data.get("final_model") or {}

        return {
            "attempt_id":    data.get("attempt_id", "imported"),
            "timestamp":     data.get("timestamp", ""),
            "scenario_text": data.get("scenario_text", ""),
            "clean_text":    data.get("scenario_text", ""),
            "evidence":      data.get("evidence") or {},
            "model_dict":    model_dict,
            "model":         None,
            "validation":    data.get("validation") or {},
            "parsed_ai":     {},
        }

    def load_stix_analysis(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a STIX-like bundle into a session-compatible dictionary
        using StixImporter.

        Args:
            data: Parsed STIX bundle dictionary.

        Returns:
            Normalized dictionary with attempt_id, timestamp, scenario_text,
            evidence, model, model_dict, and validation keys.

        Raises:
            ValueError: If the bundle fails StixImporter validation.
        """
        model: DiamondModel = self.stix_importer.from_bundle(data)

        return {
            "attempt_id":    "stix-import",
            "timestamp":     "",
            "scenario_text": "",
            "clean_text":    "",
            "evidence":      {},
            "model":         model,
            "model_dict":    model.to_dict(),
            "validation":    {},
            "parsed_ai":     {},
        }

    def import_analysis(self, text: str) -> dict[str, Any]:
        """
        Parse uploaded text, detect its format, and load it into a
        normalized session-compatible dictionary.

        Supported formats:
            - Native app JSON export (contains scenario_text, final_model, validation)
            - STIX-like bundle (type == 'bundle' with objects list)

        Args:
            text: Raw JSON string from an uploaded or pasted source.

        Returns:
            Normalized result dictionary compatible with session state.

        Raises:
            ValueError: If the text is not valid JSON or the format
                        is not recognised.
        """
        data = self.parse_uploaded_text(text)

        if self.is_native_analysis_export(data):
            return self.load_native_analysis(data)

        if self.is_stix_bundle(data):
            return self.load_stix_analysis(data)

        raise ValueError(
            "Unrecognised file format. Please upload a native JSON analysis "
            "export or a STIX-like bundle file."
        )