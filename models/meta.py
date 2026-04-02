"""
Module for representing metadata associated with a Diamond Model intrusion analysis event.
"""

from dataclasses import dataclass, field


@dataclass
class Meta:
    """
    Represents metadata for a Diamond Model event, capturing the summary,
    timestamps, analyst notes, and validation warnings accumulated
    during the analysis lifecycle.
    """

    summary: str = ""
    timestamps: list[str] = field(default_factory=list)
    analyst_notes: list[str] = field(default_factory=list)
    validation_warnings: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Returns True if summary is blank and all list fields are empty."""
        return (
            not self.summary.strip()
            and not self.timestamps
            and not self.analyst_notes
            and not self.validation_warnings
        )

    def to_dict(self) -> dict:
        """Returns a serializable dictionary of all metadata fields."""
        return {
            "summary": self.summary,
            "timestamps": self.timestamps,
            "analyst_notes": self.analyst_notes,
            "validation_warnings": self.validation_warnings,
        }