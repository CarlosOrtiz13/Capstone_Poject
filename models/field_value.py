"""
Module for representing a single structured field value within the Diamond Model of Intrusion Analysis.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FieldValue:
    """
    Represents one structured field in the Diamond Model system,
    encapsulating the field's value, confidence score, evidence,
    and review/approval state.
    """

    value: Optional[str] = None
    confidence: float = 0.0
    source: str = "unknown"
    evidence: list[str] = field(default_factory=list)
    approved: bool = False
    edited_by_user: bool = False
    notes: Optional[str] = None

    def is_empty(self) -> bool:
        """Returns True if value is None or blank after stripping whitespace."""
        return self.value is None or self.value.strip() == ""

    def mark_approved(self) -> None:
        """Marks the field as approved."""
        self.approved = True

    def mark_user_edited(self, new_value: str, note: str = "") -> None:
        """
        Updates the field with a user-provided value and marks it as edited and approved.

        Args:
            new_value: The new value supplied by the user.
            note: An optional note explaining the edit.
        """
        self.value = new_value
        self.source = "user"
        self.edited_by_user = True
        self.approved = True
        if note:
            self.notes = note

    def to_dict(self) -> dict:
        """Returns a serializable dictionary of all fields."""
        return {
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": self.evidence,
            "approved": self.approved,
            "edited_by_user": self.edited_by_user,
            "notes": self.notes,
        }