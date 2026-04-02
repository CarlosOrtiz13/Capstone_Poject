"""
Module for representing the Victim vertex of the Diamond Model of Intrusion Analysis.
"""

from dataclasses import dataclass, field

from .field_value import FieldValue


@dataclass
class Victim:
    """
    Represents the Victim vertex in the Diamond Model, capturing
    the target organization, sector, geography, role, and impact
    of an intrusion event.
    """

    organization: FieldValue = field(default_factory=FieldValue)
    sector: FieldValue = field(default_factory=FieldValue)
    geography: FieldValue = field(default_factory=FieldValue)
    role: FieldValue = field(default_factory=FieldValue)
    impact: FieldValue = field(default_factory=FieldValue)

    def is_empty(self) -> bool:
        """Returns True if all FieldValue fields are empty."""
        return (
            self.organization.is_empty()
            and self.sector.is_empty()
            and self.geography.is_empty()
            and self.role.is_empty()
            and self.impact.is_empty()
        )

    def to_dict(self) -> dict:
        """Returns a serializable dictionary with nested FieldValues converted to dicts."""
        return {
            "organization": self.organization.to_dict(),
            "sector": self.sector.to_dict(),
            "geography": self.geography.to_dict(),
            "role": self.role.to_dict(),
            "impact": self.impact.to_dict(),
        }