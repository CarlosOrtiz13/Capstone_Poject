"""
Module for representing the Capability vertex of the Diamond Model of Intrusion Analysis.
"""

from dataclasses import dataclass, field

from .field_value import FieldValue


@dataclass
class Capability:
    """
    Represents the Capability vertex in the Diamond Model, capturing
    the tools, malware, TTPs, and vulnerabilities leveraged by an
    adversary during an intrusion event.
    """

    description: FieldValue = field(default_factory=FieldValue)
    tools: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Returns True if description is empty and all list fields are empty."""
        return (
            self.description.is_empty()
            and not self.tools
            and not self.malware
            and not self.ttps
            and not self.vulnerabilities
        )

    def to_dict(self) -> dict:
        """Returns a serializable dictionary with nested FieldValues converted to dicts."""
        return {
            "description": self.description.to_dict(),
            "tools": self.tools,
            "malware": self.malware,
            "ttps": self.ttps,
            "vulnerabilities": self.vulnerabilities,
        }