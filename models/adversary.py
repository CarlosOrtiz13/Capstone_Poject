"""
Module for representing the Adversary vertex of the Diamond Model of Intrusion Analysis.
"""

from dataclasses import dataclass, field

from .field_value import FieldValue


@dataclass
class Adversary:
    """
    Represents the Adversary vertex in the Diamond Model, capturing
    identity, motivation, attribution, and intent of a threat actor.
    """

    name: FieldValue = field(default_factory=FieldValue)
    aliases: list[str] = field(default_factory=list)
    motivation: FieldValue = field(default_factory=FieldValue)
    attribution: FieldValue = field(default_factory=FieldValue)
    intent: FieldValue = field(default_factory=FieldValue)

    def is_empty(self) -> bool:
        """Returns True if all main FieldValue fields and aliases are empty."""
        return (
            self.name.is_empty()
            and self.motivation.is_empty()
            and self.attribution.is_empty()
            and self.intent.is_empty()
            and not self.aliases
        )

    def to_dict(self) -> dict:
        """Returns a serializable dictionary with nested FieldValues converted to dicts."""
        return {
            "name": self.name.to_dict(),
            "aliases": self.aliases,
            "motivation": self.motivation.to_dict(),
            "attribution": self.attribution.to_dict(),
            "intent": self.intent.to_dict(),
        }