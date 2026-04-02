"""
Module for representing a complete Diamond Model of Intrusion Analysis event.
"""

from dataclasses import dataclass, field

from .adversary import Adversary
from .capability import Capability
from .infrastructure import Infrastructure
from .meta import Meta
from .victim import Victim


@dataclass
class DiamondModel:
    """
    Represents a complete Diamond Model intrusion analysis event,
    composing the four core vertices — Adversary, Victim, Capability,
    and Infrastructure — alongside event metadata.
    """

    adversary: Adversary = field(default_factory=Adversary)
    victim: Victim = field(default_factory=Victim)
    capability: Capability = field(default_factory=Capability)
    infrastructure: Infrastructure = field(default_factory=Infrastructure)
    meta: Meta = field(default_factory=Meta)

    def is_empty(self) -> bool:
        """Returns True if all four vertices and metadata are empty."""
        return (
            self.adversary.is_empty()
            and self.victim.is_empty()
            and self.capability.is_empty()
            and self.infrastructure.is_empty()
            and self.meta.is_empty()
        )

    def to_dict(self) -> dict:
        """Returns a fully serializable dictionary of the entire Diamond Model."""
        return {
            "adversary": self.adversary.to_dict(),
            "victim": self.victim.to_dict(),
            "capability": self.capability.to_dict(),
            "infrastructure": self.infrastructure.to_dict(),
            "meta": self.meta.to_dict(),
        }