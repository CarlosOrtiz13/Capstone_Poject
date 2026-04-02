"""
Module for representing the Infrastructure vertex of the Diamond Model of Intrusion Analysis.
"""

from dataclasses import dataclass, field

from .field_value import FieldValue


@dataclass
class Infrastructure:
    """
    Represents the Infrastructure vertex in the Diamond Model, capturing
    the domains, IPs, URLs, email addresses, and hosts used by an
    adversary to support an intrusion event.
    """

    description: FieldValue = field(default_factory=FieldValue)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Returns True if description is empty and all list fields are empty."""
        return (
            self.description.is_empty()
            and not self.domains
            and not self.ips
            and not self.urls
            and not self.email_addresses
            and not self.hosts
        )

    def to_dict(self) -> dict:
        """Returns a serializable dictionary with nested FieldValues converted to dicts."""
        return {
            "description": self.description.to_dict(),
            "domains": self.domains,
            "ips": self.ips,
            "urls": self.urls,
            "email_addresses": self.email_addresses,
            "hosts": self.hosts,
        }