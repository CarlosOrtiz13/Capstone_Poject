"""
Module for importing a STIX-like JSON bundle back into a DiamondModel,
supporting a practical subset of STIX 2.1 object types.
"""

from typing import Any

from models import DiamondModel


class StixImporter:
    """
    Converts a STIX-like bundle dictionary — as produced by StixMapper —
    back into a populated DiamondModel. Handles a limited set of object
    types defensively, ignoring anything unsupported or malformed.
    """

    _SUPPORTED_TYPES: set[str] = {
        "bundle",
        "threat-actor",
        "identity",
        "attack-pattern",
        "infrastructure",
        "report",
        "relationship",
    }

    def _clean(self, value: Any) -> str | None:
        """Return a stripped string if meaningful, otherwise None."""
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _apply(self, field_obj: Any, value: Any, source: str = "user") -> None:
        """
        Set a FieldValue's value and source if the value is meaningful.

        Args:
            field_obj: A FieldValue instance.
            value:     Raw value to apply.
            source:    Source label to assign.
        """
        text = self._clean(value)
        if text is not None:
            field_obj.value = text
            field_obj.source = source

    def validate_bundle(self, bundle: dict[str, Any]) -> None:
        """
        Validate that the input is a minimal well-formed STIX-like bundle.

        Args:
            bundle: Dictionary to validate.

        Raises:
            ValueError: If the bundle is missing required keys or has the
                        wrong type value.
        """
        if not isinstance(bundle, dict):
            raise ValueError("Bundle must be a dictionary.")
        if bundle.get("type") != "bundle":
            raise ValueError(
                f"Expected type 'bundle', got '{bundle.get('type')}'."
            )
        if "objects" not in bundle:
            raise ValueError("Bundle is missing required 'objects' key.")
        if not isinstance(bundle["objects"], list):
            raise ValueError("Bundle 'objects' must be a list.")

    def from_bundle(self, bundle: dict[str, Any]) -> DiamondModel:
        """
        Parse a STIX-like bundle and populate a DiamondModel from its objects.

        Supported mappings:
            threat-actor    → adversary
            identity        → victim
            attack-pattern  → capability
            infrastructure  → infrastructure
            report          → meta summary

        Scalar fields are marked with source='user'. Unsupported object
        types are silently ignored.

        Args:
            bundle: A STIX-like bundle dictionary.

        Returns:
            A populated DiamondModel instance.

        Raises:
            ValueError: If the bundle fails validation.
        """
        self.validate_bundle(bundle)
        model = DiamondModel()

        # Index objects by type, keeping the first of each supported type
        by_type: dict[str, dict[str, Any]] = {}
        for obj in bundle["objects"]:
            obj_type = obj.get("type", "")
            if obj_type not in self._SUPPORTED_TYPES:
                continue
            if obj_type == "relationship":
                continue
            if obj_type not in by_type:
                by_type[obj_type] = obj

        # --- Threat Actor → Adversary ---
        ta = by_type.get("threat-actor", {})
        if ta:
            self._apply(model.adversary.name, ta.get("name"))

            aliases = ta.get("aliases", [])
            if isinstance(aliases, list):
                model.adversary.aliases = [
                    str(a).strip() for a in aliases if str(a).strip()
                ]

            self._apply(model.adversary.motivation, ta.get("primary_motivation"))
            self._apply(model.adversary.attribution, ta.get("description"))

            goals = ta.get("goals", [])
            if isinstance(goals, list) and goals:
                self._apply(model.adversary.intent, goals[0])

        # --- Identity → Victim ---
        identity = by_type.get("identity", {})
        if identity:
            self._apply(model.victim.organization, identity.get("name"))

            sectors = identity.get("sectors", [])
            if isinstance(sectors, list) and sectors:
                self._apply(model.victim.sector, sectors[0])

            self._apply(model.victim.geography, identity.get("contact_information"))

            description = self._clean(identity.get("description"))
            if description:
                parts = [p.strip() for p in description.split("|") if p.strip()]
                if len(parts) >= 2:
                    self._apply(model.victim.role,   parts[0])
                    self._apply(model.victim.impact, parts[1])
                elif len(parts) == 1:
                    self._apply(model.victim.role, parts[0])

        # --- Attack Pattern → Capability ---
        ap = by_type.get("attack-pattern", {})
        if ap:
            self._apply(model.capability.description, ap.get("description"))

            phases = ap.get("kill_chain_phases", [])
            if isinstance(phases, list):
                model.capability.ttps = [
                    p["phase_name"]
                    for p in phases
                    if isinstance(p, dict) and p.get("phase_name")
                ]

            refs = ap.get("external_references", [])
            if isinstance(refs, list):
                model.capability.vulnerabilities = [
                    r["external_id"]
                    for r in refs
                    if isinstance(r, dict) and r.get("external_id")
                ]

        # --- Infrastructure → Infrastructure ---
        infra = by_type.get("infrastructure", {})
        if infra:
            self._apply(model.infrastructure.description, infra.get("name"))

            details = self._clean(infra.get("description"))
            if details:
                for segment in details.split("|"):
                    segment = segment.strip()
                    if segment.startswith("Domains:"):
                        model.infrastructure.domains = [
                            v.strip() for v in segment[len("Domains:"):].split(",") if v.strip()
                        ]
                    elif segment.startswith("IPs:"):
                        model.infrastructure.ips = [
                            v.strip() for v in segment[len("IPs:"):].split(",") if v.strip()
                        ]
                    elif segment.startswith("URLs:"):
                        model.infrastructure.urls = [
                            v.strip() for v in segment[len("URLs:"):].split(",") if v.strip()
                        ]
                    elif segment.startswith("Emails:"):
                        model.infrastructure.email_addresses = [
                            v.strip() for v in segment[len("Emails:"):].split(",") if v.strip()
                        ]
                    elif segment.startswith("Hosts:"):
                        model.infrastructure.hosts = [
                            v.strip() for v in segment[len("Hosts:"):].split(",") if v.strip()
                        ]

        # --- Report → Meta ---
        report = by_type.get("report", {})
        if report:
            summary = self._clean(report.get("description"))
            if summary:
                model.meta.summary = summary

        return model