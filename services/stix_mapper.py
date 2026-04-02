"""
Module for mapping a populated DiamondModel into a STIX-like JSON bundle,
supporting a practical subset of STIX 2.1 object types for in-app use.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from models import DiamondModel


class StixMapper:
    """
    Converts a DiamondModel instance into a STIX-like bundle containing
    threat-actor, identity, attack-pattern, infrastructure, report, and
    relationship objects. Covers a practical subset of STIX 2.1 — focused
    on correctness and usability over full specification compliance.
    """

    def _new_stix_id(self, object_type: str) -> str:
        """
        Generate a STIX-format ID for a given object type.

        Args:
            object_type: STIX object type string (e.g. 'threat-actor').

        Returns:
            ID string in the form 'type--uuid4'.
        """
        return f"{object_type}--{uuid.uuid4()}"

    def _timestamp(self) -> str:
        """
        Return the current UTC time as a STIX-compatible ISO 8601 string.

        Returns:
            Timestamp string ending in 'Z'.
        """
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _clean(self, value: str | None) -> str | None:
        """
        Return a stripped string if meaningful, otherwise None.

        Args:
            value: Raw string value or None.

        Returns:
            Stripped string or None.
        """
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        now: str,
    ) -> dict[str, Any]:
        """
        Build a STIX relationship object between two entities.

        Args:
            source_id:         STIX ID of the source object.
            target_id:         STIX ID of the target object.
            relationship_type: Relationship label (e.g. 'uses').
            now:               Shared timestamp string.

        Returns:
            STIX relationship dictionary.
        """
        return {
            "type":              "relationship",
            "spec_version":      "2.1",
            "id":                self._new_stix_id("relationship"),
            "created":           now,
            "modified":          now,
            "relationship_type": relationship_type,
            "source_ref":        source_id,
            "target_ref":        target_id,
        }

    def to_bundle(self, model: DiamondModel) -> dict[str, Any]:
        """
        Convert a DiamondModel into a STIX-like bundle.

        Includes threat-actor, identity, attack-pattern, infrastructure,
        report, and relationship objects where sufficient data exists.
        Objects are only created when the model contains meaningful values
        for their required fields.

        Args:
            model: A populated DiamondModel instance.

        Returns:
            A STIX-like bundle dictionary ready for JSON serialization.
        """
        now = self._timestamp()
        objects: list[dict[str, Any]] = []

        threat_actor_id    = None
        identity_id        = None
        attack_pattern_id  = None
        infrastructure_id  = None

        # --- Threat Actor (Adversary) ---
        adv_name = self._clean(model.adversary.name.value)
        if adv_name:
            threat_actor_id = self._new_stix_id("threat-actor")
            obj: dict[str, Any] = {
                "type":         "threat-actor",
                "spec_version": "2.1",
                "id":           threat_actor_id,
                "created":      now,
                "modified":     now,
                "name":         adv_name,
            }
            if model.adversary.aliases:
                obj["aliases"] = model.adversary.aliases
            motivation = self._clean(model.adversary.motivation.value)
            if motivation:
                obj["primary_motivation"] = motivation
            attribution = self._clean(model.adversary.attribution.value)
            if attribution:
                obj["description"] = attribution
            intent = self._clean(model.adversary.intent.value)
            if intent:
                obj["goals"] = [intent]
            objects.append(obj)

        # --- Identity (Victim) ---
        org_name = self._clean(model.victim.organization.value)
        if org_name:
            identity_id = self._new_stix_id("identity")
            obj = {
                "type":           "identity",
                "spec_version":   "2.1",
                "id":             identity_id,
                "created":        now,
                "modified":       now,
                "name":           org_name,
                "identity_class": "organization",
            }
            sector = self._clean(model.victim.sector.value)
            if sector:
                obj["sectors"] = [sector]
            geography = self._clean(model.victim.geography.value)
            if geography:
                obj["contact_information"] = geography
            impact = self._clean(model.victim.impact.value)
            role = self._clean(model.victim.role.value)
            if impact or role:
                obj["description"] = " | ".join(
                    filter(None, [role, impact])
                )
            objects.append(obj)

        # --- Attack Pattern (Capability) ---
        cap_desc = self._clean(model.capability.description.value)
        if cap_desc:
            attack_pattern_id = self._new_stix_id("attack-pattern")
            obj = {
                "type":         "attack-pattern",
                "spec_version": "2.1",
                "id":           attack_pattern_id,
                "created":      now,
                "modified":     now,
                "name":         (cap_desc[:80] + "…") if len(cap_desc) > 80 else cap_desc,
                "description":  cap_desc,
            }
            if model.capability.ttps:
                obj["kill_chain_phases"] = [
                    {"kill_chain_name": "diamond-model", "phase_name": ttp}
                    for ttp in model.capability.ttps
                ]
            external_refs = []
            for vuln in model.capability.vulnerabilities:
                external_refs.append({
                    "source_name": "cve",
                    "external_id": vuln,
                })
            if external_refs:
                obj["external_references"] = external_refs
            objects.append(obj)

        # --- Infrastructure ---
        inf_desc = self._clean(model.infrastructure.description.value)
        has_inf_data = (
            inf_desc
            or model.infrastructure.domains
            or model.infrastructure.ips
            or model.infrastructure.urls
            or model.infrastructure.email_addresses
            or model.infrastructure.hosts
        )
        if has_inf_data:
            infrastructure_id = self._new_stix_id("infrastructure")
            obj = {
                "type":             "infrastructure",
                "spec_version":     "2.1",
                "id":               infrastructure_id,
                "created":          now,
                "modified":         now,
                "name":             inf_desc or "Adversary Infrastructure",
                "infrastructure_types": ["unknown"],
            }
            details: list[str] = []
            if model.infrastructure.domains:
                details.append("Domains: " + ", ".join(model.infrastructure.domains))
            if model.infrastructure.ips:
                details.append("IPs: " + ", ".join(model.infrastructure.ips))
            if model.infrastructure.urls:
                details.append("URLs: " + ", ".join(model.infrastructure.urls))
            if model.infrastructure.email_addresses:
                details.append("Emails: " + ", ".join(model.infrastructure.email_addresses))
            if model.infrastructure.hosts:
                details.append("Hosts: " + ", ".join(model.infrastructure.hosts))
            if details:
                obj["description"] = " | ".join(details)
            objects.append(obj)

        # --- Relationships ---
        if threat_actor_id and attack_pattern_id:
            objects.append(self._relationship(
                threat_actor_id, attack_pattern_id, "uses", now
            ))
        if threat_actor_id and infrastructure_id:
            objects.append(self._relationship(
                threat_actor_id, infrastructure_id, "uses", now
            ))
        if attack_pattern_id and identity_id:
            objects.append(self._relationship(
                attack_pattern_id, identity_id, "targets", now
            ))
        if infrastructure_id and identity_id:
            objects.append(self._relationship(
                infrastructure_id, identity_id, "targets", now
            ))

        # --- Report (Meta) ---
        summary = self._clean(model.meta.summary)
        if summary and objects:
            report_refs = [
                obj["id"] for obj in objects
                if obj.get("type") != "relationship"
            ]
            objects.append({
                "type":         "report",
                "spec_version": "2.1",
                "id":           self._new_stix_id("report"),
                "created":      now,
                "modified":     now,
                "name":         "Diamond Model Intrusion Analysis Report",
                "description":  summary,
                "published":    now,
                "object_refs":  report_refs,
            })

        return {
            "type":    "bundle",
            "id":      self._new_stix_id("bundle"),
            "objects": objects,
        }