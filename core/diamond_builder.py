"""
Module for mapping parsed AI output and extracted evidence
into a structured DiamondModel object.
"""

from typing import Any

from models import DiamondModel


class DiamondModelBuilder:
    """
    Constructs a populated DiamondModel from parsed AI response data
    and pre-extracted evidence, handling missing or malformed values
    defensively throughout.
    """

    def _safe_str(self, value: Any) -> str | None:
        """Return a stripped string if meaningful, else None."""
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def _safe_list(self, value: Any) -> list[str]:
        """
        Return a cleaned list of non-empty strings.
        If items are dicts with a 'value' key, extract that key.
        """
        if not isinstance(value, list):
            return []
        result = []
        for item in value:
            if isinstance(item, dict):
                text = self._safe_str(item.get("value"))
            else:
                text = self._safe_str(str(item))
            if text:
                result.append(text)
        return result

    def _merge_unique(self, first: list[str], second: list[str]) -> list[str]:
        """Merge two lists into a deduplicated ordered list."""
        seen: set[str] = set()
        result: list[str] = []
        for item in first + second:
            if item and item not in seen:
                seen.add(item)
                result.append(item)
        return result

    def _apply_field(self, field_obj: Any, raw_field: Any, source: str = "ai") -> None:
        """
        Populate a FieldValue from a raw AI field dictionary, applying
        value, source, confidence, and evidence where available.

        Args:
            field_obj: A FieldValue instance to update.
            raw_field: Raw dict from AI response, or a plain value.
            source:    Fallback source label if not present in raw_field.
        """
        if not isinstance(raw_field, dict):
            text = self._safe_str(raw_field)
            if text is not None:
                field_obj.value = text
                field_obj.source = source
            return

        text = self._safe_str(raw_field.get("value"))
        if text is not None:
            field_obj.value = text
            field_obj.source = raw_field.get("source") or source

        confidence = raw_field.get("confidence")
        if isinstance(confidence, (int, float)):
            field_obj.confidence = float(confidence)

        evidence = raw_field.get("evidence")
        if isinstance(evidence, list):
            cleaned = [str(e).strip() for e in evidence if str(e).strip()]
            if cleaned:
                field_obj.evidence = cleaned

    def build(
        self, parsed_ai: dict[str, Any], evidence: dict[str, Any]
    ) -> DiamondModel:
        """
        Build and return a populated DiamondModel from AI-parsed data
        and pre-extracted evidence indicators.

        Args:
            parsed_ai: Validated dictionary from the AI response parser.
            evidence:  Dictionary of pre-extracted IOCs and keywords.

        Returns:
            A DiamondModel instance populated with available data.
        """
        model = DiamondModel()

        ai_adv  = parsed_ai.get("adversary")     or {}
        ai_vic  = parsed_ai.get("victim")         or {}
        ai_cap  = parsed_ai.get("capability")     or {}
        ai_inf  = parsed_ai.get("infrastructure") or {}
        ai_meta = parsed_ai.get("meta")           or {}

        # --- Adversary ---
        self._apply_field(model.adversary.name,        ai_adv.get("name"))
        self._apply_field(model.adversary.motivation,  ai_adv.get("motivation"))
        self._apply_field(model.adversary.attribution, ai_adv.get("attribution"))
        self._apply_field(model.adversary.intent,      ai_adv.get("intent"))
        model.adversary.aliases = self._safe_list(ai_adv.get("aliases"))

        # --- Victim ---
        self._apply_field(model.victim.organization, ai_vic.get("organization"))
        self._apply_field(model.victim.sector,       ai_vic.get("sector"))
        self._apply_field(model.victim.geography,    ai_vic.get("geography"))
        self._apply_field(model.victim.role,         ai_vic.get("role"))
        self._apply_field(model.victim.impact,       ai_vic.get("impact"))

        # --- Capability ---
        self._apply_field(model.capability.description, ai_cap.get("description"))
        model.capability.tools           = self._safe_list(ai_cap.get("tools"))
        model.capability.malware         = self._safe_list(ai_cap.get("malware"))
        model.capability.ttps            = self._safe_list(ai_cap.get("ttps"))
        model.capability.vulnerabilities = self._safe_list(ai_cap.get("vulnerabilities"))

        keywords = [
            item if isinstance(item, str) else ""
            for item in evidence.get("keywords", [])
        ]
        keywords = [k for k in keywords if k]
        if keywords and model.capability.description.is_empty():
            model.capability.description.value  = "Observed techniques: " + ", ".join(keywords)
            model.capability.description.source = "evidence"

        # --- Infrastructure ---
        self._apply_field(model.infrastructure.description, ai_inf.get("description"))

        model.infrastructure.domains = self._merge_unique(
            self._safe_list(ai_inf.get("domains")),
            evidence.get("domains", []),
        )
        model.infrastructure.ips = self._merge_unique(
            self._safe_list(ai_inf.get("ips")),
            evidence.get("ips", []),
        )
        model.infrastructure.urls = self._merge_unique(
            self._safe_list(ai_inf.get("urls")),
            evidence.get("urls", []),
        )
        model.infrastructure.email_addresses = self._merge_unique(
            self._safe_list(ai_inf.get("email_addresses")),
            evidence.get("emails", []),
        )
        model.infrastructure.hosts = self._safe_list(ai_inf.get("hosts"))

        # --- Meta ---
        summary = self._safe_str(ai_meta.get("summary"))
        if summary:
            model.meta.summary = summary

        model.meta.timestamps          = self._safe_list(ai_meta.get("timestamps"))
        model.meta.analyst_notes       = self._safe_list(ai_meta.get("analyst_notes"))
        model.meta.validation_warnings = self._safe_list(ai_meta.get("validation_warnings"))

        return model