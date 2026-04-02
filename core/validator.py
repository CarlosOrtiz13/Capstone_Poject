"""
Module for validating the completeness, confidence, evidence quality,
and human review state of a populated DiamondModel intrusion analysis object.
"""

from typing import Any

from models import DiamondModel


class Validator:
    """
    Evaluates a DiamondModel across four dimensions — completeness, confidence,
    evidence quality, and human review — producing a structured validation report
    with warnings, scores, and a stats block for analyst review.

    Validity rule:
        is_valid = True when completeness_score >= 0.75 and warnings <= 4.
        This reflects a practically useful model, not necessarily a perfect one.
    """

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def validate(self, model: DiamondModel) -> dict[str, Any]:
        """
        Validate the DiamondModel and return a structured report.

        Args:
            model: The DiamondModel instance to validate.

        Returns:
            Dictionary containing:
                - is_valid (bool)
                - warnings (list[str])
                - completeness_score (float)
                - confidence_score (float)
                - review_score (float)
                - stats (dict)
        """
        warnings: list[str] = []
        key_fields           = self._get_key_fields(model)

        # --- Completeness ---
        completeness_score = self._check_completeness(model, warnings)

        # --- Confidence ---
        confidence_score = self._check_confidence(key_fields, warnings)

        # --- Evidence ---
        self._check_evidence(model, key_fields, warnings)

        # --- ATT&CK / list quality ---
        ttp_count, malformed_ttp_count = self._check_ttps(model, warnings)

        # --- Human review ---
        review_score = self._check_review(key_fields, warnings)

        # --- Stats ---
        stats = self._build_stats(
            key_fields          = key_fields,
            ttp_count           = ttp_count,
            malformed_ttp_count = malformed_ttp_count,
        )

        # --- Validity rule ---
        is_valid = completeness_score >= 0.75 and len(warnings) <= 4

        return {
            "is_valid":           is_valid,
            "warnings":           warnings,
            "completeness_score": round(completeness_score, 2),
            "confidence_score":   round(confidence_score, 2),
            "review_score":       round(review_score, 2),
            "stats":              stats,
        }

    # -----------------------------------------------------------------------
    # Completeness
    # -----------------------------------------------------------------------

    def _check_completeness(
        self, model: DiamondModel, warnings: list[str]
    ) -> float:
        """Check each vertex for meaningful data and build the completeness score."""
        checks = {
            "adversary":      self._has_adversary_data(model),
            "victim":         self._has_victim_data(model),
            "capability":     self._has_capability_data(model),
            "infrastructure": self._has_infrastructure_data(model),
        }
        if not checks["adversary"]:
            warnings.append(
                "Adversary vertex is empty — no name, motivation, attribution, or intent found."
            )
        if not checks["victim"]:
            warnings.append(
                "Victim vertex is empty — no organization, sector, geography, role, or impact found."
            )
        if not checks["capability"]:
            warnings.append(
                "Capability vertex is empty — no description, tools, malware, TTPs, or vulnerabilities found."
            )
        if not checks["infrastructure"]:
            warnings.append(
                "Infrastructure vertex is empty — no domains, IPs, URLs, emails, or hosts found."
            )
        populated = sum(1 for v in checks.values() if v)
        return populated / len(checks)

    def _has_adversary_data(self, model: DiamondModel) -> bool:
        adv = model.adversary
        return (
            self._field_has_meaningful_value(adv.name)
            or self._field_has_meaningful_value(adv.motivation)
            or self._field_has_meaningful_value(adv.attribution)
            or self._field_has_meaningful_value(adv.intent)
            or bool(adv.aliases)
        )

    def _has_victim_data(self, model: DiamondModel) -> bool:
        vic = model.victim
        return (
            self._field_has_meaningful_value(vic.organization)
            or self._field_has_meaningful_value(vic.sector)
            or self._field_has_meaningful_value(vic.geography)
            or self._field_has_meaningful_value(vic.role)
            or self._field_has_meaningful_value(vic.impact)
        )

    def _has_capability_data(self, model: DiamondModel) -> bool:
        cap = model.capability
        return (
            self._field_has_meaningful_value(cap.description)
            or self._is_meaningful_list(cap.tools)
            or self._is_meaningful_list(cap.malware)
            or self._is_meaningful_list(cap.ttps)
            or self._is_meaningful_list(cap.vulnerabilities)
        )

    def _has_infrastructure_data(self, model: DiamondModel) -> bool:
        inf = model.infrastructure
        return (
            self._field_has_meaningful_value(inf.description)
            or self._is_meaningful_list(inf.domains)
            or self._is_meaningful_list(inf.ips)
            or self._is_meaningful_list(inf.urls)
            or self._is_meaningful_list(inf.email_addresses)
            or self._is_meaningful_list(inf.hosts)
        )

    # -----------------------------------------------------------------------
    # Confidence
    # -----------------------------------------------------------------------

    def _check_confidence(
        self, key_fields: list[Any], warnings: list[str]
    ) -> float:
        """Compute average confidence across populated key fields and warn on low values."""
        populated   = [f for f in key_fields if self._field_has_meaningful_value(f)]
        low_conf    = [f for f in populated if self._safe_confidence(f) < 0.5]
        inferred    = [f for f in populated if self._is_inferred_source(f)]

        if low_conf:
            warnings.append(
                f"{len(low_conf)} key field(s) have low confidence (< 0.5). "
                "Consider reviewing AI attribution quality."
            )
        if len(inferred) > len(populated) // 2 and populated:
            warnings.append(
                f"{len(inferred)} of {len(populated)} populated key fields are inferred. "
                "Human review is recommended."
            )

        if not populated:
            return 0.0
        return sum(self._safe_confidence(f) for f in populated) / len(populated)

    # -----------------------------------------------------------------------
    # Evidence
    # -----------------------------------------------------------------------

    def _check_evidence(
        self,
        model: DiamondModel,
        key_fields: list[Any],
        warnings: list[str],
    ) -> None:
        """Warn when populated fields lack evidence or infrastructure is too vague."""
        missing_ev = [
            f for f in key_fields
            if self._field_has_meaningful_value(f) and not self._has_evidence(f)
        ]
        if missing_ev:
            warnings.append(
                f"{len(missing_ev)} key field(s) have a value but no supporting evidence."
            )

        cap = model.capability
        if self._has_capability_data(model):
            cap_fields = [cap.description]
            if all(not self._has_evidence(f) for f in cap_fields):
                warnings.append(
                    "Capability vertex has data but no evidence citations — "
                    "consider adding supporting references."
                )

        inf = model.infrastructure
        has_ioc = (
            self._is_meaningful_list(inf.domains)
            or self._is_meaningful_list(inf.ips)
            or self._is_meaningful_list(inf.urls)
            or self._is_meaningful_list(inf.email_addresses)
            or self._is_meaningful_list(inf.hosts)
        )
        if self._field_has_meaningful_value(inf.description) and not has_ioc:
            warnings.append(
                "Infrastructure is described but lacks specific IOCs "
                "(domains, IPs, URLs, emails, or hosts)."
            )

    # -----------------------------------------------------------------------
    # ATT&CK / TTP quality
    # -----------------------------------------------------------------------

    def _check_ttps(
        self, model: DiamondModel, warnings: list[str]
    ) -> tuple[int, int]:
        """
        Inspect capability.ttps for quality issues.

        Returns:
            Tuple of (ttp_count, malformed_ttp_count).
        """
        ttps = [t for t in model.capability.ttps if isinstance(t, str) and t.strip()]
        ttp_count = len(ttps)

        seen:      set[str] = set()
        malformed: list[str] = []
        duplicates: list[str] = []

        for t in ttps:
            clean = t.strip()
            if len(clean) < 4:
                malformed.append(clean)
            if clean.lower() in seen:
                duplicates.append(clean)
            seen.add(clean.lower())

        malformed_ttp_count = len(malformed)

        if malformed:
            warnings.append(
                f"{malformed_ttp_count} TTP entry/entries appear malformed or too short."
            )
        if duplicates:
            warnings.append(
                f"{len(duplicates)} duplicate TTP entry/entries detected."
            )
        cap = model.capability
        if ttp_count > 5 and not self._field_has_meaningful_value(cap.description):
            warnings.append(
                f"Capability has {ttp_count} TTPs but the description field is weak or empty."
            )

        return ttp_count, malformed_ttp_count

    # -----------------------------------------------------------------------
    # Human review
    # -----------------------------------------------------------------------

    def _check_review(
        self, key_fields: list[Any], warnings: list[str]
    ) -> float:
        """Compute the review score and warn if no key fields have been approved."""
        populated = [f for f in key_fields if self._field_has_meaningful_value(f)]
        approved  = [f for f in populated if getattr(f, "approved", False)]

        if populated and not approved:
            warnings.append(
                "No key fields have been approved by a human analyst. "
                "Please review and approve AI-generated values."
            )
        elif populated and len(approved) < len(populated) // 2:
            warnings.append(
                f"Only {len(approved)} of {len(populated)} populated key fields "
                "have been approved. Further human review is recommended."
            )

        if not populated:
            return 0.0
        return len(approved) / len(populated)

    # -----------------------------------------------------------------------
    # Stats
    # -----------------------------------------------------------------------

    def _build_stats(
        self,
        key_fields: list[Any],
        ttp_count: int,
        malformed_ttp_count: int,
    ) -> dict[str, Any]:
        """Assemble the stats block from computed field-level metrics."""
        populated  = [f for f in key_fields if self._field_has_meaningful_value(f)]
        low_conf   = [f for f in populated if self._safe_confidence(f) < 0.5]
        inferred   = [f for f in populated if self._is_inferred_source(f)]
        approved   = [f for f in populated if getattr(f, "approved", False)]
        no_ev      = [
            f for f in populated if not self._has_evidence(f)
        ]
        return {
            "total_key_fields":       len(key_fields),
            "populated_key_fields":   len(populated),
            "low_confidence_fields":  len(low_conf),
            "inferred_fields":        len(inferred),
            "approved_fields":        len(approved),
            "fields_missing_evidence": len(no_ev),
            "ttp_count":              ttp_count,
            "malformed_ttp_count":    malformed_ttp_count,
        }

    # -----------------------------------------------------------------------
    # Field helpers
    # -----------------------------------------------------------------------

    def _get_key_fields(self, model: DiamondModel) -> list[Any]:
        """
        Return the list of important scalar FieldValue objects used for
        confidence, evidence, and review scoring.
        """
        return [
            model.adversary.name,
            model.adversary.motivation,
            model.adversary.attribution,
            model.adversary.intent,
            model.victim.organization,
            model.victim.sector,
            model.victim.geography,
            model.victim.impact,
            model.capability.description,
            model.infrastructure.description,
        ]

    def _field_has_meaningful_value(self, field: Any) -> bool:
        """Return True if the field has a non-empty string value."""
        try:
            return isinstance(field.value, str) and bool(field.value.strip())
        except AttributeError:
            return False

    def _safe_confidence(self, field: Any) -> float:
        """Return the field's confidence as a float, defaulting to 0.0."""
        try:
            return float(field.confidence)
        except (AttributeError, TypeError, ValueError):
            return 0.0

    def _is_inferred_source(self, field: Any) -> bool:
        """Return True if the field source is 'inferred'."""
        try:
            return str(field.source).lower() == "inferred"
        except AttributeError:
            return False

    def _has_evidence(self, field: Any) -> bool:
        """Return True if the field has at least one non-empty evidence entry."""
        try:
            return any(
                isinstance(e, str) and e.strip()
                for e in field.evidence
            )
        except (AttributeError, TypeError):
            return False

    def _is_meaningful_list(self, lst: Any) -> bool:
        """Return True if the list contains at least one non-empty string."""
        if not isinstance(lst, list):
            return False
        return any(isinstance(item, str) and item.strip() for item in lst)