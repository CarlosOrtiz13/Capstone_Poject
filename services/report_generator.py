"""
Module for generating a human-readable PDF report from a populated
DiamondModel, extracted evidence, and validation results using ReportLab.
"""

import io
import textwrap
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from models import DiamondModel


class ReportGenerator:
    """
    Generates a clean, readable PDF report from a DiamondModel analysis,
    including scenario text, extracted evidence, Diamond Model vertex
    details, and validation results. Output is returned as raw bytes.
    """

    # Layout constants
    _MARGIN_X        = 50
    _TOP_Y           = 730
    _BOTTOM_Y        = 60
    _LINE_HEIGHT     = 14
    _SECTION_SPACING = 10
    _FONT_BODY       = "Helvetica"
    _FONT_BOLD       = "Helvetica-Bold"
    _FONT_TITLE      = "Helvetica-Bold"
    _SIZE_TITLE      = 16
    _SIZE_SECTION    = 12
    _SIZE_BODY       = 9

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _wrap_text(self, text: str, max_len: int = 90) -> list[str]:
        """
        Wrap a string into lines no longer than max_len characters.

        Args:
            text:    Input string to wrap.
            max_len: Maximum characters per line.

        Returns:
            List of wrapped line strings.
        """
        if not text:
            return ["—"]
        return textwrap.wrap(text, width=max_len) or ["—"]

    def _new_page(self, pdf: canvas.Canvas) -> int:
        """
        Start a new PDF page and return the starting Y position.

        Args:
            pdf: Active ReportLab canvas.

        Returns:
            Initial Y coordinate for the new page.
        """
        pdf.showPage()
        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)
        return self._TOP_Y

    def _check_space(self, pdf: canvas.Canvas, y: int, needed: int = 30) -> int:
        """
        Start a new page if there is insufficient space remaining.

        Args:
            pdf:    Active ReportLab canvas.
            y:      Current Y position.
            needed: Minimum space required before triggering a new page.

        Returns:
            Updated Y position.
        """
        if y < self._BOTTOM_Y + needed:
            y = self._new_page(pdf)
        return y

    def _draw_section_title(
        self, pdf: canvas.Canvas, title: str, x: int, y: int
    ) -> int:
        """
        Draw a bold section title and return the updated Y position.

        Args:
            pdf:   Active ReportLab canvas.
            title: Section title string.
            x:     Left margin X coordinate.
            y:     Current Y position.

        Returns:
            Updated Y position after drawing.
        """
        y -= self._SECTION_SPACING
        y  = self._check_space(pdf, y, needed=40)
        pdf.setFont(self._FONT_BOLD, self._SIZE_SECTION)
        pdf.drawString(x, y, title)
        y -= 4
        pdf.line(x, y, x + 500, y)
        y -= self._LINE_HEIGHT
        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)
        return y

    def _draw_lines(
        self,
        pdf: canvas.Canvas,
        lines: list[str],
        x: int,
        y: int,
        line_height: int = 14,
        indent: int = 0,
    ) -> int:
        """
        Draw a list of text lines and return the updated Y position.

        Args:
            pdf:         Active ReportLab canvas.
            lines:       List of strings to render.
            x:           Left margin X coordinate.
            y:           Current Y position.
            line_height: Vertical spacing between lines.
            indent:      Additional horizontal indent in points.

        Returns:
            Updated Y position after drawing all lines.
        """
        for line in lines:
            y = self._check_space(pdf, y)
            pdf.drawString(x + indent, y, line)
            y -= line_height
        return y

    def _draw_field(
        self,
        pdf: canvas.Canvas,
        label: str,
        field: dict[str, Any],
        x: int,
        y: int,
    ) -> int:
        """
        Draw a single FieldValue dict as a labelled block.

        Args:
            pdf:   Active ReportLab canvas.
            label: Field display name.
            field: FieldValue dictionary.
            x:     Left margin X coordinate.
            y:     Current Y position.

        Returns:
            Updated Y position.
        """
        value      = field.get("value") or "—"
        confidence = field.get("confidence", 0.0)
        source     = field.get("source", "unknown")
        evidence   = field.get("evidence", [])
        notes      = field.get("notes")

        pdf.setFont(self._FONT_BOLD, self._SIZE_BODY)
        y = self._check_space(pdf, y)
        pdf.drawString(x, y, f"{label}:")
        y -= self._LINE_HEIGHT
        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)

        for line in self._wrap_text(value):
            y = self._check_space(pdf, y)
            pdf.drawString(x + 10, y, line)
            y -= self._LINE_HEIGHT

        meta_line = f"Confidence: {confidence:.0%}   Source: {source}"
        y = self._check_space(pdf, y)
        pdf.setFillColorRGB(0.4, 0.4, 0.4)
        pdf.drawString(x + 10, y, meta_line)
        pdf.setFillColorRGB(0, 0, 0)
        y -= self._LINE_HEIGHT

        if evidence:
            y = self._check_space(pdf, y)
            pdf.setFont(self._FONT_BOLD, self._SIZE_BODY - 1)
            pdf.drawString(x + 10, y, "Evidence:")
            y -= self._LINE_HEIGHT
            pdf.setFont(self._FONT_BODY, self._SIZE_BODY - 1)
            for ev in evidence[:3]:
                for line in self._wrap_text(f"• {ev}", max_len=85):
                    y = self._check_space(pdf, y)
                    pdf.drawString(x + 16, y, line)
                    y -= self._LINE_HEIGHT

        if notes:
            y = self._check_space(pdf, y)
            pdf.setFont(self._FONT_BOLD, self._SIZE_BODY - 1)
            pdf.drawString(x + 10, y, f"Note: {notes}")
            y -= self._LINE_HEIGHT

        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)
        y -= 4
        return y

    def _draw_string_list(
        self,
        pdf: canvas.Canvas,
        label: str,
        items: list[str],
        x: int,
        y: int,
    ) -> int:
        """
        Draw a labelled bullet list of plain strings.

        Args:
            pdf:   Active ReportLab canvas.
            label: List section label.
            items: List of strings to render.
            x:     Left margin X coordinate.
            y:     Current Y position.

        Returns:
            Updated Y position.
        """
        if not items:
            return y
        pdf.setFont(self._FONT_BOLD, self._SIZE_BODY)
        y = self._check_space(pdf, y)
        pdf.drawString(x, y, f"{label}:")
        y -= self._LINE_HEIGHT
        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)
        for item in items:
            for line in self._wrap_text(f"• {item}", max_len=85):
                y = self._check_space(pdf, y)
                pdf.drawString(x + 10, y, line)
                y -= self._LINE_HEIGHT
        y -= 4
        return y

    # -----------------------------------------------------------------------
    # Main method
    # -----------------------------------------------------------------------

    def generate_pdf(
        self,
        model: DiamondModel,
        evidence: dict[str, Any],
        validation: dict[str, Any],
        scenario_text: str,
        attempt_id: str = "",
        timestamp: str = "",
    ) -> bytes:
        """
        Generate a PDF report and return it as bytes.

        Args:
            model:         Populated DiamondModel instance.
            evidence:      Dictionary of extracted IOCs and keywords.
            validation:    Validation report dictionary.
            scenario_text: Normalized scenario text.
            attempt_id:    Optional unique attempt identifier.
            timestamp:     Optional ISO timestamp string.

        Returns:
            Raw PDF bytes suitable for download or storage.
        """
        buffer = io.BytesIO()
        pdf    = canvas.Canvas(buffer, pagesize=letter)
        x      = self._MARGIN_X
        y      = self._TOP_Y
        d      = model.to_dict()

        # --- Title ---
        pdf.setFont(self._FONT_TITLE, self._SIZE_TITLE)
        pdf.drawString(x, y + 20, "Diamond Model — Intrusion Analysis Report")
        pdf.setFont(self._FONT_BODY, self._SIZE_BODY)
        y -= 10

        if attempt_id:
            y = self._check_space(pdf, y)
            pdf.drawString(x, y, f"Attempt ID : {attempt_id}")
            y -= self._LINE_HEIGHT
        if timestamp:
            y = self._check_space(pdf, y)
            pdf.drawString(x, y, f"Timestamp  : {timestamp}")
            y -= self._LINE_HEIGHT

        # --- Scenario Summary ---
        y = self._draw_section_title(pdf, "Scenario Summary", x, y)
        for line in self._wrap_text(scenario_text, max_len=90):
            y = self._check_space(pdf, y)
            pdf.drawString(x, y, line)
            y -= self._LINE_HEIGHT

        # --- Extracted Evidence ---
        y = self._draw_section_title(pdf, "Extracted Evidence", x, y)
        for key, items in evidence.items():
            if items:
                y = self._draw_string_list(pdf, key.upper(), items, x, y)

        # --- Adversary ---
        y  = self._draw_section_title(pdf, "Adversary", x, y)
        adv = d.get("adversary", {})
        y  = self._draw_field(pdf, "Name",        adv.get("name", {}),        x, y)
        y  = self._draw_field(pdf, "Motivation",  adv.get("motivation", {}),  x, y)
        y  = self._draw_field(pdf, "Attribution", adv.get("attribution", {}), x, y)
        y  = self._draw_field(pdf, "Intent",      adv.get("intent", {}),      x, y)
        aliases = adv.get("aliases", [])
        if aliases:
            y = self._draw_string_list(pdf, "Aliases", aliases, x, y)

        # --- Victim ---
        y   = self._draw_section_title(pdf, "Victim", x, y)
        vic = d.get("victim", {})
        y   = self._draw_field(pdf, "Organization", vic.get("organization", {}), x, y)
        y   = self._draw_field(pdf, "Sector",       vic.get("sector", {}),       x, y)
        y   = self._draw_field(pdf, "Geography",    vic.get("geography", {}),    x, y)
        y   = self._draw_field(pdf, "Role",         vic.get("role", {}),         x, y)
        y   = self._draw_field(pdf, "Impact",       vic.get("impact", {}),       x, y)

        # --- Capability ---
        y   = self._draw_section_title(pdf, "Capability", x, y)
        cap = d.get("capability", {})
        y   = self._draw_field(pdf, "Description", cap.get("description", {}), x, y)
        y   = self._draw_string_list(pdf, "Tools",           cap.get("tools", []),           x, y)
        y   = self._draw_string_list(pdf, "Malware",         cap.get("malware", []),         x, y)
        y   = self._draw_string_list(pdf, "TTPs",            cap.get("ttps", []),            x, y)
        y   = self._draw_string_list(pdf, "Vulnerabilities", cap.get("vulnerabilities", []), x, y)

        # --- Infrastructure ---
        y   = self._draw_section_title(pdf, "Infrastructure", x, y)
        inf = d.get("infrastructure", {})
        y   = self._draw_field(pdf, "Description", inf.get("description", {}), x, y)
        y   = self._draw_string_list(pdf, "Domains",         inf.get("domains", []),          x, y)
        y   = self._draw_string_list(pdf, "IP Addresses",    inf.get("ips", []),              x, y)
        y   = self._draw_string_list(pdf, "URLs",            inf.get("urls", []),             x, y)
        y   = self._draw_string_list(pdf, "Email Addresses", inf.get("email_addresses", []),  x, y)
        y   = self._draw_string_list(pdf, "Hosts",           inf.get("hosts", []),            x, y)

        # --- Validation ---
        y    = self._draw_section_title(pdf, "Validation", x, y)
        score = validation.get("completeness_score", 0.0)
        valid = validation.get("is_valid", False)
        y    = self._check_space(pdf, y)
        pdf.drawString(x, y, f"Completeness Score : {score:.0%}")
        y -= self._LINE_HEIGHT
        y  = self._check_space(pdf, y)
        pdf.drawString(x, y, f"Is Valid           : {'Yes' if valid else 'No'}")
        y -= self._LINE_HEIGHT

        warnings = validation.get("warnings", [])
        if warnings:
            y = self._draw_string_list(pdf, "Warnings", warnings, x, y)
        else:
            y = self._check_space(pdf, y)
            pdf.drawString(x, y, "No validation warnings.")
            y -= self._LINE_HEIGHT

        pdf.save()
        return buffer.getvalue()