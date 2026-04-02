"""
Module for constructing structured prompts for AI-assisted
Diamond Model of Intrusion Analysis via the Anthropic API.
"""

import json


class PromptManager:
    """
    Builds system and user prompts that instruct the AI model to perform
    structured Diamond Model analysis, returning well-formed JSON output
    with confidence scores and evidence attribution.
    """

    def build_system_prompt(self) -> str:
        """
        Construct the system prompt that establishes the AI's role,
        output format requirements, and analytical constraints.

        Returns:
            System prompt string.
        """
        return (
            "You are an expert cybersecurity analyst specializing in the Diamond Model "
            "of Intrusion Analysis. Your role is to analyze incident scenarios and extract "
            "structured intelligence across the four Diamond Model vertices: Adversary, "
            "Victim, Capability, and Infrastructure.\n\n"
            "You must adhere to the following rules:\n"
            "1. Always respond with a single valid JSON object — no prose, no markdown, "
            "no code fences.\n"
            "2. Clearly distinguish between EXPLICIT facts (directly stated in the scenario) "
            "and INFERRED claims (reasonably deduced). Use the 'source' field: "
            "'explicit' or 'inferred'.\n"
            "3. Never invent or fabricate details not supported by the scenario or evidence.\n"
            "4. Assign a confidence score (0.0 to 1.0) to each field based on the strength "
            "of available evidence.\n"
            "5. Populate the 'evidence' list for each field with direct quotes or references "
            "from the scenario that support the value.\n"
            "6. Leave fields as null if there is insufficient information to make a reasonable claim.\n"
            "7. Be concise, precise, and analytical."
        )

    def build_analysis_prompt(self, scenario_text: str, evidence: dict) -> str:
        """
        Construct the user prompt containing the scenario and pre-extracted
        evidence, instructing the AI to produce a structured Diamond Model mapping.

        Args:
            scenario_text: The normalized incident scenario text.
            evidence:      Dictionary of pre-extracted IOCs and keywords.

        Returns:
            User prompt string.
        """
        evidence_block = json.dumps(evidence, indent=2)

        return (
            f"Analyze the following incident scenario and map it to the Diamond Model "
            f"of Intrusion Analysis.\n\n"
            f"--- SCENARIO ---\n{scenario_text}\n\n"
            f"--- PRE-EXTRACTED EVIDENCE ---\n{evidence_block}\n\n"
            f"Produce a JSON object with the following top-level keys:\n\n"
            f"  adversary       — name, aliases, motivation, attribution, intent\n"
            f"  victim          — organization, sector, geography, role, impact\n"
            f"  capability      — description, tools, malware, ttps, vulnerabilities\n"
            f"  infrastructure  — description, domains, ips, urls, email_addresses, hosts\n"
            f"  meta            — summary, timestamps, analyst_notes, validation_warnings\n\n"
            f"For each descriptive field include:\n"
            f"  - 'value'      : the extracted string or null\n"
            f"  - 'confidence' : float between 0.0 and 1.0\n"
            f"  - 'source'     : 'explicit' or 'inferred'\n"
            f"  - 'evidence'   : list of supporting quotes or references from the scenario\n\n"
            f"List fields (tools, malware, ttps, ips, domains, etc.) should be plain string arrays.\n"
            f"Return only the JSON object. Do not include any explanation or surrounding text."
        )

    def build_messages(
        self, scenario_text: str, evidence: dict
    ) -> list[dict[str, str]]:
        """
        Assemble the full chat message list for the Gemini model,
        combining the system and user prompts.

        Args:
            scenario_text: The normalized incident scenario text.
            evidence:      Dictionary of pre-extracted IOCs and keywords.

        Returns:
            List of message dictionaries with 'role' and 'content' keys.
        """
        return [
            {
                "role": "system",
                "content": self.build_system_prompt(),
            },
            {
                "role": "user",
                "content": self.build_analysis_prompt(scenario_text, evidence),
            },
        ]