"""
Module for extracting structured threat indicators and keywords
from free-form incident scenario text using regex-based patterns.
"""

import re


class EvidenceExtractor:
    """
    Extracts structured indicators of compromise (IOCs) and attack-related
    keywords from raw scenario text, supporting downstream Diamond Model
    population and AI-assisted analysis.
    """

    _ATTACK_KEYWORDS: list[str] = [
        "phishing",
        "spearphishing",
        "powershell",
        "ransomware",
        "c2",
        "command and control",
        "persistence",
        "exfiltration",
        "lateral movement",
        "credential dumping",
        "malware",
        "supply chain",
        "privilege escalation",
        "defense evasion",
        "reconnaissance",
        "backdoor",
        "trojan",
        "rootkit",
        "exploit",
        "zero-day",
    ]

    # Extensions that are never valid domain TLDs
    _NON_DOMAIN_EXTENSIONS: set[str] = {
        "dll", "exe", "bin", "zip", "tar", "gz", "pdf", "doc",
        "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "log",
        "json", "xml", "js", "py", "ps1", "bat", "sh", "png", "jpg",
        "jpeg", "gif", "svg", "mp4", "mp3", "wav",
        "handler", "manager", "service", "client", "server", "agent",
        "helper", "worker", "runner", "loader", "driver", "update",
        "config", "setup", "install", "local", "internal", "external",
    }

    def _unique_sorted(self, values: list[str]) -> list[str]:
        """Return a deduplicated, sorted list of strings."""
        return sorted(set(values))

    def _defang(self, text: str) -> str:
        """
        Normalize defanged IOC notation used by security analysts
        into standard form for pattern matching.

        Args:
            text: Raw input string potentially containing defanged IOCs.

        Returns:
            String with defanging reversed.
        """
        text = text.replace("hxxps://", "https://")
        text = text.replace("hxxp://", "http://")
        text = text.replace("[.]", ".")
        text = text.replace("[@]", "@")
        text = text.replace("[at]", "@")
        return text

    def extract_ips(self, text: str) -> list[str]:
        """
        Extract IPv4 addresses from text.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of IPv4 address strings.
        """
        if not text:
            return []
        text = self._defang(text)
        pattern = (
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        )
        return self._unique_sorted(re.findall(pattern, text))

    def extract_domains(self, text: str) -> list[str]:
        """
        Extract valid domain names from text, excluding IPs, file extensions,
        and other non-domain matches.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of domain name strings.
        """
        if not text:
            return []
        text = self._defang(text)
        pattern = (
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"([a-zA-Z]{2,})\b"
        )
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        matches = re.finditer(pattern, text)
        domains = []
        for m in matches:
            full = m.group(0)
            tld = m.group(1).lower()
            if ip_pattern.match(full):
                continue
            if tld in self._NON_DOMAIN_EXTENSIONS:
                continue
            domains.append(full)
        return self._unique_sorted(domains)

    def extract_urls(self, text: str) -> list[str]:
        """
        Extract HTTP and HTTPS URLs from text, including defanged variants.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of URL strings.
        """
        if not text:
            return []
        text = self._defang(text)
        pattern = r"https?://[^\s\"'<>\)\]]+"
        return self._unique_sorted(re.findall(pattern, text))

    def extract_emails(self, text: str) -> list[str]:
        """
        Extract email addresses from text, including defanged variants.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of email address strings.
        """
        if not text:
            return []
        text = self._defang(text)
        pattern = r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        return self._unique_sorted(re.findall(pattern, text))

    def extract_cves(self, text: str) -> list[str]:
        """
        Extract CVE identifiers from text.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of CVE ID strings.
        """
        if not text:
            return []
        pattern = r"\bCVE-\d{4}-\d{4,7}\b"
        return self._unique_sorted(re.findall(pattern, text, re.IGNORECASE))

    def extract_hashes(self, text: str) -> list[str]:
        """
        Extract MD5 (32), SHA-1 (40), and SHA-256 (64) hex hashes from text.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of hash strings.
        """
        if not text:
            return []
        pattern = (
            r"\b[0-9a-fA-F]{64}\b"
            r"|\b[0-9a-fA-F]{40}\b"
            r"|\b[0-9a-fA-F]{32}\b"
        )
        return self._unique_sorted(re.findall(pattern, text))

    def extract_attack_keywords(self, text: str) -> list[str]:
        """
        Identify known attack technique keywords present in text.

        Args:
            text: Raw input string.

        Returns:
            Sorted unique list of matched attack keyword strings.
        """
        if not text:
            return []
        lower = text.lower()
        matched = [kw for kw in self._ATTACK_KEYWORDS if kw in lower]
        return self._unique_sorted(matched)

    def extract_all(self, text: str) -> dict[str, list[str]]:
        """
        Run all extractors and return a unified dictionary of indicators.

        Args:
            text: Raw input string.

        Returns:
            Dictionary with keys: ips, domains, urls, emails, cves, hashes, keywords.
        """
        return {
            "ips":      self.extract_ips(text),
            "domains":  self.extract_domains(text),
            "urls":     self.extract_urls(text),
            "emails":   self.extract_emails(text),
            "cves":     self.extract_cves(text),
            "hashes":   self.extract_hashes(text),
            "keywords": self.extract_attack_keywords(text),
        }