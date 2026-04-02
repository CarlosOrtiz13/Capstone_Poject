"""
Module for persisting and retrieving Diamond Model analysis attempt
history in a local JSON file, retaining the most recent entries.
"""

import json
import os
from typing import Any


class AttemptHistoryManager:
    """
    Manages a file-backed store of analysis attempt records,
    keeping the most recent attempts up to a configurable limit.
    """

    def __init__(
        self,
        file_path: str = "data/attempts.json",
        max_attempts: int = 10,
    ) -> None:
        self.file_path = file_path
        self.max_attempts = max_attempts

    def _ensure_directory(self) -> None:
        """Create the parent directory of the file path if it does not exist."""
        parent = os.path.dirname(self.file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def load_attempts(self) -> list[dict[str, Any]]:
        """
        Load all stored attempts from the JSON file.

        Returns:
            List of attempt dictionaries, or an empty list if the file
            does not exist or contains invalid JSON.
        """
        if not os.path.exists(self.file_path):
            return []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def save_attempt(self, attempt: dict[str, Any]) -> None:
        """
        Prepend a new attempt to the history and persist it to disk,
        trimming the list to the configured maximum length.

        Args:
            attempt: Serializable dictionary representing the analysis attempt.
        """
        attempts = self.load_attempts()
        attempts.insert(0, attempt)
        attempts = attempts[: self.max_attempts]
        self._ensure_directory()
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(attempts, f, indent=2)

    def get_recent_attempts(self) -> list[dict[str, Any]]:
        """
        Retrieve the stored list of recent analysis attempts.

        Returns:
            List of attempt dictionaries in reverse-chronological order.
        """
        return self.load_attempts()

    def clear_history(self) -> None:
        """
        Erase all stored attempts by overwriting the file with an empty list.
        """
        self._ensure_directory()
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)