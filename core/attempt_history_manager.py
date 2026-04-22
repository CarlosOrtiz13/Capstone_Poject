"""
Module for persisting and retrieving Diamond Model analysis attempt
history as individual JSON files inside a data directory, retaining
only the most recent attempts.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class AttemptHistoryManager:
    """
    Manages per-file storage of analysis attempt records. Each attempt
    is saved as its own JSON file named analysis_YYYYMMDD_HHMMSS_microseconds.json
    inside the configured data directory. Only the most recent max_attempts
    files are retained; older files are deleted automatically after each save.
    """

    _FILENAME_PREFIX  = "analysis_"
    _FILENAME_PATTERN = "analysis_*.json"

    def __init__(
        self,
        data_dir: str = "data",
        max_attempts: int = 10,
    ) -> None:
        """
        Initialise the manager with a target directory and retention limit.

        Args:
            data_dir:     Path to the folder where attempt files are stored.
            max_attempts: Maximum number of attempt files to keep on disk.
        """
        self.data_dir    = Path(data_dir)
        self.max_attempts = max_attempts

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _ensure_directory(self) -> None:
        """Create the data directory if it does not already exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _generate_filename(self) -> Path:
        """
        Generate a unique attempt filename using the current timestamp
        with microsecond precision to prevent collisions.

        Returns:
            Path object for the new file inside the data directory.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return self.data_dir / f"{self._FILENAME_PREFIX}{timestamp}.json"

    def _list_attempt_files(self) -> list[Path]:
        """
        Return all attempt JSON files in the data directory, sorted from
        newest to oldest based on filename (which encodes the timestamp).

        Returns:
            List of Path objects sorted descending by filename.
        """
        files = sorted(
            self.data_dir.glob(self._FILENAME_PATTERN),
            key=lambda p: p.name,
            reverse=True,
        )
        return files

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------

    def save_attempt(self, attempt: dict[str, Any]) -> None:
        """
        Write a single analysis attempt to its own JSON file and trim
        the directory to the configured maximum number of files.

        Args:
            attempt: Serializable dictionary representing the analysis attempt.
        """
        self._ensure_directory()
        file_path = self._generate_filename()

        with file_path.open("w", encoding="utf-8") as f:
            json.dump(attempt, f, indent=4, ensure_ascii=False)

        self._cleanup_old_files()

    def _cleanup_old_files(self) -> None:
        """
        Delete the oldest attempt files if the number of files in the
        data directory exceeds max_attempts. Only files matching the
        analysis_*.json pattern are considered; other files are untouched.
        """
        files = self._list_attempt_files()
        excess = files[self.max_attempts:]
        for old_file in excess:
            try:
                old_file.unlink()
            except OSError:
                pass

    def load_attempts(self) -> list[dict[str, Any]]:
        """
        Load all stored attempt files from disk, ordered from newest
        to oldest.

        Returns:
            List of attempt dictionaries. Files that cannot be parsed
            are silently skipped.
        """
        if not self.data_dir.exists():
            return []

        attempts = []
        for file_path in self._list_attempt_files():
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    attempts.append(json.load(f))
            except (json.JSONDecodeError, OSError):
                continue

        return attempts

    def get_recent_attempts(self) -> list[dict[str, Any]]:
        """
        Return the stored list of recent analysis attempts, newest first.

        Returns:
            List of attempt dictionaries in reverse-chronological order.
        """
        return self.load_attempts()

    def clear_history(self) -> None:
        """
        Delete all attempt files from the data directory. Non-attempt
        files are left untouched.
        """
        if not self.data_dir.exists():
            return
        for file_path in self._list_attempt_files():
            try:
                file_path.unlink()
            except OSError:
                pass