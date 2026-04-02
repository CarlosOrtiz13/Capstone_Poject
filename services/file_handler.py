"""
Module for handling file uploads in the Diamond Model analysis application,
with structured support for plain text, JSON, and STIX file formats.
"""

from pathlib import Path


class FileHandler:
    """
    Handles reading and type detection for uploaded files in the Streamlit
    interface. Supports plain text, JSON, and STIX-like bundle files,
    structured for easy expansion to additional formats.
    """

    def read_txt(self, uploaded_file) -> str:
        """
        Read and decode a plain text uploaded file.

        Args:
            uploaded_file: A Streamlit UploadedFile object.

        Returns:
            Stripped decoded string content of the file.
        """
        raw_bytes = uploaded_file.read()
        return raw_bytes.decode("utf-8", errors="ignore").strip()

    def read_json(self, uploaded_file) -> str:
        """
        Read and decode a JSON or STIX uploaded file as raw text.
        Validation and parsing are left to the caller.

        Args:
            uploaded_file: A Streamlit UploadedFile object.

        Returns:
            Stripped decoded string content of the file.
        """
        raw_bytes = uploaded_file.read()
        return raw_bytes.decode("utf-8", errors="ignore").strip()

    def get_extension(self, filename: str) -> str:
        """
        Extract the lowercase file extension from a filename.

        Args:
            filename: Name of the file including extension.

        Returns:
            Lowercase extension string including the dot (e.g. '.txt'),
            or an empty string if no extension is present.
        """
        return Path(filename).suffix.lower()

    def is_stix_filename(self, filename: str) -> bool:
        """
        Detect whether a filename refers to a STIX file, including
        the compound extension '.stix.json'.

        Args:
            filename: Name of the file to inspect.

        Returns:
            True if the filename ends with '.stix' or '.stix.json'.
        """
        lower = filename.lower()
        return lower.endswith(".stix") or lower.endswith(".stix.json")

    def read_uploaded_file(self, uploaded_file) -> str:
        """
        Detect the file type and dispatch to the appropriate reader.

        Supported formats:
            - .txt              plain text scenario
            - .json             native JSON analysis export
            - .stix             STIX bundle
            - .stix.json        STIX bundle with compound extension

        Args:
            uploaded_file: A Streamlit UploadedFile object with a .name attribute.

        Returns:
            Decoded string content of the uploaded file.

        Raises:
            ValueError: If the file type is not currently supported.
        """
        filename  = uploaded_file.name
        extension = self.get_extension(filename)

        if extension == ".txt":
            return self.read_txt(uploaded_file)

        if self.is_stix_filename(filename):
            return self.read_json(uploaded_file)

        if extension == ".json":
            return self.read_json(uploaded_file)

        raise ValueError(
            f"Unsupported file type '{extension}'. "
            "Supported formats: .txt, .json, .stix, .stix.json"
        )