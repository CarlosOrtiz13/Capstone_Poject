"""
Module for managing human-in-the-loop review, editing, and approval
of individual FieldValue objects within the Diamond Model pipeline.
"""


class HumanReviewManager:
    """
    Provides simple, defensive methods for approving, editing, and
    rejecting individual FieldValue fields during human review,
    without any dependency on UI frameworks.
    """

    def approve_field(self, field_obj) -> None:
        """
        Mark a field as approved if the attribute exists.

        Args:
            field_obj: A FieldValue instance or compatible object.
        """
        if hasattr(field_obj, "approved"):
            field_obj.approved = True

    def edit_field(self, field_obj, new_value: str, note: str = "") -> None:
        """
        Apply a user-supplied edit to a field, using its built-in
        mark_user_edited method if available, or updating attributes
        directly as a fallback.

        Args:
            field_obj: A FieldValue instance or compatible object.
            new_value: The corrected value provided by the user.
            note:      Optional note describing the reason for the edit.
        """
        if hasattr(field_obj, "mark_user_edited"):
            field_obj.mark_user_edited(new_value, note)
            return

        if hasattr(field_obj, "value"):
            field_obj.value = new_value
        if hasattr(field_obj, "source"):
            field_obj.source = "user"
        if hasattr(field_obj, "edited_by_user"):
            field_obj.edited_by_user = True
        if hasattr(field_obj, "approved"):
            field_obj.approved = True
        if note and hasattr(field_obj, "notes"):
            field_obj.notes = note

    def reject_field(self, field_obj, note: str = "") -> None:
        """
        Mark a field as not approved and optionally record a rejection note.

        Args:
            field_obj: A FieldValue instance or compatible object.
            note:      Optional note describing the reason for rejection.
        """
        if hasattr(field_obj, "approved"):
            field_obj.approved = False
        if note and hasattr(field_obj, "notes"):
            field_obj.notes = note