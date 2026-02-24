"""Key validation module with custom exception classes."""


class InvalidKeyError(Exception):
    """Raised when the transposition cipher key is invalid."""
    pass


class InputFileNotFoundError(Exception):
    """Raised when a required input file is not found."""
    pass


def validate_key(key, message_length):
    """Validate that the key is suitable for transposition cipher operations.

    Args:
        key: The key to validate (should be a positive integer).
        message_length: The length of the message to encrypt/decrypt.

    Raises:
        InvalidKeyError: If the key is not valid for the given message.
    """
    if not isinstance(key, int):
        raise InvalidKeyError(
            f"Key must be an integer, got {type(key).__name__}."
        )
    if key < 1:
        raise InvalidKeyError(
            f"Key must be >= 1, got {key}."
        )
    if message_length == 0:
        raise InvalidKeyError(
            "Message is empty; cannot use any key."
        )
    if key >= message_length:
        raise InvalidKeyError(
            f"Key ({key}) must be less than message length "
            f"({message_length})."
        )
