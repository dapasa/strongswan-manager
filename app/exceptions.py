from __future__ import annotations


class AppError(Exception):
    """Base exception for all application errors."""

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        self.message = message
        self.detail = detail
        super().__init__(message)


class NotFoundError(AppError):
    """Entity not found."""

    def __init__(self, entity_type: str, entity_id: int | str) -> None:
        super().__init__(f"{entity_type} {entity_id} not found")
        self.entity_type = entity_type
        self.entity_id = entity_id


class ConflictError(AppError):
    """Business rule conflict (e.g., duplicate name)."""

    pass


class LockConflictError(AppError):
    """Advisory lock could not be acquired — another operation is in progress."""

    def __init__(self, lock_id: int) -> None:
        super().__init__(f"Operation in progress (lock {lock_id}). Retry later.")
        self.lock_id = lock_id


class ValidationError(AppError):
    """Business validation error (beyond Pydantic input validation)."""

    pass


class InfrastructureError(AppError):
    """External service failure (S3, SSM, Terragrunt)."""

    def __init__(self, service: str, message: str, *, detail: str | None = None) -> None:
        super().__init__(f"{service}: {message}", detail=detail)
        self.service = service


class AuthenticationError(AppError):
    """Token validation failure."""

    pass


class AuthorizationError(AppError):
    """Insufficient permissions."""

    pass


class EncryptionError(AppError):
    """Encryption or decryption operation failed."""

    pass
