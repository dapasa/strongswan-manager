"""Application middleware — request ID injection, request logging, and global exception handlers."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.exceptions import (
    AppError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    InfrastructureError,
    LockConflictError,
    NotFoundError,
    ValidationError,
)
from app.logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Request ID middleware
# ---------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject a unique request ID into structlog context vars and response headers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Request logging middleware
# ---------------------------------------------------------------------------

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log method, path, status code, and duration for every request."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        logger.info(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response


# ---------------------------------------------------------------------------
# Global exception handlers
# ---------------------------------------------------------------------------

_EXCEPTION_MAP: list[tuple[type[AppError], int]] = [
    (NotFoundError, 404),
    (ConflictError, 409),
    (LockConflictError, 409),
    (ValidationError, 400),
    (AuthenticationError, 401),
    (AuthorizationError, 403),
    (InfrastructureError, 502),
    (AppError, 500),  # catch-all base — must be last
]


def _build_error_body(exc: AppError) -> dict[str, Any]:
    return {"detail": exc.message}


async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    """Resolve the correct status code and return a JSON error response."""
    status_code = 500
    for exc_type, code in _EXCEPTION_MAP:
        if isinstance(exc, exc_type):
            status_code = code
            break

    if status_code >= 500:
        logger.error(
            "unhandled_app_error",
            error_type=type(exc).__name__,
            detail=exc.message,
            path=request.url.path,
        )
    else:
        logger.warning(
            "client_error",
            error_type=type(exc).__name__,
            detail=exc.message,
            status_code=status_code,
            path=request.url.path,
        )

    # Include request_id in error responses (M19)
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    body = _build_error_body(exc)
    if request_id:
        body["request_id"] = request_id

    headers: dict[str, str] = {}
    if isinstance(exc, LockConflictError):
        headers["Retry-After"] = "5"

    return JSONResponse(status_code=status_code, content=body, headers=headers)


async def _handle_unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unexpected exceptions. Never expose stack traces to clients."""
    logger.error(
        "unhandled_exception",
        error_type=type(exc).__name__,
        error=str(exc),
        path=request.url.path,
        exc_info=True,
    )

    request_id = structlog.contextvars.get_contextvars().get("request_id")
    body: dict[str, Any] = {"detail": "Internal server error"}
    if request_id:
        body["request_id"] = request_id

    return JSONResponse(status_code=500, content=body)


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers for all custom domain exceptions."""
    for exc_type, _code in _EXCEPTION_MAP:
        app.add_exception_handler(exc_type, _handle_app_error)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _handle_unhandled_error)  # type: ignore[arg-type]
