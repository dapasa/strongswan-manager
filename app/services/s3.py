"""S3 service — manages per-connection config and secrets files in S3.

Bucket structure:
    connections/{name}.conf     — StrongSwan connection config
    secrets/{name}.secrets      — PSK secrets for the connection
"""

from __future__ import annotations

import asyncio
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError

from app.config import get_settings
from app.exceptions import InfrastructureError
from app.logging_config import get_logger

logger = get_logger(__name__)


@lru_cache
def _get_s3_client():  # noqa: ANN202
    """Return a cached boto3 S3 client."""
    settings = get_settings()
    return boto3.client("s3", region_name=settings.aws_region)


async def upload_file(key: str, content: str) -> None:
    """Upload a text file to the S3 config bucket.

    Args:
        key: S3 object key (e.g., ``connections/my-tunnel.conf``).
        content: File content as string.

    Raises:
        InfrastructureError: On S3 upload failure.
    """
    settings = get_settings()
    bucket = settings.s3_bucket

    logger.info("s3_upload_start", bucket=bucket, key=key, size=len(content))

    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: _get_s3_client().put_object(
                Bucket=bucket,
                Key=key,
                Body=content.encode("utf-8"),
                ContentType="text/plain",
            ),
        )
        logger.info("s3_upload_complete", bucket=bucket, key=key)
    except ClientError as exc:
        raise InfrastructureError(
            service="S3",
            message=f"Failed to upload s3://{bucket}/{key}",
            detail=str(exc),
        ) from exc


async def download_file(key: str) -> str:
    """Download a text file from the S3 config bucket.

    Args:
        key: S3 object key.

    Returns:
        File content as string.

    Raises:
        InfrastructureError: On S3 download failure.
    """
    settings = get_settings()
    bucket = settings.s3_bucket

    logger.info("s3_download_start", bucket=bucket, key=key)

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _get_s3_client().get_object(Bucket=bucket, Key=key),
        )
        content = await loop.run_in_executor(
            None,
            lambda: response["Body"].read().decode("utf-8"),
        )
        logger.info("s3_download_complete", bucket=bucket, key=key, size=len(content))
        return content
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "NoSuchKey":
            raise InfrastructureError(
                service="S3",
                message=f"Key {key} not found in bucket {bucket}",
                detail=str(exc),
            ) from exc
        raise InfrastructureError(
            service="S3",
            message=f"Failed to download s3://{bucket}/{key}",
            detail=str(exc),
        ) from exc


async def delete_file(key: str) -> None:
    """Delete a file from the S3 config bucket.

    Args:
        key: S3 object key to delete.

    Raises:
        InfrastructureError: On S3 delete failure.
    """
    settings = get_settings()
    bucket = settings.s3_bucket

    logger.info("s3_delete_start", bucket=bucket, key=key)

    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: _get_s3_client().delete_object(Bucket=bucket, Key=key),
        )
        logger.info("s3_delete_complete", bucket=bucket, key=key)
    except ClientError as exc:
        raise InfrastructureError(
            service="S3",
            message=f"Failed to delete s3://{bucket}/{key}",
            detail=str(exc),
        ) from exc


async def list_connections() -> list[str]:
    """List all connection config files in the bucket.

    Returns:
        List of connection names (without path prefix or extension).
    """
    settings = get_settings()
    bucket = settings.s3_bucket
    prefix = "connections/"

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _get_s3_client().list_objects_v2(
                Bucket=bucket,
                Prefix=prefix,
            ),
        )
        names = []
        for obj in response.get("Contents", []):
            key = obj["Key"]
            if key.endswith(".conf"):
                name = key.removeprefix(prefix).removesuffix(".conf")
                names.append(name)
        return sorted(names)
    except ClientError as exc:
        raise InfrastructureError(
            service="S3",
            message=f"Failed to list connections in s3://{bucket}/{prefix}",
            detail=str(exc),
        ) from exc


async def check_connectivity() -> bool:
    """Verify S3 bucket access for the health endpoint."""
    settings = get_settings()
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: _get_s3_client().head_bucket(Bucket=settings.s3_bucket),
        )
        return True
    except Exception:
        logger.warning("s3_connectivity_check_failed", bucket=settings.s3_bucket)
        return False
