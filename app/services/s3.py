"""S3 service — manages ipsec.conf upload and download via boto3."""

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


async def download_ipsec_conf() -> str:
    """Download ipsec.conf from S3.

    Returns:
        The file content as a string.

    Raises:
        InfrastructureError: On S3 download failure (missing key, permissions, etc.).
    """
    settings = get_settings()
    bucket = settings.s3_bucket
    key = settings.s3_ipsec_key

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
    except Exception as exc:
        raise InfrastructureError(
            service="S3",
            message=f"Unexpected error downloading s3://{bucket}/{key}",
            detail=str(exc),
        ) from exc


async def upload_ipsec_conf(content: str) -> None:
    """Upload ipsec.conf content to S3.

    Args:
        content: The full ipsec.conf file content.

    Raises:
        InfrastructureError: On S3 upload failure.
    """
    settings = get_settings()
    bucket = settings.s3_bucket
    key = settings.s3_ipsec_key

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
    except Exception as exc:
        raise InfrastructureError(
            service="S3",
            message=f"Unexpected error uploading s3://{bucket}/{key}",
            detail=str(exc),
        ) from exc


async def check_connectivity() -> bool:
    """Verify S3 bucket access for the health endpoint.

    Returns:
        True if the bucket is accessible, False otherwise.
    """
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
