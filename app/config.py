from __future__ import annotations

from functools import lru_cache
from typing import Annotated

import boto3
from botocore.exceptions import ClientError
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration. All values from environment variables."""

    # Application
    app_name: str = "strongswan-manager"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://vpnmanager:changeme@db:5432/vpnmanager",
        description="PostgreSQL async URL: postgresql+asyncpg://user:pass@host:5432/db",
    )
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=10, ge=0, le=50)

    # SSM — optional: if set, the app reads DATABASE_URL from this SSM parameter at startup.
    # The parameter is fetched with decryption (SecureString). When unset, DATABASE_URL
    # must be provided directly via the environment variable or .env file.
    ssm_database_url_parameter: str | None = Field(
        default=None,
        description=(
            "SSM Parameter Store name that holds the DATABASE_URL. "
            "If set, overrides DATABASE_URL at startup (SecureString, decrypted). "
            "If unset, DATABASE_URL is read from the environment as usual."
        ),
    )

    # Auth mode
    auth_mode: str = Field(
        default="local",
        description="Authentication mode: 'local' (username/password JWT) or 'oidc' (external IdP). "
        "Default is 'local'. Set to 'oidc' when an external provider is configured.",
    )

    # Local JWT auth (required when auth_mode=local)
    jwt_secret_key: str = Field(
        default="",
        description="Secret key for signing local JWTs. "
        "REQUIRED when auth_mode=local — generate with: openssl rand -hex 32. "
        "The app will refuse to start if this is empty and auth_mode=local.",
    )
    jwt_expire_minutes: int = Field(
        default=480,
        ge=5,
        le=43200,
        description="Local JWT lifetime in minutes (default 480 = 8 hours).",
    )

    # OIDC / Auth (required only when auth_mode=oidc)
    oidc_issuer_url: str | None = Field(
        default=None,
        description="OIDC issuer URL (e.g., AWS IAM Identity Center). Required when auth_mode=oidc.",
    )
    oidc_audience: str | None = Field(
        default=None,
        description="OIDC audience claim to validate. Required when auth_mode=oidc.",
    )

    # AWS
    aws_region: str = Field(default="us-east-1")

    # AWS Cross-Account
    aws_assume_role_arn: str | None = Field(
        default=None,
        description="IAM role ARN to assume for dev-account access (SSM, EC2). "
        "If unset, uses default credentials.",
    )

    # KMS — key used to encrypt/decrypt PSK values stored in the database.
    kms_psk_key_id: str = Field(
        ...,
        description=(
            "KMS key ID or alias (e.g. 'alias/strongswan-psk') used to encrypt "
            "PSK values stored in the tunnels table. Required."
        ),
    )

    # SSM
    vpn_primary_instance_name: str = Field(..., description="EC2 Name tag for primary VPN instance")
    vpn_secondary_instance_name: str = Field(..., description="EC2 Name tag for secondary VPN instance")
    vpn_primary_instance_id: str | None = Field(
        default=None,
        description="EC2 instance ID for primary VPN instance (bypasses Name tag lookup)",
    )
    vpn_secondary_instance_id: str | None = Field(
        default=None,
        description="EC2 instance ID for secondary VPN instance (bypasses Name tag lookup)",
    )
    ssm_command_timeout: int = Field(default=60, ge=10, le=300)

    # SSH Key Encryption
    ssh_command_timeout: int = Field(default=30, ge=5, le=120)
    ssh_key_encryption_key: str = Field(
        default="",
        description="Fernet key for encrypting SSH private keys. "
        "Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'",
    )

    # VPN Server Remote Paths
    vpn_conf_dir: str = Field(
        default="/opt/strongswan/config/connections",
        description="Remote path to StrongSwan connection config directory on VPN servers",
    )
    vpn_secrets_dir: str = Field(
        default="/opt/strongswan/config/secrets",
        description="Remote path to StrongSwan secrets directory on VPN servers",
    )
    vpn_stroke_secrets_dir: str = Field(
        default="/etc/ipsec.d/secrets",
        description=(
            "Remote path for stroke secrets files on VPN servers. "
            "Must be included by /etc/ipsec.secrets (e.g. 'include /etc/ipsec.d/secrets/*.secrets'). "
            "Files are written with mode 0600."
        ),
    )
    vpn_swanctl_conf_dir: str = Field(
        default="/etc/swanctl/conf.d",
        description=(
            "Remote path for swanctl connection config files on VPN servers. "
            "Must be included by /etc/swanctl/swanctl.conf (e.g. 'include conf.d/*.conf'). "
            "Files are written with mode 0600 and contain both connection and secrets sections."
        ),
    )

    # Backup / rollback for per-node config writes
    vpn_backup_dir: str = Field(
        default="/var/backups/strongswan-manager",
        description=(
            "Remote directory on each VPN node where tunnel config files are backed up "
            "before each write or delete. Created with mode 700; backup files are written "
            "with mode 600. Path must not contain spaces or shell-special characters."
        ),
    )
    vpn_backup_retention: int = Field(
        default=5,
        ge=1,
        description="Number of per-file backup copies to keep on each VPN node.",
    )

    # Reconciler — periodic retry of partial/failed tunnel syncs
    reconciler_enabled: bool = Field(
        default=True,
        description="Set to False to disable the automatic reconciler background task.",
    )
    reconciler_interval_seconds: int = Field(
        default=300,
        ge=10,
        description="How often (in seconds) the reconciler scans for partial/failed tunnels.",
    )
    reconciler_max_attempts: int = Field(
        default=5,
        ge=1,
        description=(
            "Maximum number of automated reconciler attempts per tunnel per process lifetime. "
            "After this many attempts the reconciler stops retrying until the app restarts."
        ),
    )

    # PSK age alerting
    psk_max_age_days: int = Field(
        default=90,
        ge=1,
        description=(
            "Tunnels whose PSK has not been rotated in this many days are flagged as stale "
            "on the dashboard. Age is measured from psk_rotated_at (or created_at when unset)."
        ),
    )

    # CORS
    cors_origins: list[str] = Field(default=["http://localhost:3000"])

    # ---------------------------------------------------------------------------
    # Tier 2 — Shortcut-based access request flow
    # ---------------------------------------------------------------------------
    # Tier 2 is enabled when at least one of these is set:
    #   • SHORTCUT_API_TOKEN (env var, local dev)
    #   • SHORTCUT_TOKEN_SECRET_ARN (AWS Secrets Manager, production)
    # When both are unset the poller does not start and POST /access-requests returns 503.
    shortcut_api_token: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "Shortcut API token (Shortcut-Token header). "
            "Used when SHORTCUT_TOKEN_SECRET_ARN is unset (local dev / fallback). "
            "Leave empty when the token is in Secrets Manager."
        ),
    )
    shortcut_token_secret_arn: str | None = Field(
        default=None,
        description=(
            "ARN of an AWS Secrets Manager secret that holds the Shortcut API token. "
            "When set, the token is read from Secrets Manager using the EC2 instance role "
            "(default credential chain — no role assumption) and cached for 1 hour so "
            "rotation is picked up without a restart. "
            "SHORTCUT_API_TOKEN is used as a fallback when this is unset or the fetch fails. "
            "Example: arn:aws:secretsmanager:us-east-1:941644385943:secret:"
            "master/access-grants/shortcut-token-N7nCVh"
        ),
    )
    # Workflow state IDs for the Access Requests workflow
    shortcut_wf_requested_id: int = Field(
        default=500006959,
        description="Shortcut workflow_state_id for 'Requested' state",
    )
    shortcut_wf_approved_id: int = Field(
        default=500006960,
        description="Shortcut workflow_state_id for 'Approved' state",
    )
    shortcut_wf_completed_id: int = Field(
        default=500006961,
        description="Shortcut workflow_state_id for 'Completed' state",
    )
    shortcut_wf_rejected_id: int = Field(
        default=500006962,
        description="Shortcut workflow_state_id for 'Rejected' state",
    )
    # Lead member IDs authorised to approve access requests (comma-separated UUIDs)
    shortcut_lead_member_ids: Annotated[list[str], NoDecode] = Field(
        default=[
            "65c1155a-464e-4758-aeed-ba14c1ca20c4",
            "6463d18b-0b8c-4aa8-8032-1338558d3722",
            "5f45c611-44cb-43b1-b9e0-d4ca6f70e742",
        ],
        description="Comma-separated Shortcut member UUIDs allowed to approve Tier 2 requests",
    )
    # Access request stories live in the Access Requests workflow, which belongs to no
    # project: setting a project_id makes Shortcut reject the story (422). They go to the
    # Engineers team (whose workflows include Access Requests) under the same epic the
    # access-grants Lambda uses.
    shortcut_epic_id: int | None = Field(
        default=29211,
        description="Shortcut epic_id for access request stories (Privileged Access Grants)",
    )
    shortcut_group_id: str | None = Field(
        default="615256ca-3f27-4a13-88c0-d82b192ab194",
        description="Shortcut group_id for access request stories (Engineers team)",
    )
    shortcut_environment: str = Field(
        default="dev",
        description="Environment name shown in the Shortcut card description (dev or prod)",
    )
    shortcut_poll_interval_seconds: int = Field(
        default=120,
        ge=10,
        description="How often (seconds) the access-request poller checks Shortcut",
    )

    @field_validator("shortcut_lead_member_ids", mode="before")
    @classmethod
    def parse_shortcut_lead_member_ids(cls, v: object) -> list[str]:
        """Accept comma-separated string or list for SHORTCUT_LEAD_MEMBER_IDS."""
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            return [t.strip() for t in v.split(",") if t.strip()]
        if isinstance(v, list):
            return v
        return []

    # VPC Route Management (sc-31774)
    strongswan_config_bucket: str = Field(
        default="",
        description=(
            "Name of the S3 bucket that holds the StrongSwan cluster config, "
            "including failover/config.yaml (eip_allocation_id, route_table_ids, etc.). "
            "Empty disables the route-write feature."
        ),
    )
    managed_route_table_ids: Annotated[list[str], NoDecode] = Field(
        default=[],
        description=(
            "Comma-separated list of VPC route table IDs this manager is allowed to modify "
            "(e.g. 'rtb-aaa111,rtb-bbb222'). Routes are written to ALL listed tables. "
            "Empty list disables the route-write feature entirely. "
            "Also accepts a JSON array: '[\"rtb-aaa\",\"rtb-bbb\"]'. "
            "NoDecode prevents pydantic-settings v2 from pre-parsing the value as JSON, "
            "so the field_validator always receives the raw string."
        ),
    )

    # ---------------------------------------------------------------------------
    # Packet capture
    # ---------------------------------------------------------------------------
    capture_bucket: str = Field(
        default="",
        description=(
            "S3 bucket name for packet captures. "
            "Empty string disables the feature (endpoints return 503)."
        ),
    )
    capture_max_duration_seconds: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Maximum allowed capture duration in seconds (default 300 = 5 min).",
    )
    capture_max_size_mb: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum capture file size in MB (enforced on-node before upload).",
    )

    @field_validator("managed_route_table_ids", mode="before")
    @classmethod
    def parse_managed_route_table_ids(cls, v: object) -> list[str]:
        """Accept comma-separated string or JSON array for MANAGED_ROUTE_TABLE_IDS."""
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            # JSON array format: ["rtb-aaa","rtb-bbb"]
            if v.startswith("["):
                import json
                return [t.strip() for t in json.loads(v) if t.strip()]
            # Comma-separated format: rtb-aaa,rtb-bbb
            return [t.strip() for t in v.split(",") if t.strip()]
        if isinstance(v, list):
            return v
        return []

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith("postgresql+asyncpg://"):
            raise ValueError("database_url must use postgresql+asyncpg:// scheme")
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper

    @field_validator("auth_mode")
    @classmethod
    def validate_auth_mode(cls, v: str) -> str:
        allowed = {"local", "oidc"}
        lower = v.lower()
        if lower not in allowed:
            raise ValueError(f"auth_mode must be one of {allowed}")
        return lower

    def __init__(self, **values):  # type: ignore[no-untyped-def]
        super().__init__(**values)
        if self.auth_mode == "local" and not self.jwt_secret_key:
            raise ValueError(
                "JWT_SECRET_KEY is required when AUTH_MODE=local. "
                "Generate one with: openssl rand -hex 32"
            )
        if self.auth_mode == "oidc" and not self.oidc_issuer_url:
            raise ValueError("OIDC_ISSUER_URL is required when AUTH_MODE=oidc")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


def _fetch_ssm_database_url(settings: Settings) -> str:
    """Synchronously fetch DATABASE_URL from SSM Parameter Store.

    Called once at startup when SSM_DATABASE_URL_PARAMETER is set.
    Uses the same role-assumption logic as the rest of the app when
    AWS_ASSUME_ROLE_ARN is configured.

    Returns:
        A valid postgresql+asyncpg:// connection string.

    Raises:
        RuntimeError: If the SSM parameter cannot be read.
    """
    param_name = settings.ssm_database_url_parameter
    assert param_name  # guarded by caller

    try:
        if settings.aws_assume_role_arn:
            sts = boto3.client("sts", region_name=settings.aws_region)
            creds = sts.assume_role(
                RoleArn=settings.aws_assume_role_arn,
                RoleSessionName="strongswan-manager-config",
                DurationSeconds=900,
            )["Credentials"]
            ssm = boto3.client(
                "ssm",
                region_name=settings.aws_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        else:
            ssm = boto3.client("ssm", region_name=settings.aws_region)

        response = ssm.get_parameter(Name=param_name, WithDecryption=True)
        return response["Parameter"]["Value"]

    except ClientError as exc:
        raise RuntimeError(
            f"Failed to read DATABASE_URL from SSM parameter '{param_name}': {exc}"
        ) from exc


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton Settings instance.

    If SSM_DATABASE_URL_PARAMETER is set, the DATABASE_URL is fetched from
    SSM Parameter Store (with decryption) and used in place of the environment
    variable value. This fetch happens once and is cached.
    """
    raw = Settings()
    if raw.ssm_database_url_parameter:
        db_url = _fetch_ssm_database_url(raw)
        return Settings(database_url=db_url)
    return raw
