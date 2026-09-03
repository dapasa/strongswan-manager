from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


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

    # AWS / S3
    s3_bucket: str = Field(..., description="S3 bucket for StrongSwan config files")
    aws_region: str = Field(default="us-east-1")

    # AWS Cross-Account
    aws_assume_role_arn: str | None = Field(
        default=None,
        description="IAM role ARN to assume for dev-account access (SSM, EC2, S3). "
        "If unset, uses default credentials.",
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

    # Git / Terragrunt
    github_repo_url: str = Field(..., description="GitHub HTTPS repo URL (without token)")
    github_token: str = Field(..., description="GitHub PAT for repo push/pull")
    git_repo_path: str = Field(..., description="Local path to git repo with vpn_routes.json")
    git_branch: str = Field(default="main")
    git_base_branch: str = Field(
        default="master",
        description="Branch where route commits are made before syncing to git_branch",
    )
    terragrunt_routes_path: str = Field(
        ...,
        description="Path to vpn_routes.json relative to git repo root",
    )
    terragrunt_working_dir: str = Field(..., description="Terragrunt working directory")
    terragrunt_timeout: int = Field(default=300, ge=60, le=600)

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

    # CORS
    cors_origins: list[str] = Field(default=["http://localhost:3000"])

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


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()
