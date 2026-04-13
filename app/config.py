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

    # OIDC / Auth
    oidc_issuer_url: str = Field(..., description="OIDC issuer URL (e.g., AWS IAM Identity Center)")
    oidc_audience: str = Field(..., description="OIDC audience claim to validate")

    # AWS / S3
    s3_bucket: str = Field(..., description="S3 bucket for ipsec.conf")
    s3_ipsec_key: str = Field(default="ipsec/ipsec.conf", description="S3 key for ipsec.conf")
    aws_region: str = Field(default="us-east-1")

    # SSM
    vpn_primary_instance_name: str = Field(..., description="EC2 Name tag for primary VPN instance")
    vpn_secondary_instance_name: str = Field(..., description="EC2 Name tag for secondary VPN instance")
    ssm_command_timeout: int = Field(default=60, ge=10, le=300)

    # Git / Terragrunt
    github_repo_url: str = Field(..., description="GitHub HTTPS repo URL (without token)")
    github_token: str = Field(..., description="GitHub PAT for repo push/pull")
    git_repo_path: str = Field(..., description="Local path to git repo with vpn_routes.json")
    git_branch: str = Field(default="main")
    terragrunt_routes_path: str = Field(
        ...,
        description="Path to vpn_routes.json relative to git repo root",
    )
    terragrunt_working_dir: str = Field(..., description="Terragrunt working directory")
    terragrunt_timeout: int = Field(default=300, ge=60, le=600)

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

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()
