"""Terragrunt service — manages VPN routes through Git + Terragrunt."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path

import git

from app.config import get_settings
from app.exceptions import InfrastructureError
from app.logging_config import get_logger

logger = get_logger(__name__)


def _authenticated_url() -> str:
    """Build a GitHub HTTPS URL that includes the PAT for push/pull."""
    settings = get_settings()
    url = settings.github_repo_url
    # Insert token into URL: https://<token>@github.com/...
    if url.startswith("https://"):
        return url.replace("https://", f"https://{settings.github_token}@", 1)
    return url


async def ensure_repo() -> git.Repo:
    """Ensure the local git repository is up-to-date.

    If the repository does not exist locally it is cloned. If it already
    exists, the remote URL is updated (in case the token rotated) and the
    latest changes are pulled.

    Returns:
        An open ``git.Repo`` instance.

    Raises:
        InfrastructureError: On git clone/pull failure.
    """
    settings = get_settings()
    repo_path = Path(settings.git_repo_path)
    auth_url = _authenticated_url()

    loop = asyncio.get_running_loop()

    if not repo_path.exists():
        logger.info("terragrunt_repo_clone", path=str(repo_path))
        try:
            repo = await loop.run_in_executor(
                None,
                lambda: git.Repo.clone_from(
                    auth_url,
                    str(repo_path),
                    branch=settings.git_branch,
                ),
            )
            return repo
        except git.GitCommandError as exc:
            raise InfrastructureError(
                service="Git",
                message=f"Failed to clone repository to {repo_path}",
                detail=str(exc),
            ) from exc

    logger.info("terragrunt_repo_pull", path=str(repo_path))
    try:
        repo = git.Repo(str(repo_path))
        # Update remote URL in case token rotated
        origin = repo.remotes.origin
        await loop.run_in_executor(
            None,
            lambda: origin.set_url(auth_url),
        )
        await loop.run_in_executor(
            None,
            lambda: origin.pull(settings.git_branch),
        )
        return repo
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to pull latest changes in {repo_path}",
            detail=str(exc),
        ) from exc


def _read_routes_file(routes_path: Path) -> list[str]:
    """Read the vpn_routes.json file and return the cidrs list."""
    if not routes_path.exists():
        return []
    data = json.loads(routes_path.read_text(encoding="utf-8"))
    return list(data.get("cidrs", []))


def _write_routes_file(routes_path: Path, cidrs: list[str]) -> None:
    """Write the cidrs list back to vpn_routes.json (sorted, deterministic)."""
    data = {"cidrs": sorted(cidrs)}
    routes_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


async def _run_terragrunt_apply() -> str:
    """Execute ``terragrunt apply -auto-approve`` in the configured working directory.

    Returns:
        Combined stdout from the subprocess.

    Raises:
        InfrastructureError: On non-zero exit code or timeout.
    """
    settings = get_settings()
    working_dir = settings.terragrunt_working_dir

    logger.info("terragrunt_apply_start", working_dir=working_dir)

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "apply", "-auto-approve"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.terragrunt_timeout,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply timed out after {settings.terragrunt_timeout}s",
            detail=str(exc),
        ) from exc

    if result.returncode != 0:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply failed (exit code {result.returncode})",
            detail=result.stderr or result.stdout,
        )

    logger.info("terragrunt_apply_complete")
    return result.stdout


async def add_route(cidr: str, tunnel_name: str) -> None:
    """Add a CIDR to vpn_routes.json, commit, push, and apply via Terragrunt.

    Args:
        cidr: The CIDR block to add (e.g., ``10.0.0.0/24``).
        tunnel_name: Tunnel name for the commit message.

    Raises:
        InfrastructureError: On git or terragrunt failure.
    """
    settings = get_settings()
    repo = await ensure_repo()
    routes_path = Path(settings.git_repo_path) / settings.terragrunt_routes_path

    loop = asyncio.get_running_loop()

    # Read, modify, write
    cidrs = _read_routes_file(routes_path)
    if cidr not in cidrs:
        cidrs.append(cidr)
    _write_routes_file(routes_path, cidrs)

    # Git add, commit, push
    commit_message = f"vpn-manager: add route {cidr} for tunnel {tunnel_name}"
    logger.info("terragrunt_git_commit", message=commit_message)

    try:
        await loop.run_in_executor(
            None,
            lambda: repo.index.add([str(routes_path)]),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.index.commit(commit_message),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.remotes.origin.push(settings.git_branch),
        )
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to commit and push route change for {cidr}",
            detail=str(exc),
        ) from exc

    # Terragrunt apply
    await _run_terragrunt_apply()

    logger.info("terragrunt_route_added", cidr=cidr, tunnel=tunnel_name)


async def remove_route(cidr: str, tunnel_name: str) -> None:
    """Remove a CIDR from vpn_routes.json, commit, push, and apply via Terragrunt.

    Args:
        cidr: The CIDR block to remove.
        tunnel_name: Tunnel name for the commit message.

    Raises:
        InfrastructureError: On git or terragrunt failure.
    """
    settings = get_settings()
    repo = await ensure_repo()
    routes_path = Path(settings.git_repo_path) / settings.terragrunt_routes_path

    loop = asyncio.get_running_loop()

    # Read, modify, write
    cidrs = _read_routes_file(routes_path)
    if cidr in cidrs:
        cidrs.remove(cidr)
    _write_routes_file(routes_path, cidrs)

    # Git add, commit, push
    commit_message = f"vpn-manager: remove route {cidr} from tunnel {tunnel_name}"
    logger.info("terragrunt_git_commit", message=commit_message)

    try:
        await loop.run_in_executor(
            None,
            lambda: repo.index.add([str(routes_path)]),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.index.commit(commit_message),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.remotes.origin.push(settings.git_branch),
        )
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to commit and push route removal for {cidr}",
            detail=str(exc),
        ) from exc

    # Terragrunt apply
    await _run_terragrunt_apply()

    logger.info("terragrunt_route_removed", cidr=cidr, tunnel=tunnel_name)


async def check_connectivity() -> bool:
    """Verify git repo and terragrunt binary are available.

    Returns:
        True if both are accessible, False otherwise.
    """
    settings = get_settings()
    repo_path = Path(settings.git_repo_path)

    loop = asyncio.get_running_loop()
    try:
        # Check terragrunt binary
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            ),
        )
        if result.returncode != 0:
            return False

        # Check repo path exists (or can be cloned)
        if repo_path.exists():
            git.Repo(str(repo_path))

        return True
    except Exception:
        logger.warning("terragrunt_connectivity_check_failed")
        return False
