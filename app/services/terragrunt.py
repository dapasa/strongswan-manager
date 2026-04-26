"""Terragrunt service — manages VPN routes through Git + Terragrunt."""

from __future__ import annotations

import asyncio
import json
import os
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

    base_branch = settings.git_base_branch

    if not repo_path.exists():
        logger.info("terragrunt_repo_clone", path=str(repo_path), branch=base_branch)
        try:
            repo = await loop.run_in_executor(
                None,
                lambda: git.Repo.clone_from(
                    auth_url,
                    str(repo_path),
                    branch=base_branch,
                ),
            )
            return repo
        except git.GitCommandError as exc:
            raise InfrastructureError(
                service="Git",
                message=f"Failed to clone repository to {repo_path}",
                detail=str(exc),
            ) from exc

    logger.info("terragrunt_repo_pull", path=str(repo_path), branch=base_branch)
    try:
        repo = git.Repo(str(repo_path))
        # Update remote URL in case token rotated
        origin = repo.remotes.origin
        await loop.run_in_executor(
            None,
            lambda: origin.set_url(auth_url),
        )
        # Ensure we are on the base branch before pulling
        await loop.run_in_executor(
            None,
            lambda: repo.git.checkout(base_branch),
        )
        await loop.run_in_executor(
            None,
            lambda: origin.pull(base_branch),
        )
        return repo
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to pull latest changes in {repo_path}",
            detail=str(exc),
        ) from exc


def _read_routes_file(routes_path: Path) -> list[str]:
    """Read the vpn_routes.json file and return the cidrs list.

    The file is expected to be a plain JSON array of CIDR strings, e.g.
    ``["10.0.0.0/24", "172.16.0.0/16"]``.  For backwards compatibility,
    an object with a ``cidrs`` key is also accepted.
    """
    if not routes_path.exists():
        return []
    data = json.loads(routes_path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return list(data)
    # Legacy format: {"cidrs": [...]}
    return list(data.get("cidrs", []))


def _write_routes_file(routes_path: Path, cidrs: list[str]) -> None:
    """Write the cidrs list back to vpn_routes.json as a plain JSON array."""
    routes_path.write_text(
        json.dumps(sorted(cidrs), indent=2) + "\n",
        encoding="utf-8",
    )


async def _run_terragrunt_apply() -> str:
    """Execute ``terragrunt plan`` then ``terragrunt apply`` in the configured working directory.

    The two-step flow generates a plan file first, then applies only that plan.
    This ensures the exact changes reviewed in the plan are what gets applied.

    Returns:
        Combined stdout from both plan and apply steps.

    Raises:
        InfrastructureError: On non-zero exit code or timeout in either step.
    """
    settings = get_settings()
    working_dir = settings.terragrunt_working_dir
    env = {**os.environ, "TG_NON_INTERACTIVE": "true"}

    loop = asyncio.get_running_loop()

    # Step 1: terragrunt plan -out=tfplan
    logger.info("terragrunt_plan_start", working_dir=working_dir)

    try:
        plan_result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "plan", "-out=tfplan"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.terragrunt_timeout,
                env=env,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt plan timed out after {settings.terragrunt_timeout}s",
            detail=str(exc),
        ) from exc

    if plan_result.returncode != 0:
        stderr_output = plan_result.stderr or ""
        stdout_output = plan_result.stdout or ""
        logger.error(
            "terragrunt_plan_failed",
            exit_code=plan_result.returncode,
            working_dir=working_dir,
            stderr=stderr_output,
            stdout=stdout_output,
        )
        detail = stderr_output if stderr_output else stdout_output
        if stderr_output and stdout_output:
            detail = f"STDERR:\n{stderr_output}\nSTDOUT:\n{stdout_output}"
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt plan failed (exit code {plan_result.returncode})",
            detail=detail,
        )

    logger.info("terragrunt_plan_complete")

    # Step 2: terragrunt apply tfplan
    logger.info("terragrunt_apply_start", working_dir=working_dir)

    try:
        apply_result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "apply", "tfplan"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.terragrunt_timeout,
                env=env,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply timed out after {settings.terragrunt_timeout}s",
            detail=str(exc),
        ) from exc

    if apply_result.returncode != 0:
        stderr_output = apply_result.stderr or ""
        stdout_output = apply_result.stdout or ""
        logger.error(
            "terragrunt_apply_failed",
            exit_code=apply_result.returncode,
            working_dir=working_dir,
            stderr=stderr_output,
            stdout=stdout_output,
        )
        detail = stderr_output if stderr_output else stdout_output
        if stderr_output and stdout_output:
            detail = f"STDERR:\n{stderr_output}\nSTDOUT:\n{stdout_output}"
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply failed (exit code {apply_result.returncode})",
            detail=detail,
        )

    logger.info("terragrunt_apply_complete")
    return f"{plan_result.stdout}\n{apply_result.stdout}"


async def add_route_file(cidr: str, tunnel_name: str, repo: git.Repo) -> None:
    """Add a CIDR to vpn_routes.json and stage the change (no commit/push).

    Args:
        cidr: The CIDR block to add (e.g., ``10.0.0.0/24``).
        tunnel_name: Tunnel name (for logging).
        repo: An already-cloned git.Repo instance.

    Raises:
        InfrastructureError: On file or git staging failure.
    """
    settings = get_settings()
    routes_path = Path(settings.git_repo_path) / settings.terragrunt_routes_path

    loop = asyncio.get_running_loop()

    # Read, modify, write
    cidrs = _read_routes_file(routes_path)
    if cidr not in cidrs:
        cidrs.append(cidr)
    _write_routes_file(routes_path, cidrs)

    # Git add (stage only)
    try:
        await loop.run_in_executor(
            None,
            lambda: repo.index.add([str(routes_path)]),
        )
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to stage route file change for {cidr}",
            detail=str(exc),
        ) from exc

    logger.info("terragrunt_route_file_added", cidr=cidr, tunnel=tunnel_name)


async def remove_route_file(cidr: str, tunnel_name: str, repo: git.Repo) -> None:
    """Remove a CIDR from vpn_routes.json and stage the change (no commit/push).

    Args:
        cidr: The CIDR block to remove.
        tunnel_name: Tunnel name (for logging).
        repo: An already-cloned git.Repo instance.

    Raises:
        InfrastructureError: On file or git staging failure.
    """
    settings = get_settings()
    routes_path = Path(settings.git_repo_path) / settings.terragrunt_routes_path

    loop = asyncio.get_running_loop()

    # Read, modify, write
    cidrs = _read_routes_file(routes_path)
    if cidr in cidrs:
        cidrs.remove(cidr)
    _write_routes_file(routes_path, cidrs)

    # Git add (stage only)
    try:
        await loop.run_in_executor(
            None,
            lambda: repo.index.add([str(routes_path)]),
        )
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message=f"Failed to stage route file removal for {cidr}",
            detail=str(exc),
        ) from exc

    logger.info("terragrunt_route_file_removed", cidr=cidr, tunnel=tunnel_name)


async def commit_and_push(repo: git.Repo, commit_message: str) -> None:
    """Commit staged changes to the base branch, push, then sync the release branch.

    Flow:
        1. Commit and push to ``git_base_branch`` (e.g. ``master``).
        2. Checkout ``git_branch`` (e.g. ``release/prod``), reset --hard to
           the base branch, and force-push so the release branch mirrors it.

    After this function returns the working tree is on ``git_branch``
    (the release branch), ready for Terragrunt plan/apply.

    Args:
        repo: git.Repo instance with staged changes.
        commit_message: The commit message.

    Raises:
        InfrastructureError: On git commit/push failure.
    """
    settings = get_settings()
    base_branch = settings.git_base_branch
    release_branch = settings.git_branch
    loop = asyncio.get_running_loop()

    logger.info("terragrunt_git_commit", message=commit_message, branch=base_branch)

    try:
        # Step 1: commit and push to base branch (master)
        await loop.run_in_executor(
            None,
            lambda: repo.index.commit(commit_message),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.remotes.origin.push(base_branch),
        )
        logger.info("terragrunt_git_pushed", branch=base_branch)

        # Step 2: checkout release branch, reset to base, force-push
        # Fetch to ensure we have the remote release branch ref
        await loop.run_in_executor(
            None,
            lambda: repo.remotes.origin.fetch(),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.git.checkout(release_branch),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.git.reset("--hard", base_branch),
        )
        await loop.run_in_executor(
            None,
            lambda: repo.remotes.origin.push(release_branch, force=True),
        )
        logger.info("terragrunt_git_synced_release", branch=release_branch)
    except git.GitCommandError as exc:
        raise InfrastructureError(
            service="Git",
            message="Failed to commit and push",
            detail=str(exc),
        ) from exc


async def run_apply() -> str:
    """Public wrapper around _run_terragrunt_apply (plan + apply combined).

    Returns:
        Combined stdout from plan and apply steps.
    """
    return await _run_terragrunt_apply()


async def run_plan() -> str:
    """Execute ``terragrunt plan -out=tfplan`` only.

    Returns:
        Stdout from plan step.

    Raises:
        InfrastructureError: On non-zero exit code or timeout.
    """
    settings = get_settings()
    working_dir = settings.terragrunt_working_dir
    env = {**os.environ, "TG_NON_INTERACTIVE": "true"}

    loop = asyncio.get_running_loop()

    logger.info("terragrunt_plan_start", working_dir=working_dir)

    try:
        plan_result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "plan", "-out=tfplan"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.terragrunt_timeout,
                env=env,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt plan timed out after {settings.terragrunt_timeout}s",
            detail=str(exc),
        ) from exc

    if plan_result.returncode != 0:
        stderr_output = plan_result.stderr or ""
        stdout_output = plan_result.stdout or ""
        logger.error(
            "terragrunt_plan_failed",
            exit_code=plan_result.returncode,
            working_dir=working_dir,
            stderr=stderr_output,
            stdout=stdout_output,
        )
        detail = stderr_output if stderr_output else stdout_output
        if stderr_output and stdout_output:
            detail = f"STDERR:\n{stderr_output}\nSTDOUT:\n{stdout_output}"
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt plan failed (exit code {plan_result.returncode})",
            detail=detail,
        )

    logger.info("terragrunt_plan_complete")
    return plan_result.stdout


async def run_apply_plan() -> str:
    """Execute ``terragrunt apply tfplan`` only (requires prior plan).

    Returns:
        Stdout from apply step.

    Raises:
        InfrastructureError: On non-zero exit code or timeout.
    """
    settings = get_settings()
    working_dir = settings.terragrunt_working_dir
    env = {**os.environ, "TG_NON_INTERACTIVE": "true"}

    loop = asyncio.get_running_loop()

    logger.info("terragrunt_apply_start", working_dir=working_dir)

    try:
        apply_result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["terragrunt", "apply", "tfplan"],
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=settings.terragrunt_timeout,
                env=env,
            ),
        )
    except subprocess.TimeoutExpired as exc:
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply timed out after {settings.terragrunt_timeout}s",
            detail=str(exc),
        ) from exc

    if apply_result.returncode != 0:
        stderr_output = apply_result.stderr or ""
        stdout_output = apply_result.stdout or ""
        logger.error(
            "terragrunt_apply_failed",
            exit_code=apply_result.returncode,
            working_dir=working_dir,
            stderr=stderr_output,
            stdout=stdout_output,
        )
        detail = stderr_output if stderr_output else stdout_output
        if stderr_output and stdout_output:
            detail = f"STDERR:\n{stderr_output}\nSTDOUT:\n{stdout_output}"
        raise InfrastructureError(
            service="Terragrunt",
            message=f"terragrunt apply failed (exit code {apply_result.returncode})",
            detail=detail,
        )

    logger.info("terragrunt_apply_complete")
    return apply_result.stdout


async def add_route(cidr: str, tunnel_name: str) -> None:
    """Add a CIDR to vpn_routes.json, commit, push, and apply via Terragrunt.

    This is the legacy all-in-one function. New code should use the
    individual step functions for granular status reporting.

    Args:
        cidr: The CIDR block to add (e.g., ``10.0.0.0/24``).
        tunnel_name: Tunnel name for the commit message.

    Raises:
        InfrastructureError: On git or terragrunt failure.
    """
    repo = await ensure_repo()
    await add_route_file(cidr, tunnel_name, repo)
    await commit_and_push(repo, f"vpn-manager: add route {cidr} for tunnel {tunnel_name}")
    await _run_terragrunt_apply()
    logger.info("terragrunt_route_added", cidr=cidr, tunnel=tunnel_name)


async def remove_route(cidr: str, tunnel_name: str) -> None:
    """Remove a CIDR from vpn_routes.json, commit, push, and apply via Terragrunt.

    This is the legacy all-in-one function. New code should use the
    individual step functions for granular status reporting.

    Args:
        cidr: The CIDR block to remove.
        tunnel_name: Tunnel name for the commit message.

    Raises:
        InfrastructureError: On git or terragrunt failure.
    """
    repo = await ensure_repo()
    await remove_route_file(cidr, tunnel_name, repo)
    await commit_and_push(repo, f"vpn-manager: remove route {cidr} from tunnel {tunnel_name}")
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
