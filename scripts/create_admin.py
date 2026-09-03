#!/usr/bin/env python3
"""Bootstrap the first admin user for local authentication.

Usage
-----
Interactive (prompts for password):

    python scripts/create_admin.py admin@example.com --display-name "Admin"

From environment variable (CI or first-boot scripting):

    BOOTSTRAP_PASSWORD=<secret> python scripts/create_admin.py admin@example.com

Requirements
------------
- The application .env must be present and contain JWT_SECRET_KEY and DATABASE_URL.
- Run AFTER applying Alembic migrations (alembic upgrade head).
- The password is NEVER written to disk or logs.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

# Add project root to path so app modules resolve without installation
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def _create_admin(email: str, display_name: str | None, password: str) -> None:
    from sqlalchemy import select

    from app.auth.local import hash_password
    from app.config import get_settings
    from app.db.models import User
    from app.db.session import async_session_factory, engine

    settings = get_settings()

    if settings.auth_mode != "local":
        print(f"ERROR: AUTH_MODE={settings.auth_mode!r} — this script only works in local mode.")
        sys.exit(1)

    sub = f"local:{email}"

    async with async_session_factory() as session:
        async with session.begin():
            result = await session.execute(select(User).where(User.email == email))
            existing = result.scalar_one_or_none()

            if existing is not None:
                # Update password and ensure role=admin
                existing.password_hash = hash_password(password)
                existing.role = "admin"
                existing.is_active = True
                if display_name:
                    existing.display_name = display_name
                print(f"Updated existing user: {email} (role set to admin, password reset)")
            else:
                user = User(
                    sub=sub,
                    email=email,
                    display_name=display_name or email.split("@")[0],
                    role="admin",
                    is_active=True,
                    password_hash=hash_password(password),
                )
                session.add(user)
                print(f"Created admin user: {email}")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or reset the admin user for local auth")
    parser.add_argument("email", help="Email address (used as login username)")
    parser.add_argument("--display-name", default=None, help="Display name (optional)")
    args = parser.parse_args()

    password = os.environ.get("BOOTSTRAP_PASSWORD", "")

    if not password:
        try:
            password = getpass.getpass(f"Password for {args.email}: ")
            confirm = getpass.getpass("Confirm password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

        if password != confirm:
            print("ERROR: Passwords do not match.")
            sys.exit(1)

    if len(password) < 8:
        print("ERROR: Password must be at least 8 characters.")
        sys.exit(1)

    asyncio.run(_create_admin(args.email, args.display_name, password))
    print("Done.")


if __name__ == "__main__":
    main()
