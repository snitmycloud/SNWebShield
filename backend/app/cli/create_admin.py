import argparse
from getpass import getpass

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import inspect, select

from app.core.security import hash_password, validate_password_policy
from app.db.session import SessionLocal, engine
from app.models.admin import ADMIN_ROLES
from app.models import Admin, AuthorizationAuditEvent, Client, Website, WebsiteAuthorization  # noqa: F401


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Create an internal SNWebShield account")
    parser.add_argument("--role", choices=ADMIN_ROLES, default="admin",
                        help="admin (default, bootstrap), lead_analyst or analyst")
    role = parser.parse_args(argv).role
    inspector = inspect(engine)
    if not inspector.has_table("website_authorizations") or "timestamps_verified" not in {
        column["name"] for column in inspector.get_columns("website_authorizations")
    }:
        print("Run python -m alembic upgrade head from backend before provisioning an administrator.")
        return 1
    print("SNWebShield — create an internal administrator")
    print("This local command does not expose a public admin-registration API.\n")

    full_name = input("Administrator full name: ").strip()
    if len(full_name) < 2 or len(full_name) > 150:
        print("Name must be between 2 and 150 characters.")
        return 1

    raw_email = input("Administrator email: ").strip()
    try:
        email = str(TypeAdapter(EmailStr).validate_python(raw_email)).lower()
    except ValidationError:
        print("Enter a valid email address.")
        return 1

    password = getpass("Password (12-128 characters, three character classes): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return 1
    problems = validate_password_policy(password, email)
    if problems:
        print("Password rejected: " + "; ".join(problems) + ".")
        return 1

    with SessionLocal() as db:
        existing = db.scalar(select(Admin).where(Admin.email == email))
        if existing is not None:
            print("An administrator with that email already exists.")
            return 1

        admin = Admin(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        print(f"Account created successfully (ID: {admin.id}, role: {admin.role}, email: {admin.email}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
