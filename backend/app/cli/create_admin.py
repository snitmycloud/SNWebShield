from getpass import getpass

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import Admin, AuthorizationAuditEvent, Client, Website, WebsiteAuthorization  # noqa: F401


def main() -> int:
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

    password = getpass("Password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.")
        return 1
    if len(password) < 12 or len(password) > 128:
        print("Password must be between 12 and 128 characters.")
        return 1

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        existing = db.scalar(select(Admin).where(Admin.email == email))
        if existing is not None:
            print("An administrator with that email already exists.")
            return 1

        admin = Admin(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        print(f"Administrator created successfully (ID: {admin.id}, email: {admin.email}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
