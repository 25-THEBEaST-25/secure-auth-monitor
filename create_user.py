"""Create a user from the command line (bootstraps the first admin).

    python create_user.py alice            # prompts for the password
    python create_user.py alice --admin
"""
import argparse
import sys
from getpass import getpass

from pydantic import ValidationError

from app.db.database import SessionLocal
from app.schemas.user import UserCreate
from app.services import auth_service

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("username")
parser.add_argument("--admin", action="store_true", help="give the user the admin role")
args = parser.parse_args()

password = getpass("Password: ")
if password != getpass("Repeat password: "):
    sys.exit("Passwords don't match")

try:
    data = UserCreate(username=args.username, password=password, role="admin" if args.admin else "user")
except ValidationError as err:
    sys.exit("; ".join(e["msg"] for e in err.errors()))

with SessionLocal() as db:
    if auth_service.get_by_username(db, data.username):
        sys.exit(f"User '{data.username}' already exists")
    auth_service.create_user(db, data.username, data.password, data.role)
    db.commit()

print(f"Created {data.role} '{data.username}'")
