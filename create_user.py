"""Create a user: python create_user.py <username>  (prompts for the password)"""
import sys
from getpass import getpass

from app.db.database import SessionLocal, Base, engine
from app.db.models import User
from app.core.security import hash_password

if len(sys.argv) != 2:
    sys.exit("usage: python create_user.py <username>")

username = sys.argv[1]
password = getpass("Password: ")
if len(password) < 8:
    sys.exit("Password must be at least 8 characters")

Base.metadata.create_all(bind=engine)

db = SessionLocal()
if db.query(User).filter(User.username == username).first():
    sys.exit(f"User '{username}' already exists")

db.add(User(username=username, hashed_password=hash_password(password)))
db.commit()

print(f"User '{username}' created")
