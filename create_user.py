from app.db.database import SessionLocal
from app.db.models import User
from app.core.security import hash_password

db = SessionLocal()

user = User(
    username="aryan",
    hashed_password=hash_password("123456")
)

db.add(user)
db.commit()

print("User created")