from app.db.database import SessionLocal, Base, engine
from app.db.models import User
from app.core.security import hash_password

# 🔥 CREATE TABLES FIRST
Base.metadata.create_all(bind=engine)

db = SessionLocal()

user = User(
    username="aryan",
    hashed_password=hash_password("123456")
)

db.add(user)
db.commit()

print("User created")