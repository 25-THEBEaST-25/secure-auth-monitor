from fastapi import FastAPI
from app.api.routes import auth, dashboard
from app.db.database import Base, engine

app = FastAPI(title="Secure Auth Monitor")

Base.metadata.create_all(bind=engine)

app.include_router(auth.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")

@app.get("/")
def root():
    return {"message": "Auth System Running"}