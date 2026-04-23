from fastapi import FastAPI
from app.api.routes import auth, dashboard
from app.core.config import settings
from app.core.logging import logger

app = FastAPI(
    title="Secure Auth Monitor",
    version="1.0.0"
)

# Include routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")

# Middleware setup
@app.middleware("http")
async def add_request_context(request, call_next):
    response = await call_next(request)
    return response

@app.get("/")
def root():
    return {"message": "Secure Auth Monitor Running"}