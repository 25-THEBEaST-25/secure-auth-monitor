from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api.routes import admin, auth
from app.core.config import Settings, settings
from app.core.logging import logger
from app.db.database import engine

STATIC_DIR = Path(__file__).parent / "static"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # No inline scripts or third-party sources. Event usernames are
    # attacker-controlled and shown in the dashboard, so this is a second
    # line of defence behind textContent rendering.
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}


def create_app(config: Settings = settings) -> FastAPI:
    docs = not config.is_production
    app = FastAPI(
        title="Secure Auth Monitor",
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if config.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Log the traceback, but never send it to the client.
        logger.exception("unhandled_error", extra={"fields": {"path": request.url.path}})
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    app.include_router(auth.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")

    @app.get("/health", include_in_schema=False)
    def health():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001  any DB failure means unhealthy
            logger.exception("health_check_failed")
            return JSONResponse(status_code=503, content={"status": "unavailable"})
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "dashboard.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
