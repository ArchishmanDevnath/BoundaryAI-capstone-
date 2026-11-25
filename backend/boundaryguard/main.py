"""FastAPI application. Run with: python -m boundaryguard.main"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from .api import audit, experiments, policies, runs, system
from .api.state import AppState
from .config import Settings, load_settings
from .llm import ChatClient


def create_app(settings: Settings | None = None, clients: dict[str, ChatClient] | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.bg = AppState(settings, clients)
        yield
        app.state.bg.shutdown()

    app = FastAPI(title="BoundaryGuard API", version="1.0.0", lifespan=lifespan)

    @app.middleware("http")
    async def require_json_writes(request: Request, call_next):
        # A cross-site form can send a "simple" request without a CORS preflight. Requiring
        # application/json on every write forces a preflight, which CORS then refuses.
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                return JSONResponse({"detail": "Content-Type must be application/json."}, status_code=415)
        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_origin],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    for module in (system, policies, runs, experiments, audit):
        app.include_router(module.router, prefix="/api/v1")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("boundaryguard.main:app", host="127.0.0.1", port=8000)
