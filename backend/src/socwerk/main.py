from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api import create_router
from .config import Settings
from .database import Database
from .detection import validate_expected_matches
from .scenarios import ScenarioError, ScenarioRepository


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_environment()
    repository = ScenarioRepository(config.data_dir)
    database = Database(config.database_path)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        repository.load()
        errors = [
            error
            for pack in repository.list()
            for error in validate_expected_matches(pack.events, pack.detections)
        ]
        if errors:
            raise ScenarioError("Detection integrity errors: " + "; ".join(errors))
        database.initialize()
        yield

    app = FastAPI(
        title="SOCWerk API",
        version="1.0.0",
        description="Local defensive security investigation and detection engineering API.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.exception_handler(Exception)
    async def unhandled_exception(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "socwerk-api"}

    app.include_router(create_router(repository, database))
    return app


app = create_app()
