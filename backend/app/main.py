from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app
import logging

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.scans import router as scans_router

setup_logging()

class _HealthFilter(logging.Filter):
    def filter(self, record):
        return "/health" not in record.getMessage()

logging.getLogger("uvicorn.access").addFilter(_HealthFilter())

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-assisted attack surface intelligence platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

app.include_router(scans_router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": settings.app_version}
