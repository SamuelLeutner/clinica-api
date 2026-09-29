from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import create_db_and_tables
from app.routes import (
    appointments,
    auth_routes,
    lab,
    patients,
    professionals,
    reception,
)
from app.security.headers import SecurityHeadersMiddleware
from app.security.rate_limit import limiter

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title="Clínica — API de Agendamento",
    description="API REST de agendamento de consultas médicas.",
    version="1.0.0",
    lifespan=lifespan,
)


allowed_origins = [
    origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(SecurityHeadersMiddleware)


app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


app.include_router(auth_routes.router)
app.include_router(appointments.router)
app.include_router(patients.router)
app.include_router(professionals.router)
app.include_router(reception.router)
app.include_router(lab.router)


@app.get("/health", tags=["infra"])
def health() -> dict:
    return {"status": "ok"}
