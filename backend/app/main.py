from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database.connection import init_db
from app.api.routes import health, prediction, risk, explainability, metrics, analysis, traffic, monitoring, incidents
from app.services.live_collector import live_collector_service

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup database tables
    init_db()
    yield
    # Graceful shutdown of live monitoring
    live_collector_service.stop_monitoring()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health endpoint (root level for GET /health)
app.include_router(health.router)

# API v1 routes
app.include_router(analysis.router, prefix=settings.API_V1_STR)
app.include_router(prediction.router, prefix=settings.API_V1_STR)
app.include_router(risk.router, prefix=settings.API_V1_STR)
app.include_router(explainability.router, prefix=settings.API_V1_STR)
app.include_router(metrics.router, prefix=settings.API_V1_STR)
app.include_router(traffic.router, prefix=settings.API_V1_STR)
app.include_router(monitoring.router, prefix=settings.API_V1_STR)
app.include_router(incidents.router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "message": "ML Cyber Attack Analysis, Prediction & Early Warning System API",
        "docs": "/docs",
        "health": "/health"
    }

