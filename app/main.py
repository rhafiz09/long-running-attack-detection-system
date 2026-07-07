import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db
from app.api.routers import logs, detection

# Configure root logger
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI Lifespan context manager.
    Executes database schema initialization during application startup.
    """
    logger.info("Starting up Cybersecurity Log Monitoring Pipeline API...")
    init_db()
    yield
    logger.info("Shutting down Cybersecurity Log Monitoring Pipeline API...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Set all CORS enabled origins for frontend integration (React/Next/Vue)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(logs.router, prefix=settings.API_V1_STR)
app.include_router(detection.router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Health Check"])
def health_check():
    """
    Service health check endpoint for monitoring and load balancers.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "api_version": "v1",
    }
