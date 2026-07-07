import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.logs import LogListResponseSchema
from app.repositories.log_repository import LogRepository
from app.services.log_service import LogService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Security Logs Monitoring"])


@router.get(
    "",
    response_model=LogListResponseSchema,
    summary="Retrieve paginated security firewall logs",
    description="""
    Fetches security logs from PostgreSQL database with pagination (count and offset_range).
    If database tables are empty or unseeded, automatically returns structured dummy data
    matching the raw CSV headers structure (Palo Alto, Fortinet, FortiWAF).
    """,
)
def get_logs(
    count: int = Query(
        10, ge=1, le=1000, description="Number of log records to retrieve (1 to 1000)"
    ),
    offset_range: int = Query(
        0, ge=0, description="Pagination offset index (must be >= 0)"
    ),
    vendor: str = Query(
        "palo_alto",
        description="Target vendor log table: 'palo_alto', 'fortinet', or 'fortiwaf'",
    ),
    db: Session = Depends(get_db),
):
    """
    GET /api/logs endpoint.
    Uses strict Dependency Injection (Depends) for SQLAlchemy session management.
    """
    logger.debug(
        f"GET /api/logs requested with count={count}, offset_range={offset_range}, vendor={vendor}"
    )
    repository = LogRepository(db)
    service = LogService(repository)

    return service.get_logs_paginated(
        count=count, offset_range=offset_range, vendor=vendor
    )
