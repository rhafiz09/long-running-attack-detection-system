import logging
from fastapi import APIRouter, Depends, Request, status
from app.schemas.detection import DetectionRequest, DetectionResponse
from app.services.inference_service import InferenceService, get_inference_service
from app.core.limiter import limiter
from app.core.security import verify_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detect", tags=["Real-Time Attack Detection"])


@router.post(
    "",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_api_key)],
    summary="Real-Time Cybersecurity Attack Prediction",
    description="""
    Receives a batch of raw firewall log records (e.g., over a 5-minute monitoring window),
    performs behavioral feature engineering and time-window resampling, and evaluates
    the sequences using the trained hybrid CNN-LSTM neural network.

    Protected by X-API-Key header authentication and slowapi rate limiting (100/minute).
    Returns the predicted threat category (Normal, Reconnaissance, Lateral Movement, or Beaconing)
    and confidence probability score for each evaluated origin IP address.
    """,
)
@limiter.limit("100/minute")
def detect_attacks(
    request: Request,
    payload: DetectionRequest,
    inference_service: InferenceService = Depends(get_inference_service),
) -> DetectionResponse:
    """
    POST /api/v1/detect endpoint.
    Uses strict Dependency Injection (Depends) to inject the cached ML Inference Service
    and X-API-Key verification.
    """
    logger.debug(f"POST /api/v1/detect requested from {request.client.host if request.client else 'unknown'} with {len(payload.logs)} log records.")
    return inference_service.predict(payload)
