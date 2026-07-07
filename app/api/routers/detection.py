import logging
from fastapi import APIRouter, Depends, status
from app.schemas.detection import DetectionRequest, DetectionResponse
from app.services.inference_service import InferenceService, get_inference_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detect", tags=["Real-Time Attack Detection"])


@router.post(
    "",
    response_model=DetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Real-Time Cybersecurity Attack Prediction",
    description="""
    Receives a batch of raw firewall log records (e.g., over a 5-minute monitoring window),
    performs behavioral feature engineering and time-window resampling, and evaluates
    the sequences using the trained hybrid CNN-LSTM neural network.

    Returns the predicted threat category (Normal, Reconnaissance, Lateral Movement, or Beaconing)
    and confidence probability score for each evaluated origin IP address.
    """,
)
def detect_attacks(
    request: DetectionRequest,
    inference_service: InferenceService = Depends(get_inference_service),
) -> DetectionResponse:
    """
    POST /api/v1/detect endpoint.
    Uses strict Dependency Injection (Depends) to inject the cached ML Inference Service.
    """
    logger.debug(f"POST /api/v1/detect requested with {len(request.logs)} log records.")
    return inference_service.predict(request)
