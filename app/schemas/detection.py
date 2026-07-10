from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class LogEntry(BaseModel):
    """
    Pydantic Schema representing a single raw log event for AI inference.
    """
    log_date: datetime = Field(..., description="Timestamp of the log event (e.g. ISO 8601 format)")
    ip_origin: Optional[str] = Field("0.0.0.0", description="Source/Origin IP Address")
    ip_impacted: Optional[str] = Field("0.0.0.0", description="Destination/Impacted IP Address")
    port_impacted: Optional[int] = Field(0, description="TCP/UDP Port impacted (0-65535)")
    zone_origin: Optional[str] = Field("unknown", description="Network zone of origin")
    zone_impacted: Optional[str] = Field("unknown", description="Network zone impacted")
    log_source: Optional[str] = Field("unknown", description="Source device/entity logging the event")
    additional_data: Optional[dict] = Field(default_factory=dict, description="Additional flexible log metadata")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "log_date": "2026-07-07T14:00:10Z",
                "ip_origin": "103.179.248.11",
                "ip_impacted": "10.14.202.100",
                "port_impacted": 80,
                "zone_origin": "Untrust",
                "zone_impacted": "Trust",
                "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
            }
        }
    )


class DetectionRequest(BaseModel):
    """
    Request payload containing a batch of log records to be evaluated by the CNN-LSTM model.
    """
    logs: List[LogEntry] = Field(
        ...,
        description="List of raw firewall logs captured over an incremental monitoring window (e.g., last 5 minutes)."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "logs": [
                    {
                        "log_date": "2026-07-07T14:00:10Z",
                        "ip_origin": "103.179.248.11",
                        "ip_impacted": "10.14.202.100",
                        "port_impacted": 80,
                        "zone_origin": "Untrust",
                        "zone_impacted": "Trust",
                        "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                    },
                    {
                        "log_date": "2026-07-07T14:00:14Z",
                        "ip_origin": "103.179.248.11",
                        "ip_impacted": "10.14.202.100",
                        "port_impacted": 81,
                        "zone_origin": "Untrust",
                        "zone_impacted": "Trust",
                        "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                    }
                ]
            }
        }
    )


class DetectionResult(BaseModel):
    """
    AI inference evaluation result for a single evaluated IP and time sequence.
    """
    ip_origin: str = Field(..., description="Source IP Address evaluated by the neural network")
    label: int = Field(..., description="Predicted class integer label (0: Normal, 1: Reconnaissance, 2: Lateral Movement, 3: Beaconing)")
    threat_name: str = Field(..., description="Human-readable threat category name")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Softmax prediction confidence probability (0.0 to 1.0)")


class DetectionResponse(BaseModel):
    """
    Response schema returning AI threat detection evaluations for the requested log batch.
    """
    status: str = Field("success", description="Execution status of the inference pipeline")
    message: Optional[str] = Field(None, description="Additional informational message or warning regarding sequence evaluation")
    results: List[DetectionResult] = Field(..., description="List of detection evaluation results per evaluated IP")
