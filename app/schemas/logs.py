from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class LogBaseSchema(BaseModel):
    """
    Base Pydantic Schema for Cybersecurity Firewall Logs.
    Enforces strict typing and validation for core AI model features
    and allows flexible JSONB storage for remaining columns.
    """
    log_date: datetime = Field(..., description="Timestamp of the log event")
    ip_origin: Optional[str] = Field(None, description="Source/Origin IP Address")
    ip_impacted: Optional[str] = Field(None, description="Destination/Impacted IP Address")
    port_impacted: Optional[int] = Field(None, description="TCP/UDP Port impacted (0-65535)")
    zone_origin: Optional[str] = Field(None, description="Network zone of origin")
    zone_impacted: Optional[str] = Field(None, description="Network zone impacted")
    log_source: Optional[str] = Field(None, description="Source device/entity logging the event")
    port_origin: Optional[int] = Field(None, description="TCP/UDP Port of origin")
    protocol: Optional[str] = Field(None, description="Network protocol used (TCP, UDP, ICMP, etc.)")
    action: Optional[str] = Field(None, description="Firewall action taken (drop, allow, reset, etc.)")
    severity: Optional[str] = Field(None, description="Severity level (critical, high, medium, low, info)")
    threat_name: Optional[str] = Field(None, description="Detected threat or vulnerability name")
    application: Optional[str] = Field(None, description="App-ID or application classified")
    country_origin: Optional[str] = Field(None, description="Country of origin")
    country_impacted: Optional[str] = Field(None, description="Country impacted")
    rule_name: Optional[str] = Field(None, description="Firewall rule or policy name triggered")
    classification: Optional[str] = Field(None, description="Log event classification (Attack, Traffic, etc.)")
    additional_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Dynamic JSONB dictionary containing all remaining CSV columns"
    )


class LogCreateSchema(LogBaseSchema):
    """
    Pydantic Schema used for validating log ingestion/creation payloads.
    """
    pass


class LogResponseSchema(LogBaseSchema):
    """
    Pydantic Schema used for formatting log responses returned to clients.
    Supports seamless conversion from SQLAlchemy ORM models via ConfigDict.
    """
    id: int = Field(..., description="Unique auto-incrementing database ID")

    model_config = ConfigDict(from_attributes=True)


class LogListResponseSchema(BaseModel):
    """
    Paginated Response Schema wrapping list of logs and metadata.
    """
    total_count: int = Field(..., description="Number of records returned in this request")
    offset_range: int = Field(..., description="Current offset index")
    vendor: str = Field(..., description="Vendor table queried")
    data: List[LogResponseSchema] = Field(..., description="List of log records")


class LogQueryParameters(BaseModel):
    """
    Validation schema for API endpoint query parameters.
    """
    count: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Number of log records to retrieve (1 to 1000)"
    )
    offset_range: int = Field(
        default=0,
        ge=0,
        description="Pagination offset index (must be >= 0)"
    )
    vendor: str = Field(
        default="palo_alto",
        description="Target vendor log table: 'palo_alto', 'fortinet', or 'fortiwaf'"
    )
