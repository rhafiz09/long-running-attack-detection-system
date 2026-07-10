from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class BaseLogModel(Base):
    """
    Abstract Base Model for all Security Firewall Logs.
    Enforces DRY principles across Palo Alto, Fortinet, and FortiWAF log tables.
    
    Accommodates 112+ columns from raw CSV datasets by explicitly indexing 
    the 7 core columns required for AI/ML Long Running Attack detection (CNN-LSTM)
    and storing the remaining flexible columns in a JSONB dictionary.
    """
    __abstract__ = True

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    
    # Core columns explicitly mapped and indexed for AI Model ingestion
    log_date = Column(DateTime(timezone=True), index=True, nullable=False)
    ip_origin = Column(String(100), index=True, nullable=True)
    ip_impacted = Column(String(100), index=True, nullable=True)
    port_impacted = Column(Integer, index=True, nullable=True)
    zone_origin = Column(String(100), index=True, nullable=True)
    zone_impacted = Column(String(100), index=True, nullable=True)
    log_source = Column(String(255), index=True, nullable=True)
    
    # Core columns explicitly mapped for SOC Monitoring & Frontend Investigation Dashboard
    port_origin = Column(Integer, index=True, nullable=True)
    protocol = Column(String(50), index=True, nullable=True)
    action = Column(String(100), index=True, nullable=True)
    severity = Column(String(50), index=True, nullable=True)
    threat_name = Column(String(255), index=True, nullable=True)
    application = Column(String(100), index=True, nullable=True)
    country_origin = Column(String(100), nullable=True)
    country_impacted = Column(String(100), nullable=True)
    rule_name = Column(String(255), nullable=True)
    classification = Column(String(255), index=True, nullable=True)
    
    # Dynamic schema scalability for remaining ~80+ flexible CSV columns
    additional_data = Column(JSONB, nullable=False, default=dict)


class PaloAltoLog(BaseLogModel):
    """
    SQLAlchemy Model for Palo Alto Firewall Logs.
    Mapped to PostgreSQL table: palo_alto_logs
    """
    __tablename__ = "palo_alto_logs"


class FortinetLog(BaseLogModel):
    """
    SQLAlchemy Model for Fortinet Firewall Logs.
    Mapped to PostgreSQL table: fortinet_logs
    """
    __tablename__ = "fortinet_logs"


class FortiWafLog(BaseLogModel):
    """
    SQLAlchemy Model for FortiWAF Web Application Firewall Logs.
    Mapped to PostgreSQL table: fortiwaf_logs
    """
    __tablename__ = "fortiwaf_logs"
