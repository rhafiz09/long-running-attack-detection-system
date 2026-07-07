import logging
from typing import List, Type, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from app.models.logs import BaseLogModel, PaloAltoLog, FortinetLog, FortiWafLog

logger = logging.getLogger(__name__)


class LogRepository:
    """
    Data Access Layer (Repository) for Security Firewall Logs.
    Encapsulates all database queries, pagination, and high-performance bulk insertions.
    """

    VENDOR_MODEL_MAPPING: Dict[str, Type[BaseLogModel]] = {
        "palo_alto": PaloAltoLog,
        "fortinet": FortinetLog,
        "fortiwaf": FortiWafLog,
    }

    def __init__(self, db: Session):
        self.db = db

    def get_model_by_vendor(self, vendor: str) -> Type[BaseLogModel]:
        """
        Resolve SQLAlchemy ORM model based on vendor string.
        Defaults to PaloAltoLog if vendor is unrecognized.
        """
        clean_vendor = vendor.lower().strip().replace("-", "_").replace(" ", "_")
        return self.VENDOR_MODEL_MAPPING.get(clean_vendor, PaloAltoLog)

    def get_logs(
        self, count: int, offset_range: int, vendor: str = "palo_alto"
    ) -> List[BaseLogModel]:
        """
        Retrieve paginated log records from the specified vendor table.
        Ordered by log_date descending (time-series optimized).
        """
        model_class = self.get_model_by_vendor(vendor)
        try:
            records = (
                self.db.query(model_class)
                .order_by(model_class.log_date.desc())
                .offset(offset_range)
                .limit(count)
                .all()
            )
            return records
        except SQLAlchemyError as e:
            logger.error(f"Database error while querying logs from {model_class.__tablename__}: {e}")
            raise

    def count_logs(self, vendor: str = "palo_alto") -> int:
        """
        Get total count of records in the vendor table.
        """
        model_class = self.get_model_by_vendor(vendor)
        return self.db.query(model_class).count()

    def bulk_insert_logs(
        self, model_class: Type[BaseLogModel], log_dicts: List[Dict[str, Any]]
    ) -> int:
        """
        Perform high-performance bulk insertion using SQLAlchemy bulk_insert_mappings.
        Ideal for large dataset ingestion (e.g. 5,000+ rows).
        """
        if not log_dicts:
            return 0

        try:
            self.db.bulk_insert_mappings(model_class, log_dicts)
            self.db.commit()
            logger.info(
                f"Successfully bulk inserted {len(log_dicts)} records into {model_class.__tablename__}."
            )
            return len(log_dicts)
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f"Bulk insert failed for {model_class.__tablename__}: {e}")
            raise
