#!/usr/bin/env python3
"""
Memory-Optimized Database Seeder for Large Cybersecurity Dataset Ingestion.
Reads massive CSV log exports (500MB+) using Pandas chunking (chunksize=10000)
to prevent system RAM overload. Extracts a sample of 5,000 rows, cleans the data types
using app.services.data_cleaner, and performs SQLAlchemy bulk insertion.
"""

import os
import sys
import logging
import shutil
import pandas as pd
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.database import SessionLocal, init_db
from app.models.logs import PaloAltoLog
from app.repositories.log_repository import LogRepository
from app.services.data_cleaner import clean_log_record

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seeder")

DATASET_PATH = Path("datasets/raw/firewall_log.csv")
PARENT_FALLBACK_DATASET = Path("../03_05_2026-LogRhythm_WebLogsExport (1).csv")
SAMPLE_SIZE = 5000
CHUNK_SIZE = 10000
BATCH_INSERT_SIZE = 1000


def prepare_dataset_file() -> bool:
    """
    Ensures that datasets/raw/firewall_log.csv exists.
    If missing, checks if the large dataset exists in the parent project folder
    and automatically copies/links it for user convenience.
    """
    if DATASET_PATH.exists():
        return True

    logger.warning(f"Dataset not found at {DATASET_PATH}.")
    if PARENT_FALLBACK_DATASET.exists():
        logger.info(f"Found existing dataset in parent folder: {PARENT_FALLBACK_DATASET}. Copying to {DATASET_PATH}...")
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(PARENT_FALLBACK_DATASET, DATASET_PATH)
            logger.info("Dataset copied successfully!")
            return True
        except Exception as e:
            logger.error(f"Failed copying fallback dataset: {e}")
            return False

    logger.error(
        f"Please place your massive CSV firewall log export (500MB+) at: {DATASET_PATH}"
    )
    return False


def seed_database():
    """
    Main memory-optimized seeding routine.
    """
    logger.info("=== Starting Memory-Optimized Cybersecurity Database Seeder ===")

    # 1. Verify or prepare dataset file
    if not prepare_dataset_file():
        logger.info("Seeder aborted: Missing CSV dataset file.")
        return

    # 2. Initialize database schema
    logger.info("Initializing database tables...")
    init_db()

    # 3. Read first chunk using pandas (chunksize=10000) to prevent RAM overload
    logger.info(f"Reading CSV dataset ({DATASET_PATH}) with chunksize={CHUNK_SIZE}...")
    try:
        csv_reader = pd.read_csv(
            DATASET_PATH,
            chunksize=CHUNK_SIZE,
            dtype=str,
            keep_default_na=False,
            low_memory=False,
        )
        first_chunk = next(csv_reader)
        logger.info(f"Successfully loaded first chunk of {len(first_chunk)} rows into memory.")
    except Exception as e:
        logger.error(f"Error reading CSV file {DATASET_PATH}: {e}")
        return

    # 4. Extract first 5,000 rows as sample
    sample_df = first_chunk.head(SAMPLE_SIZE)
    logger.info(f"Extracted sample of {len(sample_df)} rows for Data Type Conversion & Ingestion.")

    # 5. Apply Data Type Conversion utility from Service layer
    logger.info("Applying Data Type Conversion utility (cleaning empty strings & scientific notation dates)...")
    raw_records = sample_df.to_dict(orient="records")
    cleaned_records = [clean_log_record(row) for row in raw_records]

    # 6. Bulk insert into palo_alto_logs table
    db = SessionLocal()
    repo = LogRepository(db)
    total_inserted = 0

    try:
        logger.info(f"Beginning bulk insertion into {PaloAltoLog.__tablename__} in batches of {BATCH_INSERT_SIZE}...")
        for i in range(0, len(cleaned_records), BATCH_INSERT_SIZE):
            batch = cleaned_records[i : i + BATCH_INSERT_SIZE]
            repo.bulk_insert_logs(PaloAltoLog, batch)
            total_inserted += len(batch)
            # Terminal feedback / logging as required by prompt
            print(f"--> [SEEDER PROGRESS] Inserted {total_inserted} / {len(cleaned_records)} rows into the database...")

        logger.info(f"=== Seeding Complete! Successfully inserted {total_inserted} rows into {PaloAltoLog.__tablename__} ===")
    except Exception as e:
        logger.error(f"Database insertion failed during seeding: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
