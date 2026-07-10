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
from app.models.logs import PaloAltoLog, FortinetLog, FortiWafLog
from app.repositories.log_repository import LogRepository
from app.services.data_cleaner import clean_log_record, classify_log_vendor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seeder")

DATASET_PATH = Path("datasets/raw/firewall_log.csv")
PARENT_FALLBACK_DATASET = Path("../03_05_2026-LogRhythm_WebLogsExport (1).csv")
SAMPLE_SIZE = 10000
CHUNK_SIZE = 10000
BATCH_INSERT_SIZE = 1000

# Set to True jika ingin membagi rata data sampel ke 3 tabel (Palo Alto, Fortinet, FortiWAF)
# untuk keperluan demo & pengujian lokal saat menggunakan dataset CSV yang hanya berisi 1 vendor.
SIMULATE_MULTI_VENDOR = True

# Set to True jika ingin mengosongkan/membersihkan tabel log sebelum melakukan seeding baru
CLEAR_EXISTING_DATA = True


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
    # 2. Clear existing tables/schema if flag is set to guarantee new 18+1 columns are created cleanly
    if CLEAR_EXISTING_DATA:
        logger.info("Dropping existing tables to apply new 18+1 column schema (DROP TABLE CASCADE)...")
        db_clear = SessionLocal()
        try:
            from sqlalchemy import text
            db_clear.execute(text("DROP TABLE IF EXISTS palo_alto_logs, fortinet_logs, fortiwaf_logs CASCADE;"))
            db_clear.commit()
            logger.info("Database tables dropped successfully.")
        except Exception as e:
            db_clear.rollback()
            logger.warning(f"Drop table failed: {e}")
        finally:
            db_clear.close()

    # 3. Initialize database schema (creates new tables with 18+1 columns)
    logger.info("Initializing database tables with updated 18+1 schema...")
    init_db()

    # 3. Read dataset using pandas with chunksize to prevent RAM overload, looping until SAMPLE_SIZE is gathered
    logger.info(f"Reading CSV dataset ({DATASET_PATH}) in chunks of {CHUNK_SIZE} until gathering {SAMPLE_SIZE} records...")
    chunks = []
    total_loaded = 0
    try:
        logger.info(f"Attempting to read CSV using utf-8 encoding...")
        csv_reader = pd.read_csv(
            DATASET_PATH,
            chunksize=CHUNK_SIZE,
            dtype=str,
            keep_default_na=False,
            low_memory=False,
            encoding="utf-8",
        )
        for chunk in csv_reader:
            chunks.append(chunk)
            total_loaded += len(chunk)
            logger.info(f"Loaded chunk of {len(chunk)} rows. Total in memory: {total_loaded}")
            if total_loaded >= SAMPLE_SIZE:
                break
    except Exception as utf8_err:
        logger.warning(f"UTF-8 read failed ({utf8_err}), falling back to latin-1 encoding...")
        chunks = []
        total_loaded = 0
        try:
            csv_reader = pd.read_csv(
                DATASET_PATH,
                chunksize=CHUNK_SIZE,
                dtype=str,
                keep_default_na=False,
                low_memory=False,
                encoding="latin-1",
            )
            for chunk in csv_reader:
                chunks.append(chunk)
                total_loaded += len(chunk)
                logger.info(f"Loaded chunk of {len(chunk)} rows. Total in memory: {total_loaded}")
                if total_loaded >= SAMPLE_SIZE:
                    break
        except Exception as fallback_err:
            logger.error(f"Failed to read CSV with both utf-8 and latin-1 encodings: {fallback_err}")
            return

    if not chunks:
        logger.error("No data could be read from the CSV file.")
        return

    combined_df = pd.concat(chunks)
    sample_df = combined_df.head(SAMPLE_SIZE)
    logger.info(f"Successfully loaded and concatenated {len(sample_df)} total sample rows into memory.")


    # 5. Apply Data Type Conversion utility from Service layer
    logger.info("Applying Data Type Conversion utility (cleaning empty strings & scientific notation dates)...")
    raw_records = sample_df.to_dict(orient="records")
    cleaned_records = [clean_log_record(row) for row in raw_records]

    # 6. Group by vendor & bulk insert into multi-vendor firewall tables
    db = SessionLocal()
    repo = LogRepository(db)
    total_inserted = 0

    try:
        logger.info("Classifying records by vendor (Palo Alto, Fortinet, FortiWAF)...")
        vendor_batches = {
            "palo_alto": [],
            "fortinet": [],
            "fortiwaf": []
        }

        # Jika SIMULATE_MULTI_VENDOR aktif dan dataset hanya dari 1 vendor, bagi rata ke 3 tabel untuk demo lokal
        vendors_list = ["palo_alto", "fortinet", "fortiwaf"]
        for idx, record in enumerate(cleaned_records):
            if SIMULATE_MULTI_VENDOR:
                vendor = vendors_list[idx % 3]
                # Override log_source agar selaras dengan tabel tujuan simulasi
                record["log_source"] = f"10.14.202.200 {vendor.upper()} Firewall"
            else:
                vendor = classify_log_vendor(record)
            vendor_batches[vendor].append(record)

        for vendor_key, records_batch in vendor_batches.items():
            if not records_batch:
                logger.info(f"--> [SEEDER SKIP] 0 records detected for vendor '{vendor_key}'.")
                continue

            model_class = repo.get_model_by_vendor(vendor_key)
            logger.info(f"Beginning bulk insertion into {model_class.__tablename__} ({len(records_batch)} records) in batches of {BATCH_INSERT_SIZE}...")

            inserted_for_vendor = 0
            for i in range(0, len(records_batch), BATCH_INSERT_SIZE):
                batch = records_batch[i : i + BATCH_INSERT_SIZE]
                repo.bulk_insert_logs(model_class, batch)
                inserted_for_vendor += len(batch)
                total_inserted += len(batch)
                print(f"--> [SEEDER PROGRESS - {vendor_key.upper()}] Inserted {inserted_for_vendor} / {len(records_batch)} rows into {model_class.__tablename__}...")

        logger.info(f"=== Seeding Complete! Successfully inserted {total_inserted} total rows across vendor tables ===")
    except Exception as e:
        logger.error(f"Database insertion failed during seeding: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
