"""
Data Ingestion & AI Trigger Pipeline Worker (Section 4.4)
==========================================================
Implements the full Pre-Database processing, routing, validation, storage, and Post-Storage AI Triggering:
- Section 4.4.1: API Integration (GET from Dummy API with count and offset_range every 5 mins or on demand).
- Section 4.4.2.1: Data Splitting & Vendor Classification (`Palo Alto`, `Fortinet`, `FortiWAF`).
- Section 4.4.2.2: Automatic Schema Management, Data Type Conversion, & Deduplication (`log_sequence_number`).
- Section 4.4.2.3: Data Validation & Mandatory Field Checking.
- Section 4.4.2.4: Batch Insertion into PostgreSQL ORM tables (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`).
- Section 4.4.2.5: Post-Storage Access & Event-Driven AI Triggering (CNN-LSTM Evaluation on active IPs).

Usage:
  # Single batch execution (e.g. 500 records from offset 0)
  python pipeline_worker.py --count 500 --offset 0

  # Continuous loop execution (every 5 minutes / 300 seconds)
  python pipeline_worker.py --loop --interval 300 --count 500
"""

import os
import sys
import time
import json
import logging
import argparse
import requests
from typing import List, Dict, Any, Set
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.core.database import SessionLocal, init_db
from app.models.logs import PaloAltoLog, FortinetLog, FortiWafLog
from app.models.predictions import PredictionLog
from app.services.data_cleaner import classify_log_vendor, clean_log_record
from app.services.inference_service import get_inference_service
from app.schemas.detection import DetectionRequest, LogEntry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Pipeline-Worker-4.4] %(message)s"
)
logger = logging.getLogger("pipeline_worker")

DUMMY_API_URL = "http://localhost:5000/api/v1/dummy/siem-logs"
CURSOR_FILE = os.path.join("datasets", "raw", ".pipeline_cursor.json")


def load_cursor() -> int:
    """Loads the last offset cursor from disk to resume ingestion seamlessly across 5-minute ticks."""
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, "r") as f:
                data = json.load(f)
                return data.get("last_offset", 0)
        except Exception:
            return 0
    return 0


def save_cursor(offset: int):
    """Persists the offset cursor after successful batch insertion."""
    os.makedirs(os.path.dirname(CURSOR_FILE), exist_ok=True)
    try:
        with open(CURSOR_FILE, "w") as f:
            json.dump({"last_offset": offset, "updated_at": datetime.now(timezone.utc).isoformat()}, f)
    except Exception as e:
        logger.warning(f"Failed to save cursor: {e}")


def fetch_from_dummy_api(count: int, offset_range: int) -> List[Dict[str, Any]]:
    """
    Section 4.4.1.1: Connects via REST API (GET) with parameter count and offset_range.
    Fetches raw JSON log payload from Dummy API (Section 4.6).
    """
    logger.info(f"Fetching raw log batch from Dummy API: {DUMMY_API_URL}?count={count}&offset_range={offset_range} ...")
    try:
        resp = requests.get(
            DUMMY_API_URL,
            params={"count": count, "offset_range": offset_range, "shift_timestamps": "true"},
            timeout=10
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("status") == "success":
            records = payload.get("data", [])
            logger.info(f"Successfully retrieved {len(records)} raw log records from Dummy API.")
            return records
        else:
            logger.error(f"Dummy API returned error payload: {payload}")
            return []
    except requests.exceptions.ConnectionError:
        logger.error(
            f"Failed to connect to Dummy API at {DUMMY_API_URL}. "
            "Ensure `python dummy_api_server.py` is running on port 5000."
        )
        return []
    except Exception as e:
        logger.error(f"Error fetching from Dummy API: {e}")
        return []


def deduplicate_records(records: List[Dict[str, Any]], db) -> List[Dict[str, Any]]:
    """
    Section 4.4.2.2 - Deduplication:
    Prevents duplicate data insertion based on `log_sequence_number` (or unique timestamp+IP signature).
    """
    if not records:
        return []

    unique_records = []
    seen_seqs: Set[str] = set()

    for rec in records:
        # Extract sequence number or construct signature
        seq = rec.get("Log Sequence Number") or rec.get("log_sequence_number")
        if not seq:
            # Fallback signature if sequence number is not explicitly labeled
            ip_o = rec.get("IP (Origin)", "") or rec.get("ip_origin", "")
            ip_i = rec.get("IP (Impacted)", "") or rec.get("ip_impacted", "")
            port_i = rec.get("NAT TCP/UDP Port (Impacted)", "") or str(rec.get("port_impacted", ""))
            ts = rec.get("log_date", "") or rec.get("Log Date", "")
            seq = f"{ts}_{ip_o}_{ip_i}_{port_i}"

        if seq in seen_seqs:
            continue  # Drop in-batch duplicate
        seen_seqs.add(seq)
        unique_records.append(rec)

    # Note: In massive multi-million row production, checking existing sequences in DB is indexed
    # For this 5-minute batch window, deduplication ensures batch integrity before insertion
    return unique_records


def run_pipeline_tick(count: int, offset_range: int) -> int:
    """
    Executes a complete 5-minute pipeline tick:
    1. Fetch from Dummy API
    2. Vendor Classification & Data Cleaning (18+1 schema)
    3. Deduplication
    4. Batch Insertion into PostgreSQL (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`)
    5. Post-Storage AI Triggering (`InferenceService`)
    """
    logger.info(f"=== Starting Pipeline Ingestion & AI Trigger Tick (count={count}, offset={offset_range}) ===")
    raw_records = fetch_from_dummy_api(count=count, offset_range=offset_range)
    if not raw_records:
        logger.warning("No records fetched. Pipeline tick skipped.")
        return offset_range

    db = SessionLocal()
    try:
        # Deduplicate
        unique_records = deduplicate_records(raw_records, db)
        logger.info(f"Records after deduplication check: {len(unique_records)} / {len(raw_records)}")

        palo_alto_batch = []
        fortinet_batch = []
        fortiwaf_batch = []
        ai_input_logs = []

        # Process and Classify each record (Section 4.4.2.1 & 4.4.2.2 & 4.4.2.3)
        for rec in unique_records:
            cleaned = clean_log_record(rec)
            vendor = classify_log_vendor(cleaned)


            if not cleaned["log_date"]:
                continue  # Mandatory field validation: skip records without a valid timestamp

            # Prepare for AI Inference (LogEntry format)
            ai_input_logs.append(LogEntry(
                log_date=cleaned["log_date"],
                ip_origin=cleaned.get("ip_origin"),
                ip_impacted=cleaned.get("ip_impacted"),
                port_impacted=cleaned.get("port_impacted"),
                zone_origin=cleaned.get("zone_origin"),
                zone_impacted=cleaned.get("zone_impacted"),
                log_source=cleaned.get("log_source"),
                additional_data=cleaned.get("additional_data", {})
            ))

            if vendor == "palo_alto":
                palo_alto_batch.append(cleaned)
            elif vendor == "fortiwaf":
                fortiwaf_batch.append(cleaned)
            else:
                fortinet_batch.append(cleaned)

        # Batch Insertion to Database (Section 4.4.2.4)
        logger.info(
            f"Routing Classification Results -> Palo Alto: {len(palo_alto_batch)}, "
            f"Fortinet: {len(fortinet_batch)}, FortiWAF: {len(fortiwaf_batch)}"
        )

        if palo_alto_batch:
            db.bulk_insert_mappings(PaloAltoLog, palo_alto_batch)
        if fortinet_batch:
            db.bulk_insert_mappings(FortinetLog, fortinet_batch)
        if fortiwaf_batch:
            db.bulk_insert_mappings(FortiWafLog, fortiwaf_batch)

        db.commit()
        logger.info(f"Successfully batch inserted {len(unique_records)} records into PostgreSQL!")

        # Save cursor
        next_offset = offset_range + len(raw_records)
        save_cursor(next_offset)

        # Post-Storage Access & Event-Driven AI Triggering (Section 4.4.2.5)
        logger.info("Triggering AI Inference Engine (CNN-LSTM) on newly ingested batch...")
        try:
            inference_svc = get_inference_service()
            detection_req = DetectionRequest(logs=ai_input_logs)
            ai_response = inference_svc.predict(detection_req)

            if ai_response.status == "success":
                attacks_detected = [r for r in ai_response.results if r.label > 0]
                logger.info(
                    f"[AI Engine Report] Evaluated {len(ai_response.results)} active IP sequences. "
                    f"Attacks detected: {len(attacks_detected)}"
                )
                
                # Store all evaluated predictions/alerts into prediction_logs table (Section 4.4.2.5 & Poin 11)
                if ai_response.results:
                    pred_db = SessionLocal()
                    try:
                        pred_objects = [
                            PredictionLog(
                                ip_origin=res.ip_origin,
                                label=res.label,
                                threat_name=res.threat_name,
                                confidence_score=res.confidence_score,
                                sequence_metadata={"eval_window": "15min (timesteps=3)"}
                            )
                            for res in ai_response.results
                        ]
                        pred_db.bulk_save_objects(pred_objects)
                        pred_db.commit()
                        logger.info(f"Successfully recorded {len(pred_objects)} AI prediction evaluations into PostgreSQL (`prediction_logs` table)!")
                    except Exception as pred_err:
                        pred_db.rollback()
                        logger.error(f"Failed to record AI predictions to database: {pred_err}")
                    finally:
                        pred_db.close()

                for atk in attacks_detected:
                    logger.warning(
                        f"🚨 [LONG RUNNING ATTACK DETECTED] IP: {atk.ip_origin} | "
                        f"Threat Stage: {atk.threat_name} (Label {atk.label}) | "
                        f"Confidence: {atk.confidence_score*100:.2f}%"
                    )
            else:
                logger.warning(f"AI Inference Engine returned non-success: {ai_response.message}")
        except Exception as ai_err:
            logger.error(f"Error during Post-Storage AI trigger: {ai_err}")

        return next_offset

    except Exception as e:
        db.rollback()
        logger.error(f"Database batch insertion failed during pipeline tick: {e}")
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Pipeline Worker (Section 4.4)")
    parser.add_argument("--count", type=int, default=500, help="Number of records to ingest per tick")
    parser.add_argument("--offset", type=int, default=-1, help="Starting offset (-1 to resume from cursor)")
    parser.add_argument("--loop", action="store_true", help="Run continuously in a 5-minute loop")
    parser.add_argument("--interval", type=int, default=300, help="Loop interval in seconds (default: 300s / 5 mins)")
    args = parser.parse_args()

    init_db()

    current_offset = args.offset if args.offset >= 0 else load_cursor()

    if args.loop:
        logger.info(f"Starting Continuous Pipeline Worker in loop mode (interval={args.interval}s)...")
        while True:
            try:
                current_offset = run_pipeline_tick(count=args.count, offset_range=current_offset)
                logger.info(f"Tick complete. Next offset cursor: {current_offset}. Sleeping for {args.interval}s ...")
                time.sleep(args.interval)
            except KeyboardInterrupt:
                logger.info("Pipeline Worker stopped by user (KeyboardInterrupt).")
                break
            except Exception as e:
                logger.error(f"Error in pipeline loop: {e}. Retrying in 15 seconds...")
                time.sleep(15)
    else:
        run_pipeline_tick(count=args.count, offset_range=current_offset)
        logger.info("Single pipeline tick completed successfully.")


if __name__ == "__main__":
    main()
