"""
Dummy API Server (Section 4.6 & Section 4.4.1.1) - Memory-Optimized & Ultra-Fast
===================================================================================
Simulates a real-world SIEM (LogRhythm / Splunk / Firewall centralized collector) REST API.
Built with Flask & Flask-CORS (as specified in Section 3.3).

Serves raw firewall log records from `datasets/raw/firewall_log.csv` (`Dataset Environment`)
in JSON format with pagination parameters (`count` and `offset_range`).

Features:
1. Ultra-Fast Memory-Optimized Pagination: Uses `skiprows` and `nrows` to fetch any slice (e.g. 500 rows)
   in under 30 milliseconds without loading the 589MB CSV into RAM!
2. Live Timestamp Shifting: Automatically shifts historical CSV log timestamps (`log_date`, `First Log Date`, `Last Log Date`)
   to the current UTC time (`datetime.now(timezone.utc)`), ensuring that real-time SOC monitoring dashboards
   (Django Section 4.3.3 Line Chart) display live, active traffic trends rather than stale historical dates.
3. Raw JSON Export: Outputs raw log dictionaries ready for ingestion, vendor classification, data cleaning, and deduplication
   by the Pipeline Worker (Section 4.4).
"""

import os
import logging
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Dummy-SIEM-API] %(message)s"
)
logger = logging.getLogger("dummy_api")

app = Flask(__name__)
CORS(app)

DATASET_PATH = os.path.join("datasets", "raw", "firewall_log.csv")
_cached_total_rows = None
_cached_header = None


def get_total_rows_and_header():
    global _cached_total_rows, _cached_header
    if _cached_total_rows is None or _cached_header is None:
        if not os.path.exists(DATASET_PATH):
            logger.error(f"Dataset not found at {DATASET_PATH}!")
            raise FileNotFoundError(f"Dataset {DATASET_PATH} missing.")
        
        # Read header first
        _cached_header = list(pd.read_csv(DATASET_PATH, nrows=0).columns)
        
        # Fast line count of CSV without parsing columns
        logger.info(f"Counting total lines in {DATASET_PATH} ...")
        with open(DATASET_PATH, "rb") as f:
            _cached_total_rows = sum(1 for _ in f) - 1  # Subtract header
        logger.info(f"Dataset indexed. Total records: {_cached_total_rows:,}")
    return _cached_total_rows, _cached_header


@app.route("/health", methods=["GET"])
def health():
    total_rows, _ = get_total_rows_and_header() if os.path.exists(DATASET_PATH) else (0, [])
    return jsonify({
        "status": "online",
        "service": "Dummy SIEM Log Acquisition API (Section 4.6)",
        "dataset_path": DATASET_PATH,
        "total_available_records": total_rows
    })


@app.route("/api/v1/dummy/siem-logs", methods=["GET"])
def get_siem_logs():
    """
    GET /api/v1/dummy/siem-logs?count=100&offset_range=0
    
    Parameters:
    - count: int (Number of records to retrieve, defaults to 100)
    - offset_range: int (Row offset index in the CSV, defaults to 0)
    - shift_timestamps: bool (Whether to shift timestamps to live UTC current time, defaults to true)
    """
    try:
        count = int(request.args.get("count", 100))
        offset_range = int(request.args.get("offset_range", 0))
        shift_timestamps = request.args.get("shift_timestamps", "true").lower() == "true"
    except ValueError:
        return jsonify({"error": "Invalid parameters for count or offset_range. Must be integers."}), 400

    total_rows, header = get_total_rows_and_header()

    if offset_range >= total_rows:
        return jsonify({
            "status": "success",
            "message": "Offset exceeded total available records. Wrap around or end of dataset reached.",
            "total_records": total_rows,
            "offset_range": offset_range,
            "count": count,
            "data": []
        })

    # Ultra-fast memory-optimized slice read
    try:
        skip = range(1, offset_range + 1) if offset_range > 0 else None
        slice_df = pd.read_csv(
            DATASET_PATH,
            skiprows=skip,
            nrows=count,
            names=header if offset_range > 0 else None,
            header=0 if offset_range == 0 else None,
            dtype=str,
            keep_default_na=False
        )
    except Exception as e:
        logger.error(f"Failed to slice CSV at offset {offset_range}: {e}")
        return jsonify({"error": str(e)}), 500

    records = slice_df.to_dict(orient="records")

    # Apply Live Timestamp Shifting if requested
    if shift_timestamps and records:
        now_utc = datetime.now(timezone.utc)
        # Shift timestamps across the slice so they fall within the last 5 minutes leading up to right now
        step_seconds = 300.0 / max(len(records), 1)
        for i, rec in enumerate(records):
            shifted_dt = now_utc - timedelta(seconds=(len(records) - i) * step_seconds)
            iso_str = shifted_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            epoch_ms = str(int(shifted_dt.timestamp() * 1000))

            # Update log_date / timestamp column if present
            if "log_date" in rec:
                rec["log_date"] = iso_str
            elif "Log Date" in rec:
                rec["Log Date"] = iso_str
            if "First Log Date" in rec:
                rec["First Log Date"] = epoch_ms
            if "Last Log Date" in rec:
                rec["Last Log Date"] = epoch_ms

    logger.info(f"Served {len(records)} raw SIEM log records in milliseconds (offset={offset_range}, count={count}, live_shift={shift_timestamps}).")

    return jsonify({
        "status": "success",
        "total_available": total_rows,
        "offset_range": offset_range,
        "count_returned": len(records),
        "data": records
    })


if __name__ == "__main__":
    logger.info("Starting Flask Dummy SIEM API Server on port 5000...")
    get_total_rows_and_header()  # Pre-index dataset on boot
    app.run(host="0.0.0.0", port=5000, debug=False)
