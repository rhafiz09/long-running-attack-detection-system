#!/usr/bin/env python3
"""
Orchestrator and Training Pipeline for CNN-LSTM Cybersecurity Attack Detector.
Connects to the database to fetch raw firewall logs, passes them through
the Feature Engineering pipeline, initializes the neural network architecture,
trains the model, and serializes the resulting artifact to disk.
"""

import os
import sys
import random
import logging
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pickle

# Ensure project root is in the path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.database import SessionLocal
from app.models.logs import PaloAltoLog
from app.ai_engine.feature_engineering import LogFeatureEngineer
from app.ai_engine.model_architecture import create_cnn_lstm_model
from sklearn.utils.class_weight import compute_class_weight

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) - %(message)s")
logger = logging.getLogger("training_pipeline")

SAVED_MODELS_DIR = Path(__file__).resolve().parent / "saved_models"
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_SAVE_PATH = SAVED_MODELS_DIR / "cnn_lstm_model.keras"
ENGINEER_SAVE_PATH = SAVED_MODELS_DIR / "feature_engineer.pkl"

TIMESTEPS = 3
EPOCHS = 5
BATCH_SIZE = 32


def generate_mock_logs(count: int = 1000) -> list:
    """
    Fail-Safe Generator with Balanced Malicious Behavior Injection:
    Explicitly injects patterns for all 4 classes across 5-minute time windows
    to guarantee a balanced label distribution (~25% each):
    - Class 0 (Normal): Standard low-volume traffic (<5 connections, 1 port).
    - Class 1 (Recon): High port sweeps (>20 unique target ports per window).
    - Class 2 (Lateral Movement): Internal trust-to-trust zone scanning across multiple target IPs,
      using a previously targeted IP as the origin IP.
    - Class 3 (Beaconing): Highly regular connection intervals (low variance / std=0).
    """
    logger.info("Generating balanced synthetic raw logs with explicit malicious attack patterns...")
    
    mock_list = []
    now = datetime.now()
    # Align to exact top of hour to prevent pd.Grouper from splitting bursts across 5-minute clock boundaries
    base_time = datetime(now.year, now.month, now.day, now.hour, 0, 0) - timedelta(days=5)
    
    # 200 time windows of 5 minutes each = 1000 minutes total
    num_windows = 200
    log_id = 1
    
    for w_idx in range(num_windows):
        w_time = base_time + timedelta(minutes=w_idx * 5)
        pattern_type = w_idx % 4
        
        if pattern_type == 0:
            # Class 0: Normal Traffic (2 logs in 5 mins, within 60s)
            ip_ori = "103.179.248.10"
            ip_imp = "10.14.202.100"
            for offset in [10, 60]:
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=offset),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": 443,
                    "zone_origin": "Trust",
                    "zone_impacted": "Untrust",
                    "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                })
                log_id += 1
                
        elif pattern_type == 1:
            # Class 1: Reconnaissance (25 unique ports scanned in 100s, well within the 5-min window)
            ip_ori = "103.179.248.11"
            ip_imp = "10.14.202.100"
            for j in range(25):  # 25 unique ports > 15 threshold
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=5 + j * 4),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": 1000 + j,
                    "zone_origin": "Untrust",
                    "zone_impacted": "Trust",
                    "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                })
                log_id += 1
                
        elif pattern_type == 2:
            # Class 2: Lateral Movement (Trust-to-Trust scanning 5 unique internal IPs with irregular intervals)
            # Origin IP is 10.14.202.100 (which was previously the targeted IP in Recon & Normal!)
            ip_ori = "10.14.202.100"
            offsets = [5, 10, 35, 90, 110]
            for j, offset in enumerate(offsets):  # 5 unique target IPs > 3 threshold, irregular timing
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=offset),
                    "ip_origin": ip_ori,
                    "ip_impacted": f"10.14.202.{101 + j}",
                    "port_impacted": 445,
                    "zone_origin": "Trust",
                    "zone_impacted": "Trust",
                    "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                })
                log_id += 1
                
        elif pattern_type == 3:
            # Class 3: Beaconing (6 logs spaced exactly 20 seconds apart -> std=0, coef_of_variation=0)
            ip_ori = "103.179.248.12"
            ip_imp = "8.8.8.8"
            for j in range(6):  # exactly 20s intervals, total duration 100s
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=5 + j * 20),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": 53,
                    "zone_origin": "Trust",
                    "zone_impacted": "Untrust",
                    "log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall"
                })
                log_id += 1
                
    return mock_list


def fetch_raw_logs_from_db(limit: int = 15000) -> list:
    """
    Fetches raw logs from Palo Alto table using SQLAlchemy.
    Falls back to synthetic generator if database is empty or connection fails.
    """
    logger.info("Connecting to database to fetch raw Palo Alto security logs...")
    try:
        db = SessionLocal()
        records = db.query(PaloAltoLog).order_by(PaloAltoLog.log_date.asc()).limit(limit).all()
        db.close()
        
        if not records or len(records) < 100:
            logger.warning(f"Database contains insufficient records ({len(records)} found). Standard minimum is 100.")
            return []
            
        # Convert SQLAlchemy ORM objects to standard dictionary list
        logs_list = []
        for r in records:
            logs_list.append({
                "id": r.id,
                "log_date": r.log_date,
                "ip_origin": r.ip_origin,
                "ip_impacted": r.ip_impacted,
                "port_impacted": r.port_impacted,
                "zone_origin": r.zone_origin,
                "zone_impacted": r.zone_impacted,
                "log_source": r.log_source
            })
            
        logger.info(f"Successfully retrieved {len(logs_list)} raw logs from database.")
        return logs_list
    except Exception as e:
        logger.warning(f"Failed to fetch logs from database: {e}")
        return []


def run_pipeline():
    """
    Executes the entire training pipeline end-to-end.
    """
    logger.info("=== Starting CNN-LSTM Model Training Pipeline ===")
    
    # 1. Load data
    raw_logs = fetch_raw_logs_from_db()
    if not raw_logs:
        # DB is empty or disconnected: trigger the fail-safe mock generator
        raw_logs = generate_mock_logs()
        
    # 2. Extract features and convert to sequences
    logger.info("Starting feature engineering process...")
    engineer = LogFeatureEngineer(window_size="5min", timesteps=TIMESTEPS)
    X, y = engineer.fit_transform_pipeline(raw_logs)
    
    if len(X) == 0:
        logger.warning(
            f"No 3D sequences could be generated from real database logs (data is too sparse across source IPs to form sequences of length {TIMESTEPS}). "
            f"Falling back to synthetic mock logs to ensure model compilation and training compile successfully."
        )
        raw_logs = generate_mock_logs()
        X, y = engineer.fit_transform_pipeline(raw_logs)
        
    if len(X) == 0:
        logger.error("No 3D sequences could be generated even with mock data. Check input sequence size or timesteps.")
        return
        
    logger.info(f"Dataset compiled. Ingestion Shape: X={X.shape}, y={y.shape}")
    logger.info(f"Target Label Distribution: {np.bincount(y.astype(int))}")

    # 3. Create Model
    input_shape = (X.shape[1], X.shape[2])
    num_classes = 4
    model = create_cnn_lstm_model(input_shape=input_shape, num_classes=num_classes)
    
    # 4. Fit Model
    logger.info(f"Starting model training for {EPOCHS} epochs with batch_size={BATCH_SIZE}...")
    
    # Shuffle sequences prior to training
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    X = X[indices]
    y = y[indices]
    
    # Calculate class weights to gracefully handle any remaining class imbalances
    classes = np.unique(y)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y)
    class_weight_dict = {int(cls): float(weight) for cls, weight in zip(classes, weights)}
    logger.info(f"Computed balanced class weights: {class_weight_dict}")
    
    # Fit model execution with class weights
    history = model.fit(
        X,
        y,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_split=0.2,
        class_weight=class_weight_dict,
        verbose=1
    )
    
    # 5. Save model and feature engineer to disk
    logger.info(f"Serializing trained Keras model artifact to {MODEL_SAVE_PATH}...")
    model.save(str(MODEL_SAVE_PATH))
    
    logger.info(f"Serializing fitted LogFeatureEngineer artifact to {ENGINEER_SAVE_PATH}...")
    with open(ENGINEER_SAVE_PATH, "wb") as f:
        pickle.dump(engineer, f)
        
    logger.info("=== Training Pipeline Completed Successfully! ===")


if __name__ == "__main__":
    run_pipeline()
