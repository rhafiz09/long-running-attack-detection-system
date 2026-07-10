#!/usr/bin/env python3
"""
Orchestrator and Training Pipeline for CNN-LSTM Cybersecurity Attack Detector.
Connects to the database (or offline Custom/Public CSV datasets) to fetch raw firewall logs,
passes them through the Feature Engineering pipeline, initializes the neural network architecture,
trains 3 distinct vendor models (Palo Alto, FortiGate, FortiWAF), outputs comprehensive
evaluation metrics (Precision, Recall, F1, Accuracy), and serializes the resulting artifacts to disk.
"""

import os
import sys
import random
import logging
import pickle
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure project root is in the path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.core.database import SessionLocal
from app.models.logs import PaloAltoLog, FortinetLog, FortiWafLog as FortiwafLog
from app.ai_engine.feature_engineering import LogFeatureEngineer
from app.ai_engine.model_architecture import create_cnn_lstm_model
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) - %(message)s")
logger = logging.getLogger("training_pipeline")

SAVED_MODELS_DIR = Path(__file__).resolve().parent / "saved_models"
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)

TIMESTEPS = 3
EPOCHS = 6
BATCH_SIZE = 32

VENDOR_CONFIGS = {
    "palo_alto": {
        "display_name": "Palo Alto (Firewall Server Utama)",
        "model_file": SAVED_MODELS_DIR / "palo_alto_cnn_lstm.keras",
        "engineer_file": SAVED_MODELS_DIR / "palo_alto_feature_engineer.pkl",
        "db_model": PaloAltoLog,
        "default_log_source": "JKT-GANDUL-FW-04 Palo Alto Firewall",
        "default_ports": [443, 80, 22, 3306]
    },
    "fortigate": {
        "display_name": "FortiGate (Firewall Kantor Cabang)",
        "model_file": SAVED_MODELS_DIR / "fortigate_cnn_lstm.keras",
        "engineer_file": SAVED_MODELS_DIR / "fortigate_feature_engineer.pkl",
        "db_model": FortinetLog,
        "default_log_source": "SUB-BRANCH-FW-01 FortiGate Firewall",
        "default_ports": [443, 80, 445, 3389]
    },
    "fortiwaf": {
        "display_name": "FortiWAF (Firewall Aplikasi Website)",
        "model_file": SAVED_MODELS_DIR / "fortiwaf_cnn_lstm.keras",
        "engineer_file": SAVED_MODELS_DIR / "fortiwaf_feature_engineer.pkl",
        "db_model": FortiwafLog,
        "default_log_source": "WEB-CLUSTER-WAF-01 FortiWAF",
        "default_ports": [80, 443, 8080, 8443]
    }
}


def generate_mock_logs(vendor_key: str = "palo_alto", num_windows: int = 240) -> List[Dict[str, Any]]:
    """
    Fail-Safe & Preparation Generator with Balanced Malicious Behavior Injection:
    Explicitly injects patterns for all 4 classes across 5-minute time windows
    to guarantee a balanced label distribution (~25% each) tailored for the specific vendor:
    - Class 0 (Normal): Standard low-volume traffic (<5 connections, 1 port).
    - Class 1 (Recon): High port sweeps (>20 unique target ports per window).
    - Class 2 (Lateral Movement): Internal trust-to-trust zone scanning across multiple target IPs.
    - Class 3 (Beaconing): Highly regular connection intervals (low variance / periodic).
    """
    cfg = VENDOR_CONFIGS.get(vendor_key, VENDOR_CONFIGS["palo_alto"])
    log_src = cfg["default_log_source"]
    logger.info(f"Generating balanced synthetic training logs for vendor: {cfg['display_name']}...")
    
    mock_list = []
    now = datetime.now()
    base_time = datetime(now.year, now.month, now.day, now.hour, 0, 0) - timedelta(days=6)
    
    log_id = 1
    for w_idx in range(num_windows):
        w_time = base_time + timedelta(minutes=w_idx * 5)
        pattern_type = w_idx % 4
        
        if pattern_type == 0:
            # Class 0: Normal Traffic (2 logs in 5 mins)
            ip_ori = f"103.179.248.{10 + (w_idx % 5)}"
            ip_imp = "10.14.202.100"
            for offset in [10, 60]:
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=offset),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": cfg["default_ports"][0],
                    "zone_origin": "Trust" if w_idx % 2 == 0 else "Untrust",
                    "zone_impacted": "Untrust" if w_idx % 2 == 0 else "Trust",
                    "log_source": log_src
                })
                log_id += 1
                
        elif pattern_type == 1:
            # Class 1: Reconnaissance (25 unique ports scanned within window > 15 threshold)
            ip_ori = f"103.179.248.{20 + (w_idx % 5)}"
            ip_imp = "10.14.202.100"
            for j in range(25):
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=5 + j * 4),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": 1000 + j,
                    "zone_origin": "Untrust",
                    "zone_impacted": "Trust",
                    "log_source": log_src
                })
                log_id += 1
                
        elif pattern_type == 2:
            # Class 2: Lateral Movement (Trust-to-Trust scanning 5 unique internal IPs > 3 threshold)
            ip_ori = "10.14.202.100"
            offsets = [5, 10, 35, 90, 110]
            for j, offset in enumerate(offsets):
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=offset),
                    "ip_origin": ip_ori,
                    "ip_impacted": f"10.14.202.{101 + j}",
                    "port_impacted": 445 if vendor_key != "fortiwaf" else 8080,
                    "zone_origin": "Trust",
                    "zone_impacted": "Trust",
                    "log_source": log_src
                })
                log_id += 1
                
        elif pattern_type == 3:
            # Class 3: Beaconing (6 logs spaced exactly 20 seconds apart -> std=0, coef_of_variation=0)
            ip_ori = f"10.14.202.{50 + (w_idx % 5)}"
            ip_imp = "8.8.8.8"
            for j in range(6):
                mock_list.append({
                    "id": log_id,
                    "log_date": w_time + timedelta(seconds=5 + j * 20),
                    "ip_origin": ip_ori,
                    "ip_impacted": ip_imp,
                    "port_impacted": 53 if vendor_key != "fortiwaf" else 443,
                    "zone_origin": "Trust",
                    "zone_impacted": "Untrust",
                    "log_source": log_src
                })
                log_id += 1
                
    return mock_list


def fetch_raw_logs_from_db(vendor_key: str, limit: int = 20000) -> List[Dict[str, Any]]:
    """
    Fetches raw logs from the specific vendor's PostgreSQL table using SQLAlchemy.
    """
    cfg = VENDOR_CONFIGS.get(vendor_key)
    if not cfg:
        return []
        
    logger.info(f"Connecting to DB to fetch logs for {cfg['display_name']}...")
    try:
        db = SessionLocal()
        records = db.query(cfg["db_model"]).order_by(cfg["db_model"].log_date.asc()).limit(limit).all()
        db.close()
        
        if not records or len(records) < 100:
            logger.info(f"DB contains insufficient records ({len(records)} found for {vendor_key}).")
            return []
            
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
        logger.info(f"Retrieved {len(logs_list)} real DB logs for {vendor_key}.")
        return logs_list
    except Exception as e:
        logger.warning(f"Failed to fetch DB logs for {vendor_key}: {e}")
        return []


def load_offline_dataset_csv(csv_path: str, vendor_key: str = "palo_alto") -> List[Dict[str, Any]]:
    """
    Loads raw firewall log data from an offline CSV file (Custom or Public dataset)
    and maps the 5 core AI columns needed for training.
    """
    if not os.path.exists(csv_path):
        logger.warning(f"Offline dataset CSV not found at: {csv_path}")
        return []
        
    logger.info(f"Loading offline training dataset from CSV: {csv_path}...")
    try:
        df = pd.read_csv(csv_path, nrows=50000)  # Limit rows for fast prep
        logs_list = []
        
        # Map or fallback column names
        ip_ori_col = next((c for c in df.columns if c.lower() in ["ip address (origin)", "ip_origin", "src_ip", "source_ip"]), None)
        ip_imp_col = next((c for c in df.columns if c.lower() in ["ip address (impacted)", "ip_impacted", "dst_ip", "dest_ip"]), None)
        port_col = next((c for c in df.columns if c.lower() in ["tcp/udp port (impacted)", "port_impacted", "dst_port", "destination_port"]), None)
        zone_ori_col = next((c for c in df.columns if c.lower() in ["zone (origin)", "zone_origin", "src_zone"]), None)
        zone_imp_col = next((c for c in df.columns if c.lower() in ["zone (impacted)", "zone_impacted", "dst_zone"]), None)
        date_col = next((c for c in df.columns if c.lower() in ["log date", "log_date", "timestamp", "time"]), None)
        src_col = next((c for c in df.columns if c.lower() in ["log source", "log_source", "device"]), None)
        
        cfg = VENDOR_CONFIGS.get(vendor_key, VENDOR_CONFIGS["palo_alto"])
        
        for idx, row in df.iterrows():
            logs_list.append({
                "id": idx + 1,
                "log_date": pd.to_datetime(row[date_col]) if date_col and pd.notnull(row[date_col]) else datetime.now() - timedelta(minutes=(50000-idx)*2),
                "ip_origin": str(row[ip_ori_col]) if ip_ori_col and pd.notnull(row[ip_ori_col]) else "103.179.248.10",
                "ip_impacted": str(row[ip_imp_col]) if ip_imp_col and pd.notnull(row[ip_imp_col]) else "10.14.202.100",
                "port_impacted": int(row[port_col]) if port_col and pd.notnull(row[port_col]) and str(row[port_col]).isdigit() else cfg["default_ports"][0],
                "zone_origin": str(row[zone_ori_col]) if zone_ori_col and pd.notnull(row[zone_ori_col]) else "Untrust",
                "zone_impacted": str(row[zone_imp_col]) if zone_imp_col and pd.notnull(row[zone_imp_col]) else "Trust",
                "log_source": str(row[src_col]) if src_col and pd.notnull(row[src_col]) else cfg["default_log_source"]
            })
        logger.info(f"Successfully loaded {len(logs_list)} training records from offline CSV.")
        return logs_list
    except Exception as e:
        logger.error(f"Error parsing offline CSV dataset: {e}")
        return []


def train_vendor_model(vendor_key: str, custom_csv_path: Optional[str] = None) -> bool:
    """
    Trains and saves the CNN-LSTM model for a specific firewall vendor.
    """
    cfg = VENDOR_CONFIGS.get(vendor_key)
    if not cfg:
        logger.error(f"Unknown vendor key: {vendor_key}")
        return False
        
    logger.info(f"=== Starting Training Pipeline for {cfg['display_name']} ===")
    
    # 1. Acquire training logs (CSV Custom -> DB -> Synthetic fallback)
    raw_logs = []
    if custom_csv_path:
        raw_logs = load_offline_dataset_csv(custom_csv_path, vendor_key)
        
    if not raw_logs:
        raw_logs = fetch_raw_logs_from_db(vendor_key)
        
    if not raw_logs:
        logger.info(f"Using synthetic balanced preparation logs for {vendor_key}...")
        raw_logs = generate_mock_logs(vendor_key=vendor_key, num_windows=280)
        
    # 2. Extract features and convert to 3D sequences
    logger.info(f"Executing Feature Engineering for {cfg['display_name']}...")
    engineer = LogFeatureEngineer(window_size="5min", timesteps=TIMESTEPS)
    X, y = engineer.fit_transform_pipeline(raw_logs)
    
    if len(X) == 0:
        logger.warning(f"No 3D sequences formed from initial logs for {vendor_key}. Falling back to balanced preparation generator...")
        raw_logs = generate_mock_logs(vendor_key=vendor_key, num_windows=280)
        X, y = engineer.fit_transform_pipeline(raw_logs)
        
    if len(X) == 0:
        logger.error(f"CRITICAL: Failed to generate 3D sequences for {vendor_key}.")
        return False
        
    logger.info(f"Dataset ready -> Sequences Shape: X={X.shape}, y={y.shape}")
    logger.info(f"Target Label Distribution: {np.bincount(y.astype(int))}")
    
    # 3. Create CNN-LSTM Model
    input_shape = (X.shape[1], X.shape[2])
    num_classes = 4
    model = create_cnn_lstm_model(input_shape=input_shape, num_classes=num_classes)
    
    # 4. Shuffle & compute balanced class weights
    indices = np.arange(len(X))
    np.random.shuffle(indices)
    X = X[indices]
    y = y[indices]
    
    classes = np.unique(y)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y)
    class_weight_dict = {int(cls): float(weight) for cls, weight in zip(classes, weights)}
    logger.info(f"Computed class weights: {class_weight_dict}")
    
    # Train-test split (80% train, 20% validation/evaluation)
    split_idx = int(0.8 * len(X))
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]
    
    # Fit Model
    logger.info(f"Fitting CNN-LSTM Model for {EPOCHS} epochs...")
    history = model.fit(
        X_train,
        y_train,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        validation_data=(X_val, y_val) if len(X_val) > 0 else None,
        class_weight=class_weight_dict,
        verbose=1
    )
    
    # 5. Evaluate Model & Print Comprehensive Metrics Report
    if len(X_val) > 0:
        logger.info(f"--- EVALUATION METRICS REPORT FOR {cfg['display_name'].upper()} ---")
        y_pred_probs = model.predict(X_val, verbose=0)
        y_pred = np.argmax(y_pred_probs, axis=1)
        
        acc = accuracy_score(y_val, y_pred)
        logger.info(f"Validation Accuracy: {acc:.4f} ({acc*100:.2f}%)")
        
        target_names = ["0: Normal", "1: Reconnaissance", "2: Lateral Movement", "3: Beaconing"]
        # Filter target names to classes actually present in y_val or y_pred
        present_classes = sorted(list(set(y_val.astype(int)).union(set(y_pred.astype(int)))))
        present_names = [target_names[c] if c < len(target_names) else f"Class {c}" for c in present_classes]
        
        rep = classification_report(y_val, y_pred, labels=present_classes, target_names=present_names, zero_division=0)
        logger.info(f"\nClassification Report:\n{rep}")
        
        cm = confusion_matrix(y_val, y_pred, labels=present_classes)
        logger.info(f"Confusion Matrix:\n{cm}")
    
    # 6. Serialize artifacts to disk
    logger.info(f"Saving trained model to: {cfg['model_file']}...")
    model.save(str(cfg["model_file"]))
    
    # Also save backwards-compatible default cnn_lstm_model.keras if palo_alto
    if vendor_key == "palo_alto":
        default_model_path = SAVED_MODELS_DIR / "cnn_lstm_model.keras"
        default_eng_path = SAVED_MODELS_DIR / "feature_engineer.pkl"
        model.save(str(default_model_path))
        with open(default_eng_path, "wb") as f:
            pickle.dump(engineer, f)
            
    logger.info(f"Saving feature engineer to: {cfg['engineer_file']}...")
    with open(cfg["engineer_file"], "wb") as f:
        pickle.dump(engineer, f)
        
    logger.info(f"=== Successfully Finished Training for {cfg['display_name']} ===\n")
    return True


def run_pipeline(target_vendor: str = "ALL", custom_csv_path: Optional[str] = None):
    """
    Executes the training pipeline for either ALL vendors or a specific vendor.
    """
    logger.info(f"Starting Multi-Vendor CNN-LSTM Training Orchestrator (Target: {target_vendor})...")
    if target_vendor.upper() == "ALL":
        for v_key in VENDOR_CONFIGS.keys():
            train_vendor_model(v_key, custom_csv_path)
    elif target_vendor.lower() in VENDOR_CONFIGS:
        train_vendor_model(target_vendor.lower(), custom_csv_path)
    else:
        logger.error(f"Invalid target vendor: {target_vendor}. Options: ALL, palo_alto, fortigate, fortiwaf")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CNN-LSTM Multi-Vendor Training Pipeline")
    parser.add_argument("--vendor", type=str, default="ALL", help="Target vendor: ALL, palo_alto, fortigate, fortiwaf")
    parser.add_argument("--csv", type=str, default=None, help="Optional path to offline Custom/Public training CSV")
    args = parser.parse_args()
    
    run_pipeline(target_vendor=args.vendor, custom_csv_path=args.csv)
