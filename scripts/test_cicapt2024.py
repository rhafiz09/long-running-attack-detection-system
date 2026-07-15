#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Public Dataset Testing Script — CICAPT-IIoT2024 vs CNN-LSTM Attack Detector
===========================================================================
Tests all 3 trained vendor models (Palo Alto, FortiGate, FortiWAF) against
the modern CICAPT-IIoT2024 Advanced Persistent Threat (APT29) benchmark dataset.

Structure & Execution (Vectorized / Ultra-Fast Extraction):
1. Phase 0 (Baseline Normal Traffic) is extracted from `phase1_NetworkData.csv` (100,000 records).
2. Phase 1 (Reconnaissance/Discovery), Phase 2 (Lateral Movement), and Phase 3 (C2 Beaconing)
   are extracted from `phase2_NetworkData.csv` (100,000 records per attack phase).
3. All 3 models are evaluated across all 4 distinct campaign phases.
"""

import sys
import os
import pickle
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ai_engine.feature_engineering import LogFeatureEngineer

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("test_cicapt2024")

CIC_DIR = ROOT / "datasets" / "public" / "CICAPT-IIoT2024"
MODELS_DIR = ROOT / "app" / "ai_engine" / "saved_models"

VENDOR_ENGINEERS = {
    "Palo Alto":  MODELS_DIR / "palo_alto_feature_engineer.pkl",
    "FortiGate":  MODELS_DIR / "fortigate_feature_engineer.pkl",
    "FortiWAF":   MODELS_DIR / "fortiwaf_feature_engineer.pkl",
}
VENDOR_MODELS = {
    "Palo Alto":  MODELS_DIR / "palo_alto_cnn_lstm.keras",
    "FortiGate":  MODELS_DIR / "fortigate_cnn_lstm.keras",
    "FortiWAF":   MODELS_DIR / "fortiwaf_cnn_lstm.keras",
}

SLICES_PHASE2 = {
    "Phase 1: Internal Reconnaissance (Discovery TA0007)": {
        "ts_min": 1701563000.0,
        "ts_max": 1701590000.0,
        "true_class": 1,
        "desc": "TA0007 Discovery: find local users, network interface config, wifi scan, OS listing"
    },
    "Phase 2: Lateral Movement (Sandcat Pivoting across LAN)": {
        "ts_min": 1701622000.0,
        "ts_max": 1701640000.0,
        "true_class": 2,
        "desc": "Lateral movement: starting Sandcat and internal pivoting across Trust zones"
    },
    "Phase 3: Command & Control (C2 Beaconing)": {
        "ts_min": 1701557000.0,
        "ts_max": 1701605000.0,
        "true_class": 3,
        "desc": "C2 Beaconing: downloading payloads, regular heartbeats, and external tasking"
    }
}

_OUT = None

def _print(msg: str = ""):
    safe = msg.encode('ascii', errors='replace').decode('ascii')
    print(safe)
    if _OUT:
        _OUT.write(msg + "\n")
        _OUT.flush()

def load_vendor(vendor_name: str):
    import keras
    eng_path = VENDOR_ENGINEERS[vendor_name]
    mdl_path = VENDOR_MODELS[vendor_name]

    if not eng_path.exists() or not mdl_path.exists():
        raise FileNotFoundError(f"Model/engineer not found for {vendor_name}")

    with open(eng_path, "rb") as f:
        engineer = pickle.load(f)

    model = keras.models.load_model(str(mdl_path))
    return engineer, model

def fast_row_tuple_to_log(row_id: int, ts_val: float, src_ip: str, dst_ip: str, dst_port_raw, proto_raw, true_class: int) -> Dict:
    try:
        dst_port = int(float(dst_port_raw))
    except Exception:
        dst_port = -1

    proto = str(proto_raw).strip() if pd.notna(proto_raw) else "TCP"
    src_clean = str(src_ip).strip()
    dst_clean = str(dst_ip).strip()

    def get_zone(ip_str):
        if any(ip_str.startswith(prefix) for prefix in ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")):
            return "Trust"
        return "Untrust"

    return {
        "id": row_id,
        "log_date": pd.to_datetime(ts_val, unit="s"),
        "ip_origin": src_clean,
        "ip_impacted": dst_clean,
        "port_impacted": dst_port,
        "zone_origin": get_zone(src_clean),
        "zone_impacted": get_zone(dst_clean),
        "log_source": "CICAPT-IIoT2024-Adapter",
        "protocol": proto,
        "_true_class": true_class
    }

def extract_phase0_baseline(csv_path: Path, max_rows: int = 100000) -> List[Dict]:
    _print(f"\n[PRE-PROCESSING] Extracting {max_rows:,} Baseline Normal records from phase1_NetworkData.csv (Vectorized)...")
    df = pd.read_csv(csv_path, nrows=max_rows, usecols=["ts", "Source IP", "Destination IP", "Destination Port", "Protocol_name"])
    
    logs = []
    for i, (ts_val, src_ip, dst_ip, dst_port, proto) in enumerate(zip(df["ts"], df["Source IP"], df["Destination IP"], df["Destination Port"], df["Protocol_name"]), start=1):
        logs.append(fast_row_tuple_to_log(i, float(ts_val), src_ip, dst_ip, dst_port, proto, 0))

    _print(f"  -> Extracted {len(logs):,} Phase 0 logs across {df['Source IP'].nunique()} unique source IPs.")
    return logs

def extract_phase2_attacks(csv_path: Path, max_rows: int = 100000) -> Dict[str, List[Dict]]:
    _print(f"\n[PRE-PROCESSING] Extracting Phase 1, 2, and 3 attack records from phase2_NetworkData.csv (up to {max_rows:,} per phase - Vectorized)...")
    slice_logs = {s: [] for s in SLICES_PHASE2}
    log_id = 1000000

    for chunk_idx, chunk in enumerate(pd.read_csv(csv_path, chunksize=500000, usecols=["ts", "Source IP", "Destination IP", "Destination Port", "Protocol_name"])):
        if all(len(slice_logs[s]) >= max_rows for s in SLICES_PHASE2):
            _print("  -> Extracted 100,000 logs for all 3 attack phases! Breaking early.")
            break

        for s_name, meta in SLICES_PHASE2.items():
            if len(slice_logs[s_name]) >= max_rows:
                continue

            sub = chunk[(chunk["ts"] >= meta["ts_min"]) & (chunk["ts"] <= meta["ts_max"])]
            if sub.empty:
                continue

            for ts_val, src_ip, dst_ip, dst_port, proto in zip(sub["ts"], sub["Source IP"], sub["Destination IP"], sub["Destination Port"], sub["Protocol_name"]):
                if len(slice_logs[s_name]) >= max_rows:
                    break
                slice_logs[s_name].append(fast_row_tuple_to_log(log_id, float(ts_val), src_ip, dst_ip, dst_port, proto, meta["true_class"]))
                log_id += 1

        if chunk_idx % 2 == 0:
            status = ", ".join([f"{s.split(':')[0]}={len(slice_logs[s]):,}" for s in SLICES_PHASE2])
            _print(f"  Processed {chunk_idx * 500000:,} rows of phase2_NetworkData.csv... Extracted: [{status}]")

    return slice_logs

def evaluate_logs(logs: List[Dict], engineer: LogFeatureEngineer, model) -> Dict:
    if len(logs) < 15:
        return {"error": f"Only extracted {len(logs)} logs in this timestamp window"}

    clean_logs = [{k: v for k, v in l.items() if not k.startswith("_")} for l in logs]

    df_clean = engineer.clean_and_prepare_df(clean_logs)
    if df_clean.empty:
        return {"error": "FE returned empty after clean"}

    df_windowed = engineer.perform_time_windowing(df_clean)
    if df_windowed.empty:
        return {"error": "FE windowing returned empty"}

    df_labeled = engineer.assign_pseudo_labels(df_windowed)
    df_transformed = engineer.transform(df_labeled)
    X, y_pseudo = engineer.to_3d_sequences(df_transformed)

    if len(X) == 0:
        return {"error": "No 3D sequences generated from windowed features"}

    y_pred_probs = model.predict(X, verbose=0)
    y_pred = np.argmax(y_pred_probs, axis=1)

    confidence_scores = np.max(y_pred_probs, axis=1)
    avg_confidence = float(np.mean(confidence_scores))

    agree_count = int(np.sum(y_pred == y_pseudo))
    agreement_pct = (agree_count / len(y_pred)) * 100.0

    class_names = ["Normal (0)", "Recon (1)", "Lateral (2)", "Beaconing (3)"]
    pred_counts = {c: int(np.sum(y_pred == i)) for i, c in enumerate(class_names)}
    pseudo_counts = {c: int(np.sum(y_pseudo == i)) for i, c in enumerate(class_names)}

    return {
        "total_logs": len(logs),
        "windows_formed": len(df_windowed),
        "sequences_formed": len(X),
        "avg_confidence": avg_confidence,
        "agreement_with_fe": agreement_pct,
        "pred_dist": pred_counts,
        "pseudo_dist": pseudo_counts
    }

def print_result(r: Dict):
    if "error" in r:
        _print(f"    [ERROR] {r['error']}")
        return
    _print(f"    Logs evaluated     : {r['total_logs']:,}")
    _print(f"    Behavior windows   : {r['windows_formed']:,}")
    _print(f"    3D Sequences formed: {r['sequences_formed']:,}")
    _print(f"    Average confidence : {r['avg_confidence']:.1%}")
    _print(f"    FE Rule Agreement  : {r['agreement_with_fe']:.1f}%")
    _print(f"    Model Predictions  : {r['pred_dist']}")
    _print(f"    FE Heuristic Rules : {r['pseudo_dist']}")

def main():
    global _OUT
    out_path = ROOT / "scripts" / "test_cicapt2024_results.txt"
    _OUT = open(out_path, "w", encoding="utf-8")

    _print("=" * 75)
    _print("  CICAPT-IIoT2024 Advanced Persistent Threat Testing — CNN-LSTM Detector")
    _print("=" * 75)
    _print(f"Dataset : CICAPT-IIoT2024 (University of New Brunswick, 2024)")
    _print(f"Adapter : Direct chronological timestamp (ts -> log_date) + Private Zone mapping")
    _print("=" * 75)

    phase1_path = CIC_DIR / "phase1_NetworkData.csv"
    phase2_path = CIC_DIR / "phase2_NetworkData.csv"

    all_slices = {}
    if phase1_path.exists():
        all_slices["Phase 0: Baseline Normal Traffic"] = {
            "logs": extract_phase0_baseline(phase1_path, max_rows=100000),
            "true_class": 0,
            "desc": "Pure baseline normal traffic before APT initial compromise"
        }

    if phase2_path.exists():
        extracted_phase2 = extract_phase2_attacks(phase2_path, max_rows=100000)
        for s_name, logs_list in extracted_phase2.items():
            all_slices[s_name] = {
                "logs": logs_list,
                "true_class": SLICES_PHASE2[s_name]["true_class"],
                "desc": SLICES_PHASE2[s_name]["desc"]
            }

    vendors = ["Palo Alto", "FortiGate", "FortiWAF"]
    for v in vendors:
        _print(f"\n[{v.upper()} MODEL EVALUATION]")
        try:
            eng, mdl = load_vendor(v)
            for slice_name, meta in all_slices.items():
                _print(f"\n  ---> Testing: {slice_name}")
                _print(f"       Expected Ground Truth Class: {meta['true_class']} ({meta['desc']})")
                result = evaluate_logs(meta["logs"], eng, mdl)
                print_result(result)
        except Exception as e:
            _print(f"  [CRITICAL ERROR] Failed on vendor {v}: {e}")

    _print("\n" + "=" * 75)
    _print("Testing Completed. Results saved to scripts/test_cicapt2024_results.txt")
    _OUT.close()

if __name__ == "__main__":
    main()
