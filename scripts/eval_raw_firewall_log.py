#!/usr/bin/env python3
"""
Raw Firewall Log Evaluation Script
====================================
Tests all 3 trained vendor models against the real-world firewall log data
from datasets/raw/firewall_log.csv — actual production firewall logs from:
  - Palo Alto (10.14.202.200)
  - FortiGate (FGT-1101E-BDG, JKT-GDL-POP-FGT3501F, etc.)
  - FortiWAF (WAF-GNDL-IT-Internal)

This is a NATIVE evaluation — no adapter needed. The raw log columns map
directly to the feature engineering pipeline's expected input format.

Zone Mapping note:
  The raw log uses "External"/"Internal" while the FE heuristic checks for
  "trust"/"internal"/"lan". Since "internal" contains "internal", Class 2
  (Lateral Movement) detection should work correctly here.
"""

import sys, os, pickle, logging
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ai_engine.feature_engineering import LogFeatureEngineer

logging.basicConfig(level=logging.WARNING)

ROOT       = Path(__file__).resolve().parents[1]
RAW_CSV    = ROOT / "datasets" / "raw" / "firewall_log.csv"
MODELS_DIR = ROOT / "app" / "ai_engine" / "saved_models"
OUT_FILE   = ROOT / "scripts" / "raw_log_eval_results.txt"

CLASS_NAMES = {0: "Normal", 1: "Reconnaissance", 2: "Lateral Movement", 3: "Beaconing"}

# Map raw Log Source strings to our vendor keys
VENDOR_LOG_SOURCE_MAP = {
    "palo_alto": ["Palo Alto Firewall", "palo alto", "palo_alto"],
    "fortigate": ["FortiAnalyzer", "FortiGate", "fortigate", "FGT"],
    "fortiwaf":  ["FortiWAF", "WAF"],
}

VENDOR_MODEL_FILES = {
    "palo_alto": ("palo_alto_cnn_lstm.keras", "palo_alto_feature_engineer.pkl"),
    "fortigate": ("fortigate_cnn_lstm.keras", "fortigate_feature_engineer.pkl"),
    "fortiwaf":  ("fortiwaf_cnn_lstm.keras",  "fortiwaf_feature_engineer.pkl"),
}

_OUT = None


def p(msg=""):
    safe = msg.encode("ascii", errors="replace").decode("ascii")
    print(safe)
    if _OUT:
        _OUT.write(msg + "\n")


def load_raw_logs(vendor_key: str, max_rows: int = 50000) -> pd.DataFrame:
    """
    Load rows from firewall_log.csv that belong to the given vendor,
    then map to the standard column format expected by LogFeatureEngineer.
    """
    keywords = VENDOR_LOG_SOURCE_MAP[vendor_key]

    # Read in chunks to filter by Log Source without loading all 300K
    chunks = []
    for chunk in pd.read_csv(RAW_CSV, chunksize=50000, low_memory=False):
        mask = chunk["Log Source"].fillna("").apply(
            lambda s: any(kw.lower() in s.lower() for kw in keywords)
        )
        chunks.append(chunk[mask])
        if sum(len(c) for c in chunks) >= max_rows:
            break

    if not chunks:
        return pd.DataFrame()

    df = pd.concat(chunks, ignore_index=True).head(max_rows)

    # Rename to standard column names for feature_engineering.py
    col_map = {
        "Log Date":                 "log_date",
        "IP Address (Origin)":      "ip_origin",
        "IP Address (Impacted)":    "ip_impacted",
        "TCP/UDP Port (Impacted)":  "port_impacted",
        "Zone (Origin)":            "zone_origin",
        "Zone (Impacted)":          "zone_impacted",
        "Log Source":               "log_source",
    }
    df = df.rename(columns=col_map)

    # Keep only needed columns
    needed = list(col_map.values())
    df = df[[c for c in needed if c in df.columns]].copy()

    # Clean up
    df["log_date"]      = pd.to_datetime(df["log_date"], errors="coerce")
    df["port_impacted"] = pd.to_numeric(df["port_impacted"], errors="coerce").fillna(80).astype(int)
    df["ip_origin"]     = df["ip_origin"].fillna("0.0.0.0").astype(str)
    df["ip_impacted"]   = df["ip_impacted"].fillna("0.0.0.0").astype(str)
    df["zone_origin"]   = df["zone_origin"].fillna("Unknown").astype(str)
    df["zone_impacted"] = df["zone_impacted"].fillna("Unknown").astype(str)
    df["log_source"]    = df["log_source"].fillna("unknown").astype(str)
    df = df.dropna(subset=["log_date"])

    # Add row id for FE pipeline
    df.insert(0, "id", range(1, len(df) + 1))
    return df


def evaluate_vendor(vendor_key: str, display_name: str) -> dict:
    """Full evaluation pipeline for one vendor."""
    import keras

    mdl_file, eng_file = VENDOR_MODEL_FILES[vendor_key]
    mdl_path = MODELS_DIR / mdl_file
    eng_path = MODELS_DIR / eng_file

    if not mdl_path.exists() or not eng_path.exists():
        return {"error": f"Model/engineer files not found for {vendor_key}"}

    # Load model & engineer
    with open(eng_path, "rb") as f:
        engineer: LogFeatureEngineer = pickle.load(f)
    model = keras.models.load_model(str(mdl_path))

    # Load raw logs for this vendor
    df = load_raw_logs(vendor_key, max_rows=50000)
    if df.empty:
        return {"error": f"No rows found for {vendor_key} in firewall_log.csv"}

    p(f"  Loaded {len(df):,} rows for [{display_name}]")

    # Convert to list of dicts for FE pipeline
    raw_logs = df.to_dict(orient="records")

    # Feature engineering
    df_clean    = engineer.clean_and_prepare_df(raw_logs)
    df_windowed = engineer.perform_time_windowing(df_clean)

    if df_windowed.empty:
        return {"error": "Windowing returned empty DataFrame"}

    df_labeled     = engineer.assign_pseudo_labels(df_windowed)
    df_transformed = engineer.transform(df_labeled)
    X, y_pseudo    = engineer.to_3d_sequences(df_transformed)

    if len(X) == 0:
        return {"error": "No 3D sequences generated"}

    # Predict
    y_pred_probs   = model.predict(X, verbose=0)
    y_pred         = np.argmax(y_pred_probs, axis=1)
    confidence     = np.max(y_pred_probs, axis=1)

    # Per-class accuracy vs pseudo-labels (our ground truth)
    from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
    acc = accuracy_score(y_pseudo.astype(int), y_pred.astype(int))

    present_classes = sorted(set(y_pseudo.astype(int)) | set(y_pred.astype(int)))
    present_names   = [CLASS_NAMES[c] for c in present_classes if c in CLASS_NAMES]
    report = classification_report(
        y_pseudo.astype(int), y_pred.astype(int),
        labels=present_classes, target_names=present_names,
        zero_division=0
    )
    cm = confusion_matrix(y_pseudo.astype(int), y_pred.astype(int), labels=present_classes)

    pseudo_dist = {CLASS_NAMES[i]: int(np.sum(y_pseudo == i)) for i in range(4)}
    pred_dist   = {CLASS_NAMES[i]: int(np.sum(y_pred == i)) for i in range(4)}

    # Zone check for lateral movement conditions
    lateral_check = df_windowed[
        (df_windowed["zone_origin_mode"].str.lower().str.contains("internal|trust|lan", na=False)) &
        (df_windowed["zone_impacted_mode"].str.lower().str.contains("internal|trust|lan", na=False)) &
        (df_windowed["unique_ips_targeted"] > 3)
    ]

    return {
        "vendor": display_name,
        "raw_rows": len(df),
        "behavior_windows": len(df_windowed),
        "sequences": len(X),
        "pseudo_dist": pseudo_dist,
        "pred_dist": pred_dist,
        "accuracy_vs_pseudo": acc,
        "avg_confidence": float(np.mean(confidence)),
        "min_confidence": float(np.min(confidence)),
        "classification_report": report,
        "confusion_matrix": cm,
        "present_classes": present_classes,
        "lateral_eligible_windows": len(lateral_check),
    }


def main():
    global _OUT
    _OUT = open(OUT_FILE, "w", encoding="utf-8")

    p("=" * 70)
    p("  Real-World Firewall Log Evaluation — CNN-LSTM Attack Detector")
    p(f"  File: {RAW_CSV}")
    p("=" * 70)

    vendors = {
        "palo_alto": "Palo Alto (Server Utama)",
        "fortigate": "FortiGate (Kantor Cabang)",
        "fortiwaf":  "FortiWAF (Aplikasi Web)",
    }

    all_results = {}
    for vkey, vname in vendors.items():
        p(f"\n{'='*70}")
        p(f"  VENDOR: {vname}")
        p(f"{'='*70}")

        result = evaluate_vendor(vkey, vname)

        if "error" in result:
            p(f"  [ERROR] {result['error']}")
            all_results[vkey] = result
            continue

        p(f"\n  Raw logs loaded      : {result['raw_rows']:,}")
        p(f"  Behavior windows     : {result['behavior_windows']:,}")
        p(f"  3D Sequences formed  : {result['sequences']:,}")
        p(f"  Lateral-eligible win : {result['lateral_eligible_windows']:,}  (Internal->Internal, unique_ips>3)")
        p()
        p(f"  FE Pseudo-label dist  : {result['pseudo_dist']}")
        p(f"  Model Prediction dist : {result['pred_dist']}")
        p()
        p(f"  Accuracy vs FE pseudo-labels : {result['accuracy_vs_pseudo']:.4f} ({result['accuracy_vs_pseudo']*100:.2f}%)")
        p(f"  Avg Confidence               : {result['avg_confidence']:.1%}  (min: {result['min_confidence']:.1%})")
        p()
        p(f"  Classification Report:")
        for line in result['classification_report'].split('\n'):
            p(f"    {line}")
        p()
        p(f"  Confusion Matrix (classes: {[CLASS_NAMES[c] for c in result['present_classes']]}):")
        for row in result['confusion_matrix']:
            p(f"    {row}")

        all_results[vkey] = result

    # Summary table
    p(f"\n{'='*70}")
    p("  SUMMARY TABLE")
    p(f"{'='*70}")
    p(f"{'Vendor':<30} {'Rows':>8} {'Windows':>9} {'Seqs':>7} {'Acc':>8} {'Conf':>8}")
    p("-" * 70)
    for vkey, vname in vendors.items():
        r = all_results.get(vkey, {})
        if "error" in r:
            p(f"{vname:<30} {'ERROR':>8}")
        else:
            p(f"{vname:<30} {r['raw_rows']:>8,} {r['behavior_windows']:>9,} "
              f"{r['sequences']:>7,} {r['accuracy_vs_pseudo']:>7.2%} {r['avg_confidence']:>7.1%}")

    p(f"\n[DONE] Results saved to: {OUT_FILE}")
    _OUT.close()


if __name__ == "__main__":
    main()
