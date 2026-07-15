import pickle
import pandas as pd
from pathlib import Path
import sys

ROOT = Path(r"d:\Projects\BilCode\ML - Pendeteksi Serangan Long Running Attack\codebase_new")
sys.path.insert(0, str(ROOT))
from app.ai_engine.feature_engineering import LogFeatureEngineer

csv_path = ROOT / "datasets" / "public" / "CICAPT-IIoT2024" / "phase1_NetworkData.csv"
eng_path = ROOT / "app" / "ai_engine" / "saved_models" / "palo_alto_feature_engineer.pkl"

with open(eng_path, "rb") as f:
    engineer = pickle.load(f)

print("Reading 5,000 rows from phase1_NetworkData.csv...")
df_sub = pd.read_csv(csv_path, nrows=5000)

logs = []
for i, row in df_sub.iterrows():
    logs.append({
        "id": i + 1,
        "log_date": pd.to_datetime(float(row["ts"]), unit="s"),
        "ip_origin": str(row["Source IP"]).strip(),
        "ip_impacted": str(row["Destination IP"]).strip(),
        "port_impacted": int(float(row["Destination Port"])) if pd.notna(row["Destination Port"]) else -1,
        "zone_origin": "Trust" if str(row["Source IP"]).startswith(("10.", "172.16.", "192.168.")) else "Untrust",
        "zone_impacted": "Trust" if str(row["Destination IP"]).startswith(("10.", "172.16.", "192.168.")) else "Untrust",
        "log_source": "CICAPT-IIoT2024-Adapter",
        "protocol": str(row["Protocol_name"]) if pd.notna(row["Protocol_name"]) else "TCP",
    })

df_clean = engineer.clean_and_prepare_df(logs)
print("Clean DF shape:", df_clean.shape)
df_windowed = engineer.perform_time_windowing(df_clean)
print("Windowed DF shape:", df_windowed.shape)
if not df_windowed.empty:
    print(df_windowed.head())
    df_labeled = engineer.assign_pseudo_labels(df_windowed)
    df_transformed = engineer.transform(df_labeled)
    X, y_pseudo = engineer.to_3d_sequences(df_transformed)
    print("3D sequence X shape:", len(X))
