import pandas as pd
from pathlib import Path

csv_path = Path(r"d:\Projects\BilCode\ML - Pendeteksi Serangan Long Running Attack\codebase_new\datasets\public\CICAPT-IIoT2024\phase1_NetworkData.csv")

min_ts = float('inf')
max_ts = float('-inf')

phase_counts = {
    "Phase 0 (Baseline: 1701426437 - 1701460000)": 0,
    "Phase 1 (Discovery: 1701563000 - 1701590000)": 0,
    "Phase 2 (Lateral: 1701622000 - 1701640000)": 0,
    "Phase 3 (C2: 1701557000 - 1701605000)": 0,
}

for i, chunk in enumerate(pd.read_csv(csv_path, chunksize=1000000, usecols=["ts"])):
    c_min = chunk["ts"].min()
    c_max = chunk["ts"].max()
    if c_min < min_ts: min_ts = c_min
    if c_max > max_ts: max_ts = c_max

    phase_counts["Phase 0 (Baseline: 1701426437 - 1701460000)"] += ((chunk["ts"] >= 1701426437.0) & (chunk["ts"] <= 1701460000.0)).sum()
    phase_counts["Phase 1 (Discovery: 1701563000 - 1701590000)"] += ((chunk["ts"] >= 1701563000.0) & (chunk["ts"] <= 1701590000.0)).sum()
    phase_counts["Phase 2 (Lateral: 1701622000 - 1701640000)"] += ((chunk["ts"] >= 1701622000.0) & (chunk["ts"] <= 1701640000.0)).sum()
    phase_counts["Phase 3 (C2: 1701557000 - 1701605000)"] += ((chunk["ts"] >= 1701557000.0) & (chunk["ts"] <= 1701605000.0)).sum()

print(f"Overall Min ts: {min_ts} ({pd.to_datetime(min_ts, unit='s')})")
print(f"Overall Max ts: {max_ts} ({pd.to_datetime(max_ts, unit='s')})")
for k, v in phase_counts.items():
    print(f"  {k}: {v:,} rows")
