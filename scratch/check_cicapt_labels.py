import pandas as pd
from pathlib import Path

attack_info_path = Path(r"d:\Projects\BilCode\ML - Pendeteksi Serangan Long Running Attack\codebase_new\datasets\public\CICAPT-IIoT2024\attack_info.csv")
df_attack = pd.read_csv(attack_info_path)

print("=== All Tactics in attack_info.csv ===")
print(df_attack["Tactic Name"].value_counts())

print("\n=== All Techniques in attack_info.csv ===")
print(df_attack[["Tactic Name", "Technique Name", "readable_time"]].to_string())

csv_path = Path(r"d:\Projects\BilCode\ML - Pendeteksi Serangan Long Running Attack\codebase_new\datasets\public\CICAPT-IIoT2024\phase1_NetworkData.csv")

print("\n=== Scanning phase1_NetworkData.csv in chunks for non-zero labels ===")
unique_labels = set()
unique_sublabelcats = set()
total_attack_rows = 0

# Read in chunks of 500,000 to find what labels exist
for i, chunk in enumerate(pd.read_csv(csv_path, chunksize=500000, usecols=["ts", "Source IP", "Destination IP", "Destination Port", "label", "subLabel", "subLabelCat"])):
    unique_labels.update(chunk["label"].unique())
    unique_sublabelcats.update(chunk["subLabelCat"].unique())
    attacks = chunk[chunk["label"] != 0]
    if len(attacks) > 0:
        total_attack_rows += len(attacks)
        if total_attack_rows < 50:  # print sample attack rows
            print(f"Chunk {i} sample attacks:\n", attacks.head())
    if i % 5 == 0:
        print(f"Processed {i*500000} rows... labels found so far: {unique_labels}, subLabelCats: {unique_sublabelcats}")

print("FINAL unique 'label':", unique_labels)
print("FINAL unique 'subLabelCat':", unique_sublabelcats)
print("FINAL total attack rows where label != 0:", total_attack_rows)
