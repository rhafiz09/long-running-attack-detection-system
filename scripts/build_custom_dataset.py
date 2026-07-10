#!/usr/bin/env python3
"""
Custom Dataset Builder for CNN-LSTM Long Running Attack Detection.
Generates `datasets/custom/train_long_running_attacks.csv` adhering to Section 4.1.3.3 & Section 5.2.
Produces rich, multi-vendor training data for Palo Alto, FortiGate, and FortiWAF across 4 classes:
- 0: Normal Traffic
- 1: Internal Reconnaissance (Port sweeps / Host scanning)
- 2: Lateral Movement (Trust-to-Trust zone traversing multiple target IPs)
- 3: Beaconing (Periodic C2 heartbeats)
"""

import os
import sys
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# Set output path
ROOT_DIR = Path(__file__).resolve().parents[1]
CUSTOM_DIR = ROOT_DIR / "datasets" / "custom"
CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = CUSTOM_DIR / "train_long_running_attacks.csv"

VENDORS = [
    {
        "name": "JKT-GANDUL-FW-04 Palo Alto Firewall",
        "type": "palo_alto",
        "ports": [443, 80, 22, 3306, 53, 8080],
        "threats_recon": "Port Scan / Reconnaissance Probe",
        "threats_lateral": "Internal SMB / Lateral Movement Activity",
        "threats_beacon": "Suspicious C2 Periodic Beaconing",
        "threats_normal": "General Web / App Traffic"
    },
    {
        "name": "SUB-BRANCH-FW-01 FortiGate Firewall",
        "type": "fortigate",
        "ports": [443, 80, 445, 3389, 135, 1433],
        "threats_recon": "FortiGate SYN Port Sweep",
        "threats_lateral": "FortiGate RDP/SMB Lateral Traverse",
        "threats_beacon": "FortiGate Botnet Callback Interval",
        "threats_normal": "Allowed Branch Office Session"
    },
    {
        "name": "WEB-CLUSTER-WAF-01 FortiWAF",
        "type": "fortiwaf",
        "ports": [80, 443, 8080, 8443, 3306, 5432],
        "threats_recon": "WAF Parameter & Endpoint Scanning",
        "threats_lateral": "WAF Internal Microservice Pivot Probe",
        "threats_beacon": "WAF Automated Scraper / Bot Callback",
        "threats_normal": "Legitimate HTTPS Web Transaction"
    }
]

HEADERS = [
    "Log Date",
    "IP Address (Origin)",
    "IP Address (Impacted)",
    "TCP/UDP Port (Impacted)",
    "Zone (Origin)",
    "Zone (Impacted)",
    "Log Source",
    "Protocol",
    "Threat Name",
    "Severity",
    "Action",
    "Duration"
]

def build_dataset(rows_per_vendor_class: int = 400):
    """
    Generates time-windowed sequences for each class across each vendor.
    Each window is a 5-minute block.
    """
    print(f"Building custom training dataset: {OUTPUT_CSV}...")
    rows = []
    base_date = datetime(2026, 4, 1, 0, 0, 0)
    
    for v in VENDORS:
        print(f"Generating training sequences for vendor: {v['name']}...")
        
        # 1. Normal Traffic (Class 0)
        # Windows with 2-4 logs per 5 minutes, single or few ports, random intervals
        for w in range(rows_per_vendor_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*10)
            ip_ori = f"103.179.248.{10 + (w % 20)}"
            ip_imp = f"10.14.202.{100 + (w % 5)}"
            num_logs = random.randint(2, 4)
            for l in range(num_logs):
                log_time = w_start + timedelta(seconds=random.randint(10, 280))
                rows.append({
                    "Log Date": log_time.strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": random.choice(v["ports"]),
                    "Zone (Origin)": "Untrust" if l % 2 == 0 else "Trust",
                    "Zone (Impacted)": "Trust" if l % 2 == 0 else "Untrust",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": v["threats_normal"],
                    "Severity": "low",
                    "Action": "allow",
                    "Duration": random.randint(1, 45)
                })
                
        # 2. Internal Reconnaissance (Class 1)
        # Windows where a single IP scans > 20 distinct ports within 5 mins
        for w in range(rows_per_vendor_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*10 + 20)
            ip_ori = f"103.179.248.{50 + (w % 15)}"
            ip_imp = "10.14.202.100"
            for p_offset in range(22):  # 22 distinct ports scanned > 15 threshold
                log_time = w_start + timedelta(seconds=5 + p_offset * 10)
                rows.append({
                    "Log Date": log_time.strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": 1000 + p_offset,
                    "Zone (Origin)": "Untrust",
                    "Zone (Impacted)": "Trust",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": v["threats_recon"],
                    "Severity": "medium",
                    "Action": "drop",
                    "Duration": random.randint(0, 2)
                })
                
        # 3. Lateral Movement (Class 2)
        # Trust to Trust zone traversing across 5 distinct target IPs (>3 threshold)
        for w in range(rows_per_vendor_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*10 + 40)
            ip_ori = "10.14.202.100"  # Compromised internal host
            for t_idx in range(5):  # 5 distinct target IPs
                log_time = w_start + timedelta(seconds=10 + t_idx * 40)
                rows.append({
                    "Log Date": log_time.strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": f"10.14.202.{150 + t_idx}",
                    "TCP/UDP Port (Impacted)": 445 if v["type"] != "fortiwaf" else 8080,
                    "Zone (Origin)": "Trust",
                    "Zone (Impacted)": "Trust",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": v["threats_lateral"],
                    "Severity": "high",
                    "Action": "reset-both",
                    "Duration": random.randint(5, 120)
                })
                
        # 4. Beaconing (Class 3)
        # Periodic C2 callbacks: exactly 25s intervals (std/avg ~ 0) inside Trust to Untrust
        for w in range(rows_per_vendor_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*10 + 60)
            ip_ori = f"10.14.202.{80 + (w % 10)}"
            ip_imp = "8.8.8.8"
            for b_idx in range(7):  # 7 periodic heartbeats spaced 25s apart
                log_time = w_start + timedelta(seconds=10 + b_idx * 25)
                rows.append({
                    "Log Date": log_time.strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": 53 if v["type"] != "fortiwaf" else 443,
                    "Zone (Origin)": "Trust",
                    "Zone (Impacted)": "Untrust",
                    "Log Source": v["name"],
                    "Protocol": "UDP" if v["type"] != "fortiwaf" else "TCP",
                    "Threat Name": v["threats_beacon"],
                    "Severity": "high",
                    "Action": "drop",
                    "Duration": random.randint(1, 3)
                })

    # Sort rows chronologically
    print("Sorting rows chronologically...")
    rows.sort(key=lambda x: datetime.strptime(x["Log Date"], "%m/%d/%Y %I:%M:%S %p"))

    # Write to CSV
    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"Successfully created custom training dataset with {len(rows):,} total log records across 3 vendors!")
    return len(rows)

if __name__ == "__main__":
    build_dataset(rows_per_vendor_class=120)
