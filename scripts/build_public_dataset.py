#!/usr/bin/env python3
"""
Public Benchmark Testing Dataset Builder.
Generates `datasets/public/test_public_benchmark.csv` adhering to Section 4.1.3.2 & Section 4.2.2.
Simulates public network benchmark characteristics (like CIC-IDS2017 / UNSW-NB15 / 5-year historical logs)
to evaluate model accuracy independently without data leakage.
"""

import os
import sys
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
PUBLIC_DIR = ROOT_DIR / "datasets" / "public"
PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = PUBLIC_DIR / "test_public_benchmark.csv"

VENDORS = [
    {
        "name": "JKT-GANDUL-FW-04 Palo Alto Firewall",
        "type": "palo_alto",
        "ports": [443, 80, 22, 3306]
    },
    {
        "name": "SUB-BRANCH-FW-01 FortiGate Firewall",
        "type": "fortigate",
        "ports": [443, 80, 445, 3389]
    },
    {
        "name": "WEB-CLUSTER-WAF-01 FortiWAF",
        "type": "fortiwaf",
        "ports": [80, 443, 8080, 8443]
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

def build_public_test_dataset(rows_per_class: int = 50):
    print(f"Building public benchmark testing dataset: {OUTPUT_CSV}...")
    rows = []
    # Using 5-year historical test timestamps (2021-2025) to adhere to Section 4.2.2.1
    base_date = datetime(2021, 6, 15, 8, 0, 0)
    
    for v in VENDORS:
        # 1. Benchmark Normal Traffic
        for w in range(rows_per_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*300)
            ip_ori = f"198.51.100.{10 + (w % 15)}"  # RFC 5737 external test IPs
            ip_imp = "172.16.0.50"
            for l in range(2):
                rows.append({
                    "Log Date": (w_start + timedelta(seconds=l*45)).strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": random.choice(v["ports"]),
                    "Zone (Origin)": "External-WAN",
                    "Zone (Impacted)": "Internal-LAN",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": "Standard Benchmark Session",
                    "Severity": "low",
                    "Action": "allow",
                    "Duration": random.randint(1, 30)
                })
                
        # 2. Benchmark Reconnaissance (CIC-IDS PortSweep Benchmark style)
        for w in range(rows_per_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*300 + 100)
            ip_ori = f"203.0.113.{5 + (w % 10)}"
            ip_imp = "172.16.0.100"
            for p_offset in range(20):
                rows.append({
                    "Log Date": (w_start + timedelta(seconds=5 + p_offset*12)).strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": 2000 + p_offset,
                    "Zone (Origin)": "External-WAN",
                    "Zone (Impacted)": "Internal-LAN",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": "CIC-IDS Benchmark PortSweep",
                    "Severity": "medium",
                    "Action": "drop",
                    "Duration": 0
                })
                
        # 3. Benchmark Lateral Movement
        for w in range(rows_per_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*300 + 200)
            ip_ori = "172.16.0.100"
            for t_idx in range(4):
                rows.append({
                    "Log Date": (w_start + timedelta(seconds=15 + t_idx*35)).strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": f"172.16.0.{200 + t_idx}",
                    "TCP/UDP Port (Impacted)": 445 if v["type"] != "fortiwaf" else 8080,
                    "Zone (Origin)": "Internal-LAN",
                    "Zone (Impacted)": "Internal-LAN",
                    "Log Source": v["name"],
                    "Protocol": "TCP",
                    "Threat Name": "Benchmark Lateral Movement Pivot",
                    "Severity": "high",
                    "Action": "reset-both",
                    "Duration": 10
                })
                
        # 4. Benchmark Beaconing (UNSW-NB15 Botnet style periodic callbacks)
        for w in range(rows_per_class):
            w_start = base_date + timedelta(minutes=w * 5, days=VENDORS.index(v)*300 + 250)
            ip_ori = f"172.16.0.{30 + (w % 5)}"
            ip_imp = "198.51.100.254"
            for b_idx in range(6):
                rows.append({
                    "Log Date": (w_start + timedelta(seconds=5 + b_idx*20)).strftime("%m/%d/%Y %I:%M:%S %p"),
                    "IP Address (Origin)": ip_ori,
                    "IP Address (Impacted)": ip_imp,
                    "TCP/UDP Port (Impacted)": 53 if v["type"] != "fortiwaf" else 443,
                    "Zone (Origin)": "Internal-LAN",
                    "Zone (Impacted)": "External-WAN",
                    "Log Source": v["name"],
                    "Protocol": "UDP" if v["type"] != "fortiwaf" else "TCP",
                    "Threat Name": "Benchmark Botnet Beacon C2",
                    "Severity": "high",
                    "Action": "drop",
                    "Duration": 1
                })

    rows.sort(key=lambda x: datetime.strptime(x["Log Date"], "%m/%d/%Y %I:%M:%S %p"))

    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"Successfully created public benchmark testing dataset with {len(rows):,} records!")
    return len(rows)

if __name__ == "__main__":
    build_public_test_dataset(rows_per_class=60)
