#!/usr/bin/env python3
"""
Custom Dataset Builder for CNN-LSTM Long Running Attack Detection.
Generates `datasets/custom/train_long_running_attacks.csv` adhering to Section 4.1.3.3 & Section 5.2.
Produces rich, multi-vendor training data for Palo Alto, FortiGate, and FortiWAF across 4 classes:
- 0: Normal Traffic
- 1: Internal Reconnaissance (Port sweeps / Host scanning)
- 2: Lateral Movement (Trust-to-Trust zone traversing multiple target IPs)
- 3: Beaconing (Periodic C2 heartbeats)

FIXES (v2):
- [BUG FIX] Class 2 (Lateral Movement) was being mislabeled as Class 3 (Beaconing)
  because its logs had perfectly uniform intervals (coef_of_variation=0), which triggered
  the Beaconing check first in pseudo-labeling. Fix: inject realistic timing jitter so
  coef_of_variation > 0.15, bypassing the Beaconing filter and landing in Lateral Movement.
- [REALISM] Added noise/jitter across all classes to prevent the model from "memorizing"
  deterministic patterns. Port scan order is now randomized, beacon intervals have ±jitter.
- [SCALE] Raised rows_per_vendor_class from 120 to 500 for ~5,000+ 3D sequences (was 1,348).
- [HOLDOUT] Added build_holdout_dataset() that produces a truly-unseen test_holdout.csv
  using different IP ranges, zone naming variants, and time ranges for production validation.
"""

import os
import sys
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# Seed for reproducibility of dataset generation (not model training)
random.seed(2026)

# Set output path
ROOT_DIR = Path(__file__).resolve().parents[1]
CUSTOM_DIR = ROOT_DIR / "datasets" / "custom"
CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = CUSTOM_DIR / "train_long_running_attacks.csv"
HOLDOUT_CSV = CUSTOM_DIR / "test_holdout.csv"

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


def _fmt(dt: datetime) -> str:
    """Format datetime to CSV string."""
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def _generate_class0_normal(v: dict, w: int, base_date: datetime, day_offset: int) -> list:
    """
    Class 0 — Normal Traffic.
    2-4 logs per 5-min window, few ports, random intervals from varied IPs.
    Realistic: mix of zone directions (Untrust→Trust and Trust→Untrust).
    """
    w_start = base_date + timedelta(minutes=w * 5, days=day_offset)
    # Larger IP pool (50 IPs) for more variety
    ip_ori = f"103.179.{150 + (w % 30)}.{10 + (w % 50)}"
    ip_imp = f"10.14.{200 + (w % 5)}.{100 + (w % 20)}"
    num_logs = random.randint(2, 4)
    rows = []
    for l in range(num_logs):
        # Random intervals within the 5-min window, non-uniform
        log_time = w_start + timedelta(seconds=random.randint(5, 290))
        rows.append({
            "Log Date": _fmt(log_time),
            "IP Address (Origin)": ip_ori,
            "IP Address (Impacted)": ip_imp,
            "TCP/UDP Port (Impacted)": random.choice(v["ports"]),
            "Zone (Origin)": "Untrust" if l % 2 == 0 else "Trust",
            "Zone (Impacted)": "Trust" if l % 2 == 0 else "Untrust",
            "Log Source": v["name"],
            "Protocol": random.choice(["TCP", "UDP"]),
            "Threat Name": v["threats_normal"],
            "Severity": "low",
            "Action": "allow",
            "Duration": random.randint(1, 60)
        })
    return rows


def _generate_class1_recon(v: dict, w: int, base_date: datetime, day_offset: int) -> list:
    """
    Class 1 — Internal Reconnaissance.
    Single IP scans 22-30 distinct ports in random order within 5 min (threshold > 15).
    [FIX] Port order is now randomized (not sequential) for realism.
    """
    w_start = base_date + timedelta(minutes=w * 5, days=day_offset)
    ip_ori = f"103.179.{200 + (w % 20)}.{50 + (w % 30)}"
    ip_imp = f"10.14.202.{100 + (w % 10)}"
    # Randomize number of ports scanned (22-30, all > threshold of 15)
    num_ports = random.randint(22, 30)
    # Shuffle the port list to avoid deterministic sequential pattern
    port_pool = list(range(1000, 1100))
    random.shuffle(port_pool)
    scan_ports = port_pool[:num_ports]
    rows = []
    for p_idx, port in enumerate(scan_ports):
        # Slightly randomized timing (not perfectly uniform)
        jitter = random.randint(-2, 2)
        log_time = w_start + timedelta(seconds=5 + p_idx * 8 + jitter)
        rows.append({
            "Log Date": _fmt(log_time),
            "IP Address (Origin)": ip_ori,
            "IP Address (Impacted)": ip_imp,
            "TCP/UDP Port (Impacted)": port,
            "Zone (Origin)": "Untrust",
            "Zone (Impacted)": "Trust",
            "Log Source": v["name"],
            "Protocol": "TCP",
            "Threat Name": v["threats_recon"],
            "Severity": "medium",
            "Action": "drop",
            "Duration": random.randint(0, 2)
        })
    return rows


def _generate_class2_lateral(v: dict, w: int, base_date: datetime, day_offset: int) -> list:
    """
    Class 2 — Lateral Movement.
    Compromised INTERNAL host (Trust) connects to 5-7 distinct internal IPs (Trust).
    
    [CRITICAL FIX] Previous version used uniform 40-second intervals between logs,
    which caused coef_of_variation ≈ 0, triggering the Beaconing (Class 3) pseudo-label
    check BEFORE the Lateral Movement check, resulting in 0 samples labeled as Class 2.

    Fix: Use highly IRREGULAR intervals (simulating opportunistic lateral probe bursts):
    - Example intervals: [8s, 95s, 22s, 140s, 35s, 60s] → std/avg >> 0.15
    - This ensures coef_of_variation > 0.15, bypassing the Beaconing filter.
    
    Also: Rotate ip_origin from a pool of compromised hosts (not always the same IP)
    so that the model learns the pattern from multiple internal sources.
    """
    w_start = base_date + timedelta(minutes=w * 5, days=day_offset)
    # Rotate across a pool of compromised internal hosts (not always 10.14.202.100)
    compromised_ips = [
        "10.14.202.100", "10.14.202.101", "10.14.202.102",
        "10.14.202.103", "10.14.202.104"
    ]
    ip_ori = compromised_ips[w % len(compromised_ips)]

    # Generate 5-7 target IPs to ensure unique_ips_targeted > 3 (threshold)
    num_targets = random.randint(5, 7)
    target_base = 150 + (w % 30)

    # CRITICAL: Use highly irregular intervals so coef_of_variation >> 0.15
    # This simulates burst-then-pause lateral probe behavior (realistic attacker pattern)
    # Intervals are drawn from a wide-variance distribution: mix of short bursts and long pauses
    irregular_intervals = sorted([random.randint(5, 180) for _ in range(num_targets)])
    # Shuffle to break any accidental regularity pattern
    random.shuffle(irregular_intervals)

    rows = []
    elapsed = 5
    for t_idx in range(num_targets):
        log_time = w_start + timedelta(seconds=elapsed)
        elapsed += irregular_intervals[t_idx]
        # Make sure we stay within the 5-min window (300 seconds)
        if elapsed > 295:
            elapsed = 290 - random.randint(0, 10)

        rows.append({
            "Log Date": _fmt(log_time),
            "IP Address (Origin)": ip_ori,
            "IP Address (Impacted)": f"10.14.202.{target_base + t_idx}",
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
    return rows


def _generate_class3_beaconing(v: dict, w: int, base_date: datetime, day_offset: int) -> list:
    """
    Class 3 — Beaconing (C2 Heartbeat).
    Periodic connections with very low inter-arrival variance (coef_of_variation < 0.15).
    [FIX] Added small ±jitter (1-3s) to simulate realistic beacon timing imprecision
    while keeping coef_of_variation well below 0.15 threshold.
    """
    w_start = base_date + timedelta(minutes=w * 5, days=day_offset)
    ip_ori = f"10.14.{202 + (w % 3)}.{80 + (w % 15)}"
    ip_imp = random.choice(["8.8.8.8", "1.1.1.1", "185.220.101.1", "91.108.4.1"])
    # Base interval 20-35 seconds with tiny jitter (±2s) → cv stays well < 0.15
    base_interval = random.randint(20, 35)
    num_beacons = random.randint(6, 8)
    rows = []
    elapsed = 10
    for b_idx in range(num_beacons):
        jitter = random.randint(-2, 2)
        log_time = w_start + timedelta(seconds=elapsed)
        elapsed += base_interval + jitter
        rows.append({
            "Log Date": _fmt(log_time),
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
    return rows


def build_dataset(rows_per_vendor_class: int = 500) -> int:
    """
    Generates time-windowed sequences for each class across each vendor.
    Each window is a 5-minute block.

    Args:
        rows_per_vendor_class: Number of 5-min behavior windows per (vendor, class) pair.
                               500 → ~50,000 raw CSV rows → ~5,000+ 3D sequences after windowing.
    """
    print(f"Building custom training dataset: {OUTPUT_CSV}...")
    print(f"Config: {rows_per_vendor_class} windows × 3 vendors × 4 classes")
    rows = []
    base_date = datetime(2026, 4, 1, 0, 0, 0)

    for v in VENDORS:
        v_idx = VENDORS.index(v)
        print(f"  Generating training sequences for vendor: {v['name']}...")

        # Use separate day offsets per class to avoid time collisions between classes
        # Palo Alto:  days 0, 80, 160, 240
        # FortiGate:  days 320, 400, 480, 560
        # FortiWAF:   days 640, 720, 800, 880
        day_base = v_idx * 320

        class0_rows = []
        class1_rows = []
        class2_rows = []
        class3_rows = []

        for w in range(rows_per_vendor_class):
            class0_rows.extend(_generate_class0_normal(v, w, base_date, day_base + 0))
            class1_rows.extend(_generate_class1_recon(v, w, base_date, day_base + 80))
            class2_rows.extend(_generate_class2_lateral(v, w, base_date, day_base + 160))
            class3_rows.extend(_generate_class3_beaconing(v, w, base_date, day_base + 240))

        rows.extend(class0_rows)
        rows.extend(class1_rows)
        rows.extend(class2_rows)
        rows.extend(class3_rows)

        print(f"    Class 0 (Normal):      {len(class0_rows):,} rows")
        print(f"    Class 1 (Recon):       {len(class1_rows):,} rows")
        print(f"    Class 2 (Lateral):     {len(class2_rows):,} rows  [** WAS 0 BEFORE FIX **]")
        print(f"    Class 3 (Beaconing):   {len(class3_rows):,} rows")

    # Sort rows chronologically
    print("Sorting rows chronologically...")
    rows.sort(key=lambda x: datetime.strptime(x["Log Date"], "%m/%d/%Y %I:%M:%S %p"))

    # Write to CSV
    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n[OK] Training dataset created: {len(rows):,} total log records -> {OUTPUT_CSV}")
    return len(rows)


def build_holdout_dataset(rows_per_class: int = 100) -> int:
    """
    Generates a SEPARATE holdout test dataset (test_holdout.csv) for truly-unseen validation.
    
    Uses DIFFERENT characteristics from the training set to simulate real-world deployment:
    - Different IP address ranges (192.168.x.x instead of 10.14.x.x / 103.179.x.x)
    - Different time range (starts 2027 instead of 2026)
    - Different C2 beacon intervals (40-60s instead of 20-35s)
    - Mixed zone naming variants (e.g., "Internal" alongside "Trust")
    - Only 1 vendor (Palo Alto) for simplicity

    This dataset is NOT used for training — only for final model evaluation.
    """
    print(f"\nBuilding holdout test dataset: {HOLDOUT_CSV}...")
    rows = []
    base_date = datetime(2027, 1, 15, 8, 0, 0)  # Different time range
    v = VENDORS[0]  # Palo Alto only

    for w in range(rows_per_class):
        # Class 0 — Normal (different IP range: 192.168.x.x)
        ip_ori = f"192.168.{10 + (w % 5)}.{20 + (w % 30)}"
        ip_imp = f"172.16.{1 + (w % 3)}.{50 + (w % 20)}"
        w_start = base_date + timedelta(minutes=w * 5, days=0)
        for l in range(random.randint(2, 3)):
            rows.append({
                "Log Date": _fmt(w_start + timedelta(seconds=random.randint(10, 280))),
                "IP Address (Origin)": ip_ori,
                "IP Address (Impacted)": ip_imp,
                "TCP/UDP Port (Impacted)": random.choice([443, 80, 8443]),
                "Zone (Origin)": "Untrust",
                "Zone (Impacted)": "Internal",   # Different zone name variant
                "Log Source": v["name"],
                "Protocol": "TCP",
                "Threat Name": v["threats_normal"],
                "Severity": "low",
                "Action": "allow",
                "Duration": random.randint(5, 90)
            })

        # Class 1 — Recon (different scanner IPs)
        ip_ori_scan = f"45.33.{100 + (w % 20)}.{w % 255}"
        w_start1 = base_date + timedelta(minutes=w * 5, days=30)
        num_ports = random.randint(20, 28)
        port_pool = list(range(2000, 2100))
        random.shuffle(port_pool)
        for p_idx, port in enumerate(port_pool[:num_ports]):
            rows.append({
                "Log Date": _fmt(w_start1 + timedelta(seconds=5 + p_idx * 9 + random.randint(-1, 1))),
                "IP Address (Origin)": ip_ori_scan,
                "IP Address (Impacted)": f"172.16.1.{10 + (w % 20)}",
                "TCP/UDP Port (Impacted)": port,
                "Zone (Origin)": "Untrust",
                "Zone (Impacted)": "Internal",
                "Log Source": v["name"],
                "Protocol": "TCP",
                "Threat Name": v["threats_recon"],
                "Severity": "medium",
                "Action": "drop",
                "Duration": random.randint(0, 1)
            })

        # Class 2 — Lateral Movement (different internal range, irregular intervals)
        ip_ori_lat = f"172.16.{1 + (w % 3)}.{10 + (w % 5)}"
        w_start2 = base_date + timedelta(minutes=w * 5, days=60)
        num_targets = random.randint(5, 6)
        elapsed = 5
        for t_idx in range(num_targets):
            interval = random.randint(10, 200)
            rows.append({
                "Log Date": _fmt(w_start2 + timedelta(seconds=elapsed)),
                "IP Address (Origin)": ip_ori_lat,
                "IP Address (Impacted)": f"172.16.2.{50 + t_idx + (w % 10)}",
                "TCP/UDP Port (Impacted)": random.choice([445, 135, 3389]),
                "Zone (Origin)": "Internal",
                "Zone (Impacted)": "Internal",
                "Log Source": v["name"],
                "Protocol": "TCP",
                "Threat Name": v["threats_lateral"],
                "Severity": "high",
                "Action": "reset-both",
                "Duration": random.randint(10, 90)
            })
            elapsed = min(elapsed + interval, 290)

        # Class 3 — Beaconing (different interval: 40-60s, different C2 IPs)
        ip_ori_bcon = f"172.16.{1 + (w % 3)}.{80 + (w % 10)}"
        w_start3 = base_date + timedelta(minutes=w * 5, days=90)
        base_iv = random.randint(40, 60)  # Longer interval than training set
        elapsed = 10
        for b_idx in range(random.randint(5, 7)):
            jitter = random.randint(-3, 3)
            rows.append({
                "Log Date": _fmt(w_start3 + timedelta(seconds=elapsed)),
                "IP Address (Origin)": ip_ori_bcon,
                "IP Address (Impacted)": random.choice(["104.21.44.20", "172.67.148.77"]),
                "TCP/UDP Port (Impacted)": 443,
                "Zone (Origin)": "Internal",
                "Zone (Impacted)": "Untrust",
                "Log Source": v["name"],
                "Protocol": "TCP",
                "Threat Name": v["threats_beacon"],
                "Severity": "high",
                "Action": "drop",
                "Duration": random.randint(1, 5)
            })
            elapsed += base_iv + jitter

    # Sort chronologically
    rows.sort(key=lambda x: datetime.strptime(x["Log Date"], "%m/%d/%Y %I:%M:%S %p"))

    with open(HOLDOUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Holdout test dataset created: {len(rows):,} total log records -> {HOLDOUT_CSV}")
    return len(rows)


if __name__ == "__main__":
    print("=" * 65)
    print("  CNN-LSTM Dataset Builder v2 - Fixed & Scaled")
    print("=" * 65)

    train_count = build_dataset(rows_per_vendor_class=500)
    holdout_count = build_holdout_dataset(rows_per_class=100)

    print("\n" + "=" * 65)
    print(f"  DONE - Training CSV : {train_count:,} rows")
    print(f"         Holdout CSV  : {holdout_count:,} rows")
    print("=" * 65)
