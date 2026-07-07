import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

logger = logging.getLogger(__name__)


class LogFeatureEngineer:
    """
    Feature Engineering and Data Preprocessing Pipeline for CNN-LSTM Model.
    Transforms raw firewall log records into 3D sequential datasets (samples, timesteps, features).
    """

    def __init__(self, window_size: str = "5min", timesteps: int = 3):
        self.window_size = window_size
        self.timesteps = timesteps
        self.scaler = MinMaxScaler()
        self.label_encoders: Dict[str, LabelEncoder] = {}
        
        # Categorical columns to encode
        self.cat_cols = ["zone_origin_mode", "zone_impacted_mode", "log_source_mode"]
        # Numerical columns to scale
        self.num_cols = [
            "unique_ports_count",
            "unique_ips_targeted",
            "avg_connection_interval",
            "interval_std",
            "total_connections"
        ]
        self.is_fitted = False

    def clean_and_prepare_df(self, raw_logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Converts raw database records (dicts) into a pandas DataFrame and ensures proper typing.
        """
        if not raw_logs:
            return pd.DataFrame()

        df = pd.DataFrame(raw_logs)
        
        # Ensure log_date is datetime
        if "log_date" not in df.columns:
            df["log_date"] = pd.Timestamp.now()
        df["log_date"] = pd.to_datetime(df["log_date"])
        
        # Fill missing values with standard place-holders (and create column if missing)
        defaults = {
            "ip_origin": "0.0.0.0",
            "ip_impacted": "0.0.0.0",
            "port_impacted": -1,
            "zone_origin": "unknown",
            "zone_impacted": "unknown",
            "log_source": "unknown"
        }
        for col, val in defaults.items():
            if col not in df.columns:
                df[col] = val
            df[col] = df[col].fillna(val)
            if col == "port_impacted":
                df[col] = df[col].astype(int)
        
        return df

    def perform_time_windowing(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Groups firewall logs into incremental time windows per source IP (ip_origin).
        Extracts behavioral features: unique ports, target IPs, and connection intervals.
        """
        if df.empty:
            return pd.DataFrame()

        logger.info(f"Grouping logs into {self.window_size} time windows per ip_origin...")
        
        # Sort values by log_date to calculate correct connection intervals
        df = df.sort_values(by=["ip_origin", "log_date"])
        
        window_records = []
        
        # Group by ip_origin and resample using Grouper
        grouped = df.groupby(["ip_origin", pd.Grouper(key="log_date", freq=self.window_size)])
        
        for (ip, w_start), group in grouped:
            if group.empty:
                continue
                
            total_conn = len(group)
            unique_ports = group["port_impacted"].nunique()
            unique_ips = group["ip_impacted"].nunique()
            
            # Compute time differences in seconds
            sorted_dates = group["log_date"].sort_values()
            diffs = sorted_dates.diff().dt.total_seconds().dropna()
            
            avg_interval = float(diffs.mean()) if not diffs.empty else 0.0
            interval_std = float(diffs.std()) if len(diffs) > 1 else 0.0
            
            # Modes for categorical columns in the window
            zone_ori_mode = str(group["zone_origin"].mode().iloc[0]) if not group["zone_origin"].empty else "unknown"
            zone_imp_mode = str(group["zone_impacted"].mode().iloc[0]) if not group["zone_impacted"].empty else "unknown"
            log_src_mode = str(group["log_source"].mode().iloc[0]) if not group["log_source"].empty else "unknown"
            
            window_records.append({
                "ip_origin": ip,
                "window_start": w_start,
                "total_connections": total_conn,
                "unique_ports_count": unique_ports,
                "unique_ips_targeted": unique_ips,
                "avg_connection_interval": avg_interval,
                "interval_std": interval_std,
                "zone_origin_mode": zone_ori_mode,
                "zone_impacted_mode": zone_imp_mode,
                "log_source_mode": log_src_mode
            })
            
        window_df = pd.DataFrame(window_records)
        logger.info(f"Extracted {len(window_df)} behavior windows.")
        return window_df

    def assign_pseudo_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies heuristic-based pseudo-labeling rules for 4 classes:
        - Label 0: Normal
        - Label 1: Internal Reconnaissance (High port sweep)
        - Label 2: Lateral Movement (Internal to internal target scans)
        - Label 3: Beaconing (Steady, highly periodic connections)
        """
        if df.empty:
            return df

        labels = []
        for _, row in df.iterrows():
            # 1. Internal Reconnaissance: scanning many ports
            if row["unique_ports_count"] > 15:
                labels.append(1)
                continue
                
            # 2. Beaconing: Steady connection count, low variance of intervals (periodic)
            if row["total_connections"] >= 5 and row["avg_connection_interval"] > 0:
                coef_of_variation = row["interval_std"] / row["avg_connection_interval"]
                if 2.0 <= row["avg_connection_interval"] <= 600.0 and coef_of_variation < 0.15:
                    labels.append(3)
                    continue

            # 3. Lateral Movement: trust to trust zone traversal with multiple unique target IPs
            zone_ori = str(row["zone_origin_mode"]).lower()
            zone_imp = str(row["zone_impacted_mode"]).lower()
            is_internal_origin = any(term in zone_ori for term in ["trust", "internal", "lan", "int"])
            is_internal_impacted = any(term in zone_imp for term in ["trust", "internal", "lan", "int"])
            if is_internal_origin and is_internal_impacted and row["unique_ips_targeted"] > 3:
                labels.append(2)
                continue
                
            # Default: Normal
            labels.append(0)
            
        df["label"] = labels
        label_distribution = df["label"].value_counts().to_dict()
        logger.info(f"Pseudo-labeling completed. Distribution: {label_distribution}")
        return df

    def fit(self, df: pd.DataFrame) -> "LogFeatureEngineer":
        """
        Fits MinMaxScaler and LabelEncoders on the windowed behavior DataFrame.
        """
        if df.empty:
            raise ValueError("Cannot fit on an empty DataFrame.")

        logger.info("Fitting feature scalers and encoders...")
        
        # Fit MinMaxScaler
        self.scaler.fit(df[self.num_cols])
        
        # Fit LabelEncoders
        for col in self.cat_cols:
            le = LabelEncoder()
            # Feed raw labels and include a fallback 'unknown' class
            unique_vals = list(df[col].astype(str).unique())
            if "unknown" not in unique_vals:
                unique_vals.append("unknown")
            le.fit(unique_vals)
            self.label_encoders[col] = le
            
        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies fitted MinMaxScaler and LabelEncoders to the windowed behavior DataFrame.
        """
        if not self.is_fitted:
            raise ValueError("LogFeatureEngineer is not fitted yet. Call fit() first.")
            
        if df.empty:
            return df

        transformed_df = df.copy()
        
        # Transform numerical columns
        transformed_df[self.num_cols] = self.scaler.transform(df[self.num_cols])
        
        # Transform categorical columns
        for col in self.cat_cols:
            le = self.label_encoders[col]
            # Handle unseen labels by mapping them to 'unknown'
            unseen_mask = ~df[col].astype(str).isin(le.classes_)
            if unseen_mask.any():
                df.loc[unseen_mask, col] = "unknown"
            transformed_df[col] = le.transform(df[col].astype(str))
            
        return transformed_df

    def to_3d_sequences(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Converts 2D tabular window features into 3D sequential data (samples, timesteps, features)
        required for Conv1D-LSTM input shapes.
        """
        if df.empty:
            return np.empty((0, self.timesteps, 0)), np.empty((0,))

        # Sorting chronologically per source IP
        df = df.sort_values(by=["ip_origin", "window_start"])
        
        feature_cols = self.num_cols + self.cat_cols
        X_list = []
        y_list = []
        
        logger.info(f"Generating 3D sequences using timesteps={self.timesteps}...")
        
        # Generate sliding windows of sequences per IP
        for ip, group in df.groupby("ip_origin"):
            if len(group) < self.timesteps:
                continue  # Skip IPs with insufficient history for a sequence
                
            features_matrix = group[feature_cols].values
            labels_vector = group["label"].values
            
            # Slide window
            for idx in range(len(group) - self.timesteps + 1):
                X_seq = features_matrix[idx : idx + self.timesteps]
                # Label is determined by the last timestep's label in the sequence (current status)
                y_label = labels_vector[idx + self.timesteps - 1]
                
                X_list.append(X_seq)
                y_list.append(y_label)
                
        X = np.array(X_list) if X_list else np.empty((0, self.timesteps, len(feature_cols)))
        y = np.array(y_list) if y_list else np.empty((0,))
        
        logger.info(f"Generated 3D Sequence Shapes -> X: {X.shape}, y: {y.shape}")
        return X, y

    def fit_transform_pipeline(self, raw_logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Executes the entire feature engineering pipeline end-to-end:
        Clean -> Resample/Window -> Label -> Fit/Transform Encoders -> Convert to 3D.
        """
        df_clean = self.clean_and_prepare_df(raw_logs)
        if df_clean.empty:
            return np.empty((0, self.timesteps, len(self.num_cols) + len(self.cat_cols))), np.empty((0,))
            
        df_windowed = self.perform_time_windowing(df_clean)
        df_labeled = self.assign_pseudo_labels(df_windowed)
        
        # Fit & Transform
        self.fit(df_labeled)
        df_transformed = self.transform(df_labeled)
        
        return self.to_3d_sequences(df_transformed)
