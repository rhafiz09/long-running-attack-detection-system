import logging
import pickle
from pathlib import Path
from functools import lru_cache
from typing import List, Tuple, Dict, Any, Optional

import numpy as np
import pandas as pd
import tensorflow as tf

from app.ai_engine.feature_engineering import LogFeatureEngineer
from app.schemas.detection import DetectionRequest, DetectionResponse, DetectionResult

logger = logging.getLogger(__name__)

# Paths to serialized ML artifacts
SAVED_MODELS_DIR = Path(__file__).resolve().parents[1] / "ai_engine" / "saved_models"
MODEL_PATH = SAVED_MODELS_DIR / "cnn_lstm_model.keras"
ENGINEER_PATH = SAVED_MODELS_DIR / "feature_engineer.pkl"


class InferenceService:
    """
    High-performance Real-Time ML Inference Service.
    Loads Keras CNN-LSTM model and feature engineering scaler/encoders into memory
    and evaluates incoming security firewall logs.
    """

    THREAT_MAPPING = {
        0: "Normal",
        1: "Reconnaissance",
        2: "Lateral Movement",
        3: "Beaconing"
    }

    def __init__(self):
        logger.info("Initializing Real-Time ML Inference Service...")
        self.model: Optional[tf.keras.Model] = None
        self.engineer: Optional[LogFeatureEngineer] = None
        self._load_artifacts()

    def _load_artifacts(self):
        """
        Loads the trained CNN-LSTM Keras model and LogFeatureEngineer from disk.
        """
        if not MODEL_PATH.exists():
            logger.error(f"Trained Keras model artifact not found at {MODEL_PATH}.")
            raise FileNotFoundError(f"ML Model artifact missing: {MODEL_PATH}")

        logger.info(f"Loading Keras CNN-LSTM model from {MODEL_PATH}...")
        self.model = tf.keras.models.load_model(str(MODEL_PATH))
        logger.info("Keras model loaded successfully.")

        if ENGINEER_PATH.exists():
            logger.info(f"Loading fitted LogFeatureEngineer from {ENGINEER_PATH}...")
            with open(ENGINEER_PATH, "rb") as f:
                self.engineer = pickle.load(f)
            logger.info("LogFeatureEngineer loaded successfully.")
        else:
            logger.warning(
                f"Fitted feature engineer artifact not found at {ENGINEER_PATH}. "
                "Will instantiate a fresh LogFeatureEngineer and fit on incoming batch data as fallback."
            )
            self.engineer = LogFeatureEngineer(window_size="5min", timesteps=3)

    def prepare_sequences_with_ips(
        self, engineer: LogFeatureEngineer, df: pd.DataFrame
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Converts 2D transformed behavior windows into 3D sequential tensors (samples, timesteps, features)
        while tracking the exact origin IP address associated with each sequence.
        """
        if df.empty:
            return np.empty((0, engineer.timesteps, 0)), []

        df = df.sort_values(by=["ip_origin", "window_start"])
        feature_cols = engineer.num_cols + engineer.cat_cols
        X_list = []
        ip_list = []

        for ip, group in df.groupby("ip_origin"):
            if len(group) < engineer.timesteps:
                continue  # Skip IPs without enough timesteps for a 3D sequence
            features_matrix = group[feature_cols].values
            for idx in range(len(group) - engineer.timesteps + 1):
                X_seq = features_matrix[idx : idx + engineer.timesteps]
                X_list.append(X_seq)
                ip_list.append(str(ip))

        X = np.array(X_list) if X_list else np.empty((0, engineer.timesteps, len(feature_cols)))
        return X, ip_list

    def predict(self, request: DetectionRequest) -> DetectionResponse:
        """
        Executes end-to-end real-time inference on a batch of firewall logs:
        1. Preprocess: Clean -> Window -> Pseudo-label -> Transform features.
        2. Sequence Formation: Form 3D tensors (samples, timesteps, features).
        3. Inference: Pass tensors to neural network and map probabilities to threat categories.
        4. Fallback: Gracefully return default Normal status if logs are too sparse for sequence formation.
        """
        if not request.logs:
            return DetectionResponse(
                status="success",
                message="Empty log payload provided. No evaluations performed.",
                results=[]
            )

        # 1. Convert Pydantic request logs to dictionaries
        raw_logs = [log.model_dump() for log in request.logs]

        # 2. Preprocess logs using LogFeatureEngineer
        engineer = self.engineer
        if engineer is None:
            engineer = LogFeatureEngineer(window_size="5min", timesteps=3)

        df_clean = engineer.clean_and_prepare_df(raw_logs)
        if df_clean.empty:
            return DetectionResponse(
                status="error",
                message="Log cleaning failed. Unable to parse provided log records.",
                results=[]
            )

        df_windowed = engineer.perform_time_windowing(df_clean)
        # We assign pseudo-labels so the dataframe has the 'label' column required by transform()
        df_labeled = engineer.assign_pseudo_labels(df_windowed)

        # If engineer was not pre-fitted from disk, fit it on the current batch
        if not engineer.is_fitted:
            logger.info("Fitting fallback feature engineer on incoming batch...")
            engineer.fit(df_labeled)

        df_transformed = engineer.transform(df_labeled)

        # 3. Form 3D sequences with origin IP tracking
        X, ip_list = self.prepare_sequences_with_ips(engineer, df_transformed)

        # 4. Handle Sparsity Fallback
        if len(X) == 0:
            logger.warning(
                f"Incoming batch generated 0 sequences (requires {engineer.timesteps} timesteps per IP). "
                "Returning default Normal status for evaluated IPs."
            )
            unique_ips = df_clean["ip_origin"].unique().tolist() if not df_clean.empty else ["0.0.0.0"]
            fallback_results = [
                DetectionResult(
                    ip_origin=str(ip),
                    label=0,
                    threat_name=self.THREAT_MAPPING[0],
                    confidence_score=1.0
                )
                for ip in unique_ips
            ]
            return DetectionResponse(
                status="success",
                message="Incoming log data was too sparse across time windows to form full 3D sequences (length=3). Defaulting status to Normal (Label 0) for evaluated IPs.",
                results=fallback_results
            )

        # 5. Execute Neural Network Prediction
        logger.info(f"Executing model inference on sequence shape X={X.shape}...")
        predictions = self.model.predict(X, verbose=0)

        results: List[DetectionResult] = []
        for i in range(len(X)):
            probs = predictions[i]
            pred_label = int(np.argmax(probs))
            conf_score = float(probs[pred_label])
            threat_name = self.THREAT_MAPPING.get(pred_label, "Unknown")

            results.append(
                DetectionResult(
                    ip_origin=ip_list[i],
                    label=pred_label,
                    threat_name=threat_name,
                    confidence_score=conf_score
                )
            )

        logger.info(f"Successfully evaluated {len(results)} threat detection sequences.")
        return DetectionResponse(
            status="success",
            message="Real-time attack detection completed successfully.",
            results=results
        )


@lru_cache()
def get_inference_service() -> InferenceService:
    """
    Singleton Dependency Provider:
    Caches the InferenceService instance using @lru_cache so that model loading
    only occurs ONCE at application startup or first request.
    """
    return InferenceService()
