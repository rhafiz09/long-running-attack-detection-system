# Phase 3: Real-Time ML Inference API Integration

We are ready to integrate the trained CNN-LSTM model into the FastAPI backend to enable real-time cybersecurity attack detection. This plan outlines the architecture for Pydantic schemas, a high-performance inference service with cached model loading, a dedicated detection router, and robust error/sparsity handling.

## User Review Required

> [!IMPORTANT]
> **Model Loading & Scaler Persistence**: To ensure the ML inference service applies the exact same numerical scaling and categorical encoding weights used during training, we will update `training_pipeline.py` to serialize the fitted `LogFeatureEngineer` as `feature_engineer.pkl` alongside `cnn_lstm_model.keras`. The inference service will load both artifacts once into memory using `@lru_cache` (with a graceful fallback to fit on incoming batch data if the `.pkl` file is absent).

> [!TIP]
> **Sparse Sequence Handling**: Because the Conv1D-LSTM architecture requires 3 consecutive timesteps per origin IP, incoming log batches in `POST /api/v1/detect` that are too sparse to form full 3D tensors will be handled gracefully without throwing errors. The service will evaluate all unique origin IPs in the payload and return a default `Normal` status (Label 0, Confidence 1.0) along with an explanatory message in `DetectionResponse.message`.

## Proposed Changes

We will group files logically by architectural layer (Schemas -> Services -> Routers -> Core Application).

---

### Schemas

#### [NEW] [detection.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/schemas/detection.py)
Defines strict Pydantic models for request validation and structured prediction outputs:
- `LogEntry`: Represents a single raw log event (`ip_origin`, `ip_impacted`, `port_impacted`, `zone_origin`, `zone_impacted`, `log_date`).
- `DetectionRequest`: Contains `logs: List[LogEntry]` (representing a batch of logs from the last 5 minutes).
- `DetectionResult`: Contains `ip_origin`, detected `label` (`0`: Normal, `1`: Reconnaissance, `2`: Lateral Movement, `3`: Beaconing), `threat_name`, and `confidence_score` (float between `0.0` and `1.0`).
- `DetectionResponse`: Contains `results: List[DetectionResult]`, `status: str`, and `message: Optional[str]`.

---

### Services

#### [NEW] [inference_service.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/services/inference_service.py)
Implements an optimized AI inference layer:
- **Model Loading (`@lru_cache`)**: Loads `cnn_lstm_model.keras` and `feature_engineer.pkl` ONCE into memory to eliminate disk I/O overhead on API requests.
- **Preprocessing & Sequence Alignment**: Converts incoming `DetectionRequest` logs into a Pandas DataFrame, cleans data, performs time-windowing, and applies scaling/encoding while mapping unseen categorical values to `"unknown"`.
- **IP Tracking in 3D Sequences**: Custom sequence generator that tracks the exact `ip_origin` corresponding to each sliding window sequence in `(samples, 3, 8)`.
- **Prediction & Post-processing**: Passes 3D tensors to `model.predict()`, extracts the maximum softmax probability, maps labels to human-readable Threat Names, and formats `DetectionResult` objects.
- **Sparsity Fallback**: When incoming logs are insufficient to form 3 timesteps, returns default `Normal` status with an explanatory status message.

---

### API Routers

#### [NEW] [detection.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/api/routers/detection.py)
Creates the endpoint for real-time attack detection:
- `POST /api/v1/detect`: Accepts `DetectionRequest` and returns `DetectionResponse`.
- Uses Dependency Injection (`Depends`) to inject the cached `InferenceService`.
- Includes comprehensive OpenAPI descriptions and example schemas for Swagger UI testing.

---

### Core Application & AI Engine

#### [MODIFY] [main.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/main.py)
- Includes `detection.router` with prefix `/api/v1` and tag `"Real-Time Attack Detection"`.

#### [MODIFY] [training_pipeline.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/ai_engine/training_pipeline.py)
- Adds serialization of `engineer` to `saved_models/feature_engineer.pkl` using Python's built-in `pickle` module so the inference service can load exact training scalers and encoders.

---

## Verification Plan

### Automated Tests
1. **Syntax Compilation Check**: Verify zero Python syntax or import errors across all modified and new files:
   ```powershell
   python -m py_compile app/schemas/detection.py app/services/inference_service.py app/api/routers/detection.py app/main.py app/ai_engine/training_pipeline.py
   ```
2. **Artifact Generation**: Re-run the training pipeline to generate both `cnn_lstm_model.keras` and `feature_engineer.pkl`:
   ```powershell
   python app/ai_engine/training_pipeline.py
   ```

### Manual Verification via Swagger UI
1. **Start Local Server**:
   ```powershell
   uvicorn app.main:app --reload
   ```
2. **Test via Swagger UI (`http://127.0.0.1:8000/docs`)**:
   - Navigate to `POST /api/v1/detect`.
   - **Test Case A (Normal Traffic Batch)**: Submit a sample JSON payload with 15 logs from an IP across 15 minutes. Verify that the API returns a structured `DetectionResponse` with confidence scores and threat classifications.
   - **Test Case B (Sparse Batch Fallback)**: Submit a payload with only 1 or 2 logs. Verify that the API returns status `200 OK` with default `Normal` predictions and a clear informational message explaining sequence sparsity.
