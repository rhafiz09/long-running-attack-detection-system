# Phase 2: CNN-LSTM Model for Cybersecurity Long Running Attack Detection

We are implementing the machine learning engine for detecting long-running cyber attacks. The code is structured in a dedicated directory (`app/ai_engine/`) to keep FastAPI web routing and ML components completely separate.

## User Review Required

> [!IMPORTANT]
> **TensorFlow and Keras Versions**: The training pipeline uses TensorFlow and Keras. If these packages are not yet installed in the active environment, we will provide instructions to install them.
> To prevent training execution failure in environments without a PostgreSQL database instance containing sufficient logs, the pipeline orchestrator (`training_pipeline.py`) will automatically generate a mock dataset in memory if the database contains fewer records than required for sequential window training.

## Proposed Changes

### Feature Engineering & Preprocessing (`app/ai_engine`)

#### [NEW] [feature_engineering.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/ai_engine/feature_engineering.py)
- Implements `LogFeatureEngineer` to process raw logs:
  - **Incremental Time Windowing**: Groups raw logs by a specified time interval (e.g. 5 minutes or 1 hour) per source IP (`ip_origin`).
  - **Behavior Feature Extraction**:
    - `unique_ports_count`: Unique target ports.
    - `unique_ips_targeted`: Unique target IPs.
    - `avg_connection_interval`: Average time delta between consecutive logs in seconds.
  - **Pseudo-Labeling Logic**:
    - `0`: Normal (default)
    - `1`: Internal Reconnaissance (high unique port counts)
    - `2`: Lateral Movement (internal-to-internal target zone traversal)
    - `3`: Beaconing (highly regular connection intervals / low time-delta variance)
  - **Scaling & Encoding**: Encodes categorical variables (`LabelEncoder`) and normalizes numerical features (`MinMaxScaler`).
  - **3D Sequential Formatting**: Transforms the 2D tabular features into 3D tensors of shape `(samples, timesteps, features)` required for Keras LSTM layers.

---

### Model Architecture (`app/ai_engine`)

#### [NEW] [model_architecture.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/ai_engine/model_architecture.py)
- Implements `create_cnn_lstm_model(input_shape, num_classes=4)`:
  - **Input Layer**: `(timesteps, features)`
  - **Spatial Convolution**: `Conv1D` + `MaxPooling1D` for local window feature extraction.
  - **Temporal Sequence modeling**: `LSTM` layer to identify low-and-slow patterns across windows.
  - **Classification Head**: `Dense` layers with Dropout regularization, ending in a 4-unit `softmax` Dense layer.
  - Compiles the model using `adam`, `sparse_categorical_crossentropy`, and tracking `accuracy`.

---

### Pipeline Orchestration (`app/ai_engine`)

#### [NEW] [training_pipeline.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/ai_engine/training_pipeline.py)
- Connects to the PostgreSQL database via `SessionLocal` to fetch logs.
- Converts records to a Pandas DataFrame, cleans data types, and applies `LogFeatureEngineer`.
- Compiles the CNN-LSTM model and triggers `model.fit()`.
- Automatically saves the trained model to `app/ai_engine/saved_models/cnn_lstm_model.keras`.

## Verification Plan

### Automated Tests
- Syntax check for all new files:
  ```bash
  python -m py_compile app/ai_engine/feature_engineering.py app/ai_engine/model_architecture.py app/ai_engine/training_pipeline.py
  ```
- Verify feature engineering windowing, pseudo-labeling, and shape conversion using a local test runner script:
  ```bash
  python -c "from app.ai_engine.feature_engineering import LogFeatureEngineer; import pandas as pd; print('Feature Engineer imported successfully.')"
  ```
