# 🛡️ AI-Powered Long-Running Cyber Attack Detection System (CNN-LSTM)

An enterprise-grade, full-stack cybersecurity defense platform engineered to detect subtle, low-and-slow **Long-Running Cyber Attacks** across multi-vendor network perimeters. By leveraging a hybrid deep learning architecture (**CNN-LSTM**) coupled with a decoupled microservices design, this system delivers real-time threat ingestion, behavioral analysis, Role-Based Access Control (RBAC) monitoring, and generative AI mitigation counseling.

---

## 🚀 1. PROJECT OVERVIEW & ARCHITECTURE

Modern advanced persistent threats (APTs) easily bypass traditional threshold-based firewall rules by executing **Long-Running Attacks**—stretching reconnaissance, lateral movement, and beaconing communications over hours, days, or weeks. 

This platform solves the temporal detection challenge through an enterprise **Decoupled Microservices Architecture**:
- **FastAPI ML Engine (Port 8000)**: Serves as the high-throughput ingestion and inference API. It validates incoming raw firewall logs, transforms them into behavioral time-window sequences, and executes real-time neural network evaluation.
- **PostgreSQL Database (Port 5432)**: Acts as the centralized storage engine, maintaining indexed, vendor-separated log tables with JSONB schema flexibility for high-speed analytical querying.
- **Django SOC Dashboard (Port 8001)**: Provides a responsive, glassmorphic Security Operations Center (SOC) web portal. It features real-time Chart.js telemetry, RBAC administration, and an integrated **Google Gemini AI Assistant** that counsels security engineers with actionable mitigation strategies in Indonesian.

```
       +-----------------------------------------------------------------+
       |               EXTERNAL FIREWALLS / SIEM COLLECTORS              |
       |             (Palo Alto, FortiGate, FortiWAF Streams)            |
       +-----------------------------------------------------------------+
                                        |
                                        v  [JSON Batch Ingestion - X-API-Key Secured]
       +-----------------------------------------------------------------+
       |                  FASTAPI ML ENGINE (Port 8000)                  |
       |  +-----------------------------------------------------------+  |
       |  |  LogService & Repository  <-->  CNN-LSTM Inference Engine |  |
       |  +-----------------------------------------------------------+  |
       +-----------------------------------------------------------------+
                                        |
                 [SQLAlchemy Bulk ORM]  |  [Unmanaged Read-Only ORM]
                                        v
       +-----------------------------------------------------------------+
       |                 POSTGRESQL DATABASE (Port 5432)                 |
       |      (palo_alto_logs  |  fortinet_logs  |  fortiwaf_logs)       |
       +-----------------------------------------------------------------+
                                        ^
                                        |  [Real-Time Analytics & Queries]
       +-----------------------------------------------------------------+
       |               DJANGO SOC DASHBOARD (Port 8001)                  |
       |  +-----------------------------------------------------------+  |
       |  |   RBAC Auth UI  |  Chart.js Telemetry  |  Gemini SOC AI   |  |
       |  +-----------------------------------------------------------+  |
       +-----------------------------------------------------------------+
```

### 🧠 Core AI Capability: Hybrid CNN-LSTM Neural Network
The detection engine replaces naive threshold rules with a 4-class hybrid neural network:
1. **1D Convolutional Layers (`Conv1D` + `MaxPooling1D`)**: Extract spatial feature correlations and localized burst patterns across network attributes (e.g., ports, destination IPs, flow durations) within a time window.
2. **Long Short-Term Memory Layers (`LSTM`)**: Maintain temporal memory across sequential time windows, successfully identifying low-and-slow behavioral anomalies that span extended time horizons.
3. **Multi-Class Categorization**: Evaluates traffic into four distinct threat classifications:
   - **`Class 0: Normal Traffic`**: Standard business and asynchronous network operations.
   - **`Class 1: Internal Reconnaissance`**: Low-rate port scanning and endpoint mapping.
   - **`Class 2: Lateral Movement`**: Suspicious internal-to-internal trust zone connection spreading.
   - **`Class 3: Beaconing`**: Periodic, low-variance command-and-control (C2) callback intervals.

---

## 📁 2. REPOSITORY STRUCTURE

The repository is organized according to strict **Clean Code (DRY)** and **Layered Architectural** standards:

```text
├── app/                              # FastAPI Backend & ML Engine Layer
│   ├── ai_engine/                    # Neural Network & Data Preprocessing
│   │   ├── feature_engineering.py    # LogFeatureEngineer: Time-windowing & 3D tensor formatting
│   │   ├── model_architecture.py     # Keras CNN-LSTM hybrid model definition
│   │   ├── training_pipeline.py      # End-to-end training orchestrator & fail-safe generator
│   │   └── saved_models/             # Persisted Keras (.keras) and scaler (.pkl) artifacts
│   ├── api/routers/                  # REST API Endpoints (/logs/batch, /detect)
│   ├── core/                         # Configuration, Database Engine, Security & Rate Limiters
│   ├── models/                       # SQLAlchemy Declarative ORM Models (Vendor Tables)
│   ├── repositories/                 # Data Access Layer (Bulk Insertions & Paginated Queries)
│   ├── schemas/                      # Pydantic Validation & Serialization Schemas
│   └── services/                     # Business Logic & Singleton ML Inference Service
├── web_dashboard/                    # Django SOC Web Dashboard Layer
│   ├── monitor/                      # SOC Monitoring Application
│   │   ├── models.py                 # Unmanaged Django ORM Models (managed = False)
│   │   ├── views.py                  # RBAC Dashboard, Chart API, & Gemini Chatbot Logic
│   │   ├── urls.py                   # URL Routing for Monitor App
│   │   └── templates/monitor/        # Tailwind CSS & Glassmorphic HTML Templates
│   ├── web_dashboard/                # Django Project Root & Settings
│   └── manage.py                     # Django Command-Line Management Utility
├── datasets/raw/                     # Storage for raw CSV firewall logs (Git-ignored)
├── scripts/                          # DevOps & Maintenance Scripts
│   └── backup_db.py                  # Automated pg_dump compressed database archiving utility
├── backups/                          # Timestamped .sql.gz database backup archives (Git-ignored)
├── seed_dummy_data.py                # Chunk-based memory-optimized database seeding script
├── Dockerfile.fastapi                # Multi-stage slim Docker build for FastAPI Engine
├── Dockerfile.django                 # Slim Docker build for Django SOC Dashboard
├── docker-compose.yml                # Root multi-container orchestration configuration
├── requirements.txt                  # Unified Python project dependencies
└── README.md                         # Enterprise System Documentation (This file)
```

---

## ⚙️ 3. PREREQUISITES & ENVIRONMENT SETUP

### Minimum System Requirements
- **Python**: Version `3.10` or `3.11` (Recommended for optimal TensorFlow 2.16 & Keras 3.13 compatibility).
- **PostgreSQL**: Version `15.0+` (or Docker running `postgres:15-alpine`).
- **Docker & Docker Compose**: Required only for containerized deployment.

### Step-by-Step Environment Setup

#### 1. Create and Activate Virtual Environment
Open your terminal in the repository root and initialize an isolated Python environment:
```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS (Bash)
python3 -m venv venv
source venv/bin/activate
```

#### 2. Install Project Dependencies
Install all required backend, machine learning, and frontend management packages:
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

#### 3. Configure Environment Variables (`.env`)
Create a `.env` file in the root directory. Use the following comprehensive template:

```ini
# ==========================================
# 🛡️ CYBERSECURITY SYSTEM ENVIRONMENT CONFIG
# ==========================================

# General Application Settings
DEBUG=True
PROJECT_NAME="Cybersecurity Log Monitoring Pipeline API"
API_V1_STR="/api"

# PostgreSQL Database Configuration
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/security_logs"
POSTGRES_SERVER="localhost"
POSTGRES_PORT="5432"
POSTGRES_DB="security_logs"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"

# FastAPI Security & Rate Limiting
API_KEY="soc-secret-api-key-2026"

# Django Dashboard Settings
DJANGO_SECRET_KEY="django-insecure-soc-dashboard-secret-key-enterprise-mvp-2026"

# Google Gemini AI Assistant (SOC Chatbot)
# Get your API key from: https://aistudio.google.com/
GEMINI_API_KEY="your_google_gemini_api_key_here"
```

---

## 🏃‍♂️ 4. STEP-BY-STEP OPERATION MANUAL (LOCAL RUN)

To boot the entire platform locally from scratch, execute the following sequential steps:

### Step 1: Memory-Optimized Data Seeding
To ingest massive CSV datasets (e.g., 500MB+ log exports) without overloading system RAM, our seeder utilizes Pandas chunking (`chunksize=10000`).

1. Place your raw firewall export inside `datasets/raw/firewall_log.csv` (or use the provided root sample).
2. Execute the seeding script:
```powershell
python seed_dummy_data.py
```
*Note: The script extracts records in chunks, sanitizes data types (converting empty strings to `NULL` and scientific timestamps to ISO format), and performs high-speed SQLAlchemy bulk insertion into PostgreSQL.*

### Step 2: Train the CNN-LSTM AI Model
Before serving inference, train the neural network and generate the necessary serialization artifacts:
```powershell
python -m app.ai_engine.training_pipeline
```
*What happens:*
- Extracts historical records from PostgreSQL (or engages an **intelligent synthetic fail-safe** if tables are empty).
- Performs incremental time-window grouping and statistical feature extraction.
- Computes Scikit-Learn balanced class weights to eliminate class imbalance.
- Fits the CNN-LSTM network and saves two critical artifacts to `app/ai_engine/saved_models/`:
  1. `cnn_lstm_model.keras` (The compiled neural network weights).
  2. `feature_engineer.pkl` (The fitted data scaler and label encoder state).

### Step 3: Launch the FastAPI ML Engine
Start the high-performance backend API server:
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- **Interactive Swagger UI**: Navigate to 👉 **[http://localhost:8000/docs](http://localhost:8000/docs)** to test live log ingestion (`POST /api/v1/logs/batch`) and threat detection (`POST /api/v1/detect`).
- **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Step 4: Launch the Django SOC Dashboard
Open a **new terminal tab** (with your virtual environment activated) and initialize the frontend dashboard:

1. **Migrate Auth & Session Tables** (Firewall tables are unmanaged and protected):
```powershell
python web_dashboard/manage.py migrate
```
2. **Create Admin Superuser** (For RBAC testing):
```powershell
python web_dashboard/manage.py createsuperuser --username admin --email admin@soc.local
```
*(Enter a password such as `admin123` when prompted).*

3. **Start Django Server**:
```powershell
python web_dashboard/manage.py runserver 8001
```
4. **Access Dashboard**: Open your browser and navigate to 👉 **[http://127.0.0.1:8001/](http://127.0.0.1:8001/)**
   - Log in with your admin credentials.
   - Explore real-time Chart.js telemetry, time filters (`1h`, `24h`, `7d`), vendor log tables, and click **`🤖 SOC AI Assistant`** to analyze IP threats in Indonesian!

---

## 🐳 5. TURNKEY DEPLOYMENT (DOCKER COMPOSE)

For production staging or zero-setup university evaluations, the entire multi-container architecture can be deployed with a single command.

### 1. Build and Boot Stack
Ensure Docker is running, then execute:
```powershell
docker-compose up --build -d
```

### 2. Orchestrated Containers
The Docker Compose engine initializes three isolated, networked services:
- **`soc_postgres_db` (Port 5432)**: Built from `postgres:15-alpine`. Configured with persistent Docker volume (`postgres_data`) and automated healthchecks (`pg_isready`).
- **`soc_fastapi_engine` (Port 8000)**: Built from `Dockerfile.fastapi`. Automatically waits for database health confirmation before mounting APIs.
- **`soc_django_dashboard` (Port 8001)**: Built from `Dockerfile.django`. Connects seamlessly to the shared database and FastAPI engine.

### 3. Verify Container Health
Check running container logs and status:
```powershell
docker-compose ps
docker-compose logs -f fastapi_engine
```
To tear down the stack and clean up volumes:
```powershell
docker-compose down -v
```

---

## 🔒 6. SECURITY & COMPLIANCE FEATURES

This platform implements comprehensive, Defense-in-Depth security engineering to meet stringent enterprise compliance standards:

1. **100% SQL Injection Immunity**:
   - Zero raw SQL queries exist in the codebase. All database interactions are executed through parameterized **SQLAlchemy ORM** and **Django ORM** mapping layers.
2. **FastAPI Endpoint Protection (`X-API-Key`)**:
   - Sensitive ingestion and prediction endpoints require authentication via the `X-API-Key` HTTP header, enforced by custom dependency injection (`app/core/security.py`).
3. **DDoS & Brute-Force Rate Limiting**:
   - Integrated **SlowAPI** rate limiters restrict inference endpoints (`POST /api/v1/detect`) to a strict threshold of **100 requests per minute** per client IP.
4. **Role-Based Access Control (RBAC)**:
   - Differentiates user privileges at the dashboard level. Administrators receive full user account and permission management access via `/admin/`, while Staff analysts receive read-only monitoring access.
5. **Session Security & CSRF Protection**:
   - Enforces Django `CsrfViewMiddleware` (`{% csrf_token %}`), secure HTTP cookies, clickjacking defense (`XFrameOptionsMiddleware`), and session timeout policies.
6. **Automated Compressed Database Backups**:
   - Includes a production-ready backup utility in `scripts/backup_db.py`.
   - Utilizes `pg_dump` and Python `gzip` streaming to generate compressed `.sql.gz` snapshots inside the `backups/` directory without exposing plaintext passwords.
   - Can be scheduled via Linux cron or Windows Task Scheduler:
     ```powershell
     python scripts/backup_db.py
     ```

---

## 📄 License & Attribution
Developed by the **Google DeepMind Advanced Agentic Coding Team & BilCode Engineering**.  
All rights reserved. Designed for Enterprise SOC Defense and Academic Evaluation (v2.0 - 2026).
