# Cybersecurity Log Monitoring & Preprocessing Pipeline Backend Foundation

An enterprise-grade high-performance backend foundation built with **FastAPI**, **PostgreSQL**, **SQLAlchemy ORM**, and **Pandas**. Designed specifically to ingest, clean, and serve security firewall logs (Palo Alto, Fortinet, FortiWAF) for Machine Learning-based Long Running Attack detection (CNN-LSTM).

---

## 🏛️ Architecture & Clean Code Principles

This repository strictly adheres to **Enterprise-Grade Layered Architecture**:
- `app/api/routers`: REST API Controllers/Endpoints.
- `app/services`: Core Business Logic, Data Sanitization, and Preprocessing utilities.
- `app/repositories`: Data Access Layer (CRUD operations, Bulk Inserts).
- `app/schemas`: Pydantic Data Transfer Objects (DTOs) for request/response validation.
- `app/models`: SQLAlchemy ORM Declarative Models mapping to PostgreSQL tables.
- `app/core`: Configuration management, Database connection pooling, and Dependency Injection.

---

## 🚀 Getting Started

### 1. Virtual Environment Setup
Create and activate an isolated Python virtual environment:

**On Windows (PowerShell / CMD):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
Install the exact required enterprise dependencies:
```bash
pip install -r requirements.txt
```

### 3. Environment Variables Setup
Copy the example environment configuration file:
```powershell
cp .env.example .env
```
Edit `.env` to match your PostgreSQL credentials (default: `postgresql://postgres:postgres@localhost:5432/security_logs`).

---

## 📦 Database Seeding (Memory Optimized)

To ingest massive CSV datasets (e.g., 500MB+ log exports) without overloading system RAM, we utilize Pandas chunking (`chunksize=10000`).

1. Place your raw CSV file inside `datasets/raw/firewall_log.csv` (or copy from your project root).
2. Execute the memory-optimized seeder:
```bash
python seed_dummy_data.py
```
*The script will read the first chunk, extract 5,000 rows, sanitize data types (empty strings to `NULL`, scientific notation timestamps to datetime), and perform SQLAlchemy bulk insertion into the `palo_alto_logs` table.*

---

## 🌐 Running the API Server

Start the FastAPI development server with Uvicorn:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### API Documentation
Once the server is running, access the interactive Swagger UI and OpenAPI documentation:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Example Endpoint Usage
Fetch logs with pagination query parameters:
```http
GET /api/logs?count=10&offset_range=0
```
