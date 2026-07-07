# High-Performance Cybersecurity Log Monitoring Backend Foundation

We are initializing the backend foundation for an enterprise-grade Cybersecurity Log Monitoring and Preprocessing Pipeline. The architecture strictly follows **Enterprise-Grade Layered Architecture**, **Clean Code (DRY)**, and **Scalability** principles, using Python 3.10+, FastAPI, PostgreSQL, SQLAlchemy, and Pandas.

## User Review Required

> [!IMPORTANT]
> **Database Connection Configuration**: By default, the application will connect to PostgreSQL using the connection string defined in `.env` (defaulting to `postgresql://postgres:postgres@localhost:5432/security_logs`). Please ensure a PostgreSQL database instance is running and accessible or adjust the `.env` settings accordingly.

> [!TIP]
> **CSV Dataset Location**: The seeder script expects the raw firewall log CSV at `datasets/raw/firewall_log.csv`. For testing and verification, we can copy or symlink the existing 589MB dataset (`03_05_2026-LogRhythm_WebLogsExport (1).csv`) from the parent project directory into `datasets/raw/firewall_log.csv`.

## Open Questions

1. **Table Creation Strategy**: During startup or before running the seeder, should we use SQLAlchemy's `Base.metadata.create_all(bind=engine)` to automatically initialize the tables (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`) if they do not exist? (We propose **Yes**, including an auto-creation check or migration utility in `app/core/database.py`).
2. **Primary Key Design for ORM Models**: To ensure clean ORM mapping and prevent duplicate key collisions during sample seeding, we propose adding an auto-incrementing `id = Column(Integer, primary_key=True, index=True)` along with indexing on `log_date` and the 6 core columns. Does this align with your preferred indexing strategy?

## Proposed Changes

### Configuration & Version Control

#### [NEW] [requirements.txt](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/requirements.txt)
- Exact dependency definitions: `FastAPI==0.109.0`, `uvicorn==0.25.0`, `psycopg2-binary==2.9.12`, `SQLAlchemy`, `pandas==2.2.3`, `python-dotenv==1.2.2`, and `pydantic-settings`.

#### [NEW] [.gitignore](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/.gitignore)
- Comprehensive Git ignore rules for Python/FastAPI projects, explicitly including `venv/`, `__pycache__/`, `.env`, and `datasets/raw/`.

#### [NEW] [README.md](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/README.md)
- Instructions for creating and activating a Python virtual environment (`python -m venv venv`), installing requirements, setting up environment variables, seeding data, and running the server.

#### [NEW] [.env.example](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/.env.example)
- Template for environment variables including `DATABASE_URL` and `API_V1_STR`.

---

### Core & Database Layer (`app/core`)

#### [NEW] [app/core/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/core/__init__.py)
- Package initialization.

#### [NEW] [app/core/config.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/core/config.py)
- Pydantic Settings implementation for type-safe environment variable management and application configuration.

#### [NEW] [app/core/database.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/core/database.py)
- SQLAlchemy engine creation, `sessionmaker` (`SessionLocal`), Declarative `Base`, and the `get_db()` dependency generator for FastAPI dependency injection.

---

### Data Models Layer (`app/models`)

#### [NEW] [app/models/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/models/__init__.py)
- Exporting ORM models.

#### [NEW] [app/models/logs.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/models/logs.py)
- Definition of three main tables: `palo_alto_logs`, `fortinet_logs`, and `fortiwaf_logs`.
- Explicit mapping and indexing for the 7 core AI model attributes:
  - `ip_origin` (String/INET, indexed)
  - `ip_impacted` (String/INET, indexed)
  - `port_impacted` (Integer, indexed)
  - `zone_origin` (String, indexed)
  - `zone_impacted` (String, indexed)
  - `log_date` (DateTime with timezone, indexed)
  - `log_source` (String, indexed)
- Dynamic accommodation of 100+ remaining flexible columns via a PostgreSQL `JSONB` column named `additional_data`.

---

### Schemas & DTOs Layer (`app/schemas`)

#### [NEW] [app/schemas/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/schemas/__init__.py)
- Exporting Pydantic schemas.

#### [NEW] [app/schemas/logs.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/schemas/logs.py)
- `LogBaseSchema`, `LogCreateSchema`, and `LogResponseSchema` with full validation for core columns and dynamic `additional_data` dictionary.
- `LogQueryParameters` schema for validating pagination (`count` and `offset_range`).

---

### Business Logic & Repositories Layer (`app/services` & `app/repositories`)

#### [NEW] [app/repositories/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/repositories/__init__.py)
- Exporting repositories.

#### [NEW] [app/repositories/log_repository.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/repositories/log_repository.py)
- `LogRepository` class implementing CRUD operations:
  - `get_logs(count: int, offset_range: int, vendor: str)`
  - `bulk_insert_logs(model_class, log_dicts: list)`

#### [NEW] [app/services/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/services/__init__.py)
- Exporting service utilities.

#### [NEW] [app/services/data_cleaner.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/services/data_cleaner.py)
- Data Type Conversion utility functions:
  - `clean_empty_string(val)`: Converts empty strings `""`, `"null"`, or whitespace to `None` (`NULL`).
  - `parse_log_date(val)`: Handles scientific notation (e.g., `1.78E+12` epoch ms), standard epoch numbers, and ISO 8601 date strings, converting them into valid Python `datetime` objects.
  - `clean_log_record(row_dict)`: Maps raw CSV headers (like `"IP Address (Origin)"`, `"TCP/UDP Port (Impacted)"`) to core model fields and puts all remaining columns into `additional_data`.

#### [NEW] [app/services/log_service.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/services/log_service.py)
- `LogService` class encapsulating business rules, formatting dummy data when database tables are empty, and coordinating repository calls.

---

### API Routers Layer (`app/api/routers`)

#### [NEW] [app/api/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/api/__init__.py)
- API package initialization.

#### [NEW] [app/api/routers/__init__.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/api/routers/__init__.py)
- Exporting routers.

#### [NEW] [app/api/routers/logs.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/api/routers/logs.py)
- Dummy endpoint `GET /api/logs?count={int}&offset_range={int}`.
- Uses Dependency Injection strictly (`db: Session = Depends(get_db)`).
- Returns JSON responses adhering to `LogResponseSchema`, returning live data from the database or structured dummy data matching the CSV headers structure if empty.

#### [NEW] [app/main.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/app/main.py)
- FastAPI application entry point, registering routers, CORS middleware, and OpenAPI documentation metadata.

---

### Memory-Optimized Database Seeder

#### [NEW] [seed_dummy_data.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/seed_dummy_data.py)
- Reads massive CSV files (`datasets/raw/firewall_log.csv`) using `pandas.read_csv(..., chunksize=10000, dtype=str)` to prevent RAM overload.
- Extracts the first 5,000 rows from the first chunk.
- Passes rows through `clean_log_record()` from `app.services.data_cleaner`.
- Performs SQLAlchemy bulk insertion into `palo_alto_logs` table in batches of 1,000 rows.
- Provides real-time terminal feedback/logging (e.g., `"Inserted 1000 rows into the database..."`).

## Verification Plan

### Automated Tests
- Run Python syntax check and compilation across all created files:
  ```bash
  python -m py_compile app/main.py app/models/logs.py app/schemas/logs.py app/services/data_cleaner.py app/repositories/log_repository.py seed_dummy_data.py
  ```
- Verify unit testing of the Data Cleaner service (testing scientific notation timestamp conversion and empty string handling):
  ```bash
  python -c "from app.services.data_cleaner import parse_log_date, clean_empty_string; print('Date test:', parse_log_date('1772633968263')); print('Empty string test:', clean_empty_string('   '))"
  ```

### Manual Verification
- Verify FastAPI startup and OpenAPI schema generation without database errors:
  ```bash
  python -c "from app.main import app; print('FastAPI App Initialized Successfully:', app.title)"
  ```
- Test `seed_dummy_data.py` (after linking or copying the dataset to `datasets/raw/firewall_log.csv`) to ensure memory optimization and bulk insertion logging perform cleanly.
