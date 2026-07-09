# 🛡️ Sistem Deteksi Serangan Siber Long-Running Berbasis AI (CNN-LSTM)

[🇬🇧 Read in English](README.md)

Sebuah platform pertahanan keamanan siber full-stack tingkat enterprise yang dirancang untuk mendeteksi **Serangan Siber Long-Running** yang samar, bertahap, dan lambat (*low-and-slow*) di seluruh perimeter jaringan multi-vendor. Dengan memanfaatkan arsitektur deep learning hibrida (**CNN-LSTM**) yang dipadukan dengan desain microservices terdekopel, sistem ini menyediakan ingestion ancaman real-time, analisis perilaku, pemantauan Role-Based Access Control (RBAC), dan saran mitigasi berbasis generative AI.

---

## 🚀 1. RINGKASAN PROYEK & ARSITEKTUR

Ancaman persisten tingkat lanjut (APT) modern dengan mudah melewati aturan firewall tradisional berbasis ambang batas (threshold) dengan mengeksekusi **Serangan Long-Running**—memperpanjang komunikasi pengintaian (*reconnaissance*), pergerakan lateral (*lateral movement*), dan beaconing selama berjam-jam, berhari-hari, atau berminggu-minggu.

Platform ini menyelesaikan tantangan deteksi temporal tersebut melalui **Arsitektur Microservices Terdekopel** tingkat enterprise:
- **FastAPI ML Engine (Port 8000)**: Berfungsi sebagai API ingestion dan inferensi dengan throughput tinggi. Engine ini memvalidasi log mentah firewall yang masuk, mentransformasikannya menjadi urutan *time-window* perilaku, dan mengeksekusi evaluasi jaringan saraf tiruan (*neural network*) secara real-time.
- **Database PostgreSQL (Port 5432)**: Bertindak sebagai penyimpanan terpusat, mengelola tabel log terindeks yang dipisahkan berdasarkan vendor dengan fleksibilitas skema JSONB untuk kueri analitik berkecepatan tinggi.
- **Django SOC Dashboard (Port 8001)**: Menyediakan portal web Security Operations Center (SOC) responsif yang mengusung desain *glassmorphic*. Portal ini memiliki telemetri Chart.js real-time, administrasi RBAC, dan **Asisten AI Google Gemini** terintegrasi yang memberikan saran strategi mitigasi yang dapat ditindaklanjuti kepada analis keamanan dalam bahasa Indonesia.

```
       +-----------------------------------------------------------------+
       |               FIREWALL EKSTERNAL / KOLEKTOR SIEM                |
       |             (Aliran Palo Alto, FortiGate, FortiWAF)             |
       +-----------------------------------------------------------------+
                                        |
                                        v  [Batch Ingestion JSON - Diamankan X-API-Key]
       +-----------------------------------------------------------------+
       |                  FASTAPI ML ENGINE (Port 8000)                  |
       |  +-----------------------------------------------------------+  |
       |  |  LogService & Repository  <-->  Engine Inferensi CNN-LSTM |  |
       |  +-----------------------------------------------------------+  |
       +-----------------------------------------------------------------+
                                        |
                 [SQLAlchemy Bulk ORM]  |  [ORM Read-Only Unmanaged]
                                        v
       +-----------------------------------------------------------------+
       |                 DATABASE POSTGRESQL (Port 5432)                 |
       |      (palo_alto_logs  |  fortinet_logs  |  fortiwaf_logs)       |
       +-----------------------------------------------------------------+
                                        |
                                        v  [Kueri & Analisis Real-Time]
       +-----------------------------------------------------------------+
       |               DJANGO SOC DASHBOARD (Port 8001)                  |
       |  +-----------------------------------------------------------+  |
       |  |   UI Autentikasi RBAC | Telemetri Chart.js | AI Gemini SOC|  |
       |  +-----------------------------------------------------------+  |
       +-----------------------------------------------------------------+
```

### 🧠 Kemampuan AI Utama: Jaringan Saraf Hibrida CNN-LSTM
Engine deteksi menggantikan aturan threshold sederhana dengan jaringan saraf hibrida 4-kelas:
1. **Layer Konvolusi 1D (`Conv1D` + `MaxPooling1D`)**: Mengekstrak korelasi fitur spasial dan pola burst lokal di berbagai atribut jaringan (misalnya, port, IP tujuan, durasi aliran) dalam satu jendela waktu (*time window*).
2. **Layer Long Short-Term Memory (`LSTM`)**: Mempertahankan memori temporal di seluruh jendela waktu yang berurutan, berhasil mengidentifikasi anomali perilaku *low-and-slow* yang membentang dalam rentang waktu yang lama.
3. **Kategorisasi Multi-Kelas**: Mengevaluasi lalu lintas data ke dalam empat klasifikasi ancaman yang berbeda:
   - **`Class 0: Normal Traffic`**: Operasi bisnis standar dan aktivitas jaringan asinkron.
   - **`Class 1: Internal Reconnaissance`**: Pemindaian port tingkat rendah dan pemetaan endpoint.
   - **`Class 2: Lateral Movement`**: Penyebaran koneksi zona kepercayaan internal-ke-internal yang mencurigakan.
   - **`Class 3: Beaconing`**: Interval callback command-and-control (C2) periodik dengan varians rendah.

---

## 📁 2. STRUKTUR REPOSITORI

Repositori ini diatur sesuai dengan standar **Clean Code (DRY)** dan **Arsitektur Berlapis (Layered Architecture)** yang ketat:

```text
├── app/                              # Backend FastAPI & Layer ML Engine
│   ├── ai_engine/                    # Neural Network & Preprocessing Data
│   │   ├── feature_engineering.py    # LogFeatureEngineer: Time-windowing & pemformatan tensor 3D
│   │   ├── model_architecture.py     # Definisi model hibrida Keras CNN-LSTM
│   │   ├── training_pipeline.py      # Orkestrator pelatihan end-to-end & generator fail-safe
│   │   └── saved_models/             # Artefak Keras (.keras) dan scaler (.pkl) yang disimpan
│   ├── api/routers/                  # Endpoint API REST (/logs/batch, /detect)
│   ├── core/                         # Konfigurasi, Engine Database, Keamanan & Rate Limiter
│   ├── models/                       # Model ORM Deklaratif SQLAlchemy (Tabel Vendor)
│   ├── repositories/                 # Layer Akses Data (Penyisipan Massal & Kueri Terpaginasi)
│   ├── schemas/                      # Skema Validasi & Serialisasi Pydantic
│   └── services/                     # Logika Bisnis & Layanan Inferensi ML Singleton
├── web_dashboard/                    # Layer SOC Web Dashboard Django
│   ├── monitor/                      # Aplikasi Pemantauan SOC
│   │   ├── models.py                 # Model ORM Django Unmanaged (managed = False)
│   │   ├── views.py                  # Logika Dashboard RBAC, API Chart, & Chatbot Gemini
│   │   ├── urls.py                   # Perutean URL untuk Aplikasi Monitor
│   │   └── templates/monitor/        # Templat HTML Glassmorphic & Tailwind CSS
│   ├── web_dashboard/                # Root Proyek & Pengaturan Django
│   └── manage.py                     # Utilitas Manajemen Command-Line Django
├── datasets/raw/                     # Penyimpanan untuk log firewall CSV mentah (diabaikan Git)
├── scripts/                          # Skrip DevOps & Pemeliharaan
│   └── backup_db.py                  # Utilitas pengarsipan database terkompresi otomatis pg_dump
├── backups/                          # Arsip cadangan database .sql.gz bertanda waktu (diabaikan Git)
├── seed_dummy_data.py                # Skrip seeding database teroptimasi memori berbasis chunk
├── Dockerfile.fastapi                # Build Docker slim multi-stage untuk FastAPI Engine
├── Dockerfile.django                 # Build Docker slim untuk Django SOC Dashboard
├── docker-compose.yml                # Konfigurasi orkestrasi multi-kontainer root
├── requirements.txt                  # Dependensi proyek Python yang disatukan
└── README.md                         # Dokumentasi Sistem Enterprise (Bahasa Inggris)
```

---

## ⚙️ 3. PRASYARAT & PENYIAPAN LINGKUNGAN (ENVIRONMENT)

### Persyaratan Sistem Minimum
- **Python**: Versi `3.10` atau `3.11` (Direkomendasikan untuk kompatibilitas TensorFlow 2.16 & Keras 3.13 yang optimal).
- **PostgreSQL**: Versi `15.0+` (atau Docker yang menjalankan `postgres:15-alpine`).
- **Docker & Docker Compose**: Hanya diperlukan untuk deployment berbasis container.

### Langkah Demi Langkah Penyiapan Lingkungan

#### 1. Buat dan Aktifkan Virtual Environment
Buka terminal Anda di root repositori dan inisialisasi lingkungan Python terisolasi:
```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS (Bash)
python3 -m venv venv
source venv/bin/activate
```

#### 2. Instal Dependensi Proyek
Instal semua paket backend, machine learning, dan manajemen frontend yang diperlukan:
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

#### 3. Konfigurasikan Variabel Lingkungan (`.env`)
Buat file `.env` di direktori root. Gunakan templat komprehensif berikut:

```ini
# ==========================================
# 🛡️ CONFIG LINGKUNGAN SISTEM KEAMANAN SIBER
# ==========================================

# Pengaturan Umum Aplikasi
DEBUG=True
PROJECT_NAME="Cybersecurity Log Monitoring Pipeline API"
API_V1_STR="/api"

# Konfigurasi Database PostgreSQL
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/security_logs"
POSTGRES_SERVER="localhost"
POSTGRES_PORT="5432"
POSTGRES_DB="security_logs"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"

# Keamanan & Rate Limiting FastAPI
API_KEY="soc-secret-api-key-2026"

# Pengaturan Dashboard Django
DJANGO_SECRET_KEY="django-insecure-soc-dashboard-secret-key-enterprise-mvp-2026"

# Google Gemini AI Assistant (SOC Chatbot)
# Dapatkan API key Anda di: https://aistudio.google.com/
GEMINI_API_KEY="your_google_gemini_api_key_here"
```

---

## 🏃‍♂️ 4. PANDUAN OPERASI LANGKAH DEMI LANGKAH (MENJALANKAN SECARA LOKAL)

Untuk menjalankan seluruh platform secara lokal dari awal, jalankan langkah-langkah berurutan berikut:

### Langkah 1: Seeding Data Teroptimasi Memori
Untuk memuat (*ingest*) kumpulan data CSV yang besar (misalnya, ekspor log >500MB) tanpa membebani RAM sistem, modul seeder kami memanfaatkan metode chunking Pandas (`chunksize=10000`).

1. Tempatkan ekspor firewall mentah Anda di dalam `datasets/raw/firewall_log.csv` (atau gunakan sampel root yang disediakan).
2. Jalankan skrip seeding:
```powershell
python seed_dummy_data.py
```
*Catatan: Skrip ini mengekstrak catatan secara bertahap (dalam chunk), membersihkan tipe data (mengubah string kosong menjadi `NULL` dan stempel waktu ilmiah ke format ISO), dan melakukan penyisipan massal (bulk insertion) SQLAlchemy berkecepatan tinggi ke PostgreSQL.*

### Langkah 2: Latih Model AI CNN-LSTM
Sebelum melakukan inferensi, latih jaringan saraf tiruan dan buat artefak serialisasi yang diperlukan:
```powershell
python -m app.ai_engine.training_pipeline
```
*Apa yang terjadi:*
- Mengekstrak data historis dari PostgreSQL (atau mengaktifkan **fail-safe sintetis pintar** jika tabel kosong).
- Melakukan pengelompokan jendela waktu secara bertahap dan ekstraksi fitur statistik.
- Menghitung bobot kelas seimbang Scikit-Learn untuk menghilangkan ketidakseimbangan kelas.
- Melatih jaringan CNN-LSTM dan menyimpan dua artefak penting ke `app/ai_engine/saved_models/`:
  1. `cnn_lstm_model.keras` (Bobot jaringan saraf yang telah dikompilasi).
  2. `feature_engineer.pkl` (State scaler data dan label encoder yang telah dilatih).

### Langkah 3: Jalankan FastAPI ML Engine
Mulai server API backend berkinerja tinggi:
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- **Interactive Swagger UI**: Buka 👉 **[http://localhost:8000/docs](http://localhost:8000/docs)** untuk menguji log ingestion langsung (`POST /api/v1/logs/batch`) dan deteksi ancaman (`POST /api/v1/detect`).
- **Dokumentasi ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Langkah 4: Jalankan Django SOC Dashboard
Buka **tab terminal baru** (dengan virtual environment yang sudah diaktifkan) dan inisialisasi dashboard frontend:

1. **Migrasikan Tabel Autentikasi & Sesi** (Tabel firewall bersifat unmanaged dan terlindungi):
```powershell
python web_dashboard/manage.py migrate
```
2. **Buat Superuser Admin** (Untuk pengujian RBAC):
```powershell
python web_dashboard/manage.py createsuperuser --username admin --email admin@soc.local
```
*(Masukkan kata sandi seperti `admin123` saat diminta).*

3. **Jalankan Server Django**:
```powershell
python web_dashboard/manage.py runserver 8001
```
4. **Akses Dashboard**: Buka browser Anda dan navigasikan ke 👉 **[http://127.0.0.1:8001/](http://127.0.0.1:8001/)**
   - Masuk dengan kredensial admin Anda.
   - Jelajahi telemetri Chart.js real-time, filter waktu (`1h`, `24h`, `7d`), tabel log vendor, dan klik **`🤖 Asisten AI SOC`** untuk menganalisis ancaman IP dalam bahasa Indonesia!

---

## 🐳 5. DEPLOYMENT DENGAN DOCKER COMPOSE

Untuk pengujian produksi (*staging*) atau evaluasi akademik tanpa instalasi rumit, seluruh arsitektur multi-kontainer dapat dideploy dengan satu perintah.

### 1. Build dan Jalankan Container
Pastikan Docker sedang berjalan, lalu jalankan:
```powershell
docker-compose up --build -d
```

### 2. Kontainer yang Diorkestrasi
Mesin Docker Compose menginisialisasi tiga layanan terisolasi yang saling terhubung dalam jaringan:
- **`soc_postgres_db` (Port 5432)**: Dibuat dari `postgres:15-alpine`. Dikonfigurasi dengan volume Docker persisten (`postgres_data`) dan pemeriksaan kesehatan otomatis (`pg_isready`).
- **`soc_fastapi_engine` (Port 8000)**: Dibuat dari `Dockerfile.fastapi`. Secara otomatis menunggu konfirmasi kesehatan database sebelum memasang API.
- **`soc_django_dashboard` (Port 8001)**: Dibuat dari `Dockerfile.django`. Terhubung dengan mulus ke database bersama dan engine FastAPI.

### 3. Verifikasi Kesehatan Kontainer
Periksa log kontainer yang sedang berjalan dan statusnya:
```powershell
docker-compose ps
docker-compose logs -f fastapi_engine
```
Untuk menghentikan kontainer dan menghapus volume:
```powershell
docker-compose down -v
```

---

## 🔒 6. FITUR KEAMANAN & KEPATUHAN

Platform ini menerapkan rekayasa keamanan komprehensif (*Defense-in-Depth*) untuk memenuhi standar kepatuhan enterprise yang ketat:

1. **Kebal 100% terhadap SQL Injection**:
   - Tidak ada kueri SQL mentah di dalam codebase. Semua interaksi database dijalankan melalui layer pemetaan parameterised **SQLAlchemy ORM** dan **Django ORM**.
2. **Perlindungan Endpoint FastAPI (`X-API-Key`)**:
   - Endpoint ingestion dan prediksi yang sensitif memerlukan autentikasi melalui header HTTP `X-API-Key`, yang diterapkan dengan custom dependency injection (`app/core/security.py`).
3. **Rate Limiting untuk Mencegah DDoS & Brute-Force**:
   - Pembatas laju (*rate limiter*) terintegrasi **SlowAPI** membatasi endpoint inferensi (`POST /api/v1/detect`) dengan batasan ketat **100 permintaan per menit** per IP klien.
4. **Role-Based Access Control (RBAC)**:
   - Membedakan hak istimewa pengguna di tingkat dashboard. Administrator mendapatkan akses penuh untuk manajemen akun pengguna dan hak akses melalui `/admin/`, sementara analis staf (*Staff*) menerima akses pemantauan read-only.
5. **Keamanan Sesi & Perlindungan CSRF**:
   - Menerapkan `CsrfViewMiddleware` Django (`{% csrf_token %}`), cookie HTTP aman (*secure HTTP cookies*), pertahanan terhadap clickjacking (`XFrameOptionsMiddleware`), dan kebijakan timeout sesi.
6. **Pencadangan Database Terkompresi Otomatis**:
   - Menyertakan utilitas backup siap produksi di `scripts/backup_db.py`.
   - Menggunakan `pg_dump` dan streaming Python `gzip` untuk menghasilkan salinan `.sql.gz` terkompresi di dalam direktori `backups/` tanpa memaparkan kata sandi dalam teks biasa.
   - Dapat dijadwalkan menggunakan cron di Linux atau Penjadwal Tugas (*Task Scheduler*) di Windows:
     ```powershell
     python scripts/backup_db.py
     ```

---

## 📄 Lisensi & Atribusi
Dikembangkan oleh **Google DeepMind Advanced Agentic Coding Team & BilCode Engineering**.  
Hak cipta dilindungi undang-undang. Dirancang untuk Pertahanan SOC Enterprise dan Evaluasi Akademik (v2.0 - 2026).
