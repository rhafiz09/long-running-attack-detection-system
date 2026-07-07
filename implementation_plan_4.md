# Phase 4: Frontend Dashboard & AI Chatbot Assistant (Django)

We are ready to build a responsive, enterprise-grade Cybersecurity SOC Web Dashboard using Django, Vanilla CSS/Tailwind, Chart.js, and Google Gemini AI. This frontend will connect directly to our existing PostgreSQL database, enforce Role-Based Access Control (RBAC), visualize real-time network traffic trends, and feature a floating AI chatbot assistant that analyzes IP activity and recommends mitigations in Indonesian.

## User Review Required

> [!IMPORTANT]
> **Database Connection & Unmanaged Models**: Django will connect to the exact same PostgreSQL database as FastAPI using environment variables from `.env`. In `monitor/models.py`, our firewall log tables (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`) will be configured with `Meta: managed = False`. This ensures Django can query the logs seamlessly while `python manage.py migrate` only touches Django's internal auth/session tables without ever modifying or altering existing security tables.

> [!TIP]
> **Tailwind CDN & Premium Cyber-SOC Aesthetics**: To achieve a breathtaking, state-of-the-art dark mode UI without requiring complex Node/Webpack build pipelines, we will use the Tailwind CSS CDN combined with custom Vanilla CSS in our templates. This provides glassmorphic backdrop filters (`backdrop-blur-md`), glowing neon borders (emerald/cyan/violet), modern Outfit Google typography, and smooth micro-animations.

> [!NOTE]
> **Gemini AI Chatbot & Graceful Fallback**: When a user asks *"Analyze IP 103.179.248.11"*, the Django chatbot endpoint will use regex to extract the IP address, query PostgreSQL for recent logs involving that IP, and pass the structured data to `gemini-1.5-flash` via the `google-generativeai` SDK with instructions to answer as a SOC Assistant in Indonesian. If `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) is not configured in `.env`, the endpoint will gracefully fall back to a simulated SOC analysis response so the chat UI remains 100% functional and testable!

---

## Proposed Changes

We will create a new Django project `web_dashboard` inside our codebase root and implement the `monitor` application.

### Requirements Layer
#### [MODIFY] [requirements.txt](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/requirements.txt)
- Add `django>=5.0.0` and `google-generativeai>=0.8.0`.

---

### Project Configuration (`web_dashboard`)
#### [NEW] [web_dashboard/manage.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/manage.py)
#### [NEW] [web_dashboard/web_dashboard/settings.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/web_dashboard/settings.py)
- Connects to PostgreSQL using `python-dotenv` and environment variables (`POSTGRES_SERVER`, `POSTGRES_DB`, etc.).
- Registers `monitor` app, configures template directories, static files, and login redirect URLs.
#### [NEW] [web_dashboard/web_dashboard/urls.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/web_dashboard/urls.py)
- Routes root URL `/` to `monitor.urls` and includes Django admin `/admin/`.

---

### Monitoring Application (`web_dashboard/monitor`)
#### [NEW] [web_dashboard/monitor/models.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/models.py)
- Defines `PaloAltoLog`, `FortinetLog`, and `FortiwafLog` ORM models with `managed = False` and exact database table names.
#### [NEW] [web_dashboard/monitor/views.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/views.py)
- **`dashboard_view(request)`**: Protected by `@login_required`. Aggregates summary statistics (Total Logs Analyzed, Detected Threats, Blocked IPs), paginates recent logs across vendors, and enforces RBAC (Admin sees management links; Staff sees monitoring dashboard).
- **`chart_data_api(request)`**: JSON endpoint returning time-series log counts grouped by `log_date` with support for time filtering (`1h`, `24h`, `7d`).
- **`chatbot_api(request)`**: AJAX POST endpoint. Extracts IP via regex, queries recent log activity, invokes Gemini API (`gemini-1.5-flash`), and returns mitigation advice in Indonesian.
- **`login_view`, `logout_view`**: Custom authentication handlers.
#### [NEW] [web_dashboard/monitor/urls.py](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/urls.py)
- Defines routing for dashboard, auth, chart API, and chatbot API.

---

### Templates & UI Aesthetics (`web_dashboard/monitor/templates/monitor`)
#### [NEW] [base.html](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/templates/monitor/base.html)
- Master layout with Tailwind CDN, Google Fonts (Outfit), sleek glassmorphic navbar, and dark mode styling.
#### [NEW] [login.html](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/templates/monitor/login.html)
- Centered, glowing login card with animated cyber background.
#### [NEW] [dashboard.html](file:///d:/Projects/BilCode/ML%20-%20Pendeteksi%20Serangan%20Long%20Running%20Attack/codebase_new/web_dashboard/monitor/templates/monitor/dashboard.html)
- **Summary Cards**: Responsive metric grids with hover glow and micro-animations.
- **Interactive Chart.js Line Chart**: Dark-themed traffic trend visualization with toggle buttons for `1 Hour`, `24 Hours`, and `7 Days`.
- **Paginated Log Table**: Clean data table displaying timestamps, source/destination IPs, ports, zones, and vendor badges.
- **Floating AI Chatbot Widget**: Fixed bottom-right chat button opening an interactive glassmorphic chat window with typing indicators and real-time SOC mitigation responses.

---

## Verification Plan

### Automated Tests
1. **Dependency Installation**:
   ```powershell
   pip install -r requirements.txt
   ```
2. **Django System Check & Syntax Compilation**:
   ```powershell
   python web_dashboard/manage.py check
   python -m py_compile web_dashboard/monitor/views.py web_dashboard/monitor/models.py
   ```

### Manual Verification
1. **Initialize Django Auth Database & Superuser**:
   ```powershell
   python web_dashboard/manage.py migrate
   python web_dashboard/manage.py createsuperuser --username admin --email admin@soc.local
   ```
2. **Run Django Server Alongside FastAPI**:
   ```powershell
   python web_dashboard/manage.py runserver 8001
   ```
   *(FastAPI runs on port 8000; Django dashboard runs on port 8001).*
3. **Browser Testing (`http://127.0.0.1:8001/`)**:
   - Log in with admin credentials.
   - Verify summary cards, interactive Chart.js time filtering, and log table pagination.
   - Open floating chat widget, type *"Analyze IP 103.179.248.11"*, and verify Gemini AI mitigation analysis in Indonesian!
