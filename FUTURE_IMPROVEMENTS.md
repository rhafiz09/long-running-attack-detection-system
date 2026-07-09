# 📝 Catatan Pengembangan Sistem: Rencana Peningkatan Masa Depan (Future Improvements)
*Dokumen ini mencakup rencana peningkatan fitur pemantauan real-time untuk lingkungan pengembangan lokal (local development/testing environment).*

---

## 🚀 1. Simulasi Aliran Data Mengalir (Streaming Data Simulation)

Saat melakukan pengujian atau demonstrasi lokal (*local demo*), data di database sering kali bersifat statis karena diisi sekali melalui skrip *seeder* (`seed_dummy_data.py`). Hal ini membuat fitur pembaruan grafik otomatis (*auto-refresh chart*) dan sistem *alert notification* tidak terlihat bekerja secara interaktif.

### Solusi Pengembangan Lokal:
Untuk menyimulasikan lingkungan produksi di mana perangkat firewall terus memompakan log baru, kita dapat membuat skrip simulator Python sederhana di latar belakang (*background task*). Skrip ini akan melakukan penyisipan (*insertion*) data log acak baru secara periodik.

#### Contoh Implementasi Skrip Simulator (`scripts/sim_log_stream.py`):
```python
import time
import random
import logging
from datetime import datetime, timezone
from app.core.database import SessionLocal
from app.models.logs import PaloAltoLog
from app.services.data_cleaner import clean_log_record

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("simulator")

# Kumpulan IP Dummy untuk simulasi serangan & traffic normal
IPS_POOL = ["192.168.1.10", "10.0.0.50", "103.179.248.11", "172.16.0.5"]
IPS_IMPACTED = ["10.14.202.100", "10.14.202.101", "10.14.202.102"]
ZONES = ["Untrust", "Trust", "DMZ"]

def generate_random_log():
    return {
        "Log Date": datetime.now(timezone.utc).isoformat(),
        "IP Address (Origin)": random.choice(IPS_POOL),
        "IP Address (Impacted)": random.choice(IPS_IMPACTED),
        "TCP/UDP Port (Impacted)": str(random.choice([80, 443, 22, 3389, 445])),
        "Zone (Origin)": random.choice(ZONES),
        "Zone (Impacted)": random.choice(ZONES),
        "Log Source": "Palo Alto Networks",
        "action": random.choice(["allow", "deny", "drop"])
    }

def start_simulation(interval_seconds=10, batch_size=5):
    logger.info(f"Memulai simulator log. Menyisipkan {batch_size} log setiap {interval_seconds} detik...")
    db = SessionLocal()
    try:
        while True:
            raw_batch = [generate_random_log() for _ in range(batch_size)]
            cleaned_batch = [clean_log_record(log) for log in raw_batch]
            
            # Konversi dict ke objek SQLAlchemy
            db_records = [PaloAltoLog(**record) for record in cleaned_batch]
            db.bulk_save_objects(db_records)
            db.commit()
            
            logger.info(f"[SIMULASI] Berhasil menyisipkan {batch_size} log baru ke tabel palo_alto_logs.")
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logger.info("Simulator dihentikan oleh pengguna.")
    finally:
        db.close()

if __name__ == "__main__":
    start_simulation(interval_seconds=10, batch_size=5)
```

---

## 🔒 2. Mekanisme Pembedaan Ancaman Baru vs Ancaman Lama (Mengatasi Alert Fatigue)

Dalam Rekayasa Pusat Operasi Keamanan (SOC), memisahkan kejadian baru dari kejadian lama sangatlah krusial agar analis tidak dibanjiri oleh notifikasi yang sama secara berulang-ulang (*alert fatigue*).

Berikut adalah **4 metode standar** yang dapat diimplementasikan di lingkungan lokal:

### 1. Pelacakan Berdasarkan ID Terakhir (`last_seen_id`)
* **Konsep:** Paling ringan dan efisien untuk database relasional. Browser (Frontend) menyimpan variabel berisi ID log terakhir yang berhasil diambil.
* **Alur:**
  1. Halaman dimuat, mengambil data awal dan menyimpan ID terbesar (misal: `lastSeenId = 5231`).
  2. Saat polling berikutnya berjalan, browser memanggil API: `/api/check-new-alerts/?last_id=5231`.
  3. Backend Django mengeksekusi kueri: `SELECT * FROM palo_alto_logs WHERE id > 5231 AND label IN (1, 2, 3)`.
  4. Browser memperbarui nilai `lastSeenId` ke ID tertinggi yang baru saja diterima.

### 2. Penandaan Status Database (`is_notified` / `status` Flag)
* **Konsep:** Sangat berguna jika notifikasi harus dipastikan telah dibaca atau dikonfirmasi oleh analis SOC.
* **Alur:**
  1. Tabel log/alert memiliki kolom tambahan `is_notified` (Boolean, default `False`) atau `status` (String: `'NEW'`, `'ACKNOWLEDGED'`, `'RESOLVED'`).
  2. Ketika model ML mendeteksi ancaman baru, log tersebut disimpan dengan status `'NEW'`.
  3. API pemantau hanya akan mengambil data yang bertatus `'NEW'`.
  4. Begitu notifikasi muncul di layar browser, frontend mengirimkan request balik ke Django untuk mengubah status data tersebut menjadi `'ACKNOWLEDGED'` atau `is_notified = True`.

### 3. Berdasarkan Jendela Waktu Polling (*Timestamp-based filter*)
* **Konsep:** Memfilter data dengan mencatat stempel waktu pengujian.
* **Alur:**
  1. Frontend menyimpan variabel waktu pemeriksaan terakhir: `lastCheckTime = "2026-07-09T13:00:00Z"`.
  2. Setiap panggilan berkala mengirimkan parameter ini: `/api/alerts/?since=lastCheckTime`.
  3. Backend mencari log ancaman yang dibuat setelah stempel waktu tersebut (`log_date > since`).
  4. Waktu `lastCheckTime` diperbarui ke waktu lokal browser saat request terakhir dikirimkan.

### 4. Komunikasi Real-Time Menggunakan WebSockets (Push Event)
* **Konsep:** Menghilangkan overhead dari polling HTTP konvensional. Data didorong (*pushed*) dari server ke browser secara instan.
* **Alur:**
  1. Browser membuka koneksi WebSocket permanen ke Django/FastAPI.
  2. Begitu engine deteksi FastAPI memproses batch data log dan mendeteksi adanya klasifikasi ancaman (`label > 0`), backend langsung menyiarkan (*broadcast*) notifikasi melalui WebSocket.
  3. Browser menerima pesan event secara instan dan memunculkan pop-up alert bahaya. Kejadian masa lalu tidak akan memicu notifikasi baru karena koneksi hanya meneruskan pesan aktif saat itu.
