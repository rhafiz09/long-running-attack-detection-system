# REQUIREMENT TUGAS AKHIR "MENDETEKSI SERANGAN LONG RUNNING ATTACK MENGGUNAKAN CNN-LSTM TERHADAP TRAFFIC JARINGAN"

## 1. Latar Belakang

### 1.1 Masalah Utama
* **1.1.1** firewall perusahaan belum bisa mendeteksi serangan jangka Panjang (Long Running Attack).
* **1.1.2** adanya kegagalan dalam mendeteksi serangan (Miss Alarm).
* **1.1.3** masih terjadi salah deteksi kepada event normal di anggap serangan (False Positive)

### 1.2 Solusi
* **1.2.1** menggunakan deep Learning Model HYBRID CNN-LSTM berfungsi mendeteksi pola serangan jangka Panjang, mengurangi kesalahan deteksi false positif dan false negative, menganalisis data log secara lebih akurat dan real-time.
* **1.2.2** membuat chatbot Al Assistant untuk membantu menganalisis serangan, menjelaskan isi log serangan secara otomatis, memberikan insight jenis serangan(contoh nama firewall, IP, jenis serangan), sekaligus memberikan rekomendasi Tindakan mitigasi.

---

## 2. Alur System

### 2.1 Penjelasan Alur Sistem:

*(Diagram Alur Sistem)*
API -> Config Get data (Backend) -> Parsing -> Database -> Integrasi (backend) -> Front-end
Dataset Raw -> Config flow data (Backend) -> Preprocessing -> Model

Alur sistem ini dimulai dari data mentah yang akan di proses (raw data), lalu data itu dibagikan lewat API. Nah, dari pipeline kita akan ambil data tersebut secara otomatis setiap 5 menit sekali. Data yang masih mentah itu kemudian masuk ke proses pipeline, yaitu tahap pemisahan data menjadi 3 bagian berdasarkan jenis firewall. Setelah dipisah, data langsung disimpan ke dalam database sebagai tempat penyimpanan utama. Dari database ini, backend akan ambil lagi datanya setiap 5 menit untuk preprocessing. Di sini ada bagian config flow data di backend yang mengatur data mana saja yang di proses model mana.

Selanjutnya, data masuk ke tahap preprocessing. Di tahap ini, data diolah supaya benar-benar siap digunakan oleh model, misalnya dengan normalisasi atau penyesuaian format. Ada pula penambahan Feature Engineering, setelah penambahan FE, data akan di kirim ke database untuk update data lama Setelah itu, data dikirim ke model AI (CNN-LSTM) untuk dianalisis, apakah ada serangan atau aktivitas yang mencurigakan.

Hasil dari model ini kemudian dikirim kembali dan disimpan ke database. Lalu dari database, backend akan mengambil hasil tersebut dan mengirimkannya ke frontend melalui proses integrasi. Terakhir, hasilnya ditampilkan ke dashboard supaya user bisa melihat monitoring secara langsung. Dan semua proses ini berjalan terus setiap 5 menit, jadi sistem selalu update dan bisa mendeteksi kondisi terbaru secara real-time.

### 2.2 Proses Alur:

1. **Source → API**
   Data mentah (raw dataset) dibagikan melalui API.
2. **API Pipeline (Config Get Data)**
   Backend mengambil data dari API setiap 5 menit.
3. **Pemisahan Data Sesuai Jenis Log (Pipeline)**
   Data mentah akan di dipotong menjadi 3 bagian sesuai jenis firewall.
4. **Pipeline ke Database**
   Data hasil Pipeline disimpan sebagai data utama.
5. **Ambil Data dari Database ke Backend (Loop 5 Menit)**
   Sistem mengambil data dari database ke backend untuk di di preprocessing
6. **Parsing (Pembersihan Data Awal)**
   Data mentah dibersihkan (filter noise, format ulang).
7. **Preprocessing**
   Data diolah lebih dalam (normalisasi, feature Enginering).
8. **Update Data Database**
   Setelah penambahan Feature Engineering data akan di update ke database untuk penambahan informasi yang akan di show ke frontend
9. **Encoding**
   Data diolah menjadi angka dari 0-1.
10. **Model (CNN-LSTM)**
    Data dianalisis untuk:
    * Deteksi serangan Long Running Attack
    * Mengurangi miss detection
    * Mengurangi false alarm
11. **Hasil Model Database**
    Output model (hasil deteksi) disimpan kembali.
12. **Integrasi Frond-end (System)**
    Frond-end (System) mengambil hasil dari database.
13. **Frontend (Dashboard)**
    Data ditampilkan ke user dalam bentuk monitoring.
14. **Repeat (Setiap 5 Menit)**
    Sistem mengulang proses dari awal untuk update data terbaru.

---

## 3. TOOL

### 3.1 AI
* `tensorflow==2.16.1`
* `keras==3.13.2`
* `numpy==1.26.4`
* `pandas==2.2.3`
* `scikit-learn==1.7.0`

### 3.2 Frondend
* `Django==5.2.15`
* `asgiref==3.11.1`
* `sqlparse==0.5.5`
* `psycopg2-binary==2.9.12`
* `python-dotenv==1.2.2`

### 3.3 PIPELINE
* `psycopg2-binary==2.9.9`
* `requests==2.31.0`
* `flask==3.0.0`
* `flask-cors==4.0.0`
* `fastapi==0.109.0`
* `uvicorn==0.25.0`
* `pydantic==2.5.3`

---

## 4. Feature Project

### 4.1 AI

**2.1.1 Memiliki kemampuan mendeteksi serangan long running attack yaitu:**
* **2.1.1.1 Internal Reconnaissance** = serangan yang dilakukan hacker Ketika sudah memiliki akses ke internal. serangan ini bertujuan untuk mapping jaringan agar bisa mengumpulkan informasi, kerentanan, dan lainnya. Serangan ini juga akan diikuti oleh lateral movement.
* **2.1.1.2 Lateral Movement** = Gerakan penyerang Ketika berpindah dari 1 jaringan (IP) ke jaringan lainnya (IP). Gerakan ini pasti terjadi Ketika Internal Reconnaissance.
* **2.1.1.3 Beaconning** = Serangan yang dilakukan untuk mengirim informasi dari dalam ke luar, biasanya memiliki pola waktu.

**2.1.2 Memiliki Preprocessing terdiri dari:**
* **2.1.2.1 Incremental Windowing** (hitungan mulai dari IP terlihat hingga waktu yang ditentukan, yang berfungsi untuk mendeteksi serangan dengan batas minimum, dan di bentuk dalam kolom mandiri) dari setiap serangan Long Running Attack.
* **2.1.2.2 Labeling Attack** untuk memberikan label terhadap attack dilihat dari batas yang ditentukan dari incremental windowing.
* **2.1.2.3 Cleaning** dengan membuat PY pembersihan dataset
* **2.1.2.4 Encoding**, jika nama seperti IP atau port menggunakan embedding, jika hitungan biasa menggunakan rumus tertentu, dan untuk label menggunakan one hot system.

**2.1.3 Memiliki Dataset yang akan di pakai untuk training hingga inference testing, dengan jenis dataset yang dipakai:**
* **2.1.3.1 Dataset Environment** yaitu data asli yang akan di pakai untuk di prediksi, data ini akan masuk selang 5 menit sekali.
* **2.1.3.2 Dataset Public** yaitu dataset dari internet dengan karakteristik tertentu yang akan di pakai untuk testing.
* **2.1.3.3 Dataset Custom** yaitu Dataset untuk training yang di buat berdasarkan serangan yang terjadi di dunia nyata.

### 4.2 Dataset

**4.2.1 Dataset Environment** adalah dataset dengan 3 jenis log, dengan banyak karakteristik, tetapi semua log hanya bisa di pakai 5 kolom:
* **4.2.1.1** Log terdiri dari 3 jenis yaitu: Palo Alto, FortiGate, dan FortiWAF.
* **4.2.1.2** Log fortigate terdiri dari banyak firewall dari berbagai daerah.
* **4.2.1.3** Log dibagi juga dari zone impacted dan zone origin
* **4.2.1.4** Kolom log yang bisa kita pake Adalah: IP, Port, Zone, Log Date, Log Name

**4.2.2 Dataset Public** adalah dataset yang digunakan untuk testing, fungsinya cek apakah akurasi nya Al bagus atau tidak. Dataset ini harus memiliki karakteristik:
* **4.2.2.1** Minimal dataset 5 tahun kebelakan.
* **4.2.2.2** Dataset nya adalah dataset log jaringan atau log firewall.
* **4.2.2.3** Bisa di gunakan menyesuaikan dataset environment.

**4.2.3 Dataset Custom** adalah dataset yang di buat untuk trainig Al dengan memanfaatkan kejadian nyata untuk memberikan pengetahuan yang baik pada Al

### 4.3 Frond-end

**4.3.1 Halaman Login:**
Halaman login sudah diatur dan setting yang bisa akses hanya nama staff dan admin yang sudah terdaftar didatabase, untuk mencegah akses dari pihak luar. jika staff yang login langsung diarahkan ke halaman sistem monitoring dan halaman chatboat Al, jika admin yang login maka akan diarahkan kehalaman khusus admin, halaman sistem monitoring, dan halaman chatboat Al.

**4.3.2 Halaman Admin:**
Ketika admin login diarahkan ke halaman ini yang mana admin memiliki akses penuh dihalaman ini, dihalaman ini admin dapat melakukan mengelola akun data user seperti mendaftarkan nama user, melihat dan edit data user jika diperlukan ada perubahan, mengatur status akun, mengatur hak akses, admin juga bisa aksi dan kontrol akun user. admin juga bisa akses halaman sistem monitoring dan halaman chatboat Al.

**4.3.3 Halaman Sistem Monitoring:**
Halaman ini menampilkan monitoring serangan secara real-time, dengan komponen utama:

1. **Line Chart (Traffic Monitoring)**
   * Menampilkan jumlah serangan berdasarkan waktu
   * Data bersifat real-time (update berkala)
   * Tersedia filter waktu: 30 detik, 1 menit, 30 menit, 1 jam, 12 jam, 24 jam
   * Fungsi: melihat tren dan lonjakan serangan

2. **Tabel Log Berdasarkan Sumber Firewall**
   Terdapat 3 tabel utama:
   * Palo Alto Logs
   * FortiWAF Logs
   * FortiGate Logs
   
   Fitur:
   * Menampilkan daftar IP yang terdeteksi
   * Klasifikasi berdasarkan jenis firewall
   
   Fungsi:
   * Filter waktu (sama seperti chart)
   * Jika chart hanya menunjukkan jumlah serangan, maka tabel ini digunakan untuk melihat detail IP & log serangan

3. **Status Keamanan (Summary Card)**
   Menampilkan informasi seperti:
   * Jumlah serangan (contoh: DDoS Attack)
   * Jumlah IP yang diblokir
   * Persentase mitigasi sistem
   
   Fungsi: Memberikan ringkasan cepat kondisi jaringan

**4.3.4 Halaman Chatbot AI:**
Fungsi:
* Menganalisis log serangan secara otomatis
* Menampilkan Output Al:
  * IP target
  * Jenis serangan (contoh: DDoS Flood)
  * Kecepatan serangan
  * Error log sistem
  * Penjelasan dalam bahasa yang mudah dipahami
* Rekomendasi tindakan, seperti:
  * Aktivasi SYN Flood Protection
  * Blocking IP
  * Eskalasi ke tim SOC
* Tujuan: Mengurangi beban analisis manual, Membantu pengambilan keputusan secara cepat.

### 4.4 Pipeline

**4.4.1 Memiliki kemampuan mengakuisisi data dari berbagai sumber dengan karakteristik:**
* **4.4.1.1 Data Source Integration**
  * API Integration - Sistem mampu terhubung dengan sumber data melalui REST API (GET API) dengan parameter count dan offset_range
  * API Parameters - Mengambil data dengan parameter: Count (disesuaikan dengan data event per 5 menit), offset_range - Rentang waktu data yang diambil
  * Real-time Data Acquisition - Data diakuisisi setiap 5 menit sekali dari Source API
  * Raw Data Ingestion - Data mentah (raw dataset) diambil dari API dalam format JSON dan diteruskan ke pipeline untuk diproses lebih lanjut

**4.4.2 Memiliki kemampuan pemrosesan data sebelum masuk ke database:**
* **4.4.2.1 Data Splitting & Classification (Pre-Database)**
  * Data Splitting - Data mentah dari API dipisahkan menjadi 3 kategori berdasarkan jenis log/firewall: Palo Alto (1 device), Fortinet/FortiGate (7 device), FortiWAF (1 device)
  * Vendor Classification (Early Classification) - Sistem melakukan klasifikasi vendor sebelum data disimpan ke database. Classification Rules: "Palo Alto" pada log_source → Palo Alto, "WAF" pada log_source_host → FortiWAF, "FortiAnalyzer" pada log_source → Fortinet/FortiGate
  * Vendor Tagging - Setiap event diberi label vendor sebelum masuk ke database
  * Routing Decision - Klasifikasi menentukan kemana data akan dialokasikan di database (tabel/collection terpisah per vendor)
* **4.4.2.2 Data Ingestion & Processing**
  * Automatic Schema Management - Sistem memiliki kemampuan untuk secara otomatis mendeteksi dan menambahkan kolom yang hilang pada database (112+ kolom)
  * Data Type Conversion - Melakukan konversi tipe data secara otomatis: Empty string → NULL untuk kolom numerik dan INET, Scientific notation (1.78E+12) → Timestamp, String kosong pada kolom IP → NULL
  * Deduplication - Mencegah duplikasi data berdasarkan log_sequence_number
* **4.4.2.3 Data Validation & Quality Control**
  * Data Validation - Memvalidasi data sebelum disimpan ke database: Format validation, Mandatory field validation, Data integrity check
* **4.4.2.4 Data Storage to Database**
  * Database Insertion - Data yang sudah diklasifikasi dan dipisahkan disimpan ke database sesuai dengan routing decision (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`)
  * Batch Insertion - Data disimpan secara batch untuk optimasi performa
  * Transaction Management - Menggunakan transaksi database untuk menjamin integritas data
* **4.4.2.5 Post-Storage Data Access**
  * Immediate Data Retrieval - Setelah data berhasil disimpan ke database, backend dapat langsung mengakses dan mengambil data tersebut tanpa harus menunggu interval 5 menit berikutnya
  * Event-Driven Trigger - Sistem menggunakan mekanisme event-driven atau callback untuk memberi notifikasi ke backend bahwa data baru telah tersedia
  * On-Demand Fetch - Backend dapat mengambil data dari database otomatis setelah data tersedia, tidak terikat dengan jadwal 5 menit
  * Data Readiness - Data dianggap siap pakai (ready to use) untuk backend setelah proses insert ke database selesai

### 4.5 Database

**4.5.1 Memiliki kemampuan menyimpan dan mengelola data hasil pipeline menggunakan PostgreSQL dengan karakteristik:**
* **4.5.1.1 Database Architecture**
  * RDBMS Selection - Sistem menggunakan PostgreSQL sebagai database utama untuk menyimpan seluruh data hasil pipeline
* **4.5.1.2 Database Schema Design**
  * Table Structure - Tabel terpisah berdasarkan klasifikasi vendor (`palo_alto_logs`, `fortinet_logs`, `fortiwaf_logs`)
  * Schema Consistency - Setiap tabel memiliki struktur yang konsisten dengan 112+ kolom sesuai dengan skema data

**4.5.2 Memiliki kemampuan integrasi dengan sistem pipeline dan backend:**
* **4.5.2.1 Database Integration with Pipeline**
  * Data Ingestion - Pipeline melakukan insert data ke PostgreSQL setelah proses: Data splitting, Vendor classification, Data type conversion
* **4.5.2.2 Database Integration with Backend**
  * Data Retrieval - Backend mengambil data langsung dari PostgreSQL setelah data tersedia

### 4.6 Dummy API
Dummy API adalah dummy yang akan di gunakan untuk testing project. Dengan mengirimkan data berbentuk json dan akan di tarik oleh pipeline.

### 4.7 Cyber Security
**4.7.1 Menambahkan keamanan di bagian frond-end. Dengan keamanan yaitu:**
* **4.7.1.1** Priority Security Measure What It Does:
* **4.7.1.2** Critical Password Hashing Encrypts passwords
* **4.7.1.3** Critical SQL Injection Prevention Prevents data theft
* **4.7.1.4** Critical CSRF Protection Prevents session hijacking
* **4.7.1.5** High Session Security Prevents session theft
* **4.7.1.6** High Rate Limiting Prevents brute force
* **4.7.1.7** High Input Validation Prevents injection
* **4.7.1.8** Medium CORS Configuration Prevents data theft
* **4.7.1.9** Medium API Authentication Controls data access
* **4.7.1.10** Medium Audit Logging Tracks activity
* **4.7.1.11** Medium DB Credentials Protects database
* **4.7.1.12** Best Practice Security Headers Browser protection
* **4.7.1.13** Best Practice Database Backup Prevents data loss

---

## 5. Logika Al

### 5.1 Model
**5.1.1 Deep Learning yang di pakai:**
* **5.1.1.1** kita menggunakan CNN-LSTM karena model ini dapat melihat pola serangan jangka panjang di tambah bisa melihat pola local untuk serangan bertype burst.

**5.1.2 Jumlah Model:**
* **5.1.2.1** kita menggunakan 3 model utama dipisah berdasarkan Firewall nya, karena setiap firewall memiliki environment masing masing.

### 5.2 Feature Engineering (FE)
**5.2.1 Internal Reconnaissance:**
* **5.2.1.1** FE ini memiliki rumus hitung setiap IP internal yang scanning port IP internal lain dan melakukan Host scanning di internal.
* **5.2.1.2** perhitungannya bisa 30 detik dan/atau 1 jam atau berapapun yang mampu mendeteksi serangan jangka panjang dan jangka pendek.
* **5.2.1.3** Studi kasus: jika misalkan perhitungan nya hanya 30 menit, batas serang nya 10 host/port, dalam 30 menit attacker menyerang di menit 25 dan melanjutkan menit berikutnya tetapi di 30 menit berikutnya dia tetap tidak terdeteksi karena belum melewati batas, padahal jika dihitung mulai dari penyerangan, seharusnya akan terdeteksi.

**5.2.2 Lateral Movement**
* **5.2.3.1** FE ini adalah lanjutan dari Internal Reconnaissance. Ketika attacker selesai host scanning + port scanning, dan menemukan celah (vuln) maka dia akan berpindah device/jaringan.
* **5.2.3.2** Rumus nya adalah IP internal yang terdeteksi/berpotensi melakukan Internal Reconnaisance akan di catat host yang telah di akses, dan jika salah satu host tersebut juga melakuan hal yang sama (mapping jaringanl maka akan di anggap telah terjadi Lateral Movement

**5.2.3 Beaconing**
* **5.2.3.1** jenis serangan ketika attacker sudah ada di internal dan akan mengirimkan informasi dari dalam ke luar.
* **5.2.3.2** Biasanya bot dari beaconing ini akan menghubungi jaringan luar dengan waktu yang berpola (bisa di cek dengan interval)

### 5.3 Labeling
* **5.3.1 Internal Reconnaissance** = batas ditentukannya suatu IP internal terdeteksi tidak boleh static, harus mengikuti pergerakan dan alur traffic global, tetapi harus juga bisa mempertahankan deteksi apabila attacker benar benar main aman dan lambat agar tidak terdeteksi.
* **5.3.2 Lateral Movement** = batas nya hanya jika salah satu target dari internal reconn yang berpotensi / terdeteksi pada suatu IP, juga melakukan interna reconn
* **5.3.3 Beaconing** = interval yang kecil tetapi harus didasari banyak kasus nyata.

### 5.4 Dataset
**5.4.1 Kolom** = kita hanya menggunakan 5 kolom yaitu:
* **5.4.1.1** IP, IP impacted yaitu IP tujuan dan IP origin yaitu IP sumber
* **5.4.1.2** Port port dari IP Impacted
* **5.4.1.3** Zone, Zone juga ada berdasarkan tujuan dan sumber
* **5.4.1.4** Log Date, ini adalah waktu munculnya event
* **5.4.1.5** Log Source, ini adalah nama/entitas firewall

**5.4.2 Jenis** = dataset nya di bagi jadi 3 jenis firewall, yaitu:
* **5.4.2.1** Palo Alto: Firewall server (utama)
* **5.4.2.2** FortiGate: Firewall kantor cabang
* **5.4.2.3** FortiWAF: Firewall dari Website

---

## 6. Output Project

* Website monitoring keamanan jaringan berbasis Al
* Menampilkan:
  * Data serangan secara real-time
  * Detail log serangan
  * Analisis otomatis dari Al
* Membantu tim SOC dalam:
  * Mendeteksi serangan lebih akurat
  * Mengurangi false alarm
  * Mempercepat respon terhadap ancaman