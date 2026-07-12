# 📊 Laporan Analisis Training CNN-LSTM — Multi-Vendor
**Tanggal Run:** 2026-07-12 11:33:44 — 11:34:18 WIB  
**Dataset:** `datasets/custom/train_long_running_attacks.csv` (13.303 baris)  
**Command:** `python app/ai_engine/training_pipeline.py --vendor ALL --csv datasets/custom/...`

---

## 1. Ringkasan Hasil Training Ketiga Model

| Metrik | Palo Alto | FortiGate | FortiWAF |
|--------|-----------|-----------|----------|
| **Records CSV loaded** | 13.303 | 13.303 | 13.303 |
| **Behavior windows** | 1.440 | 1.440 | 1.440 |
| **3D Sequences (X shape)** | (1348, 3, 8) | (1348, 3, 8) | (1348, 3, 8) |
| **Label distribution** | [320, 330, 0, 698] | [320, 330, 0, 698] | [320, 330, 0, 698] |
| **Val Accuracy (Final)** | **100.00%** | **100.00%** | **100.00%** |
| **Val Loss (Final)** | 9.32e-04 | 7.96e-04 | 9.49e-04 |
| **Training duration** | ~4 detik | ~4 detik | ~4 detik |

### Per-Class Classification Report

| Class | Palo Alto (support) | FortiGate (support) | FortiWAF (support) |
|-------|---------------------|---------------------|---------------------|
| 0: Normal | P=1.00 R=1.00 F1=1.00 (57) | P=1.00 R=1.00 F1=1.00 (58) | P=1.00 R=1.00 F1=1.00 (74) |
| 1: Recon | P=1.00 R=1.00 F1=1.00 (68) | P=1.00 R=1.00 F1=1.00 (72) | P=1.00 R=1.00 F1=1.00 (65) |
| 2: Lateral | **TIDAK MUNCUL** | **TIDAK MUNCUL** | **TIDAK MUNCUL** |
| 3: Beaconing | P=1.00 R=1.00 F1=1.00 (145) | P=1.00 R=1.00 F1=1.00 (140) | P=1.00 R=1.00 F1=1.00 (131) |
| **Total Val Set** | **270** | **270** | **270** |

> **⚠️ TEMUAN KRITIS:** Class 2 (Lateral Movement) sama sekali tidak muncul di semua model — label distribution `[320, 330, 0, 698]` membuktikan tidak ada satu pun sample Class 2 yang terbentuk dari dataset ini.

---

## 2. Mengapa Hasil Bisa Berbeda Antar Run? (3 Sumber Randomness)

### 🎲 Sumber #1 — Random Weight Initialization
Saat `create_cnn_lstm_model()` dipanggil, **semua bobot** Conv1D, LSTM, dan Dense layer di-inisialisasi secara acak menggunakan distribusi default Keras (biasanya `glorot_uniform` untuk Conv1D/Dense, `orthogonal` untuk LSTM recurrent kernel).

```
Epoch 1 Accuracy — Variasi nyata antar run:
  Palo Alto  : 0.3750 → titik start bobot berbeda
  FortiGate  : 0.2812 → lebih "sial" di init
  FortiWAF   : 0.2188 → paling rendah di epoch 1
```

Perbedaan di Epoch 1 inilah "sidik jari" dari random init yang berbeda. Model yang init di titik yang lebih dekat ke optimal → konvergen lebih cepat.

### 🎲 Sumber #2 — Data Shuffling Acak
```python
indices = np.arange(len(X))
np.random.shuffle(indices)  # ← tidak ada seed, pure random
```
Urutan 1.348 sample yang masuk ke setiap batch berbeda setiap run. Ini mempengaruhi urutan update gradient, yang menentukan "jalan" yang ditempuh optimizer menuju minimum.

### 🎲 Sumber #3 — LSTM Dropout (Recurrent Dropout)
Di `model_architecture.py` line 49: `dropout=0.2` pada LSTM. Setiap forward pass saat training, 20% neuron LSTM di-drop secara acak. Ini menyebabkan setiap epoch melihat "versi berbeda" dari jaringan.

### Perbedaan Antar Model (Palo Alto vs FortiGate vs FortiWAF)
Meski dataset yang dibaca **identik persis** (13.303 baris yang sama), perbedaan kecil terjadi karena:
- `log_source` berbeda per vendor → LabelEncoder menghasilkan encoding integer berbeda
- `default_ports` fallback berbeda → nilai port yang di-fallback ketika NaN berbeda
- Kedua hal ini mengubah distribusi fitur kategorik → MinMaxScaler fit ke distribusi yang sedikit berbeda

Itulah kenapa `support` per class di val set berbeda (57 vs 58 vs 74 untuk Normal) — karena **shuffling acak** memotong train/val split di posisi berbeda.

---

## 3. Variabel Yang Berpengaruh ke Kualitas Training

### Tier 1 — SANGAT Berpengaruh 🔴

| Variabel | Lokasi | Efek |
|----------|--------|------|
| **Kualitas & kuantitas data** | Dataset CSV | Data yang buruk/bias → model yang buruk, tidak ada jalan keluarnya |
| **Distribusi label** | `feature_engineering.py` pseudo-labeling | Imbalanced class → model bias ke mayoritas |
| **`EPOCHS`** | `training_pipeline.py` L38 (saat ini: 6) | Terlalu sedikit → underfit; terlalu banyak → overfit |
| **Arsitektur model** | `model_architecture.py` | Kompleksitas model harus match dengan kompleksitas data |

### Tier 2 — Cukup Berpengaruh 🟡

| Variabel | Lokasi | Efek |
|----------|--------|------|
| **`BATCH_SIZE`** | L39 (saat ini: 32) | Kecil = noisier gradients tapi lebih generalize; Besar = smoother tapi butuh lebih banyak memori |
| **Learning Rate** | Implicit di `optimizer="adam"` | Adam default LR=0.001; terlalu tinggi = diverge, terlalu rendah = lambat |
| **`class_weight`** | L295-296 | Sudah balanced; tanpa ini model akan mengabaikan kelas minoritas |
| **`timesteps=3`** | L37 | Konteks temporal yang dibaca model; lebih besar = konteks lebih panjang tapi data lebih sedikit |

### Tier 3 — Berpengaruh Jika Data Besar 🟢

| Variabel | Lokasi | Efek |
|----------|--------|------|
| **Random seed** | Tidak ada | Menentukan reproducibility |
| **Dropout rate** | `model_architecture.py` L49, L60 | Regularisasi; terlalu besar = underfit |
| **Filters Conv1D** | L34 (64 filters) | Kapasitas ekstraksi fitur spasial |
| **LSTM units** | L47 (64 units) | Kapasitas memori temporal |

---

## 4. Kenapa Semua Model Dapat 100% Akurasi?

Ini adalah **red flag** yang perlu dipahami, bukan prestasi!

```
Label Distribution: [320, 330, 0, 698]
Total sequences: 1.348
```

Masalah utamanya:
1. **Class 2 (Lateral Movement) = 0 sample** — model tidak pernah belajar mengenali serangan ini
2. **Data terlalu "bersih" dan dapat diprediksi** — pseudo-labeling berbasis rule heuristic sederhana menghasilkan pola yang sangat deterministik
3. **Dataset untuk val set juga dari distribusi yang sama** — model tidak diuji dengan data yang truly "unseen"
4. **1.348 sample dengan 6 epoch** — model dengan kapasitas 64 Conv1D + 64 LSTM bisa dengan mudah "hafal" 1.078 sample training

**Ini disebut Overfitting yang tersembunyi** — 100% di val set dari distribusi yang sama bukan berarti 100% di data real-world.

---

## 5. Apakah Training Berulang = Lebih Pintar? (Jawaban Lengkap)

### Analogi: Mahasiswa yang Belajar dari Soal yang Sama Terus

Bayangkan kamu belajar untuk ujian tapi soal latihannya cuma 3 tipe soal, dan kunci jawabannya sudah ditentukan pakai rumus sederhana. Seberapa pun sering kamu latihan, kamu tidak akan bisa mengerjakan soal tipe ke-4 yang belum pernah kamu lihat.

### Kapan "Sabar + Hoki" Bisa Berhasil ✅

Training ulang membantu **IF dan hanya IF** masalahnya adalah random initialization yang buruk:
- Model epoch 1 cuma 27% accuracy tapi akhirnya 100% → ini sudah "hoki"
- Kalau epoch 1 cuma 22% (FortiWAF) vs 37% (Palo Alto), berarti FortiWAF lebih butuh hoki

**Strategi "hoki" yang valid:**
```python
# Jalankan N kali, pilih yang terbaik
best_accuracy = 0
for run in range(10):
    model = create_cnn_lstm_model(...)
    model.fit(...)
    acc = evaluate(model, X_val, y_val)
    if acc > best_accuracy:
        best_accuracy = acc
        model.save("best_model.keras")
```

### Kapan "Sabar + Hoki" TIDAK Cukup ❌

| Problem | Solusi Yang Benar |
|---------|-------------------|
| Class 2 tidak muncul (distribusi data) | Tambah data real Lateral Movement ke CSV |
| Dataset terlalu kecil (1.348 samples) | Perbesar dataset atau augmentasi |
| Pseudo-label tidak akurat | Gunakan label manual atau rules yang lebih kompleks |
| Model terlalu sederhana untuk pola kompleks | Tambah layer, filter, atau LSTM units |
| Overfit (100% train, 70% real-world) | Tambah dropout, regularisasi, atau early stopping |

### Kesimpulan Praktis

```
Training ulang (sabar + hoki) ≈ mengganti dadu
Memperbaiki data/arsitektur ≈ mengganti permainan

Yang kedua SELALU lebih efektif untuk improvement jangka panjang.
```

Namun untuk keperluan pengembangan awal (PoC), training ulang 2-3 kali dan memilih model terbaik adalah praktik yang **lumrah dan acceptable**, asalkan kamu sadar keterbatasannya.

---

## 6. Rekomendasi Improvement (Prioritas)

### 🔴 Kritis — Segera
1. **Tambah data Lateral Movement** ke dataset CSV — saat ini Class 2 = 0 sample
2. **Fix pseudo-labeling** — heuristik `zone: trust→trust & unique_ips > 3` tidak ter-trigger di dataset ini, kemungkinan besar karena kolom zone di CSV tidak berformat "Trust/Untrust" yang expected

### 🟡 Penting — Jangka Menengah  
3. **Tambah `random_seed`** untuk reproducibility:
   ```python
   import random, numpy as np, tensorflow as tf
   SEED = 42
   random.seed(SEED); np.random.seed(SEED); tf.random.set_seed(SEED)
   ```
4. **Naikkan EPOCHS** ke 15-20 dengan EarlyStopping
5. **Tambah data nyata** — 1.348 samples sangat kecil untuk model produksi cybersecurity

### 🟢 Opsional — Optimasi Lanjutan
6. **Hyperparameter tuning** — coba `BATCH_SIZE=64`, `LSTM units=128`
7. **Tambah Bidirectional LSTM** untuk tangkap konteks dua arah
8. **k-Fold Cross Validation** sebagai ganti static 80/20 split
