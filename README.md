# RuiixHacked
RuiixHacked — personal bug bounty toolkit  
**Ringkasan:** skrip Python interaktif (terminal) untuk membantu rekonsiliasi subdomain, port scanning, nuclei scanning, pengecekan takeover, dan scanning data sensitif. Dibuat untuk *ethical hacking* (hanya untuk target yang kamu miliki izin).

---

## Fitur utama
- Menu interaktif berbasis terminal (menggunakan `rich`)
- Recon: memanggil `assetfinder`, `subfinder`, `amass` bila tersedia
- Port scan: integrasi `nmap` (opsional)
- Nuclei scanning: jalankan `nuclei` dengan templates (opsional)
- Sensitive Data Scanner: scan isi URL atau file lokal untuk pola sensitif (API keys, private keys, JWT, dsb)
- Takeover checks: pemeriksaan CNAME sederhana untuk indikasi takeover
- Report generator: gabungkan output menjadi `report.md`
- Tema & warna: default hijau, dapat disesuaikan di file
- Peringatan besar ketika data sensitif terdeteksi (simpan hasilnya di `sensitive_findings.json`)

---

## Persyaratan
- Python 3.8+  
- Disarankan menginstall paket Python:
```bash
pip install --user rich requests dnspython
```
- Tools opsional (untuk fungsi lengkap): `assetfinder`, `subfinder`, `amass`, `nmap`, `nuclei`. Pastikan executable ada di `PATH` bila ingin memanggilnya dari skrip.

---

## Cara instal (cepat)
1. Clone repo (atau download file `RuiixHacked.py`):
```bash
git clone git@github.com:USERNAME/RuiixHacked.git
cd RuiixHacked
```
2. (Opsional) buat virtualenv:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # jika kamu buat file requirements
```

---

## Cara menjalankan
```bash
# jika sudah executable
./RuiixHacked.py

# atau pakai python
python3 RuiixHacked.py
```

Setelah dijalankan, menu interaktif akan muncul. Ikuti pilihan:
- `1` Recon — masukkan domain (contoh: `example.com`). Output akan tersimpan di folder output.
- `2` Port scan — masukkan host/IP.
- `3` Nuclei — masukkan target URL atau path file.
- `4` Sensitive Data Scan — pilih `urls` atau `files`. Masukkan daftar URL/file (koma-separasi atau file path).
- `5` Takeover check — masukkan domain.
- `6` Generate Report — kumpulkan file output menjadi `report.md`.
- `7` Settings — ubah theme / output folder.
- `0` Exit.

Contoh penggunaan sensitive-scan:
```bash
# scan beberapa URL (masukkan di prompt):
https://example.com,https://sub.example.com
# hasil: ./RuiixHacked_output/sensitive/sensitive_findings.json
```

---

## Mengubah tema & folder output
Buka `RuiixHacked.py` di editor lalu cari:
```python
GREEN_THEME = Theme({
    "logo": "bold green",
    ...
})
DEFAULT_OUTPUT = os.path.join(os.getcwd(), "RuiixHacked_output")
```
- Ganti nilai warna (`green`, `bright_green`, `cyan`, dsb) pada `GREEN_THEME`.
- Ubah `DEFAULT_OUTPUT` ke path yang diinginkan (contoh: `/storage/emulated/0/Ruiix_output`).

---

## Menambahkan tools eksternal
Untuk fitur recon/scan yang lengkap, instal:
- `assetfinder` / `subfinder` / `amass` — biasanya via `go install` atau package manager.
- `nmap` — package manager OS (Termux: `pkg install nmap`).
- `nuclei` — ikuti petunjuk instalasi resmi.

Pastikan binary berada di `PATH` agar `subprocess` di skrip dapat menemukannya.

---

## Keamanan & etika (WAJIB)
- **Hanya** jalankan terhadap target yang kamu miliki izin eksplisit untuk diuji.  
- Jika skrip menemukan data sensitif (API key, private key, dsb), **jangan** membagikannya apa adanya. Redact/mask sebelum melaporkan.  
- File sensitif/hasil scan (mis. `sensitive_findings.json`, `response_*.html`, folder output) sudah dimasukkan ke `.gitignore` agar tidak ter-commit.

---

## Contribution & License
Contributions diterima — buat issue atau pull request.  
Lisensi: MIT (atau ganti sesuai preferensi).

---

## Catatan tambahan
- Skrip ini memanggil tools eksternal bila tersedia; jika tidak, fungsi terkait akan melewati langkah itu dan menampilkan pesan.
- Untuk masalah autentikasi GitHub saat push, gunakan SSH key (direkomendasikan) atau Personal Access Token (PAT).

