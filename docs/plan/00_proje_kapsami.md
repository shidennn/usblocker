# MyLocker — Proje Kapsamı ve Belge İndeksi

## Belge seti

| # | Belge | İçerik |
|---|---|---|
| 00 | **Bu belge** | Kapsam, başarı kriterleri, terminoloji |
| 01 | [01_tehdit_modeli.md](./01_tehdit_modeli.md) | Varlıklar, saldırganlar, hedefler, "Admin açamaz" iddiasının kesin tanımı, açık dosya problemi |
| 02 | [02_mimari_ve_kriptografi.md](./02_mimari_ve_kriptografi.md) | Mimari, Python/C dağılımı, USB anahtarı, kripto, format, agent, VFS, uygulama kilidi, ADR'ler |
| 03 | [03_test_ve_demo_plani.md](./03_test_ve_demo_plani.md) | Güvenlik testleri (T-xx), performans testleri (P-xx), demolar (D-x) |
| 04 | [04_ogrenme_ve_literatur.md](./04_ogrenme_ve_literatur.md) | Windows API'leri, benzer sistemler, literatür |
| 05 | [05_fazlar_ve_mvp.md](./05_fazlar_ve_mvp.md) | MVP tanımı, fazlar, çıktılar, çıkış kriterleri, takvim |
| 06 | [06_repo_ve_gelistirme_kurallari.md](./06_repo_ve_gelistirme_kurallari.md) | Repo yapısı, kodlama kuralları, güvenli kodlama kontrol listesi, Faz 0 adımları |

---

## 1. Tek cümlelik tanım

> **MyLocker**, Windows üzerinde seçilen klasörleri, anahtar materyali taşınabilir bir USB bellekte (isteğe bağlı olarak parola ile birlikte) bulunan, standart kimlik doğrulamalı şifreleme (AES-256-GCM) ile koruyan; USB bağlı değilken host'un Administrator'ı dahil hiçbir yerel kullanıcının veriyi okuyamamasını **kriptografik olarak** garanti eden ve USB çıkarıldığında açık oturumu otomatik olarak kapatmaya çalışan taşınabilir bir şifreleme sistemidir.

## 2. Kesin kapsam

### 2.1 Kapsam dahili (tez teslimi için zorunlu)
| ID | Özellik | Faz |
|---|---|---|
| K1 | USB anahtar dosyası üretimi ve keşfi | 1–3 |
| K2 | Klasör vault'u: oluştur / kilitle / aç / listele / tek dosya çıkar | 1–3 |
| K3 | AES-256-GCM chunk'lı şifreleme, dosya adı + yapı gizleme, bütünlük | 1–2 |
| K4 | 2FA (USB + parola, Argon2id) varsayılan; yalnız-USB modu | 1 |
| K5 | Kurtarma anahtarı, ek USB slotu, parola değiştirme | 3 |
| K6 | C çekirdek (`mlcore.dll`) + Python GUI/CLI, diferansiyel testli | 2–3 |
| K7 | Atomik commit, çökme dayanıklılığı | 1–3 |
| K8 | USB-takip eden agent: çıkarma/uyku/kilitte relock, anahtar sıfırlama, açık uygulamaları kapatma | 4 |
| K9 | Güvenli IPC (named pipe) | 4 |
| K10 | Tehdit modeli, saldırı testleri, adli karşılaştırma deneyi, performans ölçümleri | Sürekli + 8 |
| K11 | Taşınabilir paket (USB'den kurulumsuz çalışma) | 3 |

### 2.2 Kapsam dahili — hedef (zaman yeterse, tezi güçlendirir)
| ID | Özellik | Faz |
|---|---|---|
| H1 | **WinFsp tabanlı şeffaf sanal sürücü** (salt-okunur → okuma-yazma) | 6 |
| H2 | Rollback tespiti (USB'de epoch) | 5 |
| H3 | FIDO2 `hmac-secret` anahtar sağlayıcı | 5 |

### 2.3 Opsiyonel / gelecek çalışma
| ID | Özellik |
|---|---|
| O1 | Uygulama kilitleme (uygulama verisi vault'u + başlatma politikası) — Faz 7 |
| O2 | Minifilter tabanlı izolasyon filtresi (yalnızca araştırma/tasarım bölümü) |
| O3 | Blob boyutu dolgulama (Padmé) |
| O4 | Çoklu kullanıcı / paylaşım |

### 2.4 Açıkça kapsam dışı
- Tam disk / sistem bölümü şifreleme (BitLocker'ın alanı).
- Kernel sürücüsü geliştirme (WinFsp hazır imzalı sürücü kullanılır).
- macOS/Linux istemcisi (ancak `mlcore` taşınabilir C olarak yazılır → fuzzing Linux'ta yapılabilir).
- Bulut senkronizasyonu, ağ paylaşımı.
- Tehdit modelindeki NG1–NG9.

## 3. Öncelik sırası (kullanıcı tarafından belirlendi)
1. Güvenlik modeli → 2. Kriptografik doğruluk → 3. Çalışan prototip → 4. Windows entegrasyonu → 5. Threat model ve saldırı testleri → 6. Kullanıcı deneyimi

**Çatışma kuralı:** Bir özellik kriptografik doğruluğu veya veri kaybetmeme garantisini (G5) riske atıyorsa, o fazda ertelenir.

## 4. Başarı kriterleri (tez savunmasında ölçülebilir)

| # | Kriter | Kanıt |
|---|---|---|
| B1 | USB yokken admin hiçbir kilitli dosyanın içeriğini/adını elde edemez | D1, T-01–T-03 |
| B2 | Her tek bit / chunk manipülasyonu tespit edilir, doğrulanmamış veri diske yazılmaz | T-05–T-07 (%100) |
| B3 | 1000 rastgele çökmede veri kaybı 0 | T-20 |
| B4 | Python referans ↔ C çekirdek bayt bayt uyumlu | T-12 |
| B5 | Kilitleme sonrası bellek dökümlerinde anahtar bulunmaz | T-14–T-16 |
| B6 | USB çıkarmasından anahtar sıfırlamasına < 1 s (güvenli çıkarmada çıkarmadan önce) | P-08 |
| B7 | Şifreleme verimi, disk veriminin darboğaz olduğu seviyede (SSD'de ≥ birkaç yüz MB/s) | P-01 |
| B8 | Parser fuzzing ≥ 24 saat, çökme 0 | §1.3 test planı |
| B9 | Tehdit modelindeki her senaryo için "korunur / kısmi / kapsam dışı" + kanıt veya gerekçe | 01 belgesi + tez |

## 5. Terminoloji

| Terim | Anlam |
|---|---|
| **Vault** | Korunan klasörün şifreli hali (`.mylocker\` dizini) |
| **K_usb** | USB'deki 256-bit kök sır |
| **VMK** | Vault Master Key — vault başına rastgele, slotlarla sarılı |
| **KEK** | Key Encryption Key — VMK'yı saran, faktörlerden türetilen anahtar |
| **Slot** | VMK'nın bir anahtar sağlayıcıyla sarılmış kopyası |
| **FK** | File Key — dosya başına HKDF ile türetilen anahtar |
| **Blob** | Tek bir dosyanın şifreli hali (`.mlf`) |
| **Manifest** | Şifreli dosya ağacı (yol → blob eşlemesi) |
| **Commit** | Vault durumunun atomik olarak güncellenmesi |
| **Relock** | Açık oturumun kapatılıp çalışma kopyalarının yeniden şifrelenmesi |
| **Çalışma kopyası** | MVP'de kullanıcının düzenlemesi için diske açılan düz metin dosya |
