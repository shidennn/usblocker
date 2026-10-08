# MyLocker — Güvenlik, Performans ve Demo Planı

Her test bir tehdit modeli senaryosuna (S-x) veya hedefe (G-x) bağlıdır. Testler **otomatik** (pytest/CI) ve **manuel/deneysel** (VM içinde, raporlanır) olarak ikiye ayrılır.

> [!IMPORTANT]
> Tüm saldırı ve adli testler **Hyper-V / VirtualBox VM'lerinde** yapılır (anlık görüntü → test → geri al). Sanal USB için VM'e USB passthrough veya VHD'yi çıkarılabilir disk olarak bağlama kullanılır.

---

## 1. Güvenlik testleri

### 1.1 Kriptografik ve format testleri (otomatik)

| ID | Test | Bağlı | Beklenen |
|---|---|---|---|
| T-01 | Admin `takeown` + `icacls /grant` sonrası blob'u okuma; entropi ölçümü (~8 bit/bayt), bilinen "kanarya" dizgisi aranması | S1, G1 | Yalnızca şifreli bayt; kanarya bulunmaz |
| T-02 | Vault'u ikinci VM'e kopyala, USB olmadan aç | S2, S6 | Red |
| T-03 | Yanlış USB (başka MyLocker anahtarı) | — | `key_id` eşleşmez, net hata |
| T-04 | Klonlanmış USB + yanlış parola; deneme başına Argon2id maliyetinin ölçülmesi → kaba kuvvet süre tablosu | S8, S9, G3 | Red; rapor: parola entropisi × maliyet |
| T-05 | **Bit-flip fuzz:** header, meta, her chunk'ın nonce/ct/tag alanında her bayt için tek bit çevir | S10, G2 | %100 tespit; **hiçbir düz metin baytı diske yazılmaz** |
| T-06 | Chunk sıralama, takas, çoğaltma, kesme, ekleme, son chunk'ı silme | S10 | Tespit |
| T-07 | Blob'ları vault içinde yer değiştir; başka vault'tan blob taşı | S11 | Tespit (`vault_id`, manifest `header_hash`) |
| T-08 | Tüm vault'u eski kopyayla değiştir | S12 | Faz 5 öncesi: tespit edilmez (belgelenir); sonrası: uyarı |
| T-09 | Slot KDF parametrelerini düşür; `content_alg` alanını değiştir | S13 | Unwrap/HMAC başarısız; minimum parametre reddi |
| T-10 | **Kötü niyetli vault:** manifestte `..\..\Windows\x`, `C:\x`, `a:stream`, `CON`, `nul.txt`, `a.txt`+`A.txt` | S18 | Çıkarma reddedilir, hedef kök dışına yazma yok |
| T-11 | Kilitleme sırasında alt klasörü junction/symlink ile değiştir (yarış betiği, binlerce deneme) | S19 | Reparse point takip edilmez; kök dışında hiçbir dosya etkilenmez |
| T-12 | Test vektörleri: Python referans ↔ C çekirdek çapraz şifreleme/çözme | ADR-06 | Bayt bayt eşit |

### 1.2 Bellek ve sistem testleri (manuel/deneysel)

| ID | Test | Bağlı | Yöntem | Beklenen |
|---|---|---|---|---|
| T-13 | **Adli karşılaştırma deneyi** (tezin ana deneyi) | G1, R-1 | Benzersiz kanaryalı dosyalar → (a) MVP düzenleme döngüsü, (b) VFS → ham disk imajı → `strings`/Autopsy/PhotoRec ile kanarya araması; HDD vs SSD, TRIM açık/kapalı | (a) kanarya bulunur, (b) bulunmaz (uygulama temp dosyaları hariç) — **ölçülmüş** sonuç |
| T-14 | Vault açıkken süreç bellek dökümü (`procdump -ma`) → VMK aranır; kilitledikten / USB çıkarıldıktan sonra tekrar | G4, S14 | Önce bulunur (beklenen, belgelenir), sonra bulunmaz |
| T-15 | Tam RAM dökümü (VM snapshot / WinPmem) + Volatility ile anahtar araması, kilitleme sonrası | G4 | Bulunmaz |
| T-16 | Hazırda bekletme sonrası `hiberfil.sys` analizi | S20 | Anahtar bulunmaz (uykuda sıfırlama) |
| T-17 | Pagefile analizi (bellek baskısı altında) | S20 | Anahtar bulunmaz |
| T-18 | Agent'ı `taskkill /f`, askıya alma (Process Explorer), DLL enjeksiyonu | S16, G5 | Durağan veri şifreli kalır; enjeksiyon ADV-4 olarak belgelenir |
| T-19 | IPC: başka kullanıcıdan bağlanma, pipe squatting (agent'tan önce aynı adlı pipe oluşturma), hatalı mesaj fuzz'ı | S17 | Red / bağlantı kapatılır / çökme yok |
| T-20 | **Fault injection:** kilitleme/commit sırasında rastgele noktalarda süreci öldür (1000 deneme), VM'in gücünü kes | G5, R-7 | Her seferinde eski ya da yeni tutarlı durum; veri kaybı 0 |
| T-21 | Açık dosya davranışı: Notepad, Notepad++, VS Code, Word, LibreOffice, Paint, Acrobat Reader, VLC ile dosya açıkken USB'yi çıkar | S15, §9 | Uygulama başına tablo: handle, temp dosya, kaydetme davranışı |
| T-22 | Yan kanal envanteri: Search indeksi, thumbcache, Recent/JumpLists, VSS (`vssadmin list shadows`) | §10 | Hangi kanalın ne sızdırdığı tablosu |

### 1.3 Kod düzeyi güvence

| Teknik | Hedef | Araç |
|---|---|---|
| Fuzzing | Header/manifest/blob parser'ları, IPC parser'ı | libFuzzer (clang-cl) veya AFL++ (çekirdek taşınabilir C olduğu için Linux build'de) |
| Sanitizer | Bellek hataları | MSVC AddressSanitizer, UBSan (clang) |
| Statik analiz | C | MSVC `/analyze`, clang-tidy, CodeQL |
| Statik analiz | Python | bandit, mypy |
| Property-based test | "Her girdi için decrypt(encrypt(x)) = x", "her tek bit değişikliği tespit edilir" | hypothesis |
| Kapsam | Hedef: format kodunda ≥ %90 satır kapsamı | coverage.py, OpenCppCoverage |

---

## 2. Performans testleri

### 2.1 Metodoloji
- Donanım ve yazılım sürümleri raporlanır (CPU, AES-NI, disk türü, USB sürümü, Windows build).
- **Sıcak / soğuk cache** ayrı ölçülür (soğuk için RAMMap ile standby list temizliği veya `FILE_FLAG_NO_BUFFERING`).
- Her ölçüm ≥ 10 tekrar; medyan + %95 güven aralığı; uç değerler raporlanır.
- Ham sonuçlar CSV, grafikler Python (matplotlib) ile; betikler repoda (tekrarlanabilirlik).

### 2.2 Testler

| ID | Test | Değişkenler | Soru |
|---|---|---|---|
| P-01 | Şifreleme/çözme verimi | Dosya boyutu 1 KiB … 4 GiB | MB/s, disk mi CPU mu darboğaz? |
| P-02 | Chunk boyutu taraması | 4, 16, 64, 256, 1024 KiB | Verim vs. rastgele erişim maliyeti → 64 KiB seçiminin gerekçesi |
| P-03 | **Python referans vs. C çekirdek vs. ctypes ek yükü** | Aynı iş yükü | "C hız için gerekli mi?" hipotezinin testi (§2.1 mimari belgesi) |
| P-04 | AES-256-GCM vs. XChaCha20-Poly1305 | AES-NI açık (/ VM'de kapalı) | Algoritma seçimi gerekçesi |
| P-05 | Çok sayıda küçük dosya | 10.000 × 4 KiB, 100.000 × 1 KiB | Metadata/manifest maliyeti, depolama ek yükü |
| P-06 | Argon2id parametre taraması | m = 64…1024 MiB, t = 1…6 | Kilit açma süresi vs. saldırgan maliyeti tablosu |
| P-07 | Çok iş parçacıklı şifreleme | 1…N thread | Ölçeklenme |
| P-08 | Agent tepki süresi | Güvenli çıkarma vs. ani çıkarma | Çıkarma → anahtar sıfırlama (ms), → relock tamam (s) |
| P-09 | VFS mikro benchmark | DiskSpd / fio: sıralı/rastgele okuma/yazma, 4K–1M | Ham NTFS vs. MyLocker VFS vs. VeraCrypt hacmi vs. Cryptomator |
| P-10 | VFS makro benchmark | Git clone + derleme, Office dosyası açma/kaydetme, 1 GB kopyalama | Gerçek kullanımda algılanan maliyet |

---

## 3. Demo senaryoları (final sunumu)

| # | Demo | Gösterdiği |
|---|---|---|
| D1 | **"Administrator vs. Vault":** Vault kilitle, USB'yi çıkar; yönetici PowerShell'de `takeown`, `icacls`, dosyayı aç → anlamsız bayt; entropi grafiği; vault'u ikinci VM'e kopyala → açılamaz | G1, S1–S3, S6 |
| D2 | **Manipülasyon:** Hex editörle tek bit değiştir; betikle iki chunk'ı takas et → hangi dosyanın hangi chunk'ında bütünlük hatası olduğu raporu | G2 |
| D3 | **Klonlanmış USB:** USB'nin birebir kopyası + yanlış parola → red; ekranda kaba kuvvet süresi tahmini | G3 |
| D4 | **Canlı USB çıkarma:** Dosya Notepad'de açıkken USB çek → bildirim, bellek taramasında VMK önce var / sonra yok, dosyalar yeniden şifrelendi; (Faz 6) M: sürücüsü kayboldu, uygulama I/O hatası aldı | G4, §9 |
| D5 | **Adli karşılaştırma:** MVP döngüsü sonrası disk imajında kanarya bulundu ↔ VFS sonrası bulunmadı | T-13, R-1 |
| D6 | **Taşınabilirlik:** Aynı USB ile ikinci bilgisayarda (VM) kopyalanmış vault'u aç | Portable |
| D7 | **Kurtarma:** USB "kayboldu" → kurtarma anahtarıyla aç, yeni USB ekle, eski slotu iptal et (ve iptalin sınırını açıkla) | G6, R-5 |
| D8 | **Çökme dayanıklılığı:** Kilitleme sırasında süreci öldür / VM gücünü kes → veri kaybı yok | G5 |
| D9 | (Opsiyonel) **FIDO2:** YubiKey dokunuşu ile açma; anahtar dosyası kopyalanamaz | Faz 5 |
| D10 | (Opsiyonel) **Uygulama kilidi:** Tarayıcı/Telegram profili vault'ta; USB yokken profil erişilemez ve başlatma engellenir | Faz 7 |

---

## 4. Araçlar

| Amaç | Araç |
|---|---|
| Süreç/dosya izleme | Sysinternals Process Monitor, Process Explorer, Handle, Strings, RAMMap, VMMap, ProcDump |
| Debug | WinDbg, Visual Studio debugger |
| Bellek adli bilişimi | WinPmem, Volatility 3 |
| Disk adli bilişimi | FTK Imager, Autopsy, PhotoRec, `strings` |
| Disk benchmark | DiskSpd, fio (Windows), CrystalDiskMark |
| Hex düzenleme | HxD, ImHex (format şablonu yazılabilir → format belgesi için de faydalı) |
| Sanallaştırma | Hyper-V, Windows Sandbox, VirtualBox |
