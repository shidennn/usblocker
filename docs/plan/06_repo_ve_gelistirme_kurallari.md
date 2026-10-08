# MyLocker — Repo Yapısı ve Geliştirme Kuralları

## 1. Repo yapısı (`c:\Projects\usblocker`)

```text
usblocker/
├── docs/
│   ├── spec/format-v1.md          ← bayt düzeyinde format (Faz 0)
│   ├── threat-model.md            ← 01 belgesinin repodaki yaşayan kopyası
│   ├── adr/0001-crypto-not-acl.md ← her ADR ayrı dosya
│   └── thesis/                    ← bölüm taslakları
├── mlref/                         ← Python referans implementasyon (Faz 1)
│   ├── keyfile.py  kdf.py  blob.py  vault.py  manifest.py  pathsafe.py  cli.py
├── mlcore/                        ← C çekirdek (Faz 2)
│   ├── include/mlcore.h
│   ├── src/  secmem.c keyfile.c kdf.c blob.c vault.c manifest.c fsutil_win.c errors.c
│   ├── fuzz/ fuzz_header.c fuzz_blob.c fuzz_manifest.c
│   ├── tests/                     ← C birim testleri
│   └── CMakeLists.txt
├── mlagent/                       ← Agent (Faz 4)
│   └── src/ main.c devnotify.c power.c ipc.c policy.c rm.c
├── mlvfs/                         ← WinFsp (Faz 6)
├── app/                           ← Python GUI/CLI (Faz 3)
│   ├── mylocker/ gui/ cli.py core_binding.py usbdiscovery.py prechecks.py
├── tests/
│   ├── vectors/                   ← deterministik test vektörleri (JSON)
│   ├── test_ref_*.py              ← referans testleri
│   ├── test_diff_c_vs_py.py       ← T-12
│   ├── attacks/                   ← T-xx saldırı betikleri
│   └── perf/                      ← P-xx benchmark betikleri + analiz notebook'ları
├── packaging/                     ← portable USB paketi üretimi
├── vcpkg.json  CMakeLists.txt  pyproject.toml
└── .github/workflows/ci.yml
```

## 2. Araçlar ve bağımlılıklar

| Alan | Seçim | Not |
|---|---|---|
| C derleyici | MSVC (VS 2022) + clang-cl (fuzz) | `/W4 /WX /sdl /guard:cf /Qspectre`, `/DYNAMICBASE /HIGHENTROPYVA /CETCOMPAT` |
| Build | CMake + vcpkg manifest modu | `libsodium` statik bağlanır → tek DLL, DLL hijacking yüzeyi azalır |
| Python | 3.12+ | `cryptography`, `argon2-cffi`, `cbor2`, `pytest`, `hypothesis` |
| CBOR | Python: `cbor2`; C: tinycbor veya sınırlı alt küme | Alternatif: manifest için sabit TLV formatı (daha basit parser → daha az fuzz yüzeyi). **Faz 0'da karar verilecek.** |
| GUI | Tkinter (MVP) → PySide6 (opsiyonel) | |

## 3. Güvenli kodlama kontrol listesi (her PR'da)

### Kriptografi
- [ ] Hiçbir primitive elle yazılmadı; yalnızca libsodium / `cryptography`
- [ ] Her anahtar yeni CSPRNG çıktısı veya etiketli HKDF türetmesi; etiketler `docs/spec`'teki listede
- [ ] Nonce'lar rastgele; aynı anahtarla tekrar kullanım olası değil
- [ ] Doğrulanmamış düz metin **asla** çağırana / diske verilmiyor (chunk doğrulandıktan sonra yazılıyor; dosya sonuna kadar doğrulanmadan hedef adla yeniden adlandırılmıyor)
- [ ] MAC/tag karşılaştırmaları sabit zamanlı (`sodium_memcmp`, `hmac.compare_digest`)
- [ ] Hata mesajları "yanlış parola" ile "bozuk dosya"yı ayırt ediyor ama oracle oluşturmuyor

### Bellek (C)
- [ ] Anahtar materyali yalnızca `ml_secbuf` (sodium_malloc) içinde
- [ ] Yığında anahtar kopyası yok; zorunluysa fonksiyon çıkışında `sodium_memzero`
- [ ] Her hata yolunda sıfırlama (`goto cleanup` deseni)
- [ ] Python'a hiçbir anahtar baytı dönmüyor

### Dosya sistemi
- [ ] Tüm yollar `\\?\` ile mutlak; kullanıcı girdisi `pathsafe` doğrulamasından geçti
- [ ] Reparse point'ler takip edilmiyor
- [ ] Yazmalar: `.tmp` → `FlushFileBuffers` → atomik rename/replace
- [ ] Düz metin silme, commit başarıyla tamamlandıktan **sonra**

### Parser'lar
- [ ] Her uzunluk alanı üst sınırla kontrol ediliyor, tamsayı taşması kontrolü var
- [ ] Bilinmeyen sürüm/alg/bayrak → red (fail-closed)
- [ ] Yeni parser kodu için fuzz hedefi eklendi

### IPC (Faz 4)
- [ ] Pipe DACL + `PIPE_REJECT_REMOTE_CLIENTS` + istemci PID/imaj doğrulaması
- [ ] Mesaj boyutu sınırı; hatalı mesaj → bağlantı kapat

## 4. Hata yönetimi ilkeleri
1. **Fail-closed:** Şüphede red. Kısmi çözme sonucu kullanıcıya verilmez.
2. **Veri kaybetmeme > her şey:** Düz metin, şifreli karşılığı doğrulanıp commit edilmeden silinmez.
3. **Teşhis edilebilirlik:** Bütünlük hatası "dosya X, chunk N, beklenen/bulunan" düzeyinde raporlanır (sır içermeden).
4. Hata kodları C'de `enum ml_err`, Python'da istisna sınıflarına eşlenir.

## 5. Test ve CI

| Katman | Ne zaman | İçerik |
|---|---|---|
| Her commit (CI) | dakikalar | pytest (referans + vektörler), C birim testleri, ASan build, diferansiyel test, 60 sn fuzz smoke |
| Gece / manuel | saatler | Uzun fuzz, fault injection (T-20), benchmark |
| Faz sonu (VM) | manuel | T-13–T-22 deneysel testler, raporlanır |

## 6. Faz 0 — somut ilk adımlar

1. `git init`, yukarıdaki iskelet, `pyproject.toml`, `vcpkg.json` (`libsodium`), kök `CMakeLists.txt`.
2. `docs/spec/format-v1.md`: 02 belgesi §3.4, §5'teki tabloları bayt ofsetleriyle, endianness (little-endian), tüm HKDF `info` etiketleri ve AAD yapıları ile kesinleştir. **Karar verilecek açık noktalar:**
   - Manifest kodlaması: CBOR mu, basit TLV mi?
   - Dosya adı normalizasyonu: NFC + büyük/küçük harf duyarsız çakışma kontrolü
   - Kurtarma anahtarı gösterimi (ör. 8×6 haneli grup + kontrol hanesi, BitLocker benzeri)
   - Argon2id varsayılan parametreleri (hedef makinede ölçüm)
3. `mlcore` için "hello libsodium" DLL + ctypes'tan `ml_init()` çağrısı → araç zinciri doğrulaması.
4. CI: Windows runner'da Python testleri + CMake build.
5. VM'ler: iki Windows 11 VM, snapshot "temiz", sanal USB disk (VHDX'i çıkarılabilir olarak bağlama).
