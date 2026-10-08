# MyLocker — Öğrenme Yol Haritası ve Literatür

## 1. Windows API'leri ve teknolojiler (faza göre)

### Faz 1–3 (çekirdek + MVP)
| Konu | API / Kavram |
|---|---|
| Dosya I/O | `CreateFileW` bayrakları (`FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_FLAG_WRITE_THROUGH`, `FILE_FLAG_NO_BUFFERING`), `FlushFileBuffers`, `ReplaceFileW`, `MoveFileExW(MOVEFILE_WRITE_THROUGH)`, `SetFileInformationByHandle` (`FileDispositionInfoEx`, `FileRenameInfoEx`), `GetFileInformationByHandleEx` |
| Dosya sistemi | NTFS temelleri (MFT, resident data, ADS, reparse point, hard link), uzun yollar (`\\?\`), `FindFirstFileW`/`FindFirstStreamW`, rezerve adlar |
| Hacim / USB | `FindFirstVolumeW`, `GetVolumePathNamesForVolumeNameW`, `GetDriveTypeW`, `DeviceIoControl` + `IOCTL_STORAGE_QUERY_PROPERTY`, SetupAPI (`SetupDiGetClassDevs`) |
| Güvenlik modeli | Access token, SID, DACL/SACL, SDDL (`ConvertStringSecurityDescriptorToSecurityDescriptorW`), privilege'ler (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeDebugPrivilege`) — **admin'in ACL'yi neden aşabildiğini** tezde açıklamak için; UAC, integrity level |
| Bellek | `VirtualLock`, `SetProcessWorkingSetSize`, `SecureZeroMemory`, `CryptProtectMemory` (ve sınırları) |
| Süreç sertleştirme | `SetDefaultDllDirectories`, `SetProcessMitigationPolicy`, WER/LocalDumps ayarları |
| Açık dosyalar | Restart Manager: `RmStartSession`, `RmRegisterResources`, `RmGetList`, `RmShutdown` |
| Kriptografi (karşılaştırma için) | CNG (`BCryptGenRandom`, `BCryptEncrypt` GCM), DPAPI (`CryptProtectData`) — neden kullanılmadığını açıklamak için |
| Python–C | ctypes (`WinDLL`, `argtypes`/`restype`, `create_string_buffer`), DLL dışa aktarma, `wchar_t`/UTF-16 dönüşümleri |

### Faz 4 (agent)
| Konu | API / Kavram |
|---|---|
| Cihaz olayları | `RegisterDeviceNotificationW`, `WM_DEVICECHANGE`, `DBT_DEVICEQUERYREMOVE`/`DBT_DEVICEREMOVECOMPLETE`, `CM_Register_Notification` (cfgmgr32) |
| Güç / oturum | `WM_POWERBROADCAST`, `RegisterSuspendResumeNotification`, `WTSRegisterSessionNotification` |
| Dizin izleme | `ReadDirectoryChangesW`, I/O completion ports |
| IPC | `CreateNamedPipeW`, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `GetNamedPipeClientProcessId`, `GetNamedPipeServerProcessId`, `ImpersonateNamedPipeClient`, `QueryFullProcessImageNameW`, `WinVerifyTrust` |
| Servisler (anlamak için) | SCM, `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SERVICE_CONTROL_DEVICEEVENT`, service SID, Protected Process Light (neden bize açık değil) |
| Handle'lar | `NtQuerySystemInformation(SystemExtendedHandleInformation)`, `DuplicateHandle` (neden tehlikeli) |
| Bildirim | Shell bildirimleri / toast |

### Faz 6–7 (VFS + uygulama kilidi)
| Konu | API / Kavram |
|---|---|
| WinFsp | `FSP_FILE_SYSTEM_INTERFACE`, `FspFileSystemCreate`, `FspFileSystemStartDispatcher`, `FileInfoTimeout`, güvenlik tanımlayıcıları, WinFsp tutorial (memfs, passthrough örnekleri) |
| I/O mimarisi | IRP, I/O Manager, Cache Manager, memory-mapped dosyalar, paging I/O, standby list |
| Kernel (araştırma) | Filter Manager, minifilter (`FltRegisterFilter`), izolasyon filtreleri, `PsSetCreateProcessNotifyRoutineEx`, sürücü imzalama, test-signing |
| Uygulama kontrolü | AppLocker, WDAC, IFEO, ETW (`Microsoft-Windows-Kernel-Process`) |
| FIDO2 (Faz 5) | CTAP2 `hmac-secret`, WebAuthn PRF, `webauthn.dll` API, `python-fido2` |

### Araç zinciri
C: MSVC + CMake + vcpkg (libsodium), clang-cl (libFuzzer), MSVC ASan. Python: 3.12+, pytest, hypothesis, `cryptography`, `argon2-cffi`, Tkinter → PySide6. Paketleme: Python embeddable distribution / PyInstaller `onedir`. Sürüm kontrolü: Git + GitHub Actions (Windows runner).

---

## 2. İncelenecek benzer sistemler (İlgili Çalışmalar bölümü)

| Sistem | Neden incelenmeli | Okunacak |
|---|---|---|
| **BitLocker (USB startup key modu)** | Projenin modeline en yakın endüstri örneği: anahtar USB'de | Microsoft dokümanları; Ferguson 2006 (AES-CBC + Elephant diffuser) |
| **EFS** | Dosya başına FEK, sertifikayla sarma → anahtar hiyerarşisi; admin/DRA zaafları | Microsoft EFS dokümanları |
| **VeraCrypt** | Keyfile + parola kombinasyonu, header formatı, gizli hacim | VeraCrypt dokümanları; QuarksLab denetimi (2016) |
| **LUKS2** | Keyslot modeli, header yedeği, Argon2id | LUKS2 on-disk format spec |
| **gocryptfs** | Dosya başına AES-GCM, 4 KiB blok, AAD'de dosya ID + blok no | Format belgesi; Taylor Hornby denetimi (2017) |
| **Cryptomator** | Vault formatı, dosya adı şifreleme (AES-SIV), masterkey sarma | Cryptomator spec; Cure53 denetimi |
| **CryFS** | Metadata (boyut, yapı) gizleme | Messmer vd. |
| **age** | STREAM tarzı chunk'lama (64 KiB, son chunk bayrağı), HKDF ile yük anahtarı | age spesifikasyonu (C2SP) |

Tezde bir **karşılaştırma tablosu**: anahtar konumu, 2FA, metadata gizleme, bütünlük, rollback, şeffaf erişim, admin'e karşı durum, taşınabilirlik.

---

## 3. Akademik literatür (konuya göre)

### Tehdit modelleme ve güvenlik mühendisliği
- A. Shostack, *Threat Modeling: Designing for Security*, Wiley, 2014.
- R. Anderson, *Security Engineering*, 3. baskı, Wiley, 2020.
- Kohnfelder & Garg, "The threats to our products" (STRIDE), Microsoft, 1999.

### Kimlik doğrulamalı şifreleme ve anahtar türetme
- P. Rogaway, "Authenticated-Encryption with Associated-Data", ACM CCS 2002.
- M. Bellare, C. Namprempre, "Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm", ASIACRYPT 2000.
- V. T. Hoang, R. Reyhanitabar, P. Rogaway, D. Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015 (STREAM).
- A. Albertini, T. Duong, S. Gueron, S. Kölbl, A. Luykx, S. Schmieg, "How to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022.
- J. Len, P. Grubbs, T. Ristenpart, "Partitioning Oracle Attacks", USENIX Security 2021.
- H. Krawczyk, "Cryptographic Extraction and Key Derivation: The HKDF Scheme", CRYPTO 2010.
- A. Biryukov, D. Dinu, D. Khovratovich, "Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications", IEEE EuroS&P 2016.
- K. Nikitin vd., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019 (Padmé dolgulama).

### Standartlar
- NIST SP 800-38D (GCM), SP 800-57 Part 1 Rev. 5 (anahtar yönetimi), SP 800-90A (RNG), SP 800-108 & 800-56C (KDF), SP 800-88 Rev. 1 (medya temizleme), SP 800-63B (kimlik doğrulayıcılar).
- RFC 5116 (AEAD arayüzü), RFC 5869 (HKDF), RFC 2104 (HMAC), RFC 8439 (ChaCha20-Poly1305), RFC 8452 (AES-GCM-SIV), RFC 9106 (Argon2), RFC 9180 (HPKE), RFC 3394 (AES Key Wrap).
- FIDO Alliance, CTAP 2.1 spesifikasyonu (`hmac-secret` uzantısı).

### Bellek güvenliği ve fiziksel saldırılar
- J. A. Halderman vd., "Lest We Remember: Cold Boot Attacks on Encryption Keys", USENIX Security 2008.
- A. T. Markettos vd., "Thunderclap: Exploring Vulnerabilities in Operating System IOMMU Protection via DMA from Untrustworthy Peripherals", NDSS 2019.
- M. H. Ligh, A. Case, J. Levy, A. Walters, *The Art of Memory Forensics*, Wiley, 2014.
- J. Rutkowska, "Evil Maid goes after TrueCrypt!", 2009.
- K. Nohl, J. Lell, "BadUSB — On Accessories that Turn Evil", Black Hat USA 2014.

### Güvenli silme ve OS sızıntıları (açık dosya problemi için kritik)
- A. Czeskis, D. J. St. Hilaire, K. Koscher, S. D. Gribble, T. Kohno, B. Schneier, "Defeating Encrypted and Deniable File Systems: TrueCrypt v5.1a and the Case of the Tattling OS and Applications", USENIX HotSec 2008. **← Projenin "açık dosya / yan kanal" bölümü için temel kaynak.**
- M. Wei, L. M. Grupp, F. E. Spada, S. Swanson, "Reliably Erasing Data from Flash-Based Solid State Drives", USENIX FAST 2011.
- J. Reardon, D. Basin, S. Capkun, "SoK: Secure Data Deletion", IEEE S&P 2013.
- P. Gutmann, "Secure Deletion of Data from Magnetic and Solid-State Memory", USENIX Security 1996.
- S. Garfinkel, A. Shelat, "Remembrance of Data Passed: A Study of Disk Sanitization Practices", IEEE S&P Magazine, 2003.

### Windows iç yapısı
- P. Yosifovich, A. Ionescu, M. Russinovich, D. Solomon, *Windows Internals, 7th ed., Part 1*, 2017; A. Allievi vd., *Part 2*, 2021 (güvenlik, I/O, cache manager, dosya sistemleri bölümleri).
- P. Yosifovich, *Windows Kernel Programming*, 2. baskı, 2023 (minifilter, süreç bildirimleri).
- WinFsp dokümantasyonu ve mimari notları.

### Uygulamalı kriptografi kitapları
- N. Ferguson, B. Schneier, T. Kohno, *Cryptography Engineering*, Wiley, 2010.
- D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography* (ücretsiz).
- J.-P. Aumasson, *Serious Cryptography*, 2. baskı, No Starch, 2024.
