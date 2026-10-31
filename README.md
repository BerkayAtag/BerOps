# BerOps

**Ajan tabanlı yama ve üçüncü parti uygulama yönetim platformu.** Windows ve macOS istemcilerdeki eksik işletim sistemi yamalarını, üçüncü parti uygulamaları ve güvenlik açıklarını tek bir tarayıcı tabanlı konsoldan izleyin ve dağıtımı kontrollü şekilde yapın.

Mimari, BigFix'in Server / Relay / Agent / Console modelini örnek alır.

> **Durum:** Spesifikasyondaki sekiz aşamanın tümü tamamlandı. Kurulum paketleri [GitHub Releases](https://github.com/BerkayAtag/BerOps/releases/latest)'ta, tanıtım sayfası <https://berkayatag.github.io/BerOps/> adresinde yayımlanır.

## Kurulum

| Ne? | Nasıl? |
|---|---|
| **Sunucu** | Windows Server için sihirbazlı MSI (`BerOps-Server-<sürüm>-x64.msi`), Linux için Docker Compose veya arşiv → [docs/kurulum-sunucu.md](docs/kurulum-sunucu.md) |
| **Windows ajanı** | `msiexec /i BerOps-Agent-<sürüm>-x64.msi /qn SERVER=… REGKEY=… CAHASH=…` → [docs/kurulum-ajan-windows.md](docs/kurulum-ajan-windows.md) |
| **macOS ajanı** | `BerOps-Agent-<sürüm>.pkg` (Intel + Apple Silicon), MDM tercihleri, PPPC profili → [docs/kurulum-ajan-macos.md](docs/kurulum-ajan-macos.md) |
| **Şube relay'i** | `berops-relay` arşivleri → [relay/README.md](relay/README.md) |

Kurulum komutlarını konsoldaki **Ajan indir** sayfası sunucu adresi, kayıt anahtarı ve CA parmak izi gömülü olarak üretir.

## Bileşenler

| Bileşen | Açıklama |
|---|---|
| **BerOps Server** | Merkezi API, PostgreSQL veritabanı, iç sertifika otoritesi, ajan kaydı, iş kuyruğu |
| **BerOps Relay** | Şubeler için önbellekleyen dağıtım noktası ([relay/README.md](relay/README.md)) |
| **BerOps Agent** | Windows servisi / macOS `launchd` daemon'ı olarak çalışan hafif Go ajanı |
| **BerOps Console** | React + TypeScript tarayıcı konsolu; Türkçe/İngilizce, açık/karanlık tema |

Ayrıntılar: [docs/mimari.md](docs/mimari.md)

## Aşama 1'de neler var?

- **Ajan kaydı ve heartbeat (mTLS):** Ajan kendi anahtarını üretir, kayıt anahtarı ve CA parmak iziyle (pin) sunucuya kaydolur, sunucunun iç CA'sından istemci sertifikası alır ve heartbeat'leri karşılıklı TLS ile gönderir.
- **Kayıt anahtarları:** Kullanım sayısı, geçerlilik süresi ve isteğe bağlı yönetici onayı. Veritabanında yalnızca özetleri saklanır.
- **Konsol girişi:** Argon2id parola özeti, `HttpOnly`/`Secure`/`SameSite=Strict` oturum çerezi, CSRF koruması, boşta kalma zaman aşımı ve giriş denemesi hız sınırı.
- **RBAC temeli:** Granüler izinler ve Admin / Teknisyen / Salt Okunur rolleri, her uç noktada sunucu tarafında zorunlu.
- **Değiştirilemez denetim kaydı:** `audit_log` tablosunda UPDATE, DELETE ve TRUNCATE veritabanı trigger'larıyla engelli.
- **Konsol:** Giriş ekranı, gösterge paneli iskeleti, Türkçe varsayılan + İngilizce, işletim sistemi tercihini izleyen ve seçimi hatırlayan karanlık mod.
- **Sanal ajan simülatörü:** Yüzlerce ajanı tek süreçte simüle eden `berops-agentsim`.

## Aşama 2'de neler var?

- **Windows tespiti:** Yama seviyesi (ör. `10.0.22631.4460`), kurulu KB'ler, Windows Update Agent ile eksik güncellemeler (çevrimiçi veya sunucudaki `wsusscn2.cab` ile çevrimdışı; KB, sınıflandırma, MSRC önemi, CVE'ler, yeniden başlatma gereksinimi), kayıt defteri/MSI/AppX uygulamaları, AD OU ve bekleyen yeniden başlatma.
- **macOS tespiti:** macOS sürümü ve build numarası, `softwareupdate --list` ile eksik güncellemeler, kurulum geçmişi, `.app` paketleri, pkg makbuzları ve Homebrew.
- **Kaynak kısıtlama:** Windows'ta Job Object ile sert CPU sınırı ve IDLE öncelik, macOS'ta arka plan QoS; ajan içi işler için CPU bütçesi; pil ve kullanıcı etkinliğinde erteleme.
- **Delta gönderim:** Bölüm özetleriyle yalnızca değişen bölümler gönderilir; sunucu tutarsızlık görürse tam envanter ister.
- **Konsol:** Arama, filtre, sıralama, sayfalama ve toplu seçimli makine listesi; eksik/kurulu yama ve uygulama sekmeli makine detay sayfası; gösterge panelinde uyumluluk ve dağılım; ajan ayarları sayfası; konsoldan yeniden tarama.
- **Tanılama:** `berops-agent inventory [-full] [-json]` envanteri makinede toplayıp yazdırır.

## Aşama 3'te neler var?

- **CVE kaynakları:** CISA KEV, FIRST EPSS, Microsoft MSRC ve NVD sunucuda eşitlenir (24 saatte bir, artımlı). İnternet erişimi olmayan ortamlar için çevrimdışı klasör desteği vardır.
- **Windows açıkları:** Makinenin yapı numarası MSRC'nin düzeltme yapısıyla karşılaştırılır. Böylece eksik toplu güncellemenin kapattığı tüm CVE'ler bulunur, Windows Update'in CVE listesinde görünmeyenler dahil. Eksik KB'ler de MSRC eşlemesiyle CVE'ye bağlanır.
- **macOS ve üçüncü parti uygulamalar:** NVD'ye karşı doğrulanmış 40'tan fazla ürünlük sözlükle (tarayıcılar, PDF, sıkıştırma, uzaktan erişim, geliştirici araçları, Homebrew) CPE eşleştirmesi ve sürüm aralığı kontrolü yapılır. Sözlükte olmayan uygulamalar için konsoldan özel kural eklenebilir.
- **Risk skoru (0–100):** CVSS, EPSS olasılığı, CISA KEV ve fidye yazılımı bilgisini birleştirir. Aktif istismar edilen açıklar öne çıkar. Formül: [docs/cve.md](docs/cve.md).
- **Konsol:** Güvenlik açıkları listesi ve CVE detayı (etkilenen makineler, düzelten KB'ler, KEV kaydı), makine detayında risk kartları ve açık sekmesi, gösterge panelinde risk özeti, önem dağılımı, 30 günlük uyumluluk eğilimi, en riskli açıklar ve makineler, CVE kaynakları ayar sayfası.
- **Raporlar:** Uyumluluk, zafiyet, eksik yama ve uygulama envanteri raporları PDF, Excel ve CSV olarak; Türkçe veya İngilizce, kullanıcının saat diliminde. Her dışa aktarma denetim kaydına yazılır.

Gerçek kaynaklarla ölçüm (MacBook, PostgreSQL 17, API anahtarı olmadan): ilk eşitleme 3 dk 24 sn sürdü (KEV 1 sn, EPSS 1,4 sn, MSRC 12 ay 47 sn, NVD 41 ürün 2 dk 29 sn). 31 makinenin yeniden hesaplanması 5,6 sn sürdü.

## Aşama 4'te neler var?

- **Paket kütüphanesi:**
  - Desteklenen türler: MSI, EXE, PKG, DMG ve "dosya + komut" paketleri.
  - Yükleme akış halinde yapılır ve sunucuda SHA-256 hesaplanır; dosyalar içerik adresli saklanır.
  - Kurulu uygulama kalıbıyla paketten eski sürümü çalıştıran makineler bulunur; tek tıkla güncelleme gönderilir.
- **Aksiyonlar:**
  - Paket dağıtımı ve CMD/PowerShell (Windows) ile sh/zsh (macOS) komutları desteklenir.
  - Makine başına durum, çıkış kodu, standart ve hata çıktısı görülür.
  - Zaman aşımı, geçerlilik süresi ve iptal ayarlanabilir.
- **Rol kuralları:** Teknisyen yalnızca kütüphanedeki paketleri gönderebilir; serbest komut ayrı bir izindir. İsteğe bağlı dört göz onayında oluşturan kişi kendi komutunu onaylayamaz.
- **İmzalı işler:**
  - Her iş, hedef makine kimliği ve dosya özetiyle birlikte sunucunun Ed25519 anahtarıyla imzalanır.
  - Ajan anahtarı sabitler; imza, makine, süre ve SHA-256 doğrulanmadan hiçbir şey çalışmaz.
  - Aynı iş ikinci kez çalıştırılmaz.
- **Hız sınırı:** İstemci başına sunucu tarafında uygulanır; varsayılan 10 Mbps, aksiyon bazında düşürülebilir. İndirmeler kaldığı yerden sürer. Aynı sınır Windows Update kataloğuna da uygulanır.
- **Denetim:** Aksiyonlar komut metniyle birlikte denetim kaydına yazılır. Kayıt yazılamazsa aksiyon oluşturulmaz.

Ayrıntılar: [docs/dagitim.md](docs/dagitim.md). Ölçüm: 1 MB'lık paket, 10 Mbps sınırla 12 sanal ajana 16 saniye içinde ulaştı; gerçek macOS ajanında komut ve betik paketi uçtan uca doğrulandı.

## Aşama 5'te neler var?

- **Active Directory (yalnızca LDAPS):**
  - Kullanıcılar AD hesaplarıyla giriş yapar; iç içe grup üyelikleri dikkate alınır.
  - Rol ve OU kapsamı grup eşlemelerinden her girişte yeniden hesaplanır.
  - Hizmet hesabı parolası sunucuda AES-256-GCM ile şifreli saklanır.
  - Bağlantı ve kullanıcı testi yapılabilir; AD'de olup ajanı kurulu olmayan bilgisayarlar listelenir.
  - AD erişilemezse yerel kurtarma hesabıyla giriş yapılır.
- **OU kapsamı:** Teknisyen ve salt okunur kullanıcılar belirli OU'larla sınırlandırılabilir. Makineler, güvenlik açıkları, aksiyonlar ve raporlar kapsama göre süzülür; kapsam dışı hedefe işlem reddedilir.
- **Kullanıcı yönetimi:**
  - Yerel kullanıcı ekleme, rol/kapsam/durum değiştirme, parola sıfırlama.
  - Son yöneticiyi ve kendini kilitlemeye karşı koruma.
  - Değişiklikte açık oturumlar kapatılır.
  - Kullanıcılar kendi parolasını değiştirebilir.
- **Denetim kaydı ekranı:** Arama, eylem/sonuç/tarih filtreleri, parametre ayrıntısı ve CSV/Excel dışa aktarma.

Ayrıntılar: [docs/ad-entegrasyonu.md](docs/ad-entegrasyonu.md), [docs/roller-ve-yetkiler.md](docs/roller-ve-yetkiler.md).

## Aşama 6'da neler var?

- **İsteğe bağlı uzaktan yönetim:** Genel ana anahtar ve makine başına özellikler vardır; hepsi varsayılan kapalıdır.
- **Performans:** CPU (eğilim çizgisiyle), bellek, takas, diskler ve en çok kaynak kullanan süreçler 5 saniyede bir yenilenir.
- **Servisler:** Windows servisleri ve macOS launchd işleri listelenir, başlatılır, durdurulur, yeniden başlatılır.
- **Kayıt defteri (Windows):** Gezinme, değer ekleme/değiştirme/silme. Önceki değer denetim kaydına yazılır.
- **Oturum modeli:** Ajan yalnızca konsolda oturum açıkken uzun yoklama yapar. İstekler Ed25519 ile imzalıdır; kapalı özellik ajan tarafında da reddedilir.

Ayrıntılar: [docs/uzaktan-yonetim.md](docs/uzaktan-yonetim.md). Ölçüm (gerçek macOS ajanı): oturuma 5 sn'de bağlandı, performans isteği 1,25 sn'de (1 sn CPU örneklemesi dahil) döndü.

## Aşama 7'de neler var?

- **Relay:** Şube ajanları relay'e bağlanır. Relay ajan kimliğini doğrulayıp sunucuya iletir, paketleri bir kez indirip SHA-256 ile doğrular ve önbellekten verir (LRU, varsayılan 50 GB). Sertifika `berops-server relay create` ile üretilir, konsoldan iptal edilir.
- **Bakım pencereleri:** Gün, saat, süre, saat dilimi ve OU kapsamı tanımlanır. "Bakım penceresine uy" seçilen aksiyonların işleri yalnızca pencere açıkken verilir.
- **Kademeli dağıtım:** Pilot ve halka hazır ayarlarıyla 2–5 aşama kurulur. Sonraki aşama, gecikmesi dolunca ve başarı oranı eşiği geçince kendiliğinden açılır; eşik altında dağıtım duraklar. Duraklatılmış aşama elle de açılabilir.
- **Bildirimler:** E-posta (SMTP) ve webhook (genel JSON, Teams, Slack, HMAC imzası). Olaylar: aksiyon tamamlandı, filoda yeni KEV açığı, CVE kaynağı eşitlenemedi. Her olay bir kez gönderilir.
- **Zamanlanmış raporlar:** PDF, Excel veya CSV, haftalık ya da günlük olarak e-posta eki halinde gönderilir.

Ayrıntılar: [docs/gelismis-dagitim.md](docs/gelismis-dagitim.md).

## Aşama 8'de neler var?

- **Yama dağıtımı:** Yamalar sayfası filodaki eksik güncellemeleri güncelleme başına gruplar. Seçilen yamalar, eksik oldukları makinelere kademeli ve bakım penceresine uygun şekilde gönderilir.
  - Windows'ta Windows Update Agent ile kurulur (3010 "yeniden başlatma gerekli" başarılı sayılır).
  - macOS'ta `softwareupdate` ile kurulur.
  - Kurulumdan sonra ajan tam tarama yapar.
- **Windows MSI'ları (Yayımcı: Berkay Atağ):**
  - **Sunucu:** Sihirbazda PostgreSQL, portlar, sunucu adı, TLS sertifikası ve ilk yönetici adımları vardır. Windows servisi olarak çalışır ve güvenlik duvarı kurallarını ekler.
  - **Ajan:** Sessiz kurulumda `SERVER`, `REGKEY` ve `CAHASH` alır (GPO, SCCM, Intune) ve iz bırakmadan kaldırılır.
  - CI her PR'da iki paketi kurar ve Yayımcı alanını, servisleri, konsol girişini ve temiz kaldırmayı doğrular.
- **macOS paketi:**
  - Universal ikili dosya ve `launchd` daemon'ı.
  - MDM tercihleriyle yapılandırma, PPPC örnek profili ve kaldırma betiği.
  - İsteğe bağlı Developer ID imzası ve notarization.
- **Docker:** Root olmayan kullanıcıyla çalışan sunucu imajı ve PostgreSQL'li `deploy/docker-compose.yml`.
- **Release iş akışı:** `v*` etiketi her şeyi derleyip GitHub Releases'a yükler:
  - Sunucu ve ajan MSI'ları, macOS paketi, Linux sunucu arşivleri, relay arşivleri.
  - Çok mimarili Docker imajı (GHCR) ve `SHA256SUMS.txt`.
  - İmza sertifikaları GitHub Secrets'ta yoksa paketler imzasız derlenir ve bu, sürüm notunda belirtilir.
- **Ajan indir sayfası:** Kayıt anahtarı üretir ve kurulum komutlarını hazırlar.
- **`berops-server setup`:** İlk kurulum komutu (yapılandırma, migration, ilk yönetici).
- **Tanıtım sayfası:** `landing/`, GitHub Pages'e otomatik yayımlanır. Türkçe ve İngilizce, karanlık mod, mimari şeması, demo verili ekran görüntüleri.
- **Belgeler:** [kurulum-sunucu](docs/kurulum-sunucu.md), [kurulum-ajan-windows](docs/kurulum-ajan-windows.md), [kurulum-ajan-macos](docs/kurulum-ajan-macos.md), [guvenlik](docs/guvenlik.md).

## Ajan kaynak kullanımı

Ölçüm: macOS 27 (Apple Silicon), ajan heartbeat aralığı 10 sn (varsayılan 60 sn'den 6 kat sık), 70 sn boyunca 5 sn aralıkla `ps` örneklemesi.

| Metrik | Hedef | Ölçülen |
|---|---|---|
| Boşta CPU | < %1 | ~%0,07 (70 sn'de toplam 0,05 sn CPU süresi) |
| Bellek (RSS) | < ~50 MB | 11–16 MB |

Aynı test sırasında 50 sanal ajan da aynı sunucuya kaydolup heartbeat gönderdi; tümü başarılı oldu.

**Tam envanter taraması sırasında** (aynı Mac, %10 CPU sınırı, 180 uygulama, 195 kurulu güncelleme, `softwareupdate --list` dahil):

| Metrik | Ölçülen |
|---|---|
| Tarama süresi (duvar saati) | 17–26 sn (çoğu Apple sunucularına yapılan `softwareupdate` sorgusu) |
| Ajan sürecinin CPU süresi | 0,09 sn |
| En yüksek bellek (RSS) | 21 MB |
| Değişiklik taraması (uygulamalar + kurulu yamalar) | ~0,75 sn |

`softwareupdate` alt sürecinin ve Apple'ın `softwareupdated` servisinin CPU kullanımı ajan sürecine dahil değildir; bu süreçler arka plan önceliğinde çalışır. Windows ölçümleri (WUA taraması dahil) Aşama 8'de MSI ile birlikte yapılacak.

## Hızlı başlangıç (geliştirme ortamı)

Gereksinimler: Go 1.27+, Node.js 24+, Docker.

PostgreSQL'i başlatın:

```bash
docker compose -f deploy/docker-compose.dev.yml up -d --wait
```

Sunucu yapılandırmasını oluşturun (`berops-server.yaml`, git'e eklenmez):

```yaml
data_dir: ./data
database_url: postgres://ber:ber@localhost:5432/ber_dev?sslmode=disable
```

İlk admin hesabını oluşturun ve sunucuyu başlatın:

```bash
go run ./server/cmd/berops-server admin create -username admin
```

```bash
go run ./server/cmd/berops-server serve
```

Konsolu geliştirme modunda açın (API istekleri `https://localhost:8443` adresine aktarılır):

```bash
npm --prefix console install && npm --prefix console run dev
```

Tarayıcıda `http://localhost:5173` adresine gidin.

### Ajanı kaydetmek

Kayıt anahtarı oluşturun; komut CA parmak izini de yazdırır:

```bash
go run ./server/cmd/berops-server regkey create -name "Geliştirme"
```

Ajanı kaydedip çalıştırın (yönetici yetkisi gerekmez, `-data-dir` ile yerel bir klasör kullanılır):

```bash
go run ./agent/cmd/berops-agent enroll -data-dir ./agent-data -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi>
```

```bash
go run ./agent/cmd/berops-agent run -data-dir ./agent-data
```

### Envanteri yerelde denemek

Sunucuya göndermeden bu makinenin envanterini görmek için (`-full` eksik güncelleme taramasını da yapar):

```bash
go run ./agent/cmd/berops-agent inventory -full
```

### CVE verisini eşitlemek

Sunucu açıldıktan bir dakika sonra kaynakları kendisi eşitler. Hemen eşitlemek için:

```bash
go run ./server/cmd/berops-server cve sync
```

### Sanal ajanlar

Gerçek ajanla aynı zamanlayıcıyı kullanan, gerçekçi sahte envanter (eksik KB'ler, CVE'ler, güncel olmayan uygulamalar, AD OU'ları) gönderen sanal ajanlar:

```bash
go run ./agent/cmd/berops-agentsim -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi> -n 100 -first-scan 30s
```

## Testler

Go testleri (PostgreSQL entegrasyon testleri `BER_TEST_DATABASE_URL` tanımlıysa çalışır):

```bash
BER_TEST_DATABASE_URL='postgres://ber:ber@localhost:5432/postgres?sslmode=disable' go test -race ./...
```

Konsol testleri:

```bash
npm --prefix console test -- --run
```

## Yol haritası

| Aşama | Kapsam | Durum |
|---|---|---|
| 1 | Repo iskeleti, CI, veritabanı şeması, API iskeleti, mTLS ajan kaydı ve heartbeat, giriş ekranı ve tema | ✅ |
| 2 | Envanter: yama seviyesi, eksik yamalar, üçüncü parti uygulamalar; kaynak kısıtlama; makine listesi ve detay | ✅ |
| 3 | CVE motoru: NVD, MSRC, KEV, EPSS; risk skoru; dashboard ve raporlar | ✅ |
| 4 | Dağıtım: paket kütüphanesi, hız limitli ve imzalı transfer, aksiyonlar | ✅ |
| 5 | Active Directory (LDAPS) ve RBAC kapsamları, denetim kaydı ekranı | ✅ |
| 6 | Uzaktan yönetim: performans, servisler, registry (opt-in) | ✅ |
| 7 | Relay, bakım pencereleri, kademeli dağıtım, bildirimler | ✅ |
| 8 | Yama dağıtımı; MSI ve pkg kurulum paketleri, Docker imajı, release iş akışı, tanıtım sayfası | ✅ |

## Dokümantasyon

- [Sunucu kurulumu](docs/kurulum-sunucu.md)
- [Windows ajanı kurulumu](docs/kurulum-ajan-windows.md)
- [macOS ajanı kurulumu](docs/kurulum-ajan-macos.md)
- [Mimari](docs/mimari.md)
- [Güvenlik modeli](docs/guvenlik.md)
- [CVE motoru ve raporlar](docs/cve.md)
- [Yama, paket dağıtımı ve komut çalıştırma](docs/dagitim.md)
- [Roller ve yetkiler](docs/roller-ve-yetkiler.md)
- [Active Directory entegrasyonu](docs/ad-entegrasyonu.md)
- [Gelişmiş dağıtım: relay, bakım pencereleri, kademeli dağıtım, bildirimler](docs/gelismis-dagitim.md)
- [Uzaktan yönetim](docs/uzaktan-yonetim.md)
- [Varsayımlar ve kararlar](docs/varsayimlar.md)
- [API](docs/api.md)
- [Katkıda bulunma](CONTRIBUTING.md)
- [Güvenlik politikası](SECURITY.md)
- [Değişiklik günlüğü](CHANGELOG.md)

## Lisans

[Apache License 2.0](LICENSE). Geliştiren: **Berkay Atağ**.
