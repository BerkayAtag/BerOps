# Değişiklik Günlüğü

Bu projedeki tüm önemli değişiklikler bu dosyada belgelenir.
Biçim [Keep a Changelog](https://keepachangelog.com/tr-TR/1.1.0/) esas alınarak hazırlanmıştır ve proje [Anlamsal Sürümleme](https://semver.org/lang/tr/) kullanır.

## [Yayımlanmamış]

## [1.1.0] — 2026-11-01

### Eklendi

- **Gösterge paneli:** En çok eksik olan 10 yama, açığı olan uygulama sürümleri ve son işler.
- **Zamanlanmış başlatma:** Aksiyonlar belirli bir tarih/saatte başlar; geçerlilik ve kademe gecikmeleri bu zamandan sayılır.
- **Yeniden başlatma yönetimi:**
  - Çıkış kodu 3010/1641 olan hedefler "yeniden başlatma bekliyor" olarak işaretlenir.
  - Bildirimli ve süreli yeniden başlatma aksiyonu (`restart`) eklendi.
- **Ajan günlükleri:** Makine detayından istenir (`collect_logs`); makine detayına iş geçmişi sekmesi eklendi.
- **Kayıt defteri:** Oturumdaki değişiklikler önceki değerleriyle listelenir ve tek tıkla geri alınır.
- **Bildirimler:** Başarısız dağıtım, filoda yeni kritik CVE (CVSS 9+) ve 24 saattir çevrimdışı makine.
- **API anahtarları:** Dış sistemler için rol ve OU kapsamlı Bearer anahtarları; konsolda yönetim sayfası.

### Değişti

- Konsol bağımlılıkları: jsdom 30, vitest 5. TypeScript 7 güncellemesi, typescript-eslint desteğine kadar bekletiliyor.
- CI eylemleri: dependency-review 5, setup-node 7, setup-go 7.

## [1.0.1] — 2026-11-01

### Değişti

- Tanıtım sayfası BeRDP ve WFI ile aynı tasarım diline taşındı:
  - Aydınlık varsayılan, yuvarlak tema düğmesi, kısa metinler.
  - Ekran görüntüleri seçilen dile (TR/EN) ve temaya (aydınlık/karanlık) göre değişir.
  - Görsele tıklanınca büyük görünüm açılır (ok tuşları, Esc).
- README kısaltıldı; temaya göre değişen ekran görüntüleri eklendi. Geliştirme adımları `docs/gelistirme.md` dosyasına taşındı.
- Kurulum dosyalarının adı sürüm numarası içermiyor (`BerOps-Server-x64.msi`, `BerOps-Agent-x64.msi`, `BerOps-Agent.pkg`); `releases/latest/download/...` bağlantıları her sürümde çalışır.

### Düzeltildi

- Konsolun ürettiği kurulum komutlarındaki dosya adları, sürümdeki dosya adlarıyla uyuşmuyordu.
- Ajan indir sayfasındaki düğmeler sürüm sayfasına gidiyordu; artık dosyayı doğrudan indirir.
- Sürüme gereksiz `.wixpdb` hata ayıklama dosyaları ekleniyordu.

## [1.0.0] — 2026-10-31

İlk kararlı sürüm: spesifikasyondaki sekiz aşamanın tümü. Ürün adı **BerOps**.

### Eklendi — Aşama 8: Yama dağıtımı, paketleme ve yayın

- **İşletim sistemi yaması dağıtımı:**
  - `deploy_patch` aksiyon türü ve `actions.deploy_patch` izni.
  - Yamalar sayfasında filo geneli eksik güncellemeler ve kademeli, pencereye uygun dağıtım.
  - Windows'ta Windows Update Agent betiği (3010 başarılı sayılır), macOS'ta `softwareupdate`.
  - Kurulumdan sonra ajan tam tarama yapar.
- **Windows MSI'ları (WiX v5, Yayımcı: Berkay Atağ):**
  - **Sunucu:** Sihirbaz (PostgreSQL, portlar, ad, TLS, ilk yönetici), servis, güvenlik duvarı.
  - **Ajan:** Sessiz kurulum (`SERVER`, `REGKEY`, `CAHASH`), temiz kaldırma.
- **macOS `.pkg`:** Universal ikili dosya, launchd daemon'ı, MDM tercihleri, PPPC profili, kaldırma betiği, isteğe bağlı imza ve notarization.
- **Docker:** Sunucu imajı ve `deploy/docker-compose.yml`; `BER_HOSTNAMES` ortam değişkeni.
- **CI:** MSI'ları kurup Yayımcı alanını, servisleri, konsol girişini ve temiz kaldırmayı doğrulayan iş; macOS paket kurulum ve kaldırma işi; Docker derlemesi.
- **Release iş akışı (`v*`):** MSI'lar, pkg, Linux sunucu ve relay arşivleri, çok mimarili GHCR imajı, `SHA256SUMS.txt`, imza durumunu belirten sürüm notu.
- **`berops-server setup`:** Yapılandırma, migration ve ilk yönetici.
- Sunucu ve ajan Windows'ta SCM servisi olarak çalışır (`shared/service`).
- Konsol: Ajan indir sayfası (kayıt anahtarları ve kurulum komutları), Yamalar sayfası.
- Tanıtım sayfası (`landing/`) ve GitHub Pages iş akışı.
- Belgeler: sunucu, Windows ajanı ve macOS ajanı kurulumu, güvenlik modeli; `docs/ad.md` → `docs/ad-entegrasyonu.md`.

### Değişti

- Yapılandırılmamış ajan çıkmak yerine yapılandırmayı bekler (anahtarsız kurulum, sonradan GPO/MDM yapılandırması).
- Sanal ajanlar GUID biçimli güncelleme kimlikleri üretir.
- Konsolun ürettiği kurulum komutları yeni paket adlarını ve yollarını kullanır.

### Eklendi — Aşama 7: Relay, bakım pencereleri, kademeli dağıtım, bildirimler

- **BerOps Relay (`berops-relay`):**
  - Ajan TLS'ini sonlandırır; ajan sertifikasını doğrulayıp `X-Ber-Agent-Cert` ile sunucuya iletir.
  - Paketleri sunucu yetkisi aldıktan sonra bir kez indirir, SHA-256 ile doğrular, önbellekten hız sınırlı ve Range destekli verir.
  - LRU önbellek temizliği yapar.
- Sunucu: relay sertifikaları (`berops-server relay create`), relay listesi ve iptali, relay'e özel paket dosyası uç noktası.
- **Bakım pencereleri:** Haftanın günleri, başlangıç, süre, saat dilimi ve OU kapsamı. "Bakım penceresine uy" seçilen aksiyonlar yalnızca pencere içinde verilir.
- **Kademeli dağıtım:**
  - 2–5 aşama; sihirbazda pilot ve halka hazır ayarları.
  - Gecikme ve başarı oranı eşiğiyle otomatik ilerleme; eşik altında duraklama.
  - "Sonraki aşamayı başlat" düğmesi; hedeflerde aşama bilgisi.
- **Bildirimler:**
  - Kanallar: e-posta (STARTTLS/TLS) ve webhook (genel JSON, Teams, Slack, HMAC-SHA256 imzası). Deneme gönderimi.
  - Olaylar: aksiyon tamamlandı, filoda yeni KEV açığı, CVE kaynağı eşitlenemedi. Her olay tekilleştirilerek bir kez gönderilir.
- **Zamanlanmış raporlar:** PDF/Excel/CSV, günlük veya haftalık, e-posta eki olarak; her gönderim denetim kaydına yazılır.
- Konsol: Ayarlar altında Relay sunucuları, Bakım pencereleri ve Bildirimler sayfaları; sihirbaza kademeli dağıtım ve bakım penceresi seçenekleri; aksiyon detayında aşama durumu.
- Belgeler: `docs/gelismis-dagitim.md`, `relay/README.md`.

### Düzeltildi

- Oturumun oluşturma ve son etkinlik zamanı uygulama saatinden yazılıyor (önceden veritabanı saati kullanılıyordu; saatler farklıysa boşta kalma süresi yanlış hesaplanabiliyordu).

### Eklendi — Aşama 6: Uzaktan yönetim

- İsteğe bağlı uzaktan yönetim: genel ana anahtar ve makine başına özellikler (performans, servisler, kayıt defteri okuma/yazma), varsayılan kapalı.
- Oturum tabanlı uzun yoklama; Ed25519 imzalı istekler; ajan tarafında da özellik denetimi.
- Performans: CPU, bellek, takas, diskler, en çok kaynak kullanan süreçler (gopsutil, cgo'suz).
- Servisler: Windows servis yöneticisi (başlat/durdur/yeniden başlat); macOS launchd (listeleme, kickstart, durdurma).
- Windows kayıt defteri: gezinme, değer yazma ve silme; önceki değer denetim kaydına yazılır.
- Denetim: oturum açılışı; durum değiştiren işlemler gönderilmeden önce ve sonuçlarıyla birlikte kaydedilir.
- Konsol: makine detayında "Uzaktan yönetim" sekmesi, Ayarlar → Uzaktan yönetim sayfası.

### Eklendi — Aşama 5: Active Directory, yetki kapsamları ve denetim ekranı

- Active Directory (yalnızca LDAPS):
  - Hizmet hesabıyla arama, kullanıcı parolasıyla doğrulama, iç içe grup üyelikleri.
  - Grup → rol ve OU kapsamı eşlemeleri; en yetkili rol seçimi.
  - Bağlantı ve kullanıcı testi; ajansız AD bilgisayarları listesi.
  - AD erişilemezse 503 ve kurtarma hesabı önerisi.
- Gizli değer şifreleme (AES-256-GCM, `data_dir/pki/secret.key`); AD hizmet hesabı parolası API'den dönmez.
- OU kapsamlı yetki: makineler, filo özeti, güvenlik açıkları, risk özeti, aksiyonlar, raporlar, paket güncelleme listesi ve AD bilgisayarları kapsama göre süzülür; kapsam dışı hedefli işlemler reddedilir.
- Kullanıcı yönetimi:
  - Yerel kullanıcı oluşturma; rol/kapsam/durum/parola değiştirme.
  - Son yönetici ve kendini kilitleme koruması.
  - Değişiklikte oturumların kapatılması.
  - Kullanıcının kendi parolasını değiştirmesi.
- Denetim kaydı: filtreler (arama, eylem öneki, sonuç, tarih), sayfalama, CSV/Excel dışa aktarma.
- Konsol: Kullanıcılar, Active Directory, Denetim Kaydı ve Hesabım sayfaları; menü öğeleri izinlere göre gösterilir.

### Eklendi — Aşama 4: Paket kütüphanesi ve dağıtım

- Paket kütüphanesi:
  - Türler: MSI, EXE, PKG, DMG ve "dosya + komut".
  - Akış halinde yükleme, sunucuda SHA-256, içerik adresli depolama.
  - Kurulu uygulama kalıbıyla güncelleme gereken makinelerin tespiti.
- Aksiyonlar:
  - Paket dağıtımı ve komut çalıştırma (cmd, PowerShell, sh, zsh).
  - Hedef başına durum, çıkış kodu, stdout/stderr.
  - Zaman aşımı, geçerlilik, iptal.
  - İsteğe bağlı dört göz onayı.
- Ed25519 aksiyon imza anahtarı:
  - Hedef başına imzalı iş tanımı.
  - Ajanda anahtar sabitleme ve imza/makine/süre/SHA-256 doğrulaması.
  - Tekrar oynatmaya karşı iş günlüğü.
- İstemci başına hız sınırı (varsayılan 10 Mbps, Range ile kaldığı yerden devam); Windows Update kataloğuna da uygulanır.
- Ajan:
  - İş yürütücüsü: betik dosyası, UTF-8 çıktı.
  - Zaman aşımında süreç ağacının sonlandırılması (Windows Job Object, macOS süreç grubu).
  - DMG kurulumu.
  - Kurulumdan sonra değişiklik taraması.
- Denetim: aksiyon oluşturma fail-closed; komut metni kayda yazılır.
- Konsol:
  - Paket Kütüphanesi (yükleme ilerlemesi) ve paket detayı.
  - Aksiyonlar listesi, yeni aksiyon sihirbazı ve aksiyon detayı (çıktılar, onay/iptal, canlı yenileme).
  - Aktarım ayarları.
  - Makine listesinde ve detayında "Paket gönder / Komut çalıştır".
- Simülatör işleri gerçek ajanla aynı yoldan alır, indirir ve doğrular.

### Eklendi — Aşama 3: CVE motoru ve raporlar

- CVE kaynakları:
  - CISA KEV, FIRST EPSS, Microsoft MSRC (CVRF) ve NVD CVE API 2.0 eşitleyicisi.
  - Artımlı NVD eşitlemesi, hız sınırına uyum ve yeniden deneme.
  - Değişen MSRC belgelerinin yeniden işlenmesi.
  - İnternet erişimi olmayan ortamlar için çevrimdışı klasör modu.
  - `berops-server cve sync` komutu.
- Korelasyon motoru:
  - Windows yapı numarası ↔ MSRC `FixedBuild` karşılaştırması.
  - Eksik KB → CVE eşlemesi.
  - macOS sürümü ve üçüncü parti uygulamalar için NVD CPE sürüm aralıkları.
  - NVD'ye karşı doğrulanmış ürün sözlüğü; konsoldan özel uygulama → CPE kuralları.
- Risk skoru (CVSS, EPSS, KEV, fidye yazılımı), makine risk özeti ve günlük uyumluluk anlık görüntüleri.
- Veritabanı tabloları: `cves`, `cve_cpe_matches`, `msrc_remediations`, `kev`, `epss`, `feed_status`, `app_cpe_rules`, `machine_vulnerabilities`, `machine_risk`, `compliance_snapshots`.
- Konsol API'si:
  - Zafiyet listesi ve CVE detayı.
  - Makine zafiyetleri.
  - Gösterge paneli risk özeti.
  - CVE kaynak durumu, eşitleme ve kurallar.
  - Rapor dışa aktarma.
  - Makine listesinde risk ve açık sayısı sütunları ile sıralaması.
- Raporlar:
  - Dört rapor: uyumluluk, zafiyet, eksik yama ve uygulama envanteri.
  - Biçimler: PDF (Türkçe karakter destekli, marka renkli), Excel (XLSX) ve CSV (UTF-8 BOM, formül enjeksiyonu koruması).
  - Türkçe ve İngilizce, kullanıcının saat diliminde.
- Konsol:
  - Güvenlik Açıkları ve CVE detay sayfaları.
  - Makine detayında risk kartları ve açık sekmesi.
  - Gösterge panelinde risk bölümü, önem dağılımı, uyumluluk eğilimi, en riskli açıklar ve makineler.
  - Raporlar sayfası ve CVE kaynakları ayar sayfası.

### Eklendi — Aşama 2: Envanter ve tespit

- Ajan envanteri: işletim sistemi ve donanım, yama seviyesi, kurulu yamalar, eksik güncellemeler ve üçüncü parti uygulamalar (Windows ve macOS).
- Windows: kayıt defteri (64/32 bit, kullanıcı hive'ları), MSI ve AppX uygulamaları; Windows Update Agent ile çevrimiçi ve `wsusscn2.cab` ile çevrimdışı eksik güncelleme taraması (KB, sınıflandırma, MSRC önemi, CVE); AD OU ve bekleyen yeniden başlatma tespiti.
- macOS: `.app` paketleri, pkg makbuzları, Homebrew; `softwareupdate --list` ile eksik güncellemeler; kurulum geçmişinden kurulu güncellemeler.
- Kaynak kısıtlama: Windows'ta Job Object CPU sert sınırı ve düşük öncelik, macOS'ta arka plan QoS; ajan içi CPU bütçesi; pil ve kullanıcı etkinliğinde erteleme.
- Tarama zamanlayıcısı: tam (24 sa) ve değişiklik (4 sa) taramaları, jitter, bölüm özetleriyle yalnızca değişenlerin gönderilmesi, başarısız yüklemelerin yeniden denenmesi, sunucunun tam envanter isteği.
- Sunucu: `machine_inventory`, `installed_patches`, `missing_patches`, `installed_apps`, `agent_settings` tabloları; gzip envanter yükleme; Range destekli katalog indirme; heartbeat'te ayar ve tarama talimatları.
- Konsol API'si: filtreli/sıralı/sayfalı makine listesi, filo özeti, makine detayı ve alt listeleri, toplu yeniden tarama, ajan ayarları.
- Konsol: makine listesi (arama, filtre, sıralama, sayfalama, toplu seçim), makine detay sayfası, gösterge panelinde uyumluluk ve dağılım, ajan ayarları sayfası.
- `berops-agent inventory` tanılama komutu; simülatöre gerçekçi sahte envanter.

### Eklendi — Aşama 1: Temel altyapı

- Monorepo iskeleti (`agent/`, `server/`, `relay/`, `console/`, `design/`, `landing/`, `installers/`, `docs/`) ve tek Go modülü.
- Mimari dokümanı, veritabanı şeması planı ve varsayımlar belgesi.
- PostgreSQL şeması: `users`, `sessions`, `registration_keys`, `machines`, `audit_log` (değiştirilemez); gömülü migration çalıştırıcısı.
- Sunucunun iç sertifika otoritesi (ECDSA P-256): ajan API'si için sunucu sertifikası, ajan CSR imzalama.
- Ajan kaydı: kayıt anahtarı (kullanım sayısı, süre, yönetici onayı), CA parmak izi pin'i ile ilk güven.
- mTLS heartbeat: sertifika seri numarası kontrolü, reddedilen makinelerin engellenmesi.
- Konsol API'si: giriş/çıkış, oturum (Argon2id, `__Host-` çerez, CSRF, boşta kalma zaman aşımı), giriş hız sınırı, güvenlik başlıkları (CSP, HSTS).
- Granüler izinler ve Admin / Teknisyen / Salt Okunur rolleri; reddedilen istekler denetim kaydına yazılır.
- OpenAPI 3.1 tanımı (`/api/openapi.yaml`).
- `berops-server` komutları: `serve`, `migrate`, `admin create`, `regkey create`, `version`.
- `berops-agent` (Windows servisi desteğiyle): `configure`, `enroll`, `run`, `status`, `version`; jitter ve üstel geri çekilmeli heartbeat, döngüsel log dosyaları.
- `berops-agentsim`: çok sayıda sanal ajanı simüle eden test aracı.
- Konsol: giriş ekranı, gösterge paneli iskeleti, Türkçe/İngilizce, açık/karanlık tema; ortak tasarım token'ları (`design/tokens.css`).
- GitHub Actions: Go lint/test/govulncheck, Windows ve macOS ajan testleri, çapraz derleme, konsol lint/test/derleme, CodeQL, bağımlılık incelemesi, Dependabot.

[Yayımlanmamış]: https://github.com/BerkayAtag/BerOps/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/BerkayAtag/BerOps/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/BerkayAtag/BerOps/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/BerkayAtag/BerOps/releases/tag/v1.0.0
