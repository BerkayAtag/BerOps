# Varsayımlar ve Kararlar

Spesifikasyonda belirsiz kalan noktalar için yapılan varsayımlar burada tutulur. Her madde, değiştirilmesi gerekirse etkilenecek yeri de belirtir.

## Aşama 1 — Temel altyapı

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 1.1 | Go modül yolu | `github.com/BerkayAtag/BerOps` (GitHub deposuyla aynı). | `go.mod`, tüm Go dosyaları |
| 1.2 | Birincil renk | `#DC0005` spesifikasyondaki örnek değerdir; resmi marka rehberinden teyit edilmedi. Değer yalnızca `design/tokens.css` içinde tanımlıdır. | `design/tokens.css` |
| 1.3 | Lisans | **Apache License 2.0**: patent hakkı devri içerir, kurumsal kullanımda yaygın kabul görür ve atıf koruması sağlar. | `LICENSE` |
| 1.4 | Ajan portu | `52311/tcp`. BigFix ile aynı port numarası kurumsal güvenlik duvarlarında tanıdıktır. Yapılandırılabilir. | `server` yapılandırması |
| 1.5 | Konsol portu | `8443/tcp` varsayılan, kurulum sihirbazında değiştirilebilir. | `server` yapılandırması |
| 1.6 | İlk güven (bootstrap) | Ajan, kurulum parametresi olarak verilen **CA parmak izi** (`CAHASH`) ile sunucuyu doğrular. Parmak izi olmadan kayıt yapılmaz. Konsoldaki "Ajan İndir" sayfası (Aşama 8) bu değeri komutlara otomatik ekler. | `agent`, kurulum belgeleri |
| 1.7 | Ajan sertifika süresi | 1 yıl. Otomatik yenileme Aşama 4'te (self-update ile birlikte) eklenecek. | `server/internal/pki` |
| 1.8 | CA anahtarının saklanması | Aşama 1'de `data_dir/pki/ca.key` dosyasında, yalnızca servis hesabının okuyabileceği izinlerle (0600) tutulur. Windows'ta DPAPI ile şifreleme Aşama 8'de (MSI kurulumu) eklenecek. | `server/internal/pki` |
| 1.9 | Onay gerektiren kayıt | Makineye sertifika hemen verilir ancak durum `pending` olur. Onaylanana kadar iş gönderilmez; reddedilirse sertifika geçersiz sayılır. Bu yaklaşım ajanın ayrıca sertifika beklemek için yoklama yapmasını gereksiz kılar. | `server/internal/api` |
| 1.10 | Yeniden kayıt | Aynı makine yeniden kurulursa yeni bir ajan ID'si alır; eski kayıt çevrimdışı görünür. Hostname/donanım kimliğiyle birleştirme Aşama 2'de ele alınacak. | `machines` |
| 1.11 | İlk admin | Kurulum sihirbazı (Aşama 8) yazılana kadar ilk admin `berops-server admin create` komutuyla oluşturulur. | `server/cmd/berops-server` |
| 1.12 | Teknisyen ve yama dağıtımı | Spesifikasyon teknisyene yalnızca "kayıtlı paket gönderme" yetkisi tanıyor. İşletim sistemi yaması dağıtma (`actions.deploy_patch`) bu nedenle teknisyende **yok**; Aşama 5'te özel rollerle eklenebilir. | `server/internal/auth/rbac.go` |
| 1.13 | Salt Okunur ve dışa aktarma | Rapor dışa aktarma veri değiştirmediği için Salt Okunur rolünde açıktır. | `server/internal/auth/rbac.go` |
| 1.14 | CSP ve satır içi stil | `style-src 'self' 'unsafe-inline'`: grafik kütüphaneleri (Recharts) satır içi `style` niteliği kullanır. Betikler için `'unsafe-inline'` yoktur. | `server/internal/api/middleware.go` |
| 1.15 | Yapılandırma dosyası | Sunucu YAML yapılandırma dosyası (`berops-server.yaml`) + ortam değişkeni geçersiz kılmaları. Kurulum sihirbazı bu dosyayı yazar. | `server/internal/config` |
| 1.16 | PostgreSQL sürümü | En az 14. CI 17 ile test eder. | CI, kurulum belgeleri |
| 1.17 | Konsol dağıtımı | Konsol derlemesi sunucu binary'sine gömülmez; sunucu `console.static_dir` dizininden sunar. Böylece konsol ayrı güncellenebilir ve Go derlemesi Node'a bağımlı olmaz. | `server/internal/api` |
| 1.18 | Ajan servis kaydı | Aşama 1'de ajan Windows servis yöneticisi altında çalışabilir (`svc` entegrasyonu). Servisin oluşturulması ve macOS `launchd` plist'i Aşama 8'de kurulum paketleriyle gelir. | `agent/internal/service` |
| 1.19 | Uyandırma bildirimi | UDP uyandırma (BigFix "UDP ping" karşılığı) Aşama 4'te iş kuyruğuyla birlikte eklenecek. Aşama 1'de ajan yalnızca heartbeat ile bağlanır. | `agent`, `server` |

## Aşama 2 — Envanter ve tespit

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 2.1 | Tarama aralıkları | Tam tarama (eksik yamalar dahil) varsayılan 24 saat, değişiklik taraması 4 saat; her ikisine ±%10 jitter eklenir. Kayıttan sonraki ilk tam tarama en geç 5 dakika içinde yapılır. Ayarlar konsoldan (Ayarlar → Ajan ayarları) değiştirilir. | `agent/internal/scanner`, `agent_settings` |
| 2.2 | Delta modeli | Değişiklik satır bazında değil **bölüm bazında** izlenir: işletim sistemi, kurulu yamalar, eksik yamalar ve uygulamalar ayrı ayrı özetlenir (SHA-256) ve yalnızca özeti değişen bölüm gönderilir. Basit, hatasız birleştirme ve sunucu tarafında tutarlılık kontrolü sağlar. | `shared/protocol`, `scanner` |
| 2.3 | Tutarlılık | Ajan heartbeat'te sunucuya yüklediği bölüm özetlerini bildirir; sunucudakiyle uyuşmazsa sunucu tam envanter ister ve ajan yeniden taramadan önbellekteki envanteri gönderir. | `api/inventory_handlers.go` |
| 2.4 | CPU sınırı (Windows) | PowerShell alt süreçleri IDLE önceliğinde ve **Job Object CPU sert sınırıyla** çalışır. Ajan süreci BELOW_NORMAL önceliğindedir. Ajan içindeki işler (kayıt defteri okuma) görev döngüsüyle (duty cycle) kısılır. | `agent/internal/sysres` |
| 2.5 | CPU sınırı (macOS) | macOS'ta süreç başına sert CPU sınırı yoktur. Alt süreçler `taskpolicy -b` ile arka plan QoS sınıfında (en düşük CPU ve disk önceliği), ajan `nice 10` ile çalışır; ajan içi işler aynı görev döngüsüyle kısılır. | `agent/internal/sysres` |
| 2.6 | Kullanıcı etkinliği | Windows servisleri oturum 0'da çalıştığı için kullanıcı girdisini göremez; "kullanıcı etkinken ertele" yalnızca macOS'ta (HIDIdleTime) uygulanır. Pil kontrolü iki platformda da çalışır. Ertelemeler en fazla 4 saat sürer; konsoldan istenen tarama hiç ertelenmez. | `sysres`, `scanner` |
| 2.7 | Eksik yama kaynağı | "Çevrimiçi" mod makinenin yapılandırılmış kaynağını (Windows Update veya GPO ile tanımlı WSUS) kullanır. "Çevrimdışı" modda ajan `wsusscn2.cab` dosyasını sunucudan (kaldığı yerden devam ederek) indirir ve WUA ile çevrimdışı tarar. Katalog dosyası şimdilik sunucunun `data_dir/wsus/` klasörüne elle konur; konsoldan yükleme ve hız sınırı Aşama 4'teki dosya aktarım altyapısıyla gelecek. | `agent/internal/inventory`, `api` |
| 2.8 | Windows kullanıcı uygulamaları | Yalnızca o anda yüklü kullanıcı hive'ları (oturumu açık kullanıcılar) okunur. Oturumu kapalı profillerin `NTUSER.DAT` dosyası, kullanıcının profiline müdahale etmemek için yüklenmez. | `inventory/windows.go` |
| 2.9 | Uygulama sayılmayanlar | `SystemComponent=1`, başka ürünün alt güncellemesi (`ParentKeyName`), KB içeren girdiler ve AppX çerçeve/sistem paketleri uygulama listesine alınmaz. | `inventory/parse.go` |
| 2.10 | macOS uygulamaları | `/Applications` (2 seviye), `/Users/*/Applications`, `/var/db/receipts` (Apple'ın `com.apple.*` paketleri hariç) ve Homebrew. Homebrew root olarak çalıştırılamadığı için `brew` komutu yerine `Cellar`/`Caskroom` dizinleri okunur. | `inventory/darwin.go` |
| 2.11 | macOS kurulu yamalar | `/Library/Receipts/InstallHistory.plist` içindeki `softwareupdated` ve `macOS Installer` kayıtları. | `inventory/parse.go` |
| 2.12 | Windows CVE'leri | Eksik Microsoft güncellemelerinin CVE kimlikleri WUA'nın `IUpdate.CveIDs` alanından alınır. CVSS, KEV, EPSS ve üçüncü parti uygulama eşleştirmesi Aşama 3'te eklenecek. | `inventory/scripts/wua.ps1` |
| 2.13 | Sınıflandırma adları | Windows Update sınıflandırma adları işletim sistemi diline göre yerelleştirildiği için GUID'den İngilizce ada çevrilir; konsol aynı adları gösterir. | `inventory/parse.go` |
| 2.14 | AD OU | Bilgisayarın OU'su Grup İlkesi'nin kaydettiği `Distinguished-Name` değerinden çıkarılır. Etki alanında olmayan makinelerde boştur. AD'den doğrudan içe aktarma Aşama 5'te. | `inventory/windows.go`, `store` |
| 2.15 | Uyumluluk yüzdesi | Eksik yama taraması tamamlanmış ve eksik yaması olmayan makinelerin, envanteri olan makinelere oranı. Risk ağırlıklı skor Aşama 3'te. | `store/machines.go` |
| 2.16 | Ayar kapsamı | Ajan ayarları şimdilik tüm filo için tektir. Grup bazlı geçersiz kılma, gruplar (Aşama 5) ile eklenecek. | `agent_settings` |
| 2.17 | Tablo kütüphanesi | TanStack Table **v8** kullanıldı. v9 yeni çıkmış ve API'si tamamen değişmiş; kararlı sürüm tercih edildi. | `console/package.json` |

## Aşama 3 — CVE motoru ve raporlar

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 3.1 | NVD kapsamı | NVD'nin tamamı (≈300 bin CVE) değil, yalnızca takip edilen ürünlerin CVE'leri çekilir; artımlı eşitlemede veritabanında olan CVE'ler güncellenir. Veritabanı küçük kalır, ilk eşitleme dakikalar sürer. | `server/internal/cve/syncer.go` |
| 3.2 | Windows işletim sistemi açıkları | Ürün adı eşleştirmesi yerine MSRC'nin `FixedBuild` alanı kullanılır: makine yapısı aynı ailedeki düzeltme yapısından küçükse savunmasızdır. Yalnızca adı "Windows" ile başlayan MSRC ürünleri alınır. | `cve/engine.go`, `cve/feeds.go` |
| 3.3 | MSRC geçmişi | Varsayılan 12 ay (`cve.msrc_months`). Daha eski yapıda kalmış makineler için açık sayısı alt sınırdır; bu makineler zaten çok sayıda eksik toplu güncelleme gösterir. | `config`, `cve/syncer.go` |
| 3.4 | Üçüncü parti eşleştirme | Kurulu uygulamalar yerleşik sözlük ve özel kurallarla CPE ürününe eşlenir (düzenli ifade). Bulanık/otomatik CPE eşleştirmesi yapılmaz; yanlış pozitifleri önlemek için açık sözlük tercih edildi. Sözlükteki tüm CPE adları NVD'ye karşı doğrulandı. | `cve/products.json` |
| 3.5 | NVD AND yapılandırmaları | "Uygulama X, platform Y üzerinde" koşulları değerlendirilmez; uygulama sürümü aralıktaysa bulgu üretilir (ihtiyatlı yaklaşım). | `cve/nvd.go` |
| 3.6 | Sürümsüz NVD kayıtları | Hiç sürüm sınırı olmayan eşleşmeler (ör. TLS BEAST) atlanır: düzeltme sürümü yoktur, aksiyon alınamaz. | `cve/engine.go` |
| 3.7 | macOS pkg makbuzları | CVE eşleştirmesine katılmaz; makbuz kurulum anındaki sürümü tutar, kendini güncelleyen uygulamalarda yanlış pozitif üretir. Makbuzlar envanterde görünmeye devam eder. | `cve/engine.go` |
| 3.8 | Risk formülü | `CVSS×6 + EPSS×25 + 15 (KEV/istismar) + 5 (fidye yazılımı)`, en fazla 100. Eşikler: Acil ≥80, Yüksek ≥60, Orta ≥40. Makine riski = en yüksek bulgu riski. Formül tek yerde (`cve.RiskScore`) tanımlıdır. | `cve/risk.go`, `console/src/risk.ts` |
| 3.9 | Kaynak birleştirme | Aynı CVE hem NVD'de hem MSRC'de varsa açıklama ve CVSS NVD'den, başlık ve "istismar edildi" bilgisi MSRC'den alınır. NVD henüz analiz etmediyse (CVSS yok) MSRC skoru kullanılır. Başlık yoksa KEV'deki açık adı gösterilir. | `store/cve.go`, `store/vulns.go` |
| 3.10 | Yeniden hesaplama | Envanter geldiğinde yalnızca o makine, kaynak eşitlemesinden ve kural değişikliğinden sonra ve sunucu açılışında tüm filo arka planda yeniden hesaplanır. Bulgunun ilk görülme zamanı korunur. | `server/internal/vuln` |
| 3.11 | Tek sunucu | Eşitleme kilidi süreç içidir. Birden fazla sunucu örneği aynı veritabanını kullanırsa eşitleme yinelenebilir (veri bozulmaz, yalnızca gereksiz istek olur). Çok sunuculu kurulum Aşama 7'de ele alınacak. | `cve/syncer.go` |
| 3.12 | PDF kütüphanesi | `go-pdf/fpdf` + Go yazı tipleri (`golang.org/x/image/font/gofont`, BSD lisanslı, Türkçe karakterleri kapsar). Excel dosyası harici kütüphane olmadan (Office Open XML) üretilir. | `server/internal/report` |
| 3.13 | Rapor boyutu | Dışa aktarmada en fazla 200 000 satır, PDF'te en fazla 5000 satır. Raporlar belleğe yazılıp sonra gönderilir; hata olursa yarım dosya yerine JSON hata döner. | `store`, `report`, `api/report_handlers.go` |
| 3.14 | Uyumluluk eğilimi | Günün özeti bakım döngüsünde (10 dk) güncellenir; geçmiş günler değişmez. Eğilim grafiği son 30 günü gösterir; yeni kurulumda birkaç gün sonra anlamlı hale gelir. | `compliance_snapshots`, `api/server.go` |
| 3.15 | Zamanlanmış rapor ve e-posta | Raporların zamanlanıp e-postayla gönderilmesi bildirim altyapısıyla birlikte Aşama 7'de eklenecek. | — |

## Aşama 4 — Paket kütüphanesi ve dağıtım

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 4.1 | İmza anahtarı | Ajan işleri CA anahtarından ayrı bir Ed25519 anahtarıyla imzalanır; anahtar `data_dir/pki/action-signing.key` (0600). Ajan açık anahtarı ilk gördüğünde sabitler (TOFU, kanal zaten CA pin'iyle doğrulanmış mTLS). Anahtar yenileme ajanların yeniden kaydını gerektirir; otomatik anahtar devri ileride eklenebilir. | `server/internal/pki/signing.go`, `agent/internal/identity` |
| 4.2 | İmza zamanı | İşler aksiyon oluşturulurken hedef başına imzalanıp veritabanına yazılır; veritabanına yazma erişimi olan biri imzasız iş ekleyemez. | `api/action_handlers.go` |
| 4.3 | Teknisyen | Yalnızca kütüphanedeki paketleri gönderebilir; paket yükleyemez, serbest komut çalıştıramaz, aksiyon onaylayamaz. | `auth/rbac.go` |
| 4.4 | Dört göz | Komut onayı varsayılan **kapalı** (küçük ekiplerde tek admin olabilir); açıldığında oluşturan kişi kendi aksiyonunu onaylayamaz. Paket dağıtımı onay gerektirmez (paket zaten admin tarafından kütüphaneye eklenmiştir). | `transfer_settings`, `api` |
| 4.5 | Fail-closed denetim | Aksiyon oluşturma, denetim kaydı yazılamazsa reddedilir (503). Diğer işlemlerde denetim hatası loglanır. | `api/action_handlers.go` |
| 4.6 | Yeniden çalıştırma | Ajan iş çalışırken yeniden başlarsa iş başarısız sayılır, otomatik tekrar edilmez. İndirme aşamasında durursa iş sunucuda "indiriliyor" kalır ve sonraki açılışta sürdürülür. | `agent/internal/jobs` |
| 4.7 | Hız sınırı | İstemci başına (bağlantı başına) sunucu tarafında uygulanır; varsayılan 10 Mbps. Ajan işleri sırayla çalıştırdığından bir makine aynı anda tek indirme yapar. Toplam (sunucu geneli) sınır ve relay önbelleği Aşama 7'de. | `api/transfer.go` |
| 4.8 | Dosya boyutu | Varsayılan en fazla 4 GB (ayarlanabilir). Yükleme diske akış halinde yazılır, bellekte tutulmaz; uzun yüklemeler için o isteğin zaman aşımı 6 saate çıkarılır. | `api/action_handlers.go` |
| 4.9 | Betik çalıştırma | Komutlar iş dizinine betik olarak yazılıp çalıştırılır. Windows'ta `cmd` için `chcp 65001`, PowerShell için UTF-8 BOM ve çıktı kodlaması ayarlanır. Çıktı 64 KB ile sınırlanır. | `agent/internal/jobs` |
| 4.10 | macOS süreç grubu | Zaman aşımında süreç grubuna SIGKILL gönderilir ve 200 ms sonra tekrarlanır; macOS'ta çatallanma anındaki süreçlerin gruptan kaçabildiği gözlendi. | `agent/internal/jobs/exec_unix.go` |
| 4.11 | Güncelleme tespiti | Paket "kurulu uygulama adı kalıbı" ile envantere bağlanır; makinedeki en yeni kurulu sürüm paketten eskiyse "güncelleme gerekli" sayılır. Satıcı kataloğundan otomatik "en son sürüm" bilgisi yoktur; en güncel sürüm kütüphanedeki pakettir. | `api/action_handlers.go` |
| 4.12 | Paket silme | Silme yumuşaktır (geçmiş aksiyonlar paket adını göstermeye devam eder). Dosya, başka paket veya açık aksiyon kullanmıyorsa diskten silinir. | `store/packages.go` |
| 4.13 | Kendini güncelleme | Ajanın kendini güncellemesi MSI/pkg paketleri hazır olduğunda (Aşama 8) paket dağıtımıyla yapılacak. | — |

## Aşama 5 — Active Directory, RBAC kapsamları ve denetim

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 5.1 | Yalnızca LDAPS | Şifresiz LDAP ve StartTLS kabul edilmez; adres `ldaps://` olmalı. Sunucu sertifikası sistem güven deposuyla ve isteğe bağlı iç CA PEM'iyle doğrulanır; doğrulamayı kapatma seçeneği yoktur. | `server/internal/ad` |
| 5.2 | Kimlik doğrulama | Hizmet hesabıyla arama + kullanıcının kendi parolasıyla bind. Boş parola ağa gitmeden reddedilir (LDAP'ta anonim bind). | `ad.Authenticate` |
| 5.3 | İç içe gruplar | AD'nin `1.2.840.113556.1.4.1941` eşleme kuralı kullanılır; desteklenmeyen dizinlerde doğrudan `memberOf` değerleri alınır. | `ad.nestedGroups` |
| 5.4 | Rol seçimi | En yetkili rol kazanır (admin > teknisyen > salt okunur). Aynı roldeki eşlemelerin kapsamları birleşir; biri kapsamsızsa sonuç kapsamsızdır. Eşleşme yoksa giriş reddedilir. | `ad.ResolveRole` |
| 5.5 | Rol güncelliği | Rol ve kapsam yalnızca girişte hesaplanır; açık oturum süresince (en fazla 12 saat) değişmez. Konsoldan yapılan rol/kapsam/durum değişikliği yerel kullanıcının oturumlarını hemen kapatır. | `api/auth_handlers.go`, `users_handlers.go` |
| 5.6 | Yerel hesap önceliği | Aynı adda yerel hesap varsa AD denenmez; AD kullanıcısı yerel hesabı ele geçiremez (`UpsertADUser` çakışmada reddeder). | `store/users.go` |
| 5.7 | Gizli değerler | AD hizmet hesabı parolası `data_dir/pki/secret.key` (32 bayt, 0600) ile AES-256-GCM şifrelenir; şifreleme etiketi alanı bağlar. Anahtar kaybolursa parola yeniden girilir. | `server/internal/secret` |
| 5.8 | OU kapsamı | Kapsam OU DN'leridir; makine OU'su kapsamdaki OU'ya eşitse veya `,<OU>` ile bitiyorsa kapsam içidir. Karşılaştırma büyük/küçük harf duyarsızdır (SQL tarafında iki taraf da PostgreSQL ile küçültülür). Admin rolünde kapsam yok sayılır. | `store/machines.go` `scopeCond`, `ad.InScope` |
| 5.9 | Kapsam dışı yanıt | Kapsam dışı makine ve aksiyonlar 404 döner (varlıkları sızmasın); kapsam dışı hedefli işlem istekleri 403 ile tamamen reddedilir. | `api` |
| 5.10 | Eğilim grafiği | Günlük uyumluluk özeti filo geneli tutulduğundan kapsamlı kullanıcıya gösterilmez. Kapsam bazlı geçmiş ileride eklenebilir. | `store/vulns.go` |
| 5.11 | Parola politikası | Yerel parolalar en az 12 karakter; karmaşıklık kuralı yerine uzunluk esas alınır (NIST SP 800-63B). Giriş denemesi hız sınırı Aşama 1'deki gibidir. | `api/users_handlers.go` |
| 5.12 | İki adımlı doğrulama | Yerel hesaplar için TOTP alanı şemada hazırdır; arayüzü ileride eklenecek. Kurumsal kullanımda AD + kurumun kendi MFA çözümü önerilir. | `users.totp_secret_enc` |
| 5.13 | AD bilgisayarları | Liste saklanmaz, her istekte AD'den okunur (en fazla 20 000 nesne, 500'lük sayfalar). Ajan eşleştirmesi ad ve DNS adının ilk parçasıyla yapılır. | `api/ad_handlers.go` |
| 5.14 | Denetim dışa aktarma | En fazla 100 000 kayıt, CSV veya Excel; dışa aktarma da denetim kaydına yazılır. Kayıtlar veritabanında değiştirilemez (Aşama 1 trigger'ları). | `api/audit_handlers.go` |
| 5.15 | API anahtarları | Dış sistemler için API anahtarı ile erişim ihtiyaç halinde eklenecek; şimdilik yalnızca oturum çerezi. | — |

## Aşama 6 — Uzaktan yönetim

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 6.1 | Opt-in | Genel ana anahtar ve makine başına özellikler varsayılan kapalı. Ajan, heartbeat'te aldığı bayraklara göre kapalı özelliği kendisi de reddeder (sunucu tarafı hata durumunda ikinci savunma). | `machine_remote`, `agent/internal/remote` |
| 6.2 | Bağlantı modeli | Kalıcı bağlantı yerine oturum: konsol oturum açınca ajan bir sonraki heartbeat'te 25 sn'lik uzun yoklamalara geçer. On binlerce ajanın sürekli açık bağlantı tutması gerekmez; karşılığında ilk bağlanma bir heartbeat aralığı kadar sürebilir. | `api/remote_handlers.go` |
| 6.3 | İmza | Uzaktan istekler aksiyon anahtarıyla imzalanır ve 40 sn geçerlidir. | `protocol.SignRemote` |
| 6.4 | Tek sunucu | İstek aracısı bellek içidir; birden fazla sunucu örneğinde oturum ve ajan yoklaması aynı örneğe düşmelidir. Çok örnekli kurulum için paylaşılan kuyruk Aşama 7 kapsamı dışındadır. | `remoteBroker` |
| 6.5 | Performans ölçümü | `gopsutil` (cgo gerektirmez). CPU kullanımı 1 sn'lik aralıkta ölçülür; süreç CPU'su aynı aralıkta işlemci zamanı farkından hesaplanır. macOS sistem bölümleri ve sanal dosya sistemleri disk listesinden çıkarılır. | `agent/internal/remote/perf.go` |
| 6.6 | Servisler (macOS) | launchd işleri `launchctl list` ile okunur; ajan root ise sistem, değilse kullanıcı alanı. Yalnızca kickstart (başlat/yeniden başlat) ve SIGTERM (durdur); etiket düzenli ifadeyle doğrulanır ve kabuk kullanılmaz. | `services_darwin.go` |
| 6.7 | Kayıt defteri | 64 bit görünüm (`KEY_WOW64_64KEY`); HKCU kapsam dışı (servis SYSTEM hesabıyla çalışır, HKU üzerinden kullanıcı hive'larına erişilir). Yazma türleri: SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY. | `registry_windows.go` |
| 6.8 | Yetkiler | Uzaktan yönetim izinleri yalnızca Admin rolünde. Teknisyene açmak için özel roller ileride eklenebilir. | `auth/rbac.go` |

## Aşama 7 — Relay, bakım pencereleri, kademeli dağıtım, bildirimler

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 7.1 | Relay kimliği | Relay ayrı bir sertifika türüdür (CN `relay:<id>`, sunucu + istemci EKU). Zincire CA eklenir; ajanın CA parmak izi sabitlemesi değişmeden çalışır. Sertifika iptali veritabanındaki `revoked_at` ile yapılır, CRL/OCSP yoktur. | `pki.IssueRelayCert`, `relays` |
| 7.2 | Ajan kimliğinin iletilmesi | Relay TLS'i sonlandırır ve ajan sertifikasını `X-Ber-Agent-Cert` (base64 DER) başlığıyla iletir. Sunucu başlığa yalnızca relay sertifikalı bağlantıda güvenir ve sertifikayı yeniden doğrular. TLS geçişi (SNI ile tünel) yerine bu yol seçildi; çünkü relay'in paket isteklerini görüp önbellekten yanıtlaması gerekir. | `api/relay_handlers.go`, `relay/relay` |
| 7.3 | Relay önbelleği | İçerik adresli (SHA-256), LRU temizleme, varsayılan 50 GB. Relay dosyayı ancak sunucu bir ajanın indirme yetkisini onayladıktan sonra çeker; relay'e sunucudan hız sınırı uygulanmaz, ajana sunucunun belirlediği istemci başına sınır uygulanır. | `relay/relay/relay.go` |
| 7.4 | Relay kaydı | Relay'ler konsoldan değil, sunucuda `berops-server relay create` komutuyla oluşturulur (özel anahtar ağ üzerinden taşınmaz). Konsol listeler ve iptal eder. | `cmd/berops-server` |
| 7.5 | Bakım penceresi semantiği | Pencere yalnızca "Bakım penceresine uy" seçilen aksiyonları etkiler. Makineye uyan etkin pencere yoksa iş hemen verilir. Birden çok pencere uyuyorsa herhangi biri yeterlidir. Gece yarısını aşan pencere başladığı güne aittir. | `store/windows.go` |
| 7.6 | Pencere ve geçerlilik süresi | Pencere dışında bekleyen işin geçerlilik süresi durmaz. Kullanıcının geçerlilik süresini pencereyi kapsayacak şekilde seçmesi beklenir; otomatik uzatma yapılmaz. | `api/rollout_handlers.go` |
| 7.7 | Kademeli dağıtım kararı | Aşama açılmadan önce açılmış hedeflerin en az yarısının sonuçlanması beklenir. Başarı oranı = başarılı / (başarılı + başarısız + süresi dolan). Eşik altında dağıtım duraklar ve yalnızca elle devam ettirilir. | `RunRollouts` |
| 7.8 | Aşama dağılımı | Hedefler aksiyon kimliği + makine kimliğinin FNV özetine göre sıralanıp yüzdelere bölünür. Ayrı "halka grubu" tablosu yerine yüzde tabanlı model seçildi; sabit pilot grupları ileride gruplar özelliğiyle eklenebilir. | `assignStages` |
| 7.9 | Bildirim teslimi | Olaylar dakikalık döngüde üretilir ve `dedupe_key` ile bir kez gönderilir. Başarısız gönderim yeniden denenmez; hata kanalın `last_error` alanında görünür. Kuyruk/yeniden deneme ileride eklenebilir. | `api/notify_handlers.go` |
| 7.10 | Webhook güvenliği | Yalnızca https (localhost için http). İsteğe bağlı HMAC-SHA256 imzası `X-Ber-Signature` başlığında. Webhook adresleri gizli sayılır; bildirim ayarları `settings.write` ister. | `validateChannel` |
| 7.11 | E-posta | SMTP AUTH PLAIN; STARTTLS varsayılan. Gövde UTF-8 düz metin, konu RFC 2047 ile kodlanır. Ek boyutu raporla sınırlıdır; büyük filolarda Excel/CSV önerilir. | `sendEmail` |
| 7.12 | Zamanlanmış raporlar | Tüm filo için üretilir (kapsam uygulanmaz); yalnızca e-posta kanalına gider. Saat ve gün kanalın değil zamanlamanın saat dilimine göredir. Kaçırılan çalışma telafi edilmez. | `runSchedules` |
| 7.13 | Oturum saati | Oturum oluşturma ve son etkinlik zamanı veritabanı saatinden değil uygulama saatinden yazılır; boşta kalma kontrolü de aynı saatle yapılır. | `store.CreateSession` |
| 7.14 | Yeniden başlatma politikaları | Spesifikasyondaki yeniden başlatma politikaları (erteleme, kullanıcıya bildirim) Aşama 7'de yok. Kurulum komutunun çıkış kodu 3010/1641 "yeniden başlatma gerekli" olarak kaydedilir; zorla yeniden başlatma yapılmaz. | — |

## Aşama 8 — Paketleme, yayın ve yama dağıtımı

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 8.1 | Gömülü veritabanı | Sunucu MSI'ı PostgreSQL içermez; sihirbaz mevcut bir PostgreSQL'e bağlanır. PostgreSQL'i pakete gömmek kurulum boyutunu ve yama sorumluluğunu büyütür. Tek makinelik kurulum için Docker Compose PostgreSQL'i birlikte getirir. | `installers/windows/server` |
| 8.2 | MSI kod sayfası | Yayımcı adı (`Berkay Atağ`) için MSI veritabanı Türkçe kod sayfası 1254 ile derlenir; Programlar ve Özellikler'de doğru görünür (CI'da kayıt defterinden doğrulanır). | `*.wxs` |
| 8.3 | Parolalar kurulumda | MSI özellikleri `Hidden` işaretlidir; `berops-server setup` parolayı komut satırından alır (yalnızca kurulum sırasında, SYSTEM olarak). Elle kurulumda `BER_ADMIN_PASSWORD` önerilir. | `berops-server setup` |
| 8.4 | Kurcalama koruması | Ajan kaldırma yerel yönetici yetkisi ister; ek sunucu onayı (kaldırma parolası/token) yoktur. Çevrimdışı kalan makine konsolda görünür. | `docs/guvenlik.md` |
| 8.5 | Kaldırmada veri | Ajan kaldırılınca veri klasörü silinir (yükseltmede korunur). Sunucu kaldırılınca iç CA ve paketler bilerek korunur. | MSI özel eylemleri |
| 8.6 | Anahtarsız ajan | Yapılandırılmamış ajan servisi çıkmaz, 30 saniyede bir yapılandırmayı bekler. Böylece paket önce dağıtılıp yapılandırma sonradan (GPO, MDM, `configure`) verilebilir. | `berops-agent run` |
| 8.7 | macOS yapılandırması | Kurulum betiği MDM yönetilen tercihlerini (`io.github.berkayatag.berops.agent`) veya `/private/tmp/berops-agent-install.conf` dosyasını okur. Dosya kaynak olarak çalıştırılmaz, yalnızca bilinen anahtarlar okunur. | `installers/macos/scripts/postinstall` |
| 8.8 | Kod imzalama | Release iş akışı sertifikalar GitHub Secrets'ta varsa imzalar ve notarize eder; yoksa imzasız derler ve sürüm notunda belirtir. | `.github/workflows/release.yml` |
| 8.9 | Yama dağıtımı | Windows'ta WUA COM API'si PowerShell betiğiyle, macOS'ta `softwareupdate` ile kurulur. Sunucu güncelleme dosyası taşımaz; makine WSUS/Windows Update/Apple'dan indirir. Makine yeniden başlatılmaz (3010 başarılı sayılır); yeniden başlatma politikası sonraki sürüme bırakıldı. | `api/patch_handlers.go` |
| 8.10 | Yama komutunun üretimi | Komut yalnızca doğrulanmış güncelleme kimliklerinden üretilir (Windows GUID, macOS güvenli karakter kümesi) ve tek tırnakla yerleştirilir; kullanıcı serbest metin veremez. Yama dağıtımı dört göz onayı gerektirmez (serbest komut değildir). | `patchJob` |
| 8.11 | Simülatör kimlikleri | Sanal ajanlar KB'den türetilen GUID biçimli güncelleme kimlikleri üretir; böylece demo ve testlerde yama dağıtımı uçtan uca denenebilir. | `agent/internal/simdata` |
| 8.12 | Docker imajı | Sunucu imajı Alpine üzerinde, root olmayan `ber` kullanıcısıyla çalışır; konsol dosyaları imaja gömülüdür. Sunucu adları `BER_HOSTNAMES` ile verilir. | `deploy/Dockerfile` |
| 8.13 | Ürün adı | Ürün adı **BerOps**'tur: paketler, servisler (`BerOpsServer`, `BerOpsAgent`), ikili dosyalar (`berops-*`), veri klasörleri, Go modülü ve depo adı buna göre adlandırıldı. Geriye dönük uyum ve kısalık için iç tanımlayıcılar korundu: `BER_*` ortam değişkenleri, `--ber-*` tasarım token'ları, `X-Ber-*` başlıkları, `berreg_` anahtar öneki, çerez ve tarayıcı depolama anahtarları. | Tüm depo |

