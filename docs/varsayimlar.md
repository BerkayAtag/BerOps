# Varsayımlar ve Kararlar

Spesifikasyonda belirsiz kalan noktalar için yapılan varsayımlar burada tutulur. Her madde, değiştirilmesi gerekirse etkilenecek yeri de belirtir.

## Aşama 1 — Temel altyapı

| # | Konu | Varsayım / Karar | Etkilenen yer |
|---|---|---|---|
| 1.1 | Go modül yolu | `github.com/BerkayAtag/automation-ber` (GitHub deposuyla aynı). | `go.mod`, tüm Go dosyaları |
| 1.2 | Birincil renk | `#DC0005` spesifikasyondaki örnek değerdir; resmi marka rehberinden teyit edilmedi. Değer yalnızca `design/tokens.css` içinde tanımlıdır. | `design/tokens.css` |
| 1.3 | Lisans | **Apache License 2.0**: patent hakkı devri içerir, kurumsal kullanımda yaygın kabul görür ve atıf koruması sağlar. | `LICENSE` |
| 1.4 | Ajan portu | `52311/tcp`. BigFix ile aynı port numarası kurumsal güvenlik duvarlarında tanıdıktır. Yapılandırılabilir. | `server` yapılandırması |
| 1.5 | Konsol portu | `8443/tcp` varsayılan, kurulum sihirbazında değiştirilebilir. | `server` yapılandırması |
| 1.6 | İlk güven (bootstrap) | Ajan, kurulum parametresi olarak verilen **CA parmak izi** (`CAHASH`) ile sunucuyu doğrular. Parmak izi olmadan kayıt yapılmaz. Konsoldaki "Ajan İndir" sayfası (Aşama 8) bu değeri komutlara otomatik ekler. | `agent`, kurulum belgeleri |
| 1.7 | Ajan sertifika süresi | 1 yıl. Otomatik yenileme Aşama 4'te (self-update ile birlikte) eklenecek. | `server/internal/pki` |
| 1.8 | CA anahtarının saklanması | Aşama 1'de `data_dir/pki/ca.key` dosyasında, yalnızca servis hesabının okuyabileceği izinlerle (0600) tutulur. Windows'ta DPAPI ile şifreleme Aşama 8'de (MSI kurulumu) eklenecek. | `server/internal/pki` |
| 1.9 | Onay gerektiren kayıt | Makineye sertifika hemen verilir ancak durum `pending` olur. Onaylanana kadar iş gönderilmez; reddedilirse sertifika geçersiz sayılır. Bu yaklaşım ajanın ayrıca sertifika beklemek için yoklama yapmasını gereksiz kılar. | `server/internal/api` |
| 1.10 | Yeniden kayıt | Aynı makine yeniden kurulursa yeni bir ajan ID'si alır; eski kayıt çevrimdışı görünür. Hostname/donanım kimliğiyle birleştirme Aşama 2'de ele alınacak. | `machines` |
| 1.11 | İlk admin | Kurulum sihirbazı (Aşama 8) yazılana kadar ilk admin `ber-server admin create` komutuyla oluşturulur. | `server/cmd/ber-server` |
| 1.12 | Teknisyen ve yama dağıtımı | Spesifikasyon teknisyene yalnızca "kayıtlı paket gönderme" yetkisi tanıyor. İşletim sistemi yaması dağıtma (`actions.deploy_patch`) bu nedenle teknisyende **yok**; Aşama 5'te özel rollerle eklenebilir. | `server/internal/auth/rbac.go` |
| 1.13 | Salt Okunur ve dışa aktarma | Rapor dışa aktarma veri değiştirmediği için Salt Okunur rolünde açıktır. | `server/internal/auth/rbac.go` |
| 1.14 | CSP ve satır içi stil | `style-src 'self' 'unsafe-inline'`: grafik kütüphaneleri (Recharts) satır içi `style` niteliği kullanır. Betikler için `'unsafe-inline'` yoktur. | `server/internal/api/middleware.go` |
| 1.15 | Yapılandırma dosyası | Sunucu YAML yapılandırma dosyası (`ber-server.yaml`) + ortam değişkeni geçersiz kılmaları. Kurulum sihirbazı bu dosyayı yazar. | `server/internal/config` |
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
