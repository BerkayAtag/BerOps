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
