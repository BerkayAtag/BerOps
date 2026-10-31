# Automation BER

**Ajan tabanlı yama ve üçüncü parti uygulama yönetim platformu.** Windows ve macOS istemcilerdeki eksik işletim sistemi yamalarını, üçüncü parti uygulamaları ve güvenlik açıklarını tek bir tarayıcı tabanlı konsoldan izleyin ve dağıtımı kontrollü şekilde yapın.

Mimari, BigFix'in Server / Relay / Agent / Console modelini örnek alır.

> **Durum:** Geliştirme aşamasında. **Aşama 1 (Temel altyapı)**, **Aşama 2 (Envanter ve tespit)** ve **Aşama 3 (CVE motoru ve raporlar)** tamamlandı. Yol haritası aşağıda.

## Bileşenler

| Bileşen | Açıklama |
|---|---|
| **BER Server** | Merkezi API, PostgreSQL veritabanı, iç sertifika otoritesi, ajan kaydı, iş kuyruğu |
| **BER Relay** | Şubeler için önbellekleyen dağıtım noktası (Aşama 7) |
| **BER Agent** | Windows servisi / macOS `launchd` daemon'ı olarak çalışan hafif Go ajanı |
| **BER Console** | React + TypeScript tarayıcı konsolu; Türkçe/İngilizce, açık/karanlık tema |

Ayrıntılar: [docs/mimari.md](docs/mimari.md)

## Aşama 1'de neler var?

- **Ajan kaydı ve heartbeat (mTLS):** Ajan kendi anahtarını üretir, kayıt anahtarı ve CA parmak iziyle (pin) sunucuya kaydolur, sunucunun iç CA'sından istemci sertifikası alır ve heartbeat'leri karşılıklı TLS ile gönderir.
- **Kayıt anahtarları:** Kullanım sayısı, geçerlilik süresi ve isteğe bağlı yönetici onayı. Veritabanında yalnızca özetleri saklanır.
- **Konsol girişi:** Argon2id parola özeti, `HttpOnly`/`Secure`/`SameSite=Strict` oturum çerezi, CSRF koruması, boşta kalma zaman aşımı ve giriş denemesi hız sınırı.
- **RBAC temeli:** Granüler izinler ve Admin / Teknisyen / Salt Okunur rolleri, her uç noktada sunucu tarafında zorunlu.
- **Değiştirilemez denetim kaydı:** `audit_log` tablosunda UPDATE, DELETE ve TRUNCATE veritabanı trigger'larıyla engelli.
- **Konsol:** Giriş ekranı, gösterge paneli iskeleti, Türkçe varsayılan + İngilizce, işletim sistemi tercihini izleyen ve seçimi hatırlayan karanlık mod.
- **Sanal ajan simülatörü:** Yüzlerce ajanı tek süreçte simüle eden `ber-agentsim`.

## Aşama 2'de neler var?

- **Windows tespiti:** Yama seviyesi (ör. `10.0.22631.4460`), kurulu KB'ler, Windows Update Agent ile eksik güncellemeler (çevrimiçi veya sunucudaki `wsusscn2.cab` ile çevrimdışı; KB, sınıflandırma, MSRC önemi, CVE'ler, yeniden başlatma gereksinimi), kayıt defteri/MSI/AppX uygulamaları, AD OU ve bekleyen yeniden başlatma.
- **macOS tespiti:** macOS sürümü ve build numarası, `softwareupdate --list` ile eksik güncellemeler, kurulum geçmişi, `.app` paketleri, pkg makbuzları ve Homebrew.
- **Kaynak kısıtlama:** Windows'ta Job Object ile sert CPU sınırı ve IDLE öncelik, macOS'ta arka plan QoS; ajan içi işler için CPU bütçesi; pil ve kullanıcı etkinliğinde erteleme.
- **Delta gönderim:** Bölüm özetleriyle yalnızca değişen bölümler gönderilir; sunucu tutarsızlık görürse tam envanter ister.
- **Konsol:** Arama, filtre, sıralama, sayfalama ve toplu seçimli makine listesi; eksik/kurulu yama ve uygulama sekmeli makine detay sayfası; gösterge panelinde uyumluluk ve dağılım; ajan ayarları sayfası; konsoldan yeniden tarama.
- **Tanılama:** `ber-agent inventory [-full] [-json]` envanteri makinede toplayıp yazdırır.

## Aşama 3'te neler var?

- **CVE kaynakları:** CISA KEV, FIRST EPSS, Microsoft MSRC ve NVD sunucuda eşitlenir (24 saatte bir, artımlı). İnternet erişimi olmayan ortamlar için çevrimdışı klasör desteği vardır.
- **Windows açıkları:** Makinenin yapı numarası MSRC'nin düzeltme yapısıyla karşılaştırılır. Böylece eksik toplu güncellemenin kapattığı tüm CVE'ler bulunur, Windows Update'in CVE listesinde görünmeyenler dahil. Eksik KB'ler de MSRC eşlemesiyle CVE'ye bağlanır.
- **macOS ve üçüncü parti uygulamalar:** NVD'ye karşı doğrulanmış 40'tan fazla ürünlük sözlükle (tarayıcılar, PDF, sıkıştırma, uzaktan erişim, geliştirici araçları, Homebrew) CPE eşleştirmesi ve sürüm aralığı kontrolü yapılır. Sözlükte olmayan uygulamalar için konsoldan özel kural eklenebilir.
- **Risk skoru (0–100):** CVSS, EPSS olasılığı, CISA KEV ve fidye yazılımı bilgisini birleştirir. Aktif istismar edilen açıklar öne çıkar. Formül: [docs/cve.md](docs/cve.md).
- **Konsol:** Güvenlik açıkları listesi ve CVE detayı (etkilenen makineler, düzelten KB'ler, KEV kaydı), makine detayında risk kartları ve açık sekmesi, gösterge panelinde risk özeti, önem dağılımı, 30 günlük uyumluluk eğilimi, en riskli açıklar ve makineler, CVE kaynakları ayar sayfası.
- **Raporlar:** Uyumluluk, zafiyet, eksik yama ve uygulama envanteri raporları PDF, Excel ve CSV olarak; Türkçe veya İngilizce, kullanıcının saat diliminde. Her dışa aktarma denetim kaydına yazılır.

Gerçek kaynaklarla ölçüm (MacBook, PostgreSQL 17, API anahtarı olmadan): ilk eşitleme 3 dk 24 sn sürdü (KEV 1 sn, EPSS 1,4 sn, MSRC 12 ay 47 sn, NVD 41 ürün 2 dk 29 sn). 31 makinenin yeniden hesaplanması 5,6 sn sürdü.

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

Sunucu yapılandırmasını oluşturun (`ber-server.yaml`, git'e eklenmez):

```yaml
data_dir: ./data
database_url: postgres://ber:ber@localhost:5432/ber_dev?sslmode=disable
```

İlk admin hesabını oluşturun ve sunucuyu başlatın:

```bash
go run ./server/cmd/ber-server admin create -username admin
```

```bash
go run ./server/cmd/ber-server serve
```

Konsolu geliştirme modunda açın (API istekleri `https://localhost:8443` adresine aktarılır):

```bash
npm --prefix console install && npm --prefix console run dev
```

Tarayıcıda `http://localhost:5173` adresine gidin.

### Ajanı kaydetmek

Kayıt anahtarı oluşturun; komut CA parmak izini de yazdırır:

```bash
go run ./server/cmd/ber-server regkey create -name "Geliştirme"
```

Ajanı kaydedip çalıştırın (yönetici yetkisi gerekmez, `-data-dir` ile yerel bir klasör kullanılır):

```bash
go run ./agent/cmd/ber-agent enroll -data-dir ./agent-data -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi>
```

```bash
go run ./agent/cmd/ber-agent run -data-dir ./agent-data
```

### Envanteri yerelde denemek

Sunucuya göndermeden bu makinenin envanterini görmek için (`-full` eksik güncelleme taramasını da yapar):

```bash
go run ./agent/cmd/ber-agent inventory -full
```

### CVE verisini eşitlemek

Sunucu açıldıktan bir dakika sonra kaynakları kendisi eşitler. Hemen eşitlemek için:

```bash
go run ./server/cmd/ber-server cve sync
```

### Sanal ajanlar

Gerçek ajanla aynı zamanlayıcıyı kullanan, gerçekçi sahte envanter (eksik KB'ler, CVE'ler, güncel olmayan uygulamalar, AD OU'ları) gönderen sanal ajanlar:

```bash
go run ./agent/cmd/ber-agentsim -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi> -n 100 -first-scan 30s
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
| 4 | Dağıtım: paket kütüphanesi, hız limitli ve imzalı transfer, aksiyonlar | ⏳ |
| 5 | Active Directory (LDAPS) ve RBAC kapsamları, denetim kaydı ekranı | ⏳ |
| 6 | Uzaktan yönetim: performans, servisler, registry (opt-in) | ⏳ |
| 7 | Relay, bakım pencereleri, kademeli dağıtım, bildirimler | ⏳ |
| 8 | MSI ve pkg kurulum paketleri, release iş akışı, tanıtım sayfası | ⏳ |

## Dokümantasyon

- [Mimari](docs/mimari.md)
- [CVE motoru ve raporlar](docs/cve.md)
- [Varsayımlar ve kararlar](docs/varsayimlar.md)
- [API](docs/api.md)
- [Katkıda bulunma](CONTRIBUTING.md)
- [Güvenlik politikası](SECURITY.md)
- [Değişiklik günlüğü](CHANGELOG.md)

## Lisans

[Apache License 2.0](LICENSE). Geliştiren: **Berkay Atağ**.
