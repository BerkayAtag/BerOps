# Automation BER

**Ajan tabanlı yama ve üçüncü parti uygulama yönetim platformu.** Windows ve macOS istemcilerdeki eksik işletim sistemi yamalarını, üçüncü parti uygulamaları ve güvenlik açıklarını tek bir tarayıcı tabanlı konsoldan izleyin ve dağıtımı kontrollü şekilde yapın.

Mimari, BigFix'in Server / Relay / Agent / Console modelini örnek alır.

> **Durum:** Geliştirme aşamasında. **Aşama 1 (Temel altyapı)** tamamlandı. Yol haritası aşağıda.

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

## Ajan kaynak kullanımı

Ölçüm: macOS 27 (Apple Silicon), ajan heartbeat aralığı 10 sn (varsayılan 60 sn'den 6 kat sık), 70 sn boyunca 5 sn aralıkla `ps` örneklemesi.

| Metrik | Hedef | Ölçülen |
|---|---|---|
| Boşta CPU | < %1 | ~%0,07 (70 sn'de toplam 0,05 sn CPU süresi) |
| Bellek (RSS) | < ~50 MB | 11–16 MB |

Aynı test sırasında 50 sanal ajan da aynı sunucuya kaydolup heartbeat gönderdi; tümü başarılı oldu. Envanter taraması Aşama 2'de eklendiğinde ölçümler Windows ve macOS'ta tekrarlanacak.

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

### Sanal ajanlar

```bash
go run ./agent/cmd/ber-agentsim -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi> -n 100
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
| 2 | Envanter: yama seviyesi, eksik yamalar, üçüncü parti uygulamalar; kaynak kısıtlama; makine listesi ve detay | ⏳ |
| 3 | CVE motoru: NVD, MSRC, KEV, EPSS; risk skoru; dashboard ve raporlar | ⏳ |
| 4 | Dağıtım: paket kütüphanesi, hız limitli ve imzalı transfer, aksiyonlar | ⏳ |
| 5 | Active Directory (LDAPS) ve RBAC kapsamları, denetim kaydı ekranı | ⏳ |
| 6 | Uzaktan yönetim: performans, servisler, registry (opt-in) | ⏳ |
| 7 | Relay, bakım pencereleri, kademeli dağıtım, bildirimler | ⏳ |
| 8 | MSI ve pkg kurulum paketleri, release iş akışı, tanıtım sayfası | ⏳ |

## Dokümantasyon

- [Mimari](docs/mimari.md)
- [Varsayımlar ve kararlar](docs/varsayimlar.md)
- [API](docs/api.md)
- [Katkıda bulunma](CONTRIBUTING.md)
- [Güvenlik politikası](SECURITY.md)
- [Değişiklik günlüğü](CHANGELOG.md)

## Lisans

[Apache License 2.0](LICENSE). Geliştiren: **Berkay Atağ**.
