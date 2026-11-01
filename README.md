<p align="center"><img src="console/public/favicon.svg" width="84" height="84" alt="BerOps logosu"></p>

<h1 align="center">BerOps</h1>

<p align="center"><b>Yamalar, açıklar, uygulamalar. Tek konsoldan.</b> Windows ve macOS · Ajan tabanlı · Açık kaynak</p>

<p align="center">
  <a href="https://github.com/BerkayAtag/BerOps/releases/latest/download/BerOps-Server-x64.msi"><b>Sunucu kurulumunu indir</b></a> ·
  <a href="https://berkayatag.github.io/BerOps/">Tanıtım sayfası</a> ·
  <a href="docs/kurulum-sunucu.md">Sunucu kurulumu</a> ·
  <a href="docs/kurulum-ajan-windows.md">Windows ajanı</a> ·
  <a href="docs/kurulum-ajan-macos.md">macOS ajanı</a> ·
  <a href="CHANGELOG.md">Sürüm geçmişi</a>
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="landing/img/dashboard-tr-dark.webp">
  <img src="landing/img/dashboard-tr-light.webp" alt="BerOps gösterge paneli — demo verisi">
</picture>

Ajanlar eksik yamaları, üçüncü parti uygulamaları ve CVE'leri toplar. Siz riske göre önceliklendirir, imzalı ve kademeli dağıtımlarla kapatırsınız. Veriler kendi sunucunuzda kalır.

## Kurulum: İleri → Kur → Bitir

1. [BerOps-Server-x64.msi](https://github.com/BerkayAtag/BerOps/releases/latest/download/BerOps-Server-x64.msi) dosyasını Windows Server'da **yönetici olarak çalıştırın**. Linux için [Docker Compose](docs/kurulum-sunucu.md#docker-compose-linux).
2. **İleri:** PostgreSQL adresi, sunucu adı, isteğe bağlı TLS sertifikası ve ilk yönetici hesabı.
3. **Kur:** Servis, iç CA, güvenlik duvarı kuralları ve veritabanı şeması hazırlanır.
4. **Bitir:** `https://<sunucu>:8443` adresinde konsola girin. **Ajan indir** sayfası, kurulum komutunu sunucu adresi ve kayıt anahtarı gömülü olarak üretir:

```bat
msiexec /i BerOps-Agent-x64.msi /qn SERVER=https://ber.ornek.local:52311 REGKEY=berreg_… CAHASH=sha256:…
```

macOS için [BerOps-Agent.pkg](https://github.com/BerkayAtag/BerOps/releases/latest/download/BerOps-Agent.pkg) (Intel + Apple Silicon, MDM uyumlu). Programlar ve Özellikler'de **BerOps Server / BerOps Agent**, yayımcı **Berkay Atağ** görünür.

## Ekranlar

| Yamalar | Kademeli yama dağıtımı |
|---|---|
| <picture><source media="(prefers-color-scheme: dark)" srcset="landing/img/patches-tr-dark.webp"><img src="landing/img/patches-tr-light.webp" alt="Filo genelinde eksik yamalar"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="landing/img/rollout-tr-dark.webp"><img src="landing/img/rollout-tr-light.webp" alt="Kademeli yama dağıtımı ve aşama durumu"></picture> |
| **Güvenlik açıkları** | **Makine detayı** |
| <picture><source media="(prefers-color-scheme: dark)" srcset="landing/img/vulnerabilities-tr-dark.webp"><img src="landing/img/vulnerabilities-tr-light.webp" alt="Riske göre sıralı güvenlik açıkları"></picture> | <picture><source media="(prefers-color-scheme: dark)" srcset="landing/img/machine-tr-dark.webp"><img src="landing/img/machine-tr-light.webp" alt="Makine detayı: risk, envanter, yamalar"></picture> |

Ekranlar demo verisiyle (sanal ajanlar) gerçek uygulamadan alınmıştır. Konsol Türkçe/İngilizce ve aydınlık/karanlık temalıdır.

## Özellikler

- **Envanter:** Windows Update Agent ve `softwareupdate` ile eksik yamalar, yama seviyesi, üçüncü parti uygulamalar.
- **CVE motoru:** NVD, MSRC, CISA KEV ve EPSS; 0-100 risk skoru, PDF/Excel/CSV raporlar.
- **Dağıtım:** İşletim sistemi yamaları, paket kütüphanesi (MSI, EXE, PKG, DMG) ve komutlar. Ed25519 imzalı işler, SHA-256 doğrulama, istemci başına hız sınırı.
- **Kontrol:** Zamanlanmış başlatma, kademeli dağıtım (pilot halka, başarı eşiği), bakım pencereleri, bildirimli yeniden başlatma, komutlarda dört göz onayı.
- **Erişim:** LDAPS ile Active Directory, OU kapsamlı roller (Yönetici, Teknisyen, Salt okunur), dış sistemler için API anahtarları, değiştirilemez denetim kaydı.
- **Ölçek:** Şube relay'leri, e-posta/Teams/Slack bildirimleri, zamanlanmış raporlar, isteğe bağlı uzaktan yönetim.

## Mimari

```
BerOps ajanı ──mTLS 52311──▶ BerOps Server ◀──HTTPS 8443── Operatör (tarayıcı)
(Windows, macOS)             │   konsol · ajan API · CVE motoru
   ▲                         ├── PostgreSQL
   └── Relay (şube) ─mTLS────┘   └── LDAPS (Active Directory)
```

Go sunucu ve ajan, React/TypeScript konsol, PostgreSQL. Ayrıntı: [mimari](docs/mimari.md), [güvenlik modeli](docs/guvenlik.md), [varsayımlar](docs/varsayimlar.md).

## Ajan kaynak kullanımı

| Metrik | Hedef | Ölçülen (macOS, Apple Silicon) |
|---|---|---|
| Boşta CPU | < %1 | ~%0,07 |
| Bellek (RSS) | < ~50 MB | 11–16 MB (tam taramada en çok 21 MB) |

Tam envanter taraması 17–26 sn sürer; bu sürenin çoğu Apple sunucularına yapılan `softwareupdate` sorgusudur. Ajan süreci bu sürede 0,09 sn CPU kullanır.

## Geliştirme

Go 1.27+, Node.js 24+ ve Docker gerekir:

```bash
docker compose -f deploy/docker-compose.dev.yml up -d --wait
BER_TEST_DATABASE_URL='postgres://ber:ber@localhost:5432/postgres?sslmode=disable' go test -race ./...
npm --prefix console install && npm --prefix console test -- --run
```

Sunucu, ajan ve sanal ajanlarla çalıştırma: [geliştirme ortamı](docs/gelistirme.md).

## Belgeler

[Sunucu kurulumu](docs/kurulum-sunucu.md) · [Windows ajanı](docs/kurulum-ajan-windows.md) · [macOS ajanı](docs/kurulum-ajan-macos.md) · [Yama ve paket dağıtımı](docs/dagitim.md) · [Gelişmiş dağıtım](docs/gelismis-dagitim.md) · [CVE motoru](docs/cve.md) · [Active Directory](docs/ad-entegrasyonu.md) · [Roller](docs/roller-ve-yetkiler.md) · [Uzaktan yönetim](docs/uzaktan-yonetim.md) · [API](docs/api.md) · [Relay](relay/README.md) · [Katkı](CONTRIBUTING.md) · [Güvenlik](SECURITY.md)

Paketler kod imzalı değildir; dosyaları sürümdeki `SHA256SUMS.txt` ile doğrulayın.

---

<p align="center">© 2026 Berkay Atağ · BerOps · <a href="LICENSE">Apache-2.0</a></p>
