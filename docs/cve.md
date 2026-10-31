# CVE Motoru

Automation BER, makinelerden gelen envanteri dört açık kaynakla eşleştirerek her makinedeki güvenlik açıklarını (CVE) ve önceliklerini hesaplar. Ajanlar internete çıkmaz; tüm kaynak verisi sunucuda tutulur.

## Kaynaklar

| Kaynak | Ne sağlar | Adres | Varsayılan eşitleme |
|---|---|---|---|
| **CISA KEV** | Aktif olarak istismar edilen açıklar, fidye yazılımı kullanımı, düzeltme son tarihi | `cisa.gov/…/known_exploited_vulnerabilities.json` | 24 saatte bir, tamamı |
| **FIRST EPSS** | Önümüzdeki 30 günde istismar edilme olasılığı (0–1) | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | 24 saatte bir, tamamı (~400 bin CVE) |
| **Microsoft MSRC** | Windows güvenlik güncellemeleri: KB → CVE eşlemesi, ürün başına düzeltme yapısı (`FixedBuild`), önem, istismar durumu | `api.msrc.microsoft.com/cvrf/v3.0` | Son 12 aylık belge; yalnızca değişen belgeler yeniden indirilir |
| **NVD (NIST)** | CVSS skorları, açıklamalar, üçüncü parti uygulamaların savunmasız sürüm aralıkları (CPE) | `services.nvd.nist.gov/rest/json/cves/2.0` | İlk seferde takip edilen her ürün için tam çekim, sonra son değişiklik tarihine göre artımlı |

NVD'den bütün veritabanı değil, yalnızca **takip edilen ürünler** (aşağıdaki sözlük + özel kurallar) ve veritabanında zaten bulunan CVE'lerin güncellemeleri çekilir. İlk eşitleme API anahtarı olmadan yaklaşık 3–5 dakika sürer; NVD API anahtarı (`BER_NVD_API_KEY`) bu süreyi kısaltır.

## Eşleştirme

Her makine için üç yoldan bulgu üretilir; aynı CVE birden fazla yoldan gelirse tek bulguda birleşir.

| Kaynak etiketi | Platform | Yöntem |
|---|---|---|
| `os_build` | Windows | Makinenin yapı numarası (ör. `10.0.22631.4460`), MSRC'de aynı yapı ailesi (`10.0.22631`) için verilen düzeltme yapısından (`10.0.22631.7652`) küçükse işletim sistemi savunmasızdır. Toplu güncellemeler kümülatif olduğundan bu karşılaştırma, eksik toplu güncellemenin kapattığı ama Windows Update'in CVE listesinde göstermediği açıkları da yakalar. |
| `missing_patch` | Windows | Eksik güncellemenin Windows Update'ten gelen CVE listesi ve MSRC'deki KB → CVE eşlemesi (Office, .NET gibi işletim sistemi dışı Microsoft ürünleri dahil). |
| `os` | macOS | macOS sürümü (ör. `15.1`) NVD'deki `apple:macos` sürüm aralıklarıyla karşılaştırılır. |
| `app` | İkisi de | Kurulu uygulama, ürün sözlüğüyle bir CPE ürününe (ör. `google:chrome`) eşlenir ve sürümü NVD aralıklarıyla karşılaştırılır. |

Eşleşmede dikkate alınmayanlar:

- NVD'de hiçbir sürüm sınırı taşımayan ("tüm sürümler") kayıtlar. Bunlar çoğunlukla protokol düzeyindeki eski açıklardır (ör. TLS BEAST) ve düzeltme sürümleri olmadığından aksiyon alınamaz.
- macOS paket makbuzları (`pkgutil`). Makbuz kurulum anındaki sürümü tutar ve kendini güncelleyen uygulamalarda eski kalır; gerçek sürüm `.app` paketinden okunur.
- Güncelleme alanı belirli bir değer taşıyan tam sürüm CPE'leri (ör. `macos:10.15.7:security_update_2021-001`).

### Ürün sözlüğü

Yerleşik sözlük [server/internal/cve/products.json](../server/internal/cve/products.json) dosyasındadır. Sözlükte yaygın tarayıcılar, ofis ve PDF uygulamaları, sıkıştırma araçları, uzaktan erişim yazılımları, geliştirici araçları ve Homebrew paketleri yer alır. Her kural şunları içerir:

- `name`: uygulama adı kalıbı (büyük/küçük harf duyarsız düzenli ifade).
- `identifier`: MSI ürün kodu, bundle kimliği veya Homebrew formül adı kalıbı (isteğe bağlı).
- `publisher`: yayıncı kalıbı (isteğe bağlı).
- `vendor:product`: NVD CPE adı.

Tüm CPE adları NVD'ye karşı doğrulanmıştır. Sözlükte olmayan bir uygulama için **Ayarlar → CVE kaynakları → Uygulama → CPE kuralları** ekranından özel kural eklenir. Özel kurallar yerleşik sözlükten önce uygulanır. Yeni bir ürün eklendiğinde o ürünün CVE'leri hemen eşitlenir.

## Risk skoru

Her bulgunun 0–100 arası bir önceliklendirme skoru vardır:

```
risk = CVSS taban skoru × 6          (en fazla 60)
     + EPSS olasılığı × 25            (en fazla 25)
     + 15  CISA KEV'de veya Microsoft "istismar edildi" diyorsa
     + 5   fidye yazılımı kampanyalarında kullanıldığı biliniyorsa
```

CVSS yoksa önem derecesinden tahmini skor kullanılır (Kritik 9,5 · Yüksek/Önemli 7,5 · Orta 5 · Düşük 2,5 · bilinmiyor 5).

| Düzey | Skor | Anlamı |
|---|---|---|
| Acil | ≥ 80 | Aktif istismar edilen yüksek etkili açık; hemen kapatılmalı |
| Yüksek | 60–79 | Kısa vadede planlanmalı |
| Orta | 40–59 | Normal yama döngüsünde |
| Düşük | < 40 | İzlenmeli |

Bu formülle, aktif istismar edilen orta skorlu bir açık (CVSS 6,5 + KEV + EPSS %90 → 81,5), istismarı bilinmeyen kritik bir açığın (CVSS 9,8 → 58,8) önüne geçer. Makinenin risk skoru, üzerindeki en yüksek bulgu skorudur.

## Çevrimdışı (internet erişimi olmayan) ortamlar

`ber-server.yaml` içinde `cve.offline_dir` tanımlanırsa sunucu internete çıkmaz; kaynakları bu klasörden okur:

```
offline_dir/
├── kev.json                          (known_exploited_vulnerabilities.json da olur)
├── epss_scores-current.csv.gz        (epss*.csv veya epss*.csv.gz)
├── msrc/
│   ├── 2026-Sep.json                 (https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep, Accept: application/json)
│   └── 2026-Oct.json
└── nvd/
    ├── nvdcve-2.0-2025.json.gz       (https://nvd.nist.gov/feeds/json/cve/2.0/ yıllık dosyaları)
    └── nvdcve-2.0-2026.json.gz
```

Dosyalar internete erişimi olan bir makinede indirilip taşınabilir ortamla aktarılır. MSRC belgeleri dosya değişiklik zamanına göre yalnızca değişince yeniden işlenir.

## Yapılandırma

```yaml
cve:
  enabled: true          # false: eşitleme yapılmaz, mevcut veriyle hesaplama sürer
  sync_interval: 24h     # en az 1h
  msrc_months: 12        # 1–60; Windows yapı karşılaştırmasının geriye dönük kapsamı
  offline_dir: ""        # doluysa çevrimdışı mod
  # nvd_api_key: dosyada tutmayın, BER_NVD_API_KEY ortam değişkenini kullanın
```

Sunucu proxy kullanıyorsa standart `HTTPS_PROXY` ortam değişkeni dikkate alınır.

Eşitleme sunucu açıldıktan bir dakika sonra ve sonra her 15 dakikada bir kontrol edilir; aralığı dolan kaynaklar eşitlenir, hata veren kaynak bir saat sonra yeniden denenir. Konsoldan **Şimdi eşitle** veya komut satırından hemen eşitlenebilir:

```bash
ber-server cve sync -config ber-server.yaml
```

```bash
ber-server cve sync -config ber-server.yaml -feeds kev,epss
```

## Raporlar

**Raporlar** sayfasından ve zafiyet listesinden dört rapor PDF, Excel (XLSX) ve CSV olarak alınır:

| Rapor | İçerik |
|---|---|
| Uyumluluk | Makine başına eksik yama, açık sayısı, KEV, en yüksek risk, yeniden başlatma, durum, OU |
| Zafiyet | CVE, başlık, önem, CVSS, EPSS, KEV, risk, etkilenen makine, kaynak, yayın tarihi |
| Eksik yama | Makine × eksik güncelleme: KB/sürüm, sınıflandırma, önem, yayın tarihi, CVE sayısı |
| Uygulama envanteri | Uygulama, sürüm, yayıncı, platform, makine sayısı |

- Raporlar kullanıcının dilinde (Türkçe/İngilizce) ve saat diliminde oluşturulur.
- Her dışa aktarma denetim kaydına yazılır.
- PDF en fazla 5000 satır içerir; daha büyük raporlar için Excel kullanılmalıdır.
- CSV dosyaları UTF-8 BOM ile yazılır. Hesap tablosu formül enjeksiyonuna karşı `=`, `+`, `-`, `@` ile başlayan metinlerin başına `'` eklenir.

## Sınırlamalar

- NVD yapılandırmalarındaki "şu platformda çalışırken" (AND) koşulları değerlendirilmez; uygulama sürümü aralıktaysa platformdan bağımsız savunmasız sayılır. Bu ihtiyatlı (fazla raporlayan) bir yaklaşımdır.
- Sürüm karşılaştırması sayısal parçalara göre yapılır. OpenSSL'in eski `1.1.1w` gibi harf sonekli sürümleri, `1.1.1` ile karşılaştırıldığında ön sürüm sayılır.
- Linux istemciler kapsam dışıdır; MSRC'deki Azure Linux kayıtları saklanmaz.
