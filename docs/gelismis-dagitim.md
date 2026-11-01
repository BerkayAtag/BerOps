# Gelişmiş dağıtım: bakım pencereleri, kademeli dağıtım, relay ve bildirimler

Bu belge Aşama 7'de eklenen özellikleri anlatır. Temel dağıtım akışı için [dagitim.md](dagitim.md) belgesine bakın.

## Bakım pencereleri

Bakım penceresi; haftanın günleri, başlangıç saati, süre ve saat dilimiyle tanımlanır. İsteğe bağlı bir OU kapsamı verilebilir; boşsa tüm makinelere uygulanır.

- Aksiyon oluştururken **"Bakım penceresine uy"** seçilirse iş makineye yalnızca ona uyan pencerelerden biri açıkken verilir.
- Makineye uyan etkin pencere yoksa iş hemen verilir; yani pencere tanımlamak, bu seçeneği işaretlemeyen aksiyonları etkilemez.
- Gece yarısını aşan pencereler başladıkları güne aittir: "Cumartesi 23:00, 4 saat" penceresi Pazar 03:00'e kadar sürer.
- Pencere süresi 15 dakika ile 24 saat arasındadır. Pencereler 30 saniye önbelleğe alınır; değişiklik anında geçerli olur.
- İş pencere dışında bekler ama aksiyonun geçerlilik süresi işlemeye devam eder. Geçerlilik süresini en az bir pencereyi kapsayacak şekilde seçin.

Konsol: Ayarlar → Bakım pencereleri. Okuma `settings.read`, değiştirme `settings.write` ister.

## Kademeli dağıtım

Aksiyon, hedeflerin yüzdelerine bölünmüş 2–5 aşamada dağıtılabilir. Her aşamanın aksiyon oluşturulduktan sonra en erken açılacağı gecikme (saat) vardır. Sihirbazda iki hazır ayar bulunur:

| Hazır ayar | Aşamalar | En düşük başarı |
|---|---|---|
| Pilot | %10 hemen, %90 24 saat sonra | %90 |
| Halkalar | %5 hemen, %25 1 gün sonra, %70 3 gün sonra | %95 |

- Hedefler aşamalara aksiyon kimliğiyle karıştırılarak dağıtılır. Böylece pilot halka her aksiyonda aynı makinelerden oluşmaz, ama aynı aksiyon için dağılım hep aynıdır. Her aşamada en az bir makine bulunur.
- Sunucu her dakika denetler. Sonraki aşama şu koşullarda kendiliğinden açılır:
  - aşamanın gecikmesi dolmuştur,
  - açılmış hedeflerin en az yarısı sonuçlanmıştır,
  - başarı oranı eşiğin üzerindedir.
- Başarı oranı eşiğin altındaysa dağıtım **duraklatılır** ve nedeni aksiyon detayında gösterilir.
- Yetkili kullanıcı **"Sonraki aşamayı başlat"** düğmesiyle beklemedeki veya duraklatılmış aşamayı elle açabilir. Bu işlem denetim kaydına yazılır.
- Kademeli dağıtım ve bakım penceresi birlikte kullanılabilir: açılan aşamanın işleri de pencere içinde verilir.

## Gruplar ve etiketler

**Gruplar** ekranında iki tür grup tanımlanır:

- **Statik:** Üyeler elle seçilir. Makineler listesinde seçim yapıp **Gruba ekle** ile eklenir.
- **Dinamik:** Üyeler bir kurala göre her sorguda yeniden hesaplanır. Kural en çok 10 koşuldan oluşur; **Tüm koşullar** (ve) veya **Herhangi bir koşul** (veya) ile birleştirilir. Kaydetmeden önce **Önizle** ile eşleşen makineler görülür.

| Alan | İşlemler | Örnek |
|---|---|---|
| Platform | eşittir | `windows`, `darwin` |
| İşletim sistemi | içerir, eşittir | `Windows 11` |
| Yama seviyesi (build) | sürümü küçüktür, sürümü büyük/eşittir, ile başlar | `10.0.22631.4460` |
| Makine adı | içerir, ile başlar, eşittir | `WS-` |
| AD OU | altında | `OU=Şubeler,DC=ornek,DC=local` |
| Etiket | var | `pilot` |
| Uygulama | kurulu, kurulu değil, sürümü küçüktür, sürümü büyük/eşittir | `Chrome` sürümü küçüktür `120` |
| Eksik yama | var | `KB5046617` |
| Ajan sürümü | sürümü küçüktür, sürümü büyük/eşittir | `1.2.0` |
| Risk skoru | en az | `80` |

- Sürümler sayı dizisi olarak karşılaştırılır (`10.0.9` < `10.0.10`).
- Koşullar sunucudaki beyaz listeyle doğrulanır ve parametreli SQL'e çevrilir; serbest sorgu yazılamaz.
- Grup tanımları herkese görünür; üye sayısı ve üyeler kullanıcının OU kapsamına göre süzülür.
- **Etiketler** makine detayından eklenir (makine başına en çok 20; harf, rakam, boşluk, `.`, `_`, `-`; en çok 40 karakter). Makineler listesi etiket ve gruba göre süzülebilir.
- Grup ekranındaki **Aksiyon gönder**, sihirbazı o grup seçili olarak açar.

## Relay

Şubelerdeki ajanlar sunucuya relay üzerinden bağlanır, paketler relay'de önbelleğe alınır. Kurulum ve çalışma biçimi: [relay/README.md](../relay/README.md).

Güvenlik özeti:

- Relay sertifikasının CN değeri `relay:<id>` biçimindedir. Sertifikada hem sunucu hem istemci kullanımı (EKU) bulunur.
- Sunucu, `X-Ber-Agent-Cert` başlığına yalnızca kaydı olan ve iptal edilmemiş bir relay'in sertifikasıyla gelen bağlantılarda güvenir.
- İletilen ajan sertifikası iç CA'ya göre yeniden doğrulanır. Relay sertifikası ajan sertifikası yerine kullanılamaz.
- Relay'in paket dosyası uç noktası yalnızca relay sertifikasına açıktır. Relay, bu dosyayı ancak bir ajanın yetkili indirme isteğinden sonra çeker.

## Bildirimler

Kanallar e-posta (SMTP) veya webhook olabilir. Her kanal hangi olaylara abone olduğunu seçer.

| Olay | Ne zaman? |
|---|---|
| `action.completed` | Aksiyon tamamlandığında (son 2 saat içinde tamamlananlar). Başlıkta başarısız hedef sayısı yer alır. |
| `vulnerability.kev_new` | Son 7 günde CISA KEV kataloğuna eklenen ve filoda bulunan açık |
| `cve.sync_failed` | Bir CVE kaynağı (NVD, MSRC, KEV, EPSS) eşitlenemediğinde, kaynak ve gün başına bir kez |

- Her olay tekilleştirilir (`notification_events.dedupe_key`). Aynı olay ikinci kez gönderilmez; sunucu yeniden başlasa da bu korunur.
- **E-posta:** STARTTLS (varsayılan, 587), doğrudan TLS (465) veya şifresiz (yalnızca iç ağ). Kimlik doğrulama PLAIN'dir; Go'nun SMTP istemcisi PLAIN'i şifresiz bağlantıda yalnızca localhost için kabul eder.
- **Webhook:** Yalnızca `https` adresleri kabul edilir (`http` yalnızca localhost/127.0.0.1 için, test amaçlı). Biçimler:
  - `generic`: `{event, title, text, payload, occurred_at}`
  - `teams`: MessageCard
  - `slack`: `{text}`
- **İmza:** İmza anahtarı girilirse gövde HMAC-SHA256 ile imzalanır ve `X-Ber-Signature: sha256=<hex>` başlığında gönderilir.
- SMTP parolası ve HMAC anahtarı AES-256-GCM ile şifrelenerek saklanır ve API'den hiçbir zaman dönmez.
- Webhook adresleri (Slack/Teams) kendileri gizli değer sayıldığı için bildirim ayarları yalnızca `settings.write` iznine sahip kullanıcılara gösterilir.
- Her kanalın son gönderim zamanı ve son hatası konsolda görünür. **Dene** düğmesi deneme iletisi gönderir.

### Zamanlanmış raporlar

Uyumluluk, güvenlik açıkları, eksik yamalar ve uygulama envanteri raporları PDF, Excel veya CSV olarak, haftanın belirli bir günü ya da her gün belirli bir saatte bir e-posta kanalına ek olarak gönderilir.

- Raporlar tüm filo için üretilir (kullanıcı kapsamı uygulanmaz). Bu nedenle zamanlama yalnızca `settings.write` izniyle yapılabilir.
- Aynı zamanlama iki saat içinde ikinci kez çalışmaz. Sunucu o saat içinde kapalıysa rapor bir sonraki uygun zamana kalır.
- Her gönderim denetim kaydına `report.scheduled` olarak yazılır.
