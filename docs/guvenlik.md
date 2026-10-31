# Güvenlik modeli

Bu belge Automation BER'in güvenlik kararlarını ve sınırlarını özetler. Güvenlik açığı bildirimi için [SECURITY.md](../SECURITY.md) dosyasına bakın.

## Güven zinciri

| Bileşen | Mekanizma |
|---|---|
| **İç sertifika otoritesi** | Sunucu ilk açılışta ECDSA P-256 kök CA üretir (`data/pki/ca.key`, 0600). Ajan, relay ve (isteğe bağlı) konsol sertifikalarını bu CA imzalar. |
| **Ajan → sunucu** | Kayıt dışındaki tüm ajan istekleri karşılıklı TLS (mTLS) ile yapılır. Ajan, kurulumda verilen **CA parmak izini** sabitler. Böylece sahte bir sunucuya veya TLS'i açan bir vekil sunucuya bağlanmaz. |
| **Kayıt** | Tek kullanımlık ya da sınırlı kullanımlı kayıt anahtarı gerekir. Anahtar sunucuda yalnızca özet olarak saklanır ve isteğe bağlı olarak yönetici onayı ister. Ajanın özel anahtarı makineden çıkmaz (CSR ile imzalatılır). |
| **İş imzası** | Her iş, sunucunun Ed25519 aksiyon anahtarıyla **makine başına** imzalanır. İmza makine kimliği, son geçerlilik zamanı ve paket SHA-256 özetini kapsar. Ajan anahtarı ilk heartbeat'te sabitler; imzası geçersiz, süresi dolmuş veya başka makineye ait işi reddeder. İş günlüğü tekrar oynatmayı engeller. |
| **Dosya bütünlüğü** | İndirilen paket SHA-256 ile doğrulanmadan çalıştırılmaz. Relay de önbelleğe almadan önce özeti doğrular. |
| **Relay** | Relay'in kendi sertifikası vardır (CN `relay:<id>`). Sunucu, ajan kimliği başlığına yalnızca kayıtlı ve iptal edilmemiş relay bağlantısında güvenir ve iletilen ajan sertifikasını yeniden doğrular. |

## Konsol ve API

- **Yetki kontrolü** her API uç noktasında sunucu tarafında yapılır (`authed(izin, …)`). Arayüzdeki gizleme yalnızca kullanıcı deneyimi içindir. Reddedilen istekler denetim kaydına yazılır.
- **OU kapsamı:** Teknisyen ve salt okunur kullanıcılar OU kapsamıyla sınırlandırılabilir. Makine, açık, rapor ve aksiyon sorguları kapsama göre süzülür; kapsam dışı hedefli aksiyonlar reddedilir.
- **Oturum:**
  - `__Host-` önekli, `Secure`, `HttpOnly`, `SameSite=Strict` çerez.
  - 30 dakika boşta kalma ve 12 saat mutlak süre sınırı.
  - Durum değiştiren isteklerde CSRF token'ı.
- **Parolalar:** Argon2id ile özetlenir (64 MiB, t=3, p=2) ve en az 12 karakter olmalıdır. Giriş denemeleri hız sınırına tabidir.
- **Active Directory:** Yalnızca LDAPS. Hizmet hesabı parolası şifreli saklanır ve API'den dönmez.
- **HTTP başlıkları:** Katı CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors 'none'`. Dosya indirmeleri `attachment` ve `sandbox` ile sunulur.
- **Dört göz ilkesi:** Serbest komut aksiyonları isteğe bağlı olarak ikinci bir yöneticinin onayını gerektirir. Oluşturan kişi kendi aksiyonunu onaylayamaz.

## Gizli değerler

AD hizmet hesabı parolası, SMTP parolası ve webhook imza anahtarı AES-256-GCM ile şifrelenir (`data/pki/secret.key`) ve API yanıtlarında hiç dönmez. Webhook adresleri (Slack/Teams) de gizli sayılır; bildirim ayarlarını yalnızca `settings.write` iznine sahip kullanıcılar görebilir. Kurulum paketleri parolaları MSI günlüğüne yazmaz (gizli özellikler).

## Uzaktan yönetim

Uzaktan yönetim varsayılan olarak kapalıdır:

- Genel ana anahtar ve makine başına özellikler ayrı ayrı açılır.
- Ajan, kapalı özelliğe gelen isteği kendisi de reddeder.
- İstekler imzalıdır ve 40 saniye geçerlidir.
- Durum değiştiren işlemler, sonucu beklenmeden önce denetim kaydına yazılır. Kayıt defteri değişikliklerinde önceki değer de kaydedilir.

## Denetim kaydı

Giriş, yetki reddi, ayar değişikliği, aksiyon, onay, uzaktan işlem ve dışa aktarma gibi olaylar `audit_log` tablosuna yazılır. Tablo veritabanı tetikleyicileriyle değiştirilemez ve silinemez.

## Bildirimler

Webhook istekleri isteğe bağlı olarak `X-Ber-Signature: sha256=<HMAC>` başlığıyla imzalanır. Yalnızca `https` adresleri kabul edilir.

## Bilinen sınırlar

- **Kurcalama koruması:** Ajanı yerel yönetici durdurabilir veya kaldırabilir. Sunucu tarafında kaldırma onayı yoktur. Makine çevrimdışı olduğunda konsolda görünür.
- **Sertifika iptali:** CRL/OCSP yoktur. Ajan ve relay sertifikaları veritabanındaki iptal kaydıyla reddedilir.
- **Kod imzalama:** Release paketleri yalnızca imza sırları tanımlıysa imzalanır. İmzasız paketleri `SHA256SUMS.txt` ile doğrulayın.
- **Tek sunucu:** Uzaktan yönetim istek aracısı bellek içidir; çok örnekli kurulumda yapışkan yönlendirme gerekir.

Ayrıntılı kararlar: [varsayimlar.md](varsayimlar.md).
