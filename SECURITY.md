# Güvenlik Politikası

## Desteklenen sürümler

Proje henüz 1.0 öncesi geliştirme aşamasındadır. Güvenlik düzeltmeleri yalnızca `main` dalına ve en son yayımlanan sürüme uygulanır.

## Güvenlik açığı bildirme

Güvenlik açıklarını **herkese açık issue olarak bildirmeyin.**

Bunun yerine GitHub'ın [özel güvenlik açığı bildirimi](https://docs.github.com/tr/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) özelliğini kullanın: repodaki **Security → Report a vulnerability** sekmesi.

Bildiriminizde şunlar yer alırsa değerlendirme hızlanır:

- Etkilenen bileşen (sunucu, ajan, relay, konsol) ve sürüm
- Açığın türü ve etkisi
- Yeniden üretme adımları veya kavram kanıtı
- Biliniyorsa önerilen düzeltme

Bildirimler 5 iş günü içinde yanıtlanır. Düzeltme yayımlandıktan sonra, isterseniz katkınız güvenlik duyurusunda belirtilir.

## Kapsam

Özellikle şu alanlardaki bulgular önemlidir:

- Ajan ↔ sunucu kimlik doğrulaması (mTLS, kayıt anahtarları, CA pin'i)
- Aksiyon manifesti imzası ve dosya bütünlüğü doğrulaması
- Konsol kimlik doğrulaması, oturum yönetimi ve CSRF
- Rol tabanlı yetkilendirme (RBAC) atlatma
- Uzaktan komut, servis ve registry işlemleri
- Denetim kaydının değiştirilebilmesi

Güvenlik modelinin ayrıntıları: [docs/mimari.md](docs/mimari.md#3-güvenlik-modeli)
