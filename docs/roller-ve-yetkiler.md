# Roller ve Yetkiler

BerOps'de her API uç noktası **sunucu tarafında** granüler bir izinle korunur. Konsol yalnızca kullanıcının izinlerine göre düğmeleri gizler ve devre dışı bırakır; asıl denetim sunucudadır. Reddedilen her istek denetim kaydına `authz.denied` olarak yazılır.

## Yerleşik roller

| İzin | Açıklama | Admin | Teknisyen | Salt Okunur |
|---|---|:-:|:-:|:-:|
| `machines.read` | Makineler, gruplar, etiketler, envanter, aksiyon listesi ve sonuçları | ✅ | ✅ | ✅ |
| `machines.manage` | Makine onaylama/reddetme, yeniden tarama, grup ve etiket yönetimi | ✅ | — | — |
| `reports.read` | Gösterge paneli, güvenlik açıkları | ✅ | ✅ | ✅ |
| `reports.export` | PDF/Excel/CSV rapor indirme | ✅ | ✅ | ✅ |
| `packages.read` | Paket kütüphanesini görme | ✅ | ✅ | ✅ |
| `packages.upload` / `packages.delete` | Paket yükleme ve silme | ✅ | — | — |
| `actions.deploy_package` | Kütüphanedeki paketi gönderme | ✅ | ✅ | — |
| `actions.run_command` | Serbest CMD/PowerShell/sh komutu | ✅ | — | — |
| `actions.approve` | Dört göz onayı (kendi aksiyonu hariç) | ✅ | — | — |
| `actions.deploy_patch` | İşletim sistemi yaması dağıtımı ve bildirimli yeniden başlatma | ✅ | — | — |
| `remote.*` | Uzaktan performans, servis, kayıt defteri (Aşama 6) | ✅ | — | — |
| `settings.read` | Ayarları görme (bakım pencereleri dahil; bildirim ayarları hariç) | ✅ | ✅ | ✅ |
| `settings.write` | Ajan, CVE, bakım penceresi ve bildirim ayarları; relay iptali | ✅ | — | — |
| `transfer.limits.manage` | Hız sınırı ve komut onayı ayarı | ✅ | — | — |
| `users.manage` | Kullanıcı yönetimi | ✅ | — | — |
| `ad.configure` | Active Directory ayarları ve eşlemeler | ✅ | — | — |
| `regkeys.manage` | Ajan kayıt anahtarları | ✅ | — | — |
| `audit.read` | Denetim kaydı ve dışa aktarma | ✅ | ✅ | ✅ |

- **Teknisyen** yalnızca kütüphanede var olan paketleri gönderebilir. Paket yükleyemez, komut yazamaz, ayar değiştiremez.
- **Salt Okunur** hiçbir şeyi değiştiremez ama tüm ekranları görür ve rapor alabilir.

## OU kapsamı

Teknisyen ve Salt Okunur kullanıcılar bir veya daha fazla **OU** ile sınırlandırılabilir (ör. `OU=İzmir,OU=Şubeler,DC=corp,DC=example`). Kapsamlı kullanıcı için şunlar geçerlidir:

- Yalnızca OU'su kapsamdaki bir OU'ya eşit olan veya onun altındaki makineleri görür. Makine listesi, detayı, filo özeti, güvenlik açıkları, risk özeti, paket "güncelleme gerekli" listesi, raporlar ve AD bilgisayarları buna göre süzülür.
- Kapsam dışındaki makine "bulunamadı" (404) döner; varlığı belli olmaz.
- Yalnızca kapsamındaki makinelere aksiyon gönderebilir ve tarama isteyebilir. Kapsam dışı bir hedef varsa istek tamamen reddedilir.
- Aksiyon listesinde kendi oluşturduğu aksiyonları ve kapsamındaki makineleri hedefleyen aksiyonları görür; aksiyon detayında yalnızca kapsamındaki hedefler listelenir.
- Uyumluluk eğilimi (filo geneli günlük özet) gösterilmez.

Admin rolünde kapsam uygulanmaz. Makinenin OU'su, Windows ajanının bildirdiği AD ayırt edici adından alınır; etki alanında olmayan makinelerin OU'su boştur ve yalnızca kapsamsız kullanıcılar tarafından görülür.

## Kullanıcılar

**Ayarlar → Kullanıcılar** ekranından yerel kullanıcı eklenir; rol, kapsam ve durum değiştirilir, parola belirlenir.

- Parola en az 12 karakterdir ve Argon2id ile saklanır.
- Rol, kapsam veya durum değişince ya da parola sıfırlanınca kullanıcının açık oturumları kapatılır.
- Kullanıcı kendi rolünü düşüremez ve kendini devre dışı bırakamaz. Son etkin yönetici kaldırılamaz.
- AD kullanıcılarının rolü ve kapsamı her girişte grup eşlemelerinden yeniden hesaplanır; konsoldan yalnızca devre dışı bırakılabilirler.

Active Directory: [ad-entegrasyonu.md](ad-entegrasyonu.md).
