# Uzaktan Yönetim

Makinelerin anlık performansı, servisleri ve (Windows'ta) kayıt defteri konsoldan yönetilebilir. Özellik **isteğe bağlıdır (opt-in)** ve varsayılan olarak tamamen kapalıdır.

## Açma

1. **Ayarlar → Uzaktan yönetim → Uzaktan yönetimi etkinleştir**. Bu genel ana anahtardır; kapalıyken makine bazındaki ayarlar yok sayılır.
2. Makine detayında **Uzaktan yönetim** sekmesinden o makinede açılacak özellikleri seçin:

   | Özellik | Platform | İzin |
   |---|---|---|
   | Performans: CPU, bellek, takas, diskler, en çok kaynak kullanan 15 süreç | Windows, macOS | `remote.performance` |
   | Servisler: listeleme; başlat/durdur/yeniden başlat | Windows (servis yöneticisi), macOS (launchd: listeleme, kickstart, durdurma) | `remote.services` |
   | Kayıt defteri okuma | Windows | `remote.registry.read` |
   | Kayıt defteri yazma: değer ekleme/değiştirme/silme | Windows | `remote.registry.write` |

Özellik açma/kapama `remote.settings` iznini gerektirir. Yerleşik rollerde bu izinlerin hepsi yalnızca **Admin** rolündedir. OU kapsamı uzaktan yönetime de uygulanır.

## Oturum

**Uzaktan oturum aç** ile oturum başlar ve varsayılan 10 dakika sürer. Akış şöyledir:

1. Ajan oturumu bir sonraki heartbeat'te öğrenir. Gecikme en fazla heartbeat aralığı kadardır (varsayılan 60 sn).
2. Ajan uzun yoklamaya (long-poll) geçer ve istekler etkileşimli hızda iletilir. Performans ekranı 5 saniyede bir yenilenir.
3. Oturum bitince ajan yoklamayı bırakır. Oturum yokken ajan sunucuya ek bağlantı açmaz.

## Güvenlik

- Her istek, aksiyonlar gibi sunucunun **Ed25519 imza anahtarıyla** imzalanır.
  - İstek makine kimliğini ve 40 saniyelik geçerlilik süresini içerir.
  - Ajan imzayı, makineyi ve süreyi doğrular; özellik makinede kapalıysa isteği **kendisi de reddeder**.
- Sunucu parametreleri ajana göndermeden önce doğrular: kayıt defteri kökü (HKLM, HKU, HKCR, HKCC), servis işlemi, değer türü ve boyutu.
- **Denetim kaydı:**
  - Oturum açılışı yazılır.
  - Servis kontrolü ve kayıt defteri yazma/silme işlemleri, gönderilmeden **önce** yazılır; denetim kaydı yazılamazsa işlem gönderilmez.
  - Sonuç ve kayıt defterindeki **önceki değer** ayrıca yazılır; bu kayıt geri alma için kullanılabilir.
- Okuma işlemleri (performans, servis listesi, kayıt defteri gezinme) yalnızca oturum açılışında kaydedilir.

## Sınırlamalar

- Kayıt defterinde anahtar başına en fazla 2000 alt anahtar ve değer listelenir. Anahtar silme ve yeniden adlandırma yoktur; yalnızca değer yazma ve silme yapılır.
- macOS'ta launchd işlerinin kalıcı olarak etkinleştirilmesi ve devre dışı bırakılması desteklenmez.
- Sunucu birden fazla örnekle çalışıyorsa uzaktan oturumlar tek örneğe bağlıdır ([varsayimlar.md](varsayimlar.md) 6.4).
