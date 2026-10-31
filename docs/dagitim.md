# Paket Dağıtımı ve Komut Çalıştırma

Automation BER, kütüphanedeki paketleri ve serbest komutları seçilen makinelere **aksiyon** olarak gönderir. Her aksiyon imzalanır, istemci başına hız sınırıyla aktarılır ve sonuçları (çıkış kodu, standart çıktı, hata çıktısı) makine başına konsolda görünür.

## Yetkiler

| Rol | Paket yükleme/silme | Kütüphaneden paket gönderme | Serbest komut | Komut onayı |
|---|---|---|---|---|
| Admin | ✅ | ✅ | ✅ | ✅ (kendi oluşturduğu hariç) |
| Teknisyen | — | ✅ | — | — |
| Salt Okunur | — | — | — | — |

Teknisyen yalnızca kütüphanede **var olan** paketleri gönderebilir; komut yazamaz, paket yükleyemez. Tüm roller aksiyon listesini ve sonuçlarını görebilir.

## Paket kütüphanesi

**Paket Kütüphanesi → Paket yükle** ile paket eklenir.

| Platform | Yükleyici | Varsayılan kurulum komutu | Başarı kodları |
|---|---|---|---|
| Windows | MSI | `msiexec.exe /i "{file}" /qn /norestart` (cmd) | 0, 1641, 3010 |
| Windows | EXE | Belirtilmeli, ör. `"{file}" /S` | 0 |
| Windows | Dosya + komut | Belirtilmeli (PowerShell veya cmd) | 0 |
| macOS | PKG | `/usr/sbin/installer -pkg "{file}" -target /` | 0 |
| macOS | DMG | Boşsa ajan imajı bağlar, içindeki `.pkg`'yi kurar veya `.app`'i `/Applications`'a kopyalar | 0 |
| macOS | Dosya + komut | Belirtilmeli (sh veya zsh) | 0 |

- `{file}`, ajanın indirdiği dosyanın tam yoludur.
- Dosyalar sunucuda içerik adresli saklanır (`data_dir/packages/<sha256>`); aynı dosya iki kez yüklenirse tek kopya tutulur.
- **Kurulu uygulama adı kalıbı** (ör. `^7-zip`) tanımlanırsa paket detayında, uygulamanın paketten **eski sürümünü** çalıştıran makineler listelenir ve tek tıkla bu makinelere gönderilebilir. Üçüncü parti uygulamalardaki eksik güncellemeler bu şekilde takip edilir.
- Paket silindiğinde geçmiş aksiyon kayıtları korunur; dosya, başka paket veya açık aksiyon kullanmıyorsa silinir.

## Aksiyonlar

**Aksiyonlar → Yeni aksiyon** veya makine listesinde seçim yapıp **Paket gönder / Komut çalıştır**:

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| Zaman aşımı | 3600 sn | Aşılırsa komut ve başlattığı tüm alt süreçler sonlandırılır (Windows Job Object, macOS süreç grubu) |
| İstemci başına hız | Genel sınır (10 Mbps) | Aksiyon için daha düşük bir değer verilebilir; genel sınırın üstüne çıkılamaz |
| Geçerlilik | 72 saat | Bu süre içinde çevrimiçi olmayan makinelerde iş "süresi doldu" olur |

- Komutlar Windows'ta **SYSTEM**, macOS'ta **root** yetkisiyle çalışır.
- Komut önce iş dizinine betik dosyası olarak yazılır (`.cmd`, `.ps1`, `.sh`). Böylece tırnak ve satır sonu kaçışlama sorunu olmaz.
- Çıktılar UTF-8'e çevrilir; her biri en fazla 64 KB saklanır.
- Yalnızca **aktif** makinelere iş gönderilir; onay bekleyen makineler hedeflenemez.
- Aksiyon oluşturma **denetim kaydına komut metniyle birlikte** yazılır. Denetim kaydı yazılamazsa aksiyon oluşturulmaz.
- Başarıyla kurulan paketten sonra ajan hemen değişiklik taraması yapar; konsol yeni sürümü birkaç dakika içinde görür.

### Dört göz onayı

**Ayarlar → Aktarım ayarları → Komut aksiyonları dört göz onayı gerektirsin** açıksa:

- Yeni komut aksiyonu "Onay bekliyor" durumunda başlar.
- Başka bir yönetici (`actions.approve` izni) onaylayana kadar ajana gönderilmez.
- Aksiyonu oluşturan kişi kendi aksiyonunu onaylayamaz.

### Durumlar

| Hedef durumu | Anlamı |
|---|---|
| Bekliyor | Ajan henüz almadı |
| İndiriliyor | Paket indiriliyor (kesilirse kaldığı yerden sürer) |
| Çalışıyor | Komut çalışıyor |
| Başarılı / Başarısız | Çıkış kodu başarı kodlarında mı |
| İptal | Aksiyon iptal edildi veya reddedildi |
| Süresi doldu | Makine geçerlilik süresi içinde işi almadı |

Ajan iş çalışırken yeniden başlarsa iş **başarısız** bildirilir ve tekrar çalıştırılmaz (yükleyicinin iki kez çalışması daha büyük sorun yaratabilir); gerekirse yeni aksiyon oluşturulur.

## Hız sınırı

İstemci başına hız sınırı sunucuda uygulanır. Varsayılan 10 Mbps'tir; **Ayarlar → Aktarım ayarları** ekranından değiştirilir. Sınır şu indirmelerin hepsine uygulanır:

- paket dosyaları
- çevrimdışı Windows Update kataloğu (`wsusscn2.cab`)

İndirmeler HTTP Range ile kaldığı yerden sürer. Şubeler için önbellekleyen relay ve toplam bant genişliği sınırı Aşama 7'de eklenecek.

## Güvenlik

İmza ve sabitleme modeli: [mimari.md §3.5](mimari.md#35-aksiyon-imzası-aşama-4).
