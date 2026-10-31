# Windows ajanı kurulumu

Windows ajanı `BerOpsAgent` adlı bir Windows servisi olarak `LocalSystem` hesabıyla çalışır. Kurulum paketi: `BerOps-Agent-<sürüm>-x64.msi` ([GitHub Releases](https://github.com/BerkayAtag/BerOps/releases/latest)). Yayımcı alanı **Berkay Atağ**'dır.

**Desteklenen sürümler:** Windows 10/11 ve Windows Server 2016 veya üstü (x64).

## Kurulum komutu

Konsoldaki **Ajan indir** sayfası komutu sunucu adresi, kayıt anahtarı ve CA parmak izi gömülü olarak üretir:

```bat
msiexec /i BerOps-Agent-1.0.0-x64.msi /qn SERVER="https://ber.ornek.local:52311" REGKEY="berreg_..." CAHASH="sha256:..."
```

| Özellik | Açıklama |
|---|---|
| `SERVER` | Sunucunun (veya şube relay'inin) ajan adresi |
| `REGKEY` | Kayıt anahtarı. Günlüğe yazılmaz, kayıt başarılı olunca yapılandırmadan silinir. |
| `CAHASH` | Sunucu CA parmak izi. Ajan sunucuyu bu değerle doğrular; ilk bağlantıdaki ortadaki adam saldırısını önler. |

`REGKEY` verilmezse servis kurulur ve yapılandırma bekler. Yapılandırma sonradan şu komutla yazılabilir; servis 30 saniye içinde kaydı başlatır:

```bat
"C:\Program Files\BerOps\Agent\berops-agent.exe" configure -server https://ber.ornek.local:52311 -key berreg_... -ca-hash sha256:...
```

Kayıt anahtarı **onay gerektirecek** şekilde oluşturulduysa makine konsolda *Onay bekleyen* olarak görünür; yönetici onaylayınca çalışmaya başlar.

## Toplu dağıtım

- **Microsoft Intune (Win32 uygulaması):** `.msi` dosyasını `.intunewin` olarak paketleyin.
  - Kurulum komutu: yukarıdaki `msiexec` satırı.
  - Kaldırma komutu: `msiexec /x {ÜrünKodu} /qn`.
  - Algılama kuralı: MSI ürün kodu.
- **Configuration Manager (SCCM/MECM):** Uygulama dağıtım türü olarak aynı komut satırı.
- **Grup İlkesi:** GPO yazılım yüklemesi MSI özelliklerini doğrudan alamaz. İki yol vardır:
  - Bilgisayar başlangıç betiğinde `msiexec` komutunu çalıştırın.
  - `SERVER`, `REGKEY` ve `CAHASH` özelliklerini içeren bir dönüşüm (`.mst`) hazırlayıp GPO'ya ekleyin.

Aynı kayıt anahtarını birçok makinede kullanabilirsiniz. Kullanım sınırı ve geçerlilik süresi konsoldan belirlenir.

## Dosyalar ve servis

| Yol | İçerik |
|---|---|
| `C:\Program Files\BerOps\Agent\berops-agent.exe` | Ajan |
| `C:\ProgramData\BerOps\Agent\` | Yapılandırma, ajan sertifikası ve anahtarı, iş günlüğü, `logs\` |

- Servis hata verirse 60 saniye sonra kendiliğinden yeniden başlar.
- Durum: `berops-agent.exe status`.
- Tanılama envanteri: `berops-agent.exe inventory -full`.

## Güncelleme ve kaldırma

- **Güncelleme:** Yeni MSI'ı aynı şekilde kurun. Kimlik ve yapılandırma korunur, ajan yeniden kayıt yapmaz.
- **Kaldırma:** Programlar ve Özellikler'den ya da `msiexec /x BerOps-Agent-1.0.0-x64.msi /qn` ile. Servis, program dosyaları ve `C:\ProgramData\BerOps\Agent` (kimlik, günlükler) silinir; iz kalmaz. Makine konsolda çevrimdışı görünür ve oradan silinebilir.

Kaldırma için yerel yönetici yetkisi gerekir. Sunucu tarafında ayrı bir kurcalama koruması yoktur; bkz. [varsayimlar.md](varsayimlar.md) 8.4.

## Ağ

Ajan yalnızca sunucuya (veya relay'e) **giden** HTTPS bağlantısı kurar (TCP 52311). Ajanda gelen bağlantı için port açılmaz. Paket indirmeleri sunucudaki istemci başına hız sınırına uyar.

## Sorun giderme

| Belirti | Kontrol |
|---|---|
| Makine konsolda görünmüyor | `logs\agent.log` dosyasında `kayıt başarısız` satırları. Ağ, `SERVER` adresi ve kayıt anahtarının süresi. |
| `sertifika parmak izi uyuşmuyor` | `CAHASH` değeri yanlış ya da araya giren bir vekil sunucu TLS'i açıyor. |
| Eksik yamalar boş | Windows Update servisi (`wuauserv`) devre dışı mı? Çevrim dışı tarama seçiliyse `wsusscn2.cab` sunucuda var mı? |
| Yama dağıtımı başarısız | Aksiyon detayında hedefin çıktısı. WSUS veya Windows Update erişimi gerekir; çıkış kodu 3010 "yeniden başlatma gerekli" anlamına gelir ve başarılı sayılır. |
