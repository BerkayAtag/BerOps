# macOS ajanı kurulumu

macOS ajanı `io.github.berkayatag.berops.agent` etiketli bir `launchd` daemon'ı olarak root yetkisiyle çalışır. Kurulum paketi `BerOps-Agent.pkg` dosyasıdır ([GitHub Releases](https://github.com/BerkayAtag/BerOps/releases/latest)). Paket, Intel ve Apple Silicon'u tek dosyada destekleyen universal bir ikili dosya içerir. Paket bilgilerinde yayımcı **Berkay Atağ** olarak görünür.

**Desteklenen sürümler:** macOS 12 veya üstü.

## Tek makineye kurulum

Konsoldaki **Ajan indir** sayfası komutu hazırlar:

```bash
sudo installer -pkg BerOps-Agent.pkg -target / && \
sudo /usr/local/bin/berops-agent configure -server "https://ber.ornek.local:52311" -key "berreg_..." -ca-hash "sha256:..."
```

Paket kurulunca daemon başlar ve yapılandırma bekler. `configure` komutu yapılandırmayı yazdıktan sonra en geç 30 saniye içinde kayıt yapılır.

## MDM ile dağıtım

1. **Paketi dağıtın.** Jamf, Intune, Kandji veya benzeri bir MDM ile `.pkg` dosyasını dağıtın. Üretim ortamında Developer ID ile imzalanmış ve notarize edilmiş paket kullanın (bkz. [İmzalama](#imzalama)).
2. **Yapılandırmayı verin.** Bir "Özel ayarlar / Custom Settings" yükü ile `io.github.berkayatag.berops.agent` tercih alanına şu anahtarları ekleyin. Kurulum betiği bunları `/Library/Managed Preferences/` altından okuyup ajanı yapılandırır.

   ```xml
   <key>Server</key>          <string>https://ber.ornek.local:52311</string>
   <key>RegistrationKey</key> <string>berreg_...</string>
   <key>CAHash</key>          <string>sha256:...</string>
   ```

   Alternatif olarak paket kurulmadan önce `/private/tmp/berops-agent-install.conf` dosyası yazılabilir. Dosya `SERVER=`, `REGKEY=` ve `CAHASH=` satırlarını içerir ve okunduktan sonra silinir.
3. **Tam Disk Erişimi verin.** `pppc-berops-agent.mobileconfig` örnek profilini (sürüm dosyaları arasında ve `installers/macos/` klasöründe) MDM ile dağıtın. Bu izin olmadan ajan bazı kullanıcı klasörlerindeki uygulamaları göremeyebilir. Profildeki `TEAMID_DEGISTIR` değerini Developer ID ekip kimliğinizle değiştirin.

## Dosyalar

| Yol | İçerik |
|---|---|
| `/usr/local/bin/berops-agent` | Ajan |
| `/usr/local/bin/berops-agent-uninstall` | Kaldırma betiği |
| `/Library/LaunchDaemons/io.github.berkayatag.berops.agent.plist` | launchd tanımı |
| `/Library/Application Support/BerOps/Agent/` | Yapılandırma, kimlik, iş günlüğü, `logs/` |

- Durum: `sudo berops-agent status`.
- Daemon: `sudo launchctl print system/io.github.berkayatag.berops.agent`.

## Güncelleme ve kaldırma

- **Güncelleme:** Yeni paketi kurun. Kimlik korunur.
- **Kaldırma:** `sudo /usr/local/bin/berops-agent-uninstall`. Daemon durdurulur; program, launchd tanımı, veri klasörü ve paket kaydı (`pkgutil --forget`) silinir.

## Yama dağıtımı

Konsoldan gönderilen macOS yamaları `softwareupdate --install <etiket>` ile kurulur.

- Yeniden başlatma gerektiren güncellemeler kurulur, ama makine kendiliğinden yeniden başlatılmaz.
- Apple Silicon'da işletim sistemi sürüm güncellemeleri kullanıcı onayı veya MDM gerektirebilir. Bu durumda hedef "başarısız" olur ve çıktıda nedeni görünür.

## İmzalama

Release iş akışı aşağıdaki GitHub Secrets tanımlıysa ikili dosyayı imzalar, paketi imzalar ve notarize eder:

- `MACOS_CERT_P12`, `MACOS_CERT_PASSWORD`
- `MACOS_APP_IDENTITY`, `MACOS_INSTALLER_IDENTITY`
- `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`

Tanımlı değilse paket imzasız üretilir ve sürüm notunda bu belirtilir. İmzasız paket Finder'dan açılırken Gatekeeper uyarı verir. `sudo installer -pkg ...` ile ya da MDM üzerinden kurulabilir.
