# macOS Kurulum Paketi

| Dosya | Açıklama |
|---|---|
| `build-pkg.sh` | Universal ikili dosyadan `.pkg` üretir. Ortam değişkenleri verilirse imzalar ve notarize eder. |
| `distribution.xml`, `resources/` | Kurulum sihirbazının başlığı, karşılama ve bilgi sayfaları (Yayımcı: Berkay Atağ) |
| `io.github.berkayatag.ber.agent.plist` | `launchd` daemon tanımı |
| `scripts/preinstall`, `scripts/postinstall` | Yükseltmede daemon'ı durdurur; kurulumdan sonra MDM tercihlerinden yapılandırır ve başlatır |
| `uninstall.sh` | İz bırakmadan kaldırma (`/usr/local/bin/ber-agent-uninstall` olarak kurulur) |
| `pppc-ber-agent.mobileconfig` | Tam Disk Erişimi için örnek MDM (PPPC) profili |

Derleme:

```bash
GOARCH=arm64 go build -o dist/ber-agent-arm64 ./agent/cmd/ber-agent
GOARCH=amd64 go build -o dist/ber-agent-amd64 ./agent/cmd/ber-agent
lipo -create -output dist/ber-agent dist/ber-agent-arm64 dist/ber-agent-amd64
installers/macos/build-pkg.sh 1.0.0 dist/ber-agent dist/AutomationBER-Agent-1.0.0.pkg
```

CI'da her PR'da `installers-macos` işi paketi derler, kurar, daemon'ı doğrular ve kaldırır. Kullanım: [docs/kurulum-ajan-macos.md](../../docs/kurulum-ajan-macos.md).
