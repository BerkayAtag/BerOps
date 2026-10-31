# macOS Kurulum Paketi

| Dosya | Açıklama |
|---|---|
| `build-pkg.sh` | Universal ikili dosyadan `.pkg` üretir. Ortam değişkenleri verilirse imzalar ve notarize eder. |
| `distribution.xml`, `resources/` | Kurulum sihirbazının başlığı, karşılama ve bilgi sayfaları (Yayımcı: Berkay Atağ) |
| `io.github.berkayatag.berops.agent.plist` | `launchd` daemon tanımı |
| `scripts/preinstall`, `scripts/postinstall` | Yükseltmede daemon'ı durdurur; kurulumdan sonra MDM tercihlerinden yapılandırır ve başlatır |
| `uninstall.sh` | İz bırakmadan kaldırma (`/usr/local/bin/berops-agent-uninstall` olarak kurulur) |
| `pppc-berops-agent.mobileconfig` | Tam Disk Erişimi için örnek MDM (PPPC) profili |

Derleme:

```bash
GOARCH=arm64 go build -o dist/berops-agent-arm64 ./agent/cmd/berops-agent
GOARCH=amd64 go build -o dist/berops-agent-amd64 ./agent/cmd/berops-agent
lipo -create -output dist/berops-agent dist/berops-agent-arm64 dist/berops-agent-amd64
installers/macos/build-pkg.sh 1.0.0 dist/berops-agent dist/BerOps-Agent-1.0.0.pkg
```

CI'da her PR'da `installers-macos` işi paketi derler, kurar, daemon'ı doğrular ve kaldırır. Kullanım: [docs/kurulum-ajan-macos.md](../../docs/kurulum-ajan-macos.md).
