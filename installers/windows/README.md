# Windows Kurulum Paketleri

WiX Toolset v5 ile derlenen iki MSI. İkisinde de `Manufacturer` = **Berkay Atağ**; Programlar ve Özellikler'deki Yayımcı alanında bu ad görünür.

| Dosya | Paket |
|---|---|
| `agent/BerAgent.wxs` | **BerOps Agent**: `BerOpsAgent` servisi; sessiz kurulumda `SERVER`, `REGKEY`, `CAHASH` özellikleri; temiz kaldırma |
| `server/BerServer.wxs` | **BerOps Server**: sihirbaz (dizin → sunucu ayarları → ilk yönetici); `BerOpsServer` servisi; güvenlik duvarı kuralları; `berops-server setup` |
| `build.ps1` | İki MSI'ı derler (WiX'i gerekirse `dotnet tool` ile kurar) |
| `test-msi.ps1` | Kurulum, Yayımcı alanı, servis, konsol girişi ve temiz kaldırma doğrulaması (CI) |

Derleme (Windows, .NET SDK 8+):

```powershell
./installers/windows/build.ps1 -Version 1.0.0 -AgentExe dist/berops-agent.exe -ServerExe dist/berops-server.exe -ConsoleDir console/dist -OutDir dist
```

CI'da her PR'da `installers-windows` işi paketleri derler, kurar, doğrular ve kaldırır. Kullanım: [docs/kurulum-sunucu.md](../../docs/kurulum-sunucu.md), [docs/kurulum-ajan-windows.md](../../docs/kurulum-ajan-windows.md).
