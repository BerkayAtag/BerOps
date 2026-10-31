<#
.SYNOPSIS
  MSI paketlerini kurar, Yayımcı alanını, servisleri ve temiz kaldırmayı doğrular (CI).
  Sunucu testi için yerel PostgreSQL gerekir (-DatabaseUrl).
#>
param(
  [Parameter(Mandatory)] [string] $AgentMsi,
  [Parameter(Mandatory)] [string] $ServerMsi,
  [Parameter(Mandatory)] [string] $DatabaseUrl
)
$ErrorActionPreference = 'Stop'

function Get-Arp([string] $name) {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -eq $name }
}
function Assert([bool] $cond, [string] $msg) {
  if (-not $cond) { throw "DOĞRULAMA BAŞARISIZ: $msg" }
  Write-Host "✓ $msg"
}
function Invoke-Msi([string[]] $msiArgs) {
  $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "msiexec $($msiArgs -join ' ') çıkış kodu $($p.ExitCode)" }
}

# --- Ajan: anahtarsız kurulum, servis yapılandırma bekler ---
Invoke-Msi @('/i', $AgentMsi, '/qn', '/l*v', 'agent-install.log')
$arp = Get-Arp 'BerOps Agent'
Assert ($null -ne $arp) 'Ajan Programlar ve Özellikler listesinde'
Assert ($arp.Publisher -eq 'Berkay Atağ') "Ajan yayımcısı 'Berkay Atağ' (bulunan: '$($arp.Publisher)')"
$svc = Get-Service BerOpsAgent
Assert ($svc.Status -eq 'Running') "BerOpsAgent servisi çalışıyor ($($svc.Status))"
Start-Sleep -Seconds 3
Assert (Test-Path "$env:ProgramData\BerOps\Agent") 'Ajan veri klasörü oluştu'
Assert (-not (Select-String -Path agent-install.log -Pattern 'berreg_' -Quiet)) 'Kurulum günlüğünde kayıt anahtarı yok'

Invoke-Msi @('/x', $AgentMsi, '/qn')
Assert ($null -eq (Get-Arp 'BerOps Agent')) 'Ajan kaldırıldı'
Assert ($null -eq (Get-Service BerOpsAgent -ErrorAction SilentlyContinue)) 'BerOpsAgent servisi silindi'
Assert (-not (Test-Path "$env:ProgramData\BerOps\Agent")) 'Ajan veri klasörü silindi'
Assert (-not (Test-Path "$env:ProgramFiles\BerOps\Agent")) 'Ajan program klasörü silindi'

# --- Sunucu: sessiz kurulum, servis ve konsol ---
$password = 'Ci-' + [guid]::NewGuid().ToString('N')
Invoke-Msi @('/i', $ServerMsi, '/qn', '/l*v', 'server-install.log', "DATABASE_URL=$DatabaseUrl",
  'HOSTNAMES=localhost', 'ADMIN_USERNAME=ci-admin', "ADMIN_PASSWORD=$password")
$arp = Get-Arp 'BerOps Server'
Assert ($null -ne $arp) 'Sunucu Programlar ve Özellikler listesinde'
Assert ($arp.Publisher -eq 'Berkay Atağ') "Sunucu yayımcısı 'Berkay Atağ' (bulunan: '$($arp.Publisher)')"
Assert (-not (Select-String -Path server-install.log -SimpleMatch -Pattern $password -Quiet)) 'Kurulum günlüğünde yönetici parolası yok'
$svc = Get-Service BerOpsServer
Assert ($svc.Status -eq 'Running') "BerOpsServer servisi çalışıyor ($($svc.Status))"
Assert (Test-Path "$env:ProgramData\BerOps\Server\berops-server.yaml") 'Sunucu yapılandırması yazıldı'

$ok = $false
for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
  try {
    $r = Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -SkipCertificateCheck -UseBasicParsing
    $ok = $r.StatusCode -eq 200
  } catch { Start-Sleep -Seconds 2 }
}
Assert $ok 'Konsol https://localhost:8443 yanıt veriyor'
$page = Invoke-WebRequest -Uri 'https://localhost:8443/' -SkipCertificateCheck -UseBasicParsing
Assert ($page.Content -match 'BerOps') 'Konsol arayüzü sunuluyor'
$login = Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/auth/login' -Method Post -SkipCertificateCheck `
  -ContentType 'application/json' -Body (@{ username = 'ci-admin'; password = $password } | ConvertTo-Json) -UseBasicParsing
Assert ($login.StatusCode -eq 200) 'İlk yönetici giriş yapabiliyor'

Invoke-Msi @('/x', $ServerMsi, '/qn')
Assert ($null -eq (Get-Arp 'BerOps Server')) 'Sunucu kaldırıldı'
Assert ($null -eq (Get-Service BerOpsServer -ErrorAction SilentlyContinue)) 'BerOpsServer servisi silindi'
Assert (Test-Path "$env:ProgramData\BerOps\Server\data\pki") 'Sunucu verisi (iç CA) kaldırmada korundu'
Write-Host 'Tüm MSI doğrulamaları başarılı.'
