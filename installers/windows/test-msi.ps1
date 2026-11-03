<#
.SYNOPSIS
  MSI paketlerini kurar, Yayımcı alanını, servisleri ve temiz kaldırmayı doğrular (CI).
  Uçtan uca: ajan sunucuya kaydolur, sunucudan gönderilen aksiyonla -AgentUpdateMsi
  sürümüne kendini günceller; kaldırma koruması açıkken kodsuz kaldırma reddedilir.
  Sunucu testi için yerel PostgreSQL gerekir (-DatabaseUrl).
#>
param(
  [Parameter(Mandatory)] [string] $AgentMsi,
  [Parameter(Mandatory)] [string] $AgentUpdateMsi,
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
  if ($p.ExitCode -ne 0) { throw "msiexec çıkış kodu $($p.ExitCode)" }
}
# Wait-Until, koşul sağlanana kadar bekler; sağlanmazsa son değeri hata iletisine ekler.
function Wait-Until([scriptblock] $cond, [int] $seconds, [string] $what) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    try { if (& $cond) { return } } catch { }
    Start-Sleep -Seconds 3
  }
  throw "ZAMAN AŞIMI: $what"
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

# --- Uçtan uca: kayıt, ajan güncellemesi, kaldırma koruması ---
# Heartbeat aralığı testi hızlandırmak için kısaltılır (agent: bölümü dosyanın sonundadır).
$cfg = "$env:ProgramData\BerOps\Server\berops-server.yaml"
Add-Content -Path $cfg -Value '  heartbeat_seconds: 10'
Restart-Service BerOpsServer
$base = 'https://localhost:8443'
Wait-Until { (Invoke-WebRequest -Uri "$base/api/v1/health" -SkipCertificateCheck -UseBasicParsing).StatusCode -eq 200 } 60 'sunucu yeniden başlamadı'
$me = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method Post -SkipCertificateCheck -SessionVariable web `
  -ContentType 'application/json' -Body (@{ username = 'ci-admin'; password = $password } | ConvertTo-Json)
$headers = @{ 'X-CSRF-Token' = $me.csrf_token }
function Api([string] $method, [string] $path, $body) {
  $p = @{ Uri = "$base$path"; Method = $method; WebSession = $web; SkipCertificateCheck = $true; Headers = $headers }
  if ($null -ne $body) { $p.ContentType = 'application/json'; $p.Body = ($body | ConvertTo-Json -Depth 6) }
  Invoke-RestMethod @p
}
$info = Api GET '/api/v1/server-info'
$key = Api POST '/api/v1/registration-keys' @{ name = 'ci'; require_approval = $false }
Invoke-Msi @('/i', $AgentMsi, '/qn', '/l*v', 'agent-enroll.log', "SERVER=$($info.agent_url)", "REGKEY=$($key.secret)", "CAHASH=$($info.ca_fingerprint)")
Assert (-not (Select-String -Path agent-enroll.log -SimpleMatch -Pattern $key.secret -Quiet)) 'Kurulum günlüğünde kayıt anahtarı yok'
$script:machine = $null
Wait-Until { $script:machine = (Api GET '/api/v1/machines').items | Where-Object { $_.status -eq 'active' -and $_.agent_version } | Select-Object -First 1; $null -ne $script:machine } 120 'ajan kaydolmadı'
$oldVersion = $script:machine.agent_version
Write-Host "Kayıtlı ajan: $($script:machine.hostname) $oldVersion"
# Veri dizini (anahtar, koruma özeti, paket önbelleği) standart kullanıcılara kapalı olmalı.
$acl = Get-Acl "$env:ProgramData\BerOps\Agent"
$sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })
Assert $acl.AreAccessRulesProtected 'Ajan veri dizini ProgramData izinlerini devralmıyor'
Assert (-not ($sids | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544') })) "Ajan veri dizininde yalnızca SYSTEM ve Administrators var ($($sids -join ', '))"

$meta = @{ name = 'BerOps Agent'; version = 'ci-guncelleme'; platform = 'windows'; installer = 'msi' } | ConvertTo-Json
$pkg = Invoke-RestMethod -Uri "$base/api/v1/packages" -Method Post -WebSession $web -SkipCertificateCheck -Headers $headers `
  -Form @{ metadata = $meta; file = Get-Item $AgentUpdateMsi }
$action = Api POST '/api/v1/actions' @{ kind = 'update_agent'; package_id = $pkg.id; machine_ids = @($script:machine.id) }
$script:target = $null
Wait-Until { $script:target = (Api GET "/api/v1/actions/$($action.id)").targets[0]; $script:target.status -in @('succeeded', 'failed') } 300 'ajan güncellemesi sonuçlanmadı'
if ($script:target.status -ne 'succeeded') { Write-Host ($script:target | ConvertTo-Json -Depth 4) }
Assert ($script:target.status -eq 'succeeded') "Ajan güncellemesi başarılı ($($script:target.status): $($script:target.error))"
Write-Host $script:target.stdout
$arps = @(Get-Arp 'BerOps Agent')
Assert ($arps.Count -eq 1) "Programlar ve Özellikler'de tek ajan kaydı ($($arps.Count))"
Assert ($arps[0].DisplayVersion -eq '0.0.1') "Ajan sürümü 0.0.1 (bulunan: $($arps[0].DisplayVersion))"
Wait-Until { ((Api GET "/api/v1/machines/$($script:machine.id)").machine.agent_version) -ne $oldVersion } 60 'konsolda ajan sürümü güncellenmedi'
Assert ((Get-Service BerOpsAgent).Status -eq 'Running') 'Güncellenen ajan servisi çalışıyor'

$code = 'Ci-Kod-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
Api PUT '/api/v1/settings/agent-protection' @{ enabled = $true; code = $code } | Out-Null
Wait-Until { Test-Path "$env:ProgramData\BerOps\Agent\protection.json" } 120 'kaldırma koruması ajana ulaşmadı'
$p = Start-Process msiexec.exe -ArgumentList @('/x', $AgentUpdateMsi, '/qn', '/l*v', 'agent-uninstall-denied.log') -Wait -PassThru
Assert ($p.ExitCode -ne 0) "Kodsuz kaldırma reddedildi (çıkış kodu $($p.ExitCode))"
Assert ($null -ne (Get-Arp 'BerOps Agent')) 'Ajan reddedilen kaldırmadan sonra kurulu'
Assert ((Get-Service BerOpsAgent).Status -eq 'Running') 'Ajan servisi reddedilen kaldırmadan sonra çalışıyor'
$p = Start-Process msiexec.exe -ArgumentList @('/x', $AgentUpdateMsi, '/qn', '/l*v', 'agent-uninstall-wrong.log', 'UNINSTALLCODE=yanlis-kod-1') -Wait -PassThru
Assert ($p.ExitCode -ne 0) 'Yanlış kodla kaldırma reddedildi'
Invoke-Msi @('/x', $AgentUpdateMsi, '/qn', '/l*v', 'agent-uninstall.log', "UNINSTALLCODE=$code")
Assert ($null -eq (Get-Arp 'BerOps Agent')) 'Doğru kodla ajan kaldırıldı'
Assert (-not (Select-String -Path agent-uninstall.log -SimpleMatch -Pattern $code -Quiet)) 'Kaldırma günlüğünde kod yok'

Invoke-Msi @('/x', $ServerMsi, '/qn')
Assert ($null -eq (Get-Arp 'BerOps Server')) 'Sunucu kaldırıldı'
Assert ($null -eq (Get-Service BerOpsServer -ErrorAction SilentlyContinue)) 'BerOpsServer servisi silindi'
Assert (Test-Path "$env:ProgramData\BerOps\Server\data\pki") 'Sunucu verisi (iç CA) kaldırmada korundu'
Write-Host 'Tüm MSI doğrulamaları başarılı.'
