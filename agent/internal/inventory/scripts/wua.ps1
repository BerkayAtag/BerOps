# BerOps — Windows Update Agent ile eksik güncelleme taraması.
# BER_WSUS_CAB tanımlıysa çevrimdışı tarama sunucudan indirilen wsusscn2.cab ile yapılır;
# değilse makinenin yapılandırılmış kaynağı (Windows Update veya WSUS) kullanılır.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'BerOps'
$searcher = $session.CreateUpdateSearcher()
$source = 'online'
$service = $null
if ($env:BER_WSUS_CAB) {
    $manager = New-Object -ComObject Microsoft.Update.ServiceManager
    $service = $manager.AddScanPackageService('BerOps Offline', $env:BER_WSUS_CAB, 1)
    $searcher.ServerSelection = 3   # ssOthers
    $searcher.ServiceID = $service.ServiceID
    $source = 'offline'
}

try {
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
} finally {
    if ($service) { $manager.RemoveService($service.ServiceID) }
}

$updates = @(foreach ($u in $result.Updates) {
    $cls = $u.Categories | Where-Object { $_.Type -eq 'UpdateClassification' } | Select-Object -First 1
    $released = ''
    if ($u.LastDeploymentChangeTime) { $released = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    [pscustomobject]@{
        id                = [string]$u.Identity.UpdateID
        kb                = @($u.KBArticleIDs | ForEach-Object { [string]$_ })
        title             = [string]$u.Title
        classification_id = [string]$cls.CategoryID
        classification    = [string]$cls.Name
        severity          = [string]$u.MsrcSeverity
        released_at       = $released
        reboot_required   = ($u.InstallationBehavior.RebootBehavior -ne 0)
        size_bytes        = [int64]$u.MaxDownloadSize
        cves              = @($u.CveIDs | ForEach-Object { [string]$_ })
        support_url       = [string]$u.SupportUrl
    }
})

[pscustomobject]@{ source = $source; updates = $updates } | ConvertTo-Json -Depth 4 -Compress
