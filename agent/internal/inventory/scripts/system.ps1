# BerOps — Windows sistem bilgisi: kurulu KB'ler, donanım, etki alanı, son açılış
# ve (istenirse) Microsoft Store paketleri. Çıktı tek satır JSON'dur.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$cs   = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS
$os   = Get-CimInstance -ClassName Win32_OperatingSystem
$cpu  = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1

$hotfixes = @(Get-CimInstance -ClassName Win32_QuickFixEngineering | ForEach-Object {
    $on = $_.InstalledOn
    if ($on -is [datetime]) { $on = $on.ToString('yyyy-MM-dd') } else { $on = [string]$on }
    [pscustomobject]@{ id = [string]$_.HotFixID; description = [string]$_.Description; installed_on = $on }
})

$appx = @()
if ($env:BER_INCLUDE_APPX -eq '1') {
    $appx = @(Get-AppxPackage -AllUsers | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' } |
        Sort-Object -Property PackageFullName -Unique | ForEach-Object {
            [pscustomobject]@{
                name      = [string]$_.Name
                version   = [string]$_.Version
                publisher = [string]$_.Publisher
                family    = [string]$_.PackageFamilyName
                location  = [string]$_.InstallLocation
                arch      = [string]$_.Architecture
            }
        })
}

$lastBoot = ''
if ($os.LastBootUpTime) { $lastBoot = $os.LastBootUpTime.ToString('o') }

[pscustomobject]@{
    hotfixes       = $hotfixes
    manufacturer   = [string]$cs.Manufacturer
    model          = [string]$cs.Model
    serial         = [string]$bios.SerialNumber
    cpu            = [string]$cpu.Name
    memory         = [uint64]$cs.TotalPhysicalMemory
    domain         = [string]$cs.Domain
    part_of_domain = [bool]$cs.PartOfDomain
    last_boot      = $lastBoot
    appx           = $appx
} | ConvertTo-Json -Depth 4 -Compress
