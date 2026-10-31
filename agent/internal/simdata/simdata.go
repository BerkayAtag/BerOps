// Package simdata, sanal ajanlar ve demo ortamı için gerçekçi sahte envanter üretir.
// Üretilen veri ajan sırasına göre deterministiktir (aynı ajan her seferinde aynı envanteri verir).
package simdata

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/BerkayAtag/automation-ber/agent/internal/inventory"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

type appDef struct {
	name, publisher string
	versions        []string // eskiden yeniye; son eleman en güncel
	source          string
}

var windowsApps = []appDef{
	{"Google Chrome", "Google LLC", []string{"128.0.6613.120", "129.0.6668.101", "130.0.6723.92", "131.0.6778.86"}, protocol.AppSourceMSI},
	{"Mozilla Firefox (x64 tr)", "Mozilla", []string{"128.4.0", "131.0.3", "132.0.2"}, protocol.AppSourceRegistry},
	{"Microsoft Edge", "Microsoft Corporation", []string{"129.0.2792.89", "130.0.2849.80", "131.0.2903.70"}, protocol.AppSourceRegistry},
	{"Zoom Workplace (64-bit)", "Zoom Video Communications, Inc.", []string{"6.1.11", "6.2.5", "6.2.11"}, protocol.AppSourceMSI},
	{"7-Zip 23.01 (x64)", "Igor Pavlov", []string{"19.00", "23.01", "24.08"}, protocol.AppSourceRegistry},
	{"Notepad++ (64-bit x64)", "Notepad++ Team", []string{"8.6.9", "8.7", "8.7.1"}, protocol.AppSourceRegistry},
	{"Adobe Acrobat Reader (64-bit)", "Adobe", []string{"24.002.21005", "24.003.20180", "24.004.20220"}, protocol.AppSourceMSI},
	{"Java 8 Update 421 (64-bit)", "Oracle Corporation", []string{"8.0.4010.10", "8.0.4210.9", "8.0.4310.10"}, protocol.AppSourceMSI},
	{"VLC media player", "VideoLAN", []string{"3.0.18", "3.0.20", "3.0.21"}, protocol.AppSourceRegistry},
	{"Microsoft Teams", "Microsoft Corporation", []string{"24215.1007.3082.1590", "24277.3507.3205.5228"}, protocol.AppSourceAppX},
	{"Microsoft 365 Apps for enterprise - tr-tr", "Microsoft Corporation", []string{"16.0.17928.20156", "16.0.18129.20158"}, protocol.AppSourceRegistry},
	{"WinRAR 6.24 (64-bit)", "win.rar GmbH", []string{"6.24.0", "7.01.0"}, protocol.AppSourceRegistry},
	{"PuTTY release 0.81 (64-bit)", "Simon Tatham", []string{"0.78.0.0", "0.81.0.0", "0.82.0.0"}, protocol.AppSourceMSI},
	{"Git", "The Git Development Community", []string{"2.45.2", "2.47.0"}, protocol.AppSourceRegistry},
	{"Python 3.12.7 (64-bit)", "Python Software Foundation", []string{"3.12.4150.0", "3.12.7150.0"}, protocol.AppSourceMSI},
	{"Cisco Secure Client - AnyConnect VPN", "Cisco Systems, Inc.", []string{"5.1.4.74", "5.1.6.103"}, protocol.AppSourceMSI},
}

var macApps = []appDef{
	{"Google Chrome", "Google LLC", []string{"129.0.6668.101", "130.0.6723.92", "131.0.6778.86"}, protocol.AppSourceAppBundle},
	{"Firefox", "Mozilla Corporation", []string{"131.0.3", "132.0.2"}, protocol.AppSourceAppBundle},
	{"zoom.us", "Zoom Video Communications, Inc", []string{"6.2.5 (41699)", "6.2.11 (43613)"}, protocol.AppSourceAppBundle},
	{"Microsoft Teams", "Microsoft Corporation", []string{"24277.3502.3161.3007", "24295.605.3225.8804"}, protocol.AppSourceAppBundle},
	{"Microsoft Outlook", "Microsoft Corporation", []string{"16.89.1", "16.91"}, protocol.AppSourceAppBundle},
	{"Slack", "Slack Technologies, Inc.", []string{"4.40.128", "4.41.97"}, protocol.AppSourceAppBundle},
	{"VLC", "VideoLAN", []string{"3.0.20", "3.0.21"}, protocol.AppSourceAppBundle},
	{"Visual Studio Code", "Microsoft Corporation", []string{"1.94.2", "1.95.3"}, protocol.AppSourceAppBundle},
	{"git", "", []string{"2.46.2", "2.47.1"}, protocol.AppSourceHomebrew},
	{"openssl@3", "", []string{"3.3.2", "3.4.0"}, protocol.AppSourceHomebrew},
}

type patchDef struct {
	kb, title, classification, severity string
	cves                                []string
	reboot                              bool
}

var windowsPatches = []patchDef{
	{"KB5046617", "2024-11 Windows 11 Version 23H2 için x64 tabanlı Sistemlere Yönelik Toplu Güncelleştirme (KB5046617)", "Security Updates", "Critical",
		[]string{"CVE-2024-43451", "CVE-2024-49039", "CVE-2024-43639"}, true},
	{"KB5044285", "2024-10 Windows 11 Version 23H2 için Toplu Güncelleştirme (KB5044285)", "Security Updates", "Critical",
		[]string{"CVE-2024-43573", "CVE-2024-43572"}, true},
	{"KB5046540", "2024-11 .NET Framework 3.5 ve 4.8.1 için Toplu Güncelleştirme (KB5046540)", "Security Updates", "Important",
		[]string{"CVE-2024-43499"}, false},
	{"KB5007651", "Windows Güvenlik platformu güncelleştirmesi (KB5007651)", "Updates", "", nil, false},
	{"KB890830", "Windows Kötü Amaçlı Yazılımları Temizleme Aracı x64 - v5.129 (KB890830)", "Update Rollups", "", nil, false},
	{"KB2267602", "Microsoft Defender Antivirus güvenlik zekası güncelleştirmesi (KB2267602)", "Definition Updates", "", nil, false},
	{"KB5002623", "Microsoft Office 2016 için güvenlik güncelleştirmesi (KB5002623)", "Security Updates", "Important",
		[]string{"CVE-2024-49029"}, false},
}

// Profile, sanal makinenin işletim sistemi profilidir.
type Profile struct {
	Platform, Name, Version, Build, Arch string
}

// Generate, index numaralı sanal makine için bir envanter anlık görüntüsü üretir.
// round her çağrıda artırılırsa bazı uygulamalar zamanla güncellenmiş gibi görünür.
func Generate(index int, p Profile, includeMissing bool) *inventory.Snapshot {
	r := rand.New(rand.NewPCG(uint64(index), 0x42455221))
	// Gün başına yuvarlanır; böylece aynı gün içinde üretilen envanterin özeti değişmez.
	now := time.Now().UTC().Truncate(24 * time.Hour)
	s := &inventory.Snapshot{Collected: map[string]bool{"os": true, "apps": true, "installed_patches": true}}
	s.OS = &protocol.OSInventory{
		Platform: p.Platform, Name: p.Name, Version: p.Version, Build: p.Build, Arch: p.Arch,
		CPUCores: []int{4, 8, 8, 12, 16}[r.IntN(5)], MemoryBytes: uint64([]int{8, 16, 16, 32}[r.IntN(4)]) << 30,
		RebootPending: r.IntN(6) == 0,
	}
	boot := now.Add(-time.Duration(r.IntN(240)) * time.Hour)
	s.OS.LastBootAt = &boot

	catalog := macApps
	if p.Platform == protocol.PlatformWindows {
		catalog = windowsApps
		s.OS.Manufacturer = []string{"Dell Inc.", "HP", "Lenovo"}[r.IntN(3)]
		s.OS.Model = []string{"Latitude 7440", "EliteBook 840 G10", "ThinkPad T14 Gen 4"}[r.IntN(3)]
		ou := []string{"OU=İstanbul,OU=Şubeler", "OU=Ankara,OU=Şubeler", "OU=İzmir,OU=Şubeler", "OU=Genel Müdürlük"}[r.IntN(4)]
		s.OS.Domain = "corp.example"
		s.OS.ADDN = fmt.Sprintf("CN=SIM-%04d,%s,DC=corp,DC=example", index, ou)
	} else {
		s.OS.Manufacturer, s.OS.Model = "Apple", []string{"MacBookPro18,1", "Mac14,2", "Mac15,3"}[r.IntN(3)]
	}
	s.OS.SerialNumber = fmt.Sprintf("SIM%07d", index)

	for _, a := range catalog {
		if r.IntN(10) < 2 { // her uygulama makinelerin ~%80'inde kurulu
			continue
		}
		// Çoğu makine güncel, bir kısmı bir veya iki sürüm geride.
		vi := len(a.versions) - 1
		if r.IntN(10) < 4 {
			vi = r.IntN(len(a.versions))
		}
		installed := now.AddDate(0, 0, -r.IntN(400)).Format("2006-01-02")
		s.Apps = append(s.Apps, protocol.App{
			Name: a.name, Version: a.versions[vi], Publisher: a.publisher, Source: a.source,
			InstallDate: installed, Scope: "machine",
		})
	}

	if p.Platform == protocol.PlatformWindows {
		for i := 0; i < 20+r.IntN(30); i++ {
			s.InstalledPatches = append(s.InstalledPatches, protocol.InstalledPatch{
				ID: fmt.Sprintf("KB50%05d", 30000+i*97), Source: "hotfix",
				InstalledOn: now.AddDate(0, 0, -i*14).Format("2006-01-02"),
			})
		}
	} else {
		s.InstalledPatches = append(s.InstalledPatches, protocol.InstalledPatch{
			ID: p.Name + " " + p.Version, Title: p.Name, Source: "softwareupdate", InstalledOn: now.AddDate(0, -1, 0).Format("2006-01-02"),
		})
	}

	if includeMissing {
		s.Collected["missing_patches"] = true
		s.MissingScan = &protocol.MissingScanInfo{Source: protocol.ScanSourceOnline, ScannedAt: now}
		if p.Platform == protocol.PlatformWindows {
			for i, d := range windowsPatches {
				if r.IntN(10) < 5 {
					continue
				}
				released := now.AddDate(0, 0, -7-i*9)
				s.MissingPatches = append(s.MissingPatches, protocol.MissingPatch{
					ID: fmt.Sprintf("sim-%s", d.kb), KB: d.kb, Title: d.title, Classification: d.classification,
					Severity: d.severity, CVEs: d.cves, RebootRequired: d.reboot, ReleasedAt: &released,
					SizeBytes: int64(5+r.IntN(800)) << 20, SupportURL: "https://support.microsoft.com/help/" + d.kb[2:],
				})
			}
		} else {
			s.MissingScan.Source = protocol.ScanSourceSoftwareUpdate
			if r.IntN(2) == 0 {
				s.MissingPatches = append(s.MissingPatches, protocol.MissingPatch{
					ID: "macOS Sequoia 15.1.1-24B91", Title: "macOS Sequoia 15.1.1", Version: "15.1.1",
					Classification: "macOS", Recommended: true, RebootRequired: true, SizeBytes: 1659427 * 1024,
				})
			}
			if r.IntN(3) == 0 {
				s.MissingPatches = append(s.MissingPatches, protocol.MissingPatch{
					ID: "Safari18.1.1SonomaAuto-18.1.1", Title: "Safari", Version: "18.1.1",
					Classification: "Application", Recommended: true, SizeBytes: 196215 * 1024,
				})
			}
		}
	}
	s.Apps = inventory.SortAndDedupeApps(s.Apps)
	s.InstalledPatches = inventory.SortInstalledPatches(s.InstalledPatches)
	s.MissingPatches = inventory.SortMissingPatches(s.MissingPatches)
	return s
}
