// Package inventory, ajanın işletim sistemi, yama ve uygulama envanterini toplar.
//
// Bu dosyadaki ayrıştırıcılar platformdan bağımsızdır ve her işletim sisteminde test
// edilir; veriyi okuyan platforma özel kod windows.go ve darwin.go dosyalarındadır.
package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// --- Windows: Uninstall kayıt defteri girdileri ---

// UninstallEntry, HKLM/HKU ...\Uninstall altındaki bir anahtarın okunan değerleridir.
type UninstallEntry struct {
	KeyName          string
	DisplayName      string
	DisplayVersion   string
	Publisher        string
	InstallDate      string
	InstallLocation  string
	ReleaseType      string
	ParentKeyName    string
	SystemComponent  uint64
	WindowsInstaller uint64
	Arch             string // x64, x86
	Scope            string // machine, user:<SID>
}

var kbInName = regexp.MustCompile(`(?i)\(KB\d{6,8}\)|^(Security )?Update for `)

// NormalizeUninstall, kayıt defteri girdisini uygulama kaydına çevirir. Sistem bileşenleri,
// başka bir ürünün güncellemeleri ve KB'ler uygulama olarak sayılmaz (yamalar ayrı toplanır).
func NormalizeUninstall(e UninstallEntry) (protocol.App, bool) {
	name := strings.TrimSpace(e.DisplayName)
	if name == "" || e.SystemComponent == 1 || e.ParentKeyName != "" || kbInName.MatchString(name) {
		return protocol.App{}, false
	}
	switch strings.ToLower(e.ReleaseType) {
	case "update", "hotfix", "security update", "servicepack":
		return protocol.App{}, false
	}
	src := protocol.AppSourceRegistry
	if e.WindowsInstaller == 1 {
		src = protocol.AppSourceMSI
	}
	return protocol.App{
		Name:            name,
		Version:         strings.TrimSpace(e.DisplayVersion),
		Publisher:       strings.TrimSpace(e.Publisher),
		InstallDate:     NormalizeDate(e.InstallDate),
		InstallLocation: strings.TrimSpace(e.InstallLocation),
		Source:          src,
		Identifier:      e.KeyName,
		Arch:            e.Arch,
		Scope:           e.Scope,
	}, true
}

// NormalizeDate, kayıt defteri ve WMI'da görülen tarih biçimlerini YYYY-MM-DD'ye çevirir.
// Tanınmayan biçimler için boş döner.
func NormalizeDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range []string{"20060102", "2006-01-02", "1/2/2006", "01/02/2006", "2.1.2006", "02.01.2006", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil && t.Year() > 1990 && t.Year() < 2100 {
			return t.Format("2006-01-02")
		}
	}
	if len(s) >= 10 {
		if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return ""
}

// --- Windows: PowerShell betik çıktıları ---

// classificationNames, Windows Update sınıflandırma GUID'lerinin İngilizce adlarıdır. Ad
// işletim sistemi diline göre yerelleştirildiği için GUID esas alınır.
var classificationNames = map[string]string{
	"0fa1201d-4330-4fa8-8ae9-b877473b6441": "Security Updates",
	"e6cf1350-c01b-414d-a61f-263d14d133b4": "Critical Updates",
	"cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83": "Updates",
	"28bc880e-0592-4cbf-8f95-c79b17911d5f": "Update Rollups",
	"68c5b0a3-d1a6-4553-ae49-01d3a7827828": "Service Packs",
	"b54e7d24-7add-428f-8b75-90a396fa584f": "Feature Packs",
	"e0789628-ce08-4437-be74-2495b842f43b": "Definition Updates",
	"ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0": "Drivers",
	"3689bdc8-b205-4af4-8d4a-a63924c5e9d5": "Upgrades",
	"b4832bd8-e735-4761-8daf-37f882276dab": "Tools",
}

type wuaUpdate struct {
	ID               string   `json:"id"`
	KB               []string `json:"kb"`
	Title            string   `json:"title"`
	ClassificationID string   `json:"classification_id"`
	Classification   string   `json:"classification"`
	Severity         string   `json:"severity"`
	ReleasedAt       string   `json:"released_at"`
	RebootRequired   bool     `json:"reboot_required"`
	SizeBytes        int64    `json:"size_bytes"`
	CVEs             []string `json:"cves"`
	SupportURL       string   `json:"support_url"`
}

type wuaResult struct {
	Source  string      `json:"source"`
	Updates []wuaUpdate `json:"updates"`
}

// ParseWUAResult, Windows Update Agent betiğinin JSON çıktısını ayrıştırır.
func ParseWUAResult(b []byte) ([]protocol.MissingPatch, string, error) {
	b = trimBOM(b)
	var r wuaResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, "", fmt.Errorf("Windows Update çıktısı okunamadı: %w", err)
	}
	out := make([]protocol.MissingPatch, 0, len(r.Updates))
	for _, u := range r.Updates {
		if u.ID == "" {
			continue
		}
		cls := classificationNames[strings.ToLower(u.ClassificationID)]
		if cls == "" {
			cls = u.Classification
		}
		var kbs []string
		for _, k := range u.KB {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(k), "KB") {
				k = "KB" + k
			}
			kbs = append(kbs, strings.ToUpper(k))
		}
		p := protocol.MissingPatch{
			ID:             strings.ToLower(u.ID),
			KB:             strings.Join(kbs, ","),
			Title:          u.Title,
			Classification: cls,
			Severity:       u.Severity,
			RebootRequired: u.RebootRequired,
			SizeBytes:      u.SizeBytes,
			CVEs:           normalizeCVEs(u.CVEs),
			SupportURL:     u.SupportURL,
		}
		if t, err := time.Parse(time.RFC3339, u.ReleasedAt); err == nil {
			t = t.UTC()
			p.ReleasedAt = &t
		}
		out = append(out, p)
	}
	return out, r.Source, nil
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func normalizeCVEs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if cvePattern.MatchString(c) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// SystemInfo, Windows sistem betiğinin çıktısıdır (WMI/CIM sorguları).
type SystemInfo struct {
	Hotfixes []struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		InstalledOn string `json:"installed_on"`
	} `json:"hotfixes"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	CPU          string `json:"cpu"`
	Memory       uint64 `json:"memory"`
	Domain       string `json:"domain"`
	PartOfDomain bool   `json:"part_of_domain"`
	LastBoot     string `json:"last_boot"`
	AppX         []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Publisher string `json:"publisher"`
		Family    string `json:"family"`
		Location  string `json:"location"`
		Arch      string `json:"arch"`
	} `json:"appx"`
}

// ParseSystemInfo, Windows sistem betiğinin JSON çıktısını ayrıştırır.
func ParseSystemInfo(b []byte) (*SystemInfo, error) {
	var si SystemInfo
	if err := json.Unmarshal(trimBOM(b), &si); err != nil {
		return nil, fmt.Errorf("sistem bilgisi okunamadı: %w", err)
	}
	return &si, nil
}

// HotfixPatches, sistem bilgisindeki KB listesini kurulu yamalara çevirir.
func (si *SystemInfo) HotfixPatches() []protocol.InstalledPatch {
	out := make([]protocol.InstalledPatch, 0, len(si.Hotfixes))
	for _, h := range si.Hotfixes {
		id := strings.ToUpper(strings.TrimSpace(h.ID))
		if id == "" || id == "FILE 1" {
			continue
		}
		out = append(out, protocol.InstalledPatch{
			ID: id, Title: strings.TrimSpace(h.Description), InstalledOn: NormalizeDate(h.InstalledOn), Source: "hotfix",
		})
	}
	return out
}

// AppXApps, Microsoft Store (AppX/MSIX) paketlerini uygulama kayıtlarına çevirir.
func (si *SystemInfo) AppXApps() []protocol.App {
	out := make([]protocol.App, 0, len(si.AppX))
	for _, a := range si.AppX {
		if a.Name == "" {
			continue
		}
		out = append(out, protocol.App{
			Name: a.Name, Version: a.Version, Publisher: publisherCN(a.Publisher), InstallLocation: a.Location,
			Source: protocol.AppSourceAppX, Identifier: a.Family, Arch: strings.ToLower(a.Arch), Scope: "machine",
		})
	}
	return out
}

// publisherCN, "CN=Microsoft Corporation, O=Microsoft Corporation, ..." biçiminden adı çıkarır.
func publisherCN(s string) string {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return s
}

func trimBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}

// --- macOS ---

// ParseSoftwareUpdateList, `softwareupdate --list` çıktısını ayrıştırır.
//
//   - Label: macOS Sequoia 15.1.1-24B91
//     Title: macOS Sequoia 15.1.1, Version: 15.1.1, Size: 1659427KiB, Recommended: YES, Action: restart,
func ParseSoftwareUpdateList(out string) []protocol.MissingPatch {
	var res []protocol.MissingPatch
	var cur *protocol.MissingPatch
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if label, ok := strings.CutPrefix(line, "* Label:"); ok {
			res = append(res, protocol.MissingPatch{ID: strings.TrimSpace(label), Classification: "macOS"})
			cur = &res[len(res)-1]
			continue
		}
		if cur == nil || !strings.HasPrefix(line, "Title:") {
			continue
		}
		for _, field := range strings.Split(line, ",") {
			k, v, ok := strings.Cut(field, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "Title":
				cur.Title = v
			case "Version":
				cur.Version = v
			case "Size":
				cur.SizeBytes = parseKiB(v)
			case "Recommended":
				cur.Recommended = strings.EqualFold(v, "YES")
			case "Action":
				cur.RebootRequired = strings.EqualFold(v, "restart") || strings.EqualFold(v, "shut down")
			}
		}
		if cur.Title == "" {
			cur.Title = cur.ID
		}
		if !strings.HasPrefix(cur.Title, "macOS") {
			cur.Classification = "Application"
		}
		cur = nil
	}
	for i := range res {
		if res[i].Title == "" {
			res[i].Title = res[i].ID
		}
	}
	return res
}

func parseKiB(v string) int64 {
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(v, "KiB"), "K"))
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n * 1024
}

type infoPlist struct {
	Name           string `plist:"CFBundleName"`
	DisplayName    string `plist:"CFBundleDisplayName"`
	ShortVersion   string `plist:"CFBundleShortVersionString"`
	Version        string `plist:"CFBundleVersion"`
	Identifier     string `plist:"CFBundleIdentifier"`
	Copyright      string `plist:"NSHumanReadableCopyright"`
	BackgroundOnly bool   `plist:"LSBackgroundOnly"`
}

// ParseInfoPlist, bir .app paketinin Info.plist içeriğini (XML veya ikili) uygulama kaydına çevirir.
func ParseInfoPlist(data []byte, appPath string) (protocol.App, error) {
	var ip infoPlist
	if _, err := plist.Unmarshal(data, &ip); err != nil {
		return protocol.App{}, err
	}
	name := ip.DisplayName
	if name == "" {
		name = ip.Name
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(appPath), ".app")
	}
	ver := ip.ShortVersion
	if ver == "" {
		ver = ip.Version
	}
	return protocol.App{
		Name:            strings.TrimSpace(name),
		Version:         strings.TrimSpace(ver),
		Publisher:       publisherFromCopyright(ip.Copyright),
		InstallLocation: appPath,
		Source:          protocol.AppSourceAppBundle,
		Identifier:      ip.Identifier,
	}, nil
}

var (
	rightsRe    = regexp.MustCompile(`(?i)all rights reserved\.?`)
	copyMarkRe  = regexp.MustCompile(`(?i)copyright|©|\(c\)`)
	yearRangeRe = regexp.MustCompile(`\b\d{4}(\s*[-–]\s*(\d{4}|present))?\b`)
)

// publisherFromCopyright, "Copyright © 2010-2024 Google LLC. All rights reserved." gibi
// bir metinden yayıncıyı ("Google LLC") çıkarır; çıkaramazsa boş döner.
func publisherFromCopyright(s string) string {
	s = rightsRe.ReplaceAllString(s, "")
	s = copyMarkRe.ReplaceAllString(s, "")
	s = yearRangeRe.ReplaceAllString(s, "")
	s = strings.Trim(s, " \t\n.,;")
	if s == "" || len(s) > 80 {
		return ""
	}
	return s
}

type receiptPlist struct {
	PackageIdentifier string    `plist:"PackageIdentifier"`
	PackageVersion    string    `plist:"PackageVersion"`
	InstallDate       time.Time `plist:"InstallDate"`
	InstallPrefixPath string    `plist:"InstallPrefixPath"`
}

// ParseReceipt, /var/db/receipts/*.plist dosyasını uygulama kaydına çevirir. Apple'ın
// kendi paketleri (com.apple.*) işletim sisteminin parçası olduğu için atlanır.
func ParseReceipt(data []byte) (protocol.App, bool) {
	var r receiptPlist
	if _, err := plist.Unmarshal(data, &r); err != nil || r.PackageIdentifier == "" {
		return protocol.App{}, false
	}
	if strings.HasPrefix(r.PackageIdentifier, "com.apple.") {
		return protocol.App{}, false
	}
	a := protocol.App{
		Name: r.PackageIdentifier, Version: r.PackageVersion, Source: protocol.AppSourcePkg,
		Identifier: r.PackageIdentifier, InstallLocation: r.InstallPrefixPath, Scope: "machine",
	}
	if !r.InstallDate.IsZero() {
		a.InstallDate = r.InstallDate.UTC().Format("2006-01-02")
	}
	return a, true
}

type historyEntry struct {
	Date           time.Time `plist:"date"`
	DisplayName    string    `plist:"displayName"`
	DisplayVersion string    `plist:"displayVersion"`
	ProcessName    string    `plist:"processName"`
}

// ParseInstallHistory, /Library/Receipts/InstallHistory.plist içindeki Apple yazılım
// güncellemelerini kurulu yamalar olarak döner.
func ParseInstallHistory(data []byte) ([]protocol.InstalledPatch, error) {
	var entries []historyEntry
	if _, err := plist.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []protocol.InstalledPatch
	for _, e := range entries {
		if e.ProcessName != "softwareupdated" && e.ProcessName != "macOS Installer" {
			continue
		}
		id := strings.TrimSpace(e.DisplayName + " " + e.DisplayVersion)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		p := protocol.InstalledPatch{ID: id, Title: e.DisplayName, Source: "softwareupdate"}
		if !e.Date.IsZero() {
			p.InstalledOn = e.Date.UTC().Format("2006-01-02")
		}
		out = append(out, p)
	}
	return out, nil
}

// ScanHomebrew, Homebrew Cellar (formüller) veya Caskroom dizinini okur. Her paket için
// en yüksek sürüm dizini alınır. Homebrew root olarak çalıştırılamadığı için komut yerine
// dizin yapısı okunur.
func ScanHomebrew(root, source string) []protocol.App {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []protocol.App
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		vers, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		var names []string
		for _, v := range vers {
			if v.IsDir() && !strings.HasPrefix(v.Name(), ".") {
				names = append(names, v.Name())
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Slice(names, func(i, j int) bool { return CompareVersions(names[i], names[j]) < 0 })
		latest := names[len(names)-1]
		out = append(out, protocol.App{
			Name: e.Name(), Version: latest, Source: source, Identifier: e.Name(),
			InstallLocation: filepath.Join(root, e.Name(), latest), Scope: "machine",
		})
	}
	return out
}

// CompareVersions, noktalı sürüm dizgelerini sayısal olarak karşılaştırır (1.10 > 1.9).
// Sayısal olmayan parçalar metin olarak karşılaştırılır.
func CompareVersions(a, b string) int {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == '+' || r == ' ' })
	}
	pa, pb := split(a), split(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.ParseInt(x, 10, 64)
		ny, ey := strconv.ParseInt(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if nx != ny {
				if nx < ny {
					return -1
				}
				return 1
			}
		case x != y:
			if x == "" {
				return -1
			}
			if y == "" {
				return 1
			}
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// --- Ortak ---

// SortAndDedupeApps, uygulamaları deterministik sıraya koyar ve aynı kaydı tekilleştirir.
// Özetin (hash) yalnızca gerçek değişikliklerde değişmesi için gereklidir.
func SortAndDedupeApps(apps []protocol.App) []protocol.App {
	sort.Slice(apps, func(i, j int) bool {
		a, b := apps[i], apps[j]
		if !strings.EqualFold(a.Name, b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.InstallLocation < b.InstallLocation
	})
	out := apps[:0]
	for i, a := range apps {
		if i > 0 {
			p := out[len(out)-1]
			if strings.EqualFold(p.Name, a.Name) && p.Version == a.Version && p.Arch == a.Arch && p.Scope == a.Scope && p.Source == a.Source {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// SortInstalledPatches, kurulu yamaları kimliğe göre sıralar ve tekilleştirir.
func SortInstalledPatches(ps []protocol.InstalledPatch) []protocol.InstalledPatch {
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	out := ps[:0]
	for i, p := range ps {
		if i > 0 && out[len(out)-1].ID == p.ID {
			continue
		}
		out = append(out, p)
	}
	return out
}

// SortMissingPatches, eksik yamaları kimliğe göre sıralar.
func SortMissingPatches(ps []protocol.MissingPatch) []protocol.MissingPatch {
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	return ps
}
