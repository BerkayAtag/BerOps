package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PathInventory, envanter yükleme uç noktasıdır.
const PathInventory = "/agent/v1/inventory"

// PathWSUSCab, çevrimdışı Windows Update taraması için sunucunun dağıttığı katalog dosyasıdır.
const PathWSUSCab = "/agent/v1/files/wsusscn2.cab"

// Envanter bölümleri. Her bölüm ayrı özetlenir; delta yüklemelerde yalnızca değişen
// bölümler gönderilir.
const (
	SectionOS               = "os"
	SectionInstalledPatches = "installed_patches"
	SectionMissingPatches   = "missing_patches"
	SectionApps             = "apps"
)

// AllSections, bölümlerin sabit sırasıdır.
var AllSections = []string{SectionOS, SectionInstalledPatches, SectionMissingPatches, SectionApps}

// Uygulama kaynakları.
const (
	AppSourceRegistry     = "registry"
	AppSourceMSI          = "msi"
	AppSourceAppX         = "appx"
	AppSourceAppBundle    = "app_bundle"
	AppSourcePkg          = "pkg"
	AppSourceHomebrew     = "homebrew"
	AppSourceHomebrewCask = "homebrew_cask"
)

// Eksik yama tarama kaynakları.
const (
	ScanSourceOnline         = "online"         // Windows Update / yapılandırılmış WSUS
	ScanSourceOffline        = "offline"        // sunucunun dağıttığı wsusscn2.cab
	ScanSourceSoftwareUpdate = "softwareupdate" // macOS softwareupdate --list
)

// OSInventory, işletim sistemi ve donanım özetidir.
type OSInventory struct {
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	// Build, yama seviyesidir (Windows: 10.0.22631.4460, macOS: 24B83).
	Build         string     `json:"build"`
	Arch          string     `json:"arch"`
	Manufacturer  string     `json:"manufacturer,omitempty"`
	Model         string     `json:"model,omitempty"`
	SerialNumber  string     `json:"serial_number,omitempty"`
	CPUModel      string     `json:"cpu_model,omitempty"`
	CPUCores      int        `json:"cpu_cores,omitempty"`
	MemoryBytes   uint64     `json:"memory_bytes,omitempty"`
	Domain        string     `json:"domain,omitempty"`
	ADDN          string     `json:"ad_dn,omitempty"` // bilgisayarın AD ayırt edici adı (Windows)
	LastBootAt    *time.Time `json:"last_boot_at,omitempty"`
	RebootPending bool       `json:"reboot_pending"`
}

// InstalledPatch, kurulu bir yamadır (Windows KB, macOS güncellemesi).
type InstalledPatch struct {
	ID          string `json:"id"` // KB5034441 veya macOS güncelleme adı
	Title       string `json:"title,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"` // YYYY-MM-DD
	Source      string `json:"source"`
}

// MissingPatch, kurulması gereken bir güncellemedir.
type MissingPatch struct {
	ID             string     `json:"id"` // Windows UpdateID veya macOS etiketi
	KB             string     `json:"kb,omitempty"`
	Title          string     `json:"title"`
	Classification string     `json:"classification,omitempty"`
	Severity       string     `json:"severity,omitempty"` // MSRC: Critical, Important, Moderate, Low
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
	RebootRequired bool       `json:"reboot_required"`
	SizeBytes      int64      `json:"size_bytes,omitempty"`
	CVEs           []string   `json:"cves,omitempty"`
	Version        string     `json:"version,omitempty"`
	Recommended    bool       `json:"recommended,omitempty"`
	SupportURL     string     `json:"support_url,omitempty"`
}

// App, kurulu bir üçüncü parti uygulamadır.
type App struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher,omitempty"`
	InstallDate     string `json:"install_date,omitempty"` // YYYY-MM-DD
	InstallLocation string `json:"install_location,omitempty"`
	Source          string `json:"source"`
	// Identifier; MSI ürün kodu, AppX paket ailesi, macOS bundle/paket kimliği veya Homebrew formül adıdır.
	Identifier string `json:"identifier,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Scope      string `json:"scope,omitempty"` // "machine" veya "user:<ad>"
}

// InventoryReport, ajanın gönderdiği envanterdir. Included, raporda bulunan bölümleri
// listeler; listede olmayan bölümler sunucuda değiştirilmez. Hashes ise ajanın elindeki
// tüm bölümlerin güncel özetleridir.
type InventoryReport struct {
	Full             bool              `json:"full"`
	CollectedAt      time.Time         `json:"collected_at"`
	ScanDurationMs   int64             `json:"scan_duration_ms"`
	Included         []string          `json:"included"`
	Hashes           map[string]string `json:"hashes"`
	OS               *OSInventory      `json:"os,omitempty"`
	InstalledPatches []InstalledPatch  `json:"installed_patches,omitempty"`
	MissingPatches   []MissingPatch    `json:"missing_patches,omitempty"`
	MissingScan      *MissingScanInfo  `json:"missing_scan,omitempty"`
	Apps             []App             `json:"apps,omitempty"`
	Errors           []string          `json:"errors,omitempty"`
}

// MissingScanInfo, eksik yama taramasının nasıl yapıldığını belirtir.
type MissingScanInfo struct {
	Source    string    `json:"source"`
	ScannedAt time.Time `json:"scanned_at"`
}

// Has, bölümün raporda olup olmadığını döner.
func (r *InventoryReport) Has(section string) bool {
	for _, s := range r.Included {
		if s == section {
			return true
		}
	}
	return false
}

// Validate, raporun yapısal tutarlılığını denetler.
func (r *InventoryReport) Validate() error {
	known := map[string]bool{}
	for _, s := range AllSections {
		known[s] = true
	}
	for _, s := range r.Included {
		if !known[s] {
			return fmt.Errorf("bilinmeyen envanter bölümü: %s", s)
		}
	}
	if r.Has(SectionOS) && r.OS == nil {
		return errors.New("os bölümü bildirildi ama içerik yok")
	}
	if r.Has(SectionMissingPatches) && r.MissingScan == nil {
		return errors.New("missing_patches bölümü tarama bilgisi olmadan gönderilemez")
	}
	if len(r.Apps) > 20000 || len(r.InstalledPatches) > 20000 || len(r.MissingPatches) > 5000 {
		return errors.New("envanter boyutu sınırı aşıldı")
	}
	return nil
}

// HashSection, bir bölüm içeriğinin özetidir. İçerik çağıran tarafından deterministik
// sırada verilmelidir (ajan listeleri sıralar).
func HashSection(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AgentSettings, sunucunun heartbeat yanıtında ajana ilettiği çalışma ayarlarıdır.
type AgentSettings struct {
	// FullScanIntervalHours, eksik yama taraması dahil tam envanter aralığıdır.
	FullScanIntervalHours int `json:"full_scan_interval_hours"`
	// DeltaScanIntervalHours, ucuz bölümlerin (uygulamalar, kurulu yamalar) yeniden
	// toplanma aralığıdır; yalnızca değişen bölümler gönderilir.
	DeltaScanIntervalHours int `json:"delta_scan_interval_hours"`
	// ScanCPULimitPercent, tarama sırasında ajanın ve alt süreçlerinin kullanabileceği
	// toplam CPU üst sınırıdır.
	ScanCPULimitPercent int  `json:"scan_cpu_limit_percent"`
	DeferOnBattery      bool `json:"defer_on_battery"`
	DeferWhenUserActive bool `json:"defer_when_user_active"`
	// WindowsUpdateSource: "online" (Windows Update / WSUS) veya "offline" (sunucudaki wsusscn2.cab).
	WindowsUpdateSource string `json:"windows_update_source"`
}

// DefaultAgentSettings, kurulum sonrası varsayılan ayarlardır.
func DefaultAgentSettings() AgentSettings {
	return AgentSettings{
		FullScanIntervalHours:  24,
		DeltaScanIntervalHours: 4,
		ScanCPULimitPercent:    10,
		DeferOnBattery:         true,
		DeferWhenUserActive:    false,
		WindowsUpdateSource:    ScanSourceOnline,
	}
}

// Validate, ayarların izin verilen aralıkta olduğunu denetler.
func (s AgentSettings) Validate() error {
	var errs []error
	if s.FullScanIntervalHours < 1 || s.FullScanIntervalHours > 168 {
		errs = append(errs, errors.New("tam tarama aralığı 1-168 saat olmalı"))
	}
	if s.DeltaScanIntervalHours < 1 || s.DeltaScanIntervalHours > s.FullScanIntervalHours {
		errs = append(errs, errors.New("değişiklik taraması aralığı 1 saat ile tam tarama aralığı arasında olmalı"))
	}
	if s.ScanCPULimitPercent < 1 || s.ScanCPULimitPercent > 100 {
		errs = append(errs, errors.New("CPU sınırı %1-%100 olmalı"))
	}
	if s.WindowsUpdateSource != ScanSourceOnline && s.WindowsUpdateSource != ScanSourceOffline {
		errs = append(errs, errors.New("Windows Update kaynağı online veya offline olmalı"))
	}
	return errors.Join(errs...)
}
