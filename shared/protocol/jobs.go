package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// İş (aksiyon) uç noktaları.
const (
	// PathJobs, ajanın bekleyen işlerini döner (GET).
	PathJobs = "/agent/v1/jobs"
	// PathJobStatusFmt, işin durumunu bildirme yoludur (POST): /agent/v1/jobs/{id}/status.
	PathJobStatusFmt = "/agent/v1/jobs/%s/status"
	// PathPackageFileFmt, paket dosyasının indirme yoludur (GET, Range destekli):
	// /agent/v1/packages/{id}/file?action={aksiyon}.
	PathPackageFileFmt = "/agent/v1/packages/%s/file"
)

// İş türleri.
const (
	JobDeployPackage = "deploy_package"
	JobRunCommand    = "run_command"
	// JobDeployPatch, işletim sistemi güncellemesi kurar (Windows Update Agent / softwareupdate).
	// Ajan için komut çalıştırmadan farkı yoktur; komutu sunucu üretir ve imzalar.
	JobDeployPatch = "deploy_patch"
	// JobRestart, makineyi bildirimle ve süre tanıyarak yeniden başlatır (komutu sunucu üretir).
	JobRestart = "restart"
	// JobCollectLogs, ajanın kendi günlük dosyasının son kısmını sonuç çıktısı olarak döndürür;
	// komut çalıştırılmaz.
	JobCollectLogs = "collect_logs"
)

// Komut kabukları.
const (
	ShellCmd        = "cmd"
	ShellPowerShell = "powershell"
	ShellSh         = "sh"
	ShellZsh        = "zsh"
)

// ValidShell, kabuğun platformda kullanılabilir olup olmadığını döner.
func ValidShell(platform, shell string) bool {
	switch platform {
	case PlatformWindows:
		return shell == ShellCmd || shell == ShellPowerShell
	case PlatformDarwin:
		return shell == ShellSh || shell == ShellZsh
	}
	return false
}

// Paket yükleyici türleri.
const (
	InstallerMSI = "msi"
	InstallerEXE = "exe"
	InstallerPKG = "pkg"
	InstallerDMG = "dmg"
	// InstallerFile, yalnızca dosyayı indirip komutu çalıştırır (betik, yapılandırma dosyası vb.).
	InstallerFile = "file"
)

// İş hedef durumları.
const (
	TargetPending     = "pending"
	TargetDownloading = "downloading"
	TargetRunning     = "running"
	TargetSucceeded   = "succeeded"
	TargetFailed      = "failed"
	TargetCancelled   = "cancelled"
	TargetExpired     = "expired"
)

// FinalTargetStatus, durumun son durum olup olmadığını döner.
func FinalTargetStatus(s string) bool {
	switch s {
	case TargetSucceeded, TargetFailed, TargetCancelled, TargetExpired:
		return true
	}
	return false
}

// FilePlaceholder, kurulum komutunda indirilen dosyanın tam yoluyla değiştirilen yer tutucudur.
const FilePlaceholder = "{file}"

// MaxOutputBytes, ajanın bildirdiği stdout/stderr çıktılarının her birinin üst sınırıdır.
const MaxOutputBytes = 64 << 10

// JobPackage, işle gönderilen paket dosyasıdır.
type JobPackage struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	FileName  string `json:"file_name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Installer string `json:"installer"`
}

// Job, ajanın çalıştıracağı iştir. Sunucunun aksiyon imza anahtarıyla imzalanır; ajan imzayı,
// makine kimliğini ve süresini doğrulamadan hiçbir şey çalıştırmaz.
type Job struct {
	ID             string      `json:"id"` // aksiyon kimliği
	Kind           string      `json:"kind"`
	MachineID      string      `json:"machine_id"`
	IssuedAt       time.Time   `json:"issued_at"`
	ExpiresAt      time.Time   `json:"expires_at"`
	TimeoutSeconds int         `json:"timeout_seconds"`
	Shell          string      `json:"shell"`
	Command        string      `json:"command"`
	Package        *JobPackage `json:"package,omitempty"`
	// SuccessCodes, başarılı sayılan çıkış kodlarıdır (ör. MSI 3010: yeniden başlatma gerekli).
	SuccessCodes []int `json:"success_codes"`
	// Patches, yama dağıtımında kurulacak güncellemelerin kimlikleridir (bilgi amaçlı; ajan
	// Command'ı çalıştırır).
	Patches []string `json:"patches,omitempty"`
	// RescanAfter true ise iş bittikten sonra ajan değişiklik taraması yapar.
	RescanAfter bool `json:"rescan_after"`
}

// SignedJob, imzalı iş zarfıdır. Payload, Job'un JSON gösterimidir; imza bu baytların
// Ed25519 imzasıdır (yeniden kodlamadan doğabilecek farkları önler).
type SignedJob struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// SignJob, işi imzalar.
func SignJob(key ed25519.PrivateKey, j Job) (SignedJob, error) {
	b, err := json.Marshal(j)
	if err != nil {
		return SignedJob{}, err
	}
	return SignedJob{Payload: b, Signature: ed25519.Sign(key, b)}, nil
}

// İmza doğrulama hataları.
var (
	ErrBadSignature  = errors.New("iş imzası geçersiz")
	ErrWrongMachine  = errors.New("iş başka bir makine için imzalanmış")
	ErrJobExpired    = errors.New("işin süresi dolmuş")
	ErrInvalidJobDef = errors.New("iş tanımı geçersiz")
)

// Verify, imzayı, makine kimliğini ve süreyi doğrular ve işi döner.
func (s SignedJob) Verify(pub ed25519.PublicKey, machineID string, now time.Time) (*Job, error) {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, s.Payload, s.Signature) {
		return nil, ErrBadSignature
	}
	var j Job
	if err := json.Unmarshal(s.Payload, &j); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJobDef, err)
	}
	if j.MachineID != machineID {
		return nil, ErrWrongMachine
	}
	if !now.Before(j.ExpiresAt) {
		return nil, ErrJobExpired
	}
	switch j.Kind {
	case JobDeployPackage:
		if j.Package == nil || len(j.Package.SHA256) != 64 {
			return nil, ErrInvalidJobDef
		}
	case JobRunCommand, JobDeployPatch, JobRestart:
		if j.Command == "" {
			return nil, ErrInvalidJobDef
		}
	case JobCollectLogs:
	default:
		return nil, ErrInvalidJobDef
	}
	if j.TimeoutSeconds <= 0 {
		return nil, ErrInvalidJobDef
	}
	return &j, nil
}

// JobsResponse, bekleyen işlerdir.
type JobsResponse struct {
	Jobs []SignedJob `json:"jobs"`
}

// JobStatusRequest, ajanın iş durumu bildirimidir. Son durumlarda çıkış kodu ve çıktı eklenir.
type JobStatusRequest struct {
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Error    string `json:"error,omitempty"`
}
