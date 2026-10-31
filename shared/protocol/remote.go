package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

// Uzaktan yönetim uç noktaları.
const (
	// PathRemotePoll, uzaktan oturum sürerken ajanın uzun yoklama yaptığı uç noktadır (GET).
	// İstek yoksa 204 döner; oturum bittiyse ajan yoklamayı bırakır.
	PathRemotePoll = "/agent/v1/remote/poll"
	// PathRemoteResultFmt, isteğin sonucunu gönderme yoludur (POST).
	PathRemoteResultFmt = "/agent/v1/remote/%s/result"
)

// Uzaktan işlemler.
const (
	RemotePerformance     = "performance"
	RemoteServicesList    = "services.list"
	RemoteServicesControl = "services.control"
	RemoteRegistryList    = "registry.list"
	RemoteRegistrySet     = "registry.set"
	RemoteRegistryDelete  = "registry.delete"
)

// RemoteFlags, makinede açık olan uzaktan yönetim özellikleridir. Varsayılan hepsi kapalıdır;
// ajan bu bayraklara göre isteği kendisi de reddeder.
type RemoteFlags struct {
	Performance   bool `json:"performance"`
	Services      bool `json:"services"`
	RegistryRead  bool `json:"registry_read"`
	RegistryWrite bool `json:"registry_write"`
}

// Allows, işlemin bayraklarla izinli olup olmadığını döner.
func (f RemoteFlags) Allows(op string) bool {
	switch op {
	case RemotePerformance:
		return f.Performance
	case RemoteServicesList, RemoteServicesControl:
		return f.Services
	case RemoteRegistryList:
		return f.RegistryRead || f.RegistryWrite
	case RemoteRegistrySet, RemoteRegistryDelete:
		return f.RegistryWrite
	}
	return false
}

// Any, en az bir özelliğin açık olup olmadığını döner.
func (f RemoteFlags) Any() bool {
	return f.Performance || f.Services || f.RegistryRead || f.RegistryWrite
}

// RemoteRequest, ajana gönderilen uzaktan işlem isteğidir; işler gibi imzalanır.
type RemoteRequest struct {
	ID        string          `json:"id"`
	MachineID string          `json:"machine_id"`
	Op        string          `json:"op"`
	Params    json.RawMessage `json:"params,omitempty"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// SignRemote, isteği imzalar.
func SignRemote(key ed25519.PrivateKey, r RemoteRequest) (SignedJob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return SignedJob{}, err
	}
	return SignedJob{Payload: b, Signature: ed25519.Sign(key, b)}, nil
}

// VerifyRemote, imzayı, makine kimliğini ve süreyi doğrular.
func (s SignedJob) VerifyRemote(pub ed25519.PublicKey, machineID string, now time.Time) (*RemoteRequest, error) {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, s.Payload, s.Signature) {
		return nil, ErrBadSignature
	}
	var r RemoteRequest
	if err := json.Unmarshal(s.Payload, &r); err != nil || r.Op == "" {
		return nil, fmt.Errorf("%w: uzaktan istek", ErrInvalidJobDef)
	}
	if r.MachineID != machineID {
		return nil, ErrWrongMachine
	}
	if !now.Before(r.ExpiresAt) {
		return nil, ErrJobExpired
	}
	return &r, nil
}

// RemoteResult, ajanın döndürdüğü sonuçtur.
type RemoteResult struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// PerfSnapshot, anlık performans bilgisidir.
type PerfSnapshot struct {
	CollectedAt   time.Time     `json:"collected_at"`
	CPUPercent    float64       `json:"cpu_percent"`
	CPUCores      int           `json:"cpu_cores"`
	MemTotal      uint64        `json:"mem_total"`
	MemUsed       uint64        `json:"mem_used"`
	SwapTotal     uint64        `json:"swap_total"`
	SwapUsed      uint64        `json:"swap_used"`
	UptimeSeconds uint64        `json:"uptime_seconds"`
	Disks         []DiskUsage   `json:"disks"`
	Processes     []ProcessInfo `json:"processes"`
}

// DiskUsage, bir birimin doluluğudur.
type DiskUsage struct {
	Mount  string `json:"mount"`
	FSType string `json:"fs_type"`
	Total  uint64 `json:"total"`
	Used   uint64 `json:"used"`
}

// ProcessInfo, en çok kaynak kullanan süreçlerden biridir.
type ProcessInfo struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user,omitempty"`
	CPUPercent float64 `json:"cpu_percent"`
	RSS        uint64  `json:"rss"`
}

// ServiceInfo, işletim sistemi servisidir (Windows servisi, macOS launchd işi).
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state"` // running, stopped, starting, stopping, paused, unknown
	StartType   string `json:"start_type,omitempty"`
	PID         int    `json:"pid,omitempty"`
}

// ServiceControlParams, servis kontrol isteğidir.
type ServiceControlParams struct {
	Name   string `json:"name"`
	Action string `json:"action"` // start, stop, restart
}

// RegistryPathParams, kayıt defteri yolu parametresidir ("HKLM\SOFTWARE\Örnek").
type RegistryPathParams struct {
	Path string `json:"path"`
}

// RegistryValue, kayıt defteri değeridir. Data, türe göre metne çevrilmiş değerdir
// (DWORD/QWORD ondalık, BINARY onaltılık, MULTI_SZ satır satır).
type RegistryValue struct {
	Name string `json:"name"`
	Type string `json:"type"` // REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY
	Data string `json:"data"`
}

// RegistryKey, anahtarın alt anahtarları ve değerleridir.
type RegistryKey struct {
	Path      string          `json:"path"`
	Subkeys   []string        `json:"subkeys"`
	Values    []RegistryValue `json:"values"`
	Truncated bool            `json:"truncated,omitempty"`
}

// RegistrySetParams, değer yazma isteğidir.
type RegistrySetParams struct {
	Path  string        `json:"path"`
	Value RegistryValue `json:"value"`
}

// RegistryDeleteParams, değer silme isteğidir.
type RegistryDeleteParams struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// RegistryChange, yazma/silme sonucudur; geri alma için önceki değeri taşır.
type RegistryChange struct {
	Previous *RegistryValue `json:"previous,omitempty"`
}
