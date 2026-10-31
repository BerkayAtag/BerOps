// Package protocol, ajan ile sunucu (ve relay) arasındaki istek/yanıt tiplerini tanımlar.
// Alan adları JSON'da snake_case'tir; geriye dönük uyumluluk için alanlar silinmez,
// yalnızca eklenir.
package protocol

import "time"

// Ajan API yolları.
const (
	PathEnroll    = "/agent/v1/enroll"
	PathHeartbeat = "/agent/v1/heartbeat"
)

// Platform değerleri.
const (
	PlatformWindows = "windows"
	PlatformDarwin  = "darwin"
)

// Makine durumları.
const (
	StatusActive   = "active"
	StatusPending  = "pending"
	StatusRejected = "rejected"
	StatusRevoked  = "revoked"
)

// HostInfo, ajanın her heartbeat'te gönderdiği hafif makine bilgisidir.
// Ayrıntılı envanter (yamalar, uygulamalar) ayrı uç noktalardan gönderilir.
type HostInfo struct {
	Hostname     string   `json:"hostname"`
	OSPlatform   string   `json:"os_platform"`
	OSName       string   `json:"os_name"`
	OSVersion    string   `json:"os_version"`
	OSBuild      string   `json:"os_build"`
	Arch         string   `json:"arch"`
	IPAddresses  []string `json:"ip_addresses"`
	AgentVersion string   `json:"agent_version"`
}

// EnrollRequest, ilk kayıt isteğidir. İstemci sertifikası olmadan gönderilir.
type EnrollRequest struct {
	RegistrationKey string   `json:"registration_key"`
	CSRPEM          string   `json:"csr_pem"`
	Host            HostInfo `json:"host"`
}

// EnrollResponse, imzalanmış istemci sertifikasını ve CA'yı döner.
type EnrollResponse struct {
	AgentID          string `json:"agent_id"`
	Status           string `json:"status"`
	CertificatePEM   string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
	// ActionKey, sunucunun aksiyon imza anahtarının (Ed25519) açık anahtarıdır. Ajan bu anahtarı
	// sabitler ve yalnızca bu anahtarla imzalanmış işleri çalıştırır.
	ActionKey []byte `json:"action_key,omitempty"`
}

// HeartbeatRequest, mTLS ile gönderilir; ajan kimliği istemci sertifikasından alınır.
type HeartbeatRequest struct {
	Host           HostInfo  `json:"host"`
	AgentStartedAt time.Time `json:"agent_started_at"`
	Errors         []string  `json:"errors,omitempty"`
	// InventoryHashes, ajanın sunucuya son başarıyla yüklediği envanter bölümlerinin özetleridir.
	// Sunucudaki özetlerle uyuşmazsa sunucu tam envanter ister.
	InventoryHashes map[string]string `json:"inventory_hashes,omitempty"`
}

// HeartbeatResponse, sunucunun ajana verdiği talimatları taşır.
type HeartbeatResponse struct {
	Status           string         `json:"status"`
	HeartbeatSeconds int            `json:"heartbeat_seconds"`
	ServerTime       time.Time      `json:"server_time"`
	Settings         *AgentSettings `json:"settings,omitempty"`
	// RequestFullInventory, sunucunun envanteri eksik veya tutarsızsa true olur; ajan
	// elindeki son envanterin tamamını (yoksa yeni bir tarama) gönderir.
	RequestFullInventory bool `json:"request_full_inventory,omitempty"`
	// ScanRequestedAt, konsoldan "yeniden tara" istendiğinde isteğin zamanını taşır. Tarama
	// sonucu sunucuya ulaşana kadar her heartbeat'te tekrarlanır; ajan aynı isteği bir kez işler.
	ScanRequestedAt *time.Time `json:"scan_requested_at,omitempty"`
	// PendingJobs, ajanı bekleyen iş sayısıdır; sıfırdan büyükse ajan işleri çeker.
	PendingJobs int `json:"pending_jobs,omitempty"`
	// ActionKey, aksiyon imza anahtarıdır. Aşama 4'ten önce kaydolan ajanlar anahtarı ilk
	// heartbeat'te öğrenip sabitler.
	ActionKey []byte `json:"action_key,omitempty"`
}

// ErrorResponse, tüm API hatalarının ortak gövdesidir. Code makine tarafından okunur
// (konsol bunu çeviri anahtarına eşler), Message insan içindir.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
