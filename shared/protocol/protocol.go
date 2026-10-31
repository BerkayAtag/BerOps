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
}

// HeartbeatRequest, mTLS ile gönderilir; ajan kimliği istemci sertifikasından alınır.
type HeartbeatRequest struct {
	Host           HostInfo  `json:"host"`
	AgentStartedAt time.Time `json:"agent_started_at"`
	Errors         []string  `json:"errors,omitempty"`
}

// HeartbeatResponse, sunucunun ajana verdiği talimatları taşır.
type HeartbeatResponse struct {
	Status           string    `json:"status"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	ServerTime       time.Time `json:"server_time"`
}

// ErrorResponse, tüm API hatalarının ortak gövdesidir. Code makine tarafından okunur
// (konsol bunu çeviri anahtarına eşler), Message insan içindir.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
