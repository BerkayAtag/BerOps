package cve

import "math"

// Meta, risk hesabında kullanılan CVE bilgileridir.
type Meta struct {
	CVSS       *float64
	Severity   string // NVD: CRITICAL, HIGH, MEDIUM, LOW; MSRC önemi: Critical, Important, Moderate, Low
	EPSS       *float64
	KEV        bool
	Ransomware bool
	Exploited  bool // MSRC "Exploited: Yes"
}

// severityScore, CVSS yokken önem derecesinden tahmini taban skordur.
func severityScore(sev string) float64 {
	switch sev {
	case "CRITICAL", "Critical":
		return 9.5
	case "HIGH", "Important":
		return 7.5
	case "MEDIUM", "Moderate":
		return 5.0
	case "LOW", "Low":
		return 2.5
	case "NONE":
		return 0
	}
	return 5.0
}

// RiskScore, 0-100 arası önceliklendirme skorudur:
//
//	CVSS taban skoru × 6        (en fazla 60)
//	+ EPSS olasılığı × 25        (en fazla 25)
//	+ 15 (CISA KEV'de veya MSRC "istismar edildi")
//	+ 5  (fidye yazılımı kampanyalarında kullanıldığı biliniyor)
//
// Böylece aktif istismar edilen orta skorlu bir açık, istismarı bilinmeyen kritik bir
// açığın önüne geçebilir. Ayrıntı: docs/varsayimlar.md.
func RiskScore(m Meta) float64 {
	base := severityScore(m.Severity)
	if m.CVSS != nil {
		base = *m.CVSS
	}
	score := base * 6
	if m.EPSS != nil {
		score += math.Max(0, math.Min(1, *m.EPSS)) * 25
	}
	if m.KEV || m.Exploited {
		score += 15
	}
	if m.Ransomware {
		score += 5
	}
	return math.Round(math.Min(100, score)*10) / 10
}

// Risk düzeyleri.
const (
	RiskUrgent = "urgent"
	RiskHigh   = "high"
	RiskMedium = "medium"
	RiskLow    = "low"
)

// RiskLevel, skorun düzeyidir.
func RiskLevel(score float64) string {
	switch {
	case score >= 80:
		return RiskUrgent
	case score >= 60:
		return RiskHigh
	case score >= 40:
		return RiskMedium
	}
	return RiskLow
}

// NormalizeSeverity, MSRC önem derecesini NVD ölçeğine çevirir.
func NormalizeSeverity(s string) string {
	switch s {
	case "Critical", "CRITICAL":
		return "CRITICAL"
	case "Important", "HIGH", "High":
		return "HIGH"
	case "Moderate", "MEDIUM", "Medium":
		return "MEDIUM"
	case "Low", "LOW":
		return "LOW"
	case "NONE", "None":
		return "NONE"
	}
	return ""
}

// SeverityFromCVSS, CVSS v3 skorundan önem derecesi türetir.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "NONE"
}
