package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/cve"
	"github.com/BerkayAtag/automation-ber/server/internal/report"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// Rapor türleri.
const (
	reportCompliance = "compliance"
	reportVulns      = "vulnerabilities"
	reportMissing    = "missing-patches"
	reportApps       = "apps"
)

// reportText, rapor başlıkları ve sütun adlarıdır (konsoldaki çevirilerle uyumlu).
var reportText = map[string]map[string]string{
	"tr": {
		"compliance.title": "Uyumluluk Raporu", "compliance.file": "uyumluluk-raporu",
		"vulnerabilities.title": "Zafiyet Raporu", "vulnerabilities.file": "zafiyet-raporu",
		"missing-patches.title": "Eksik Yama Raporu", "missing-patches.file": "eksik-yama-raporu",
		"apps.title": "Uygulama Envanteri Raporu", "apps.file": "uygulama-raporu",
		"machine": "Makine", "platform": "Platform", "os": "İşletim sistemi", "build": "Yapı", "ou": "OU",
		"lastSeen": "Son görülme", "inventory": "Son envanter", "missing": "Eksik yama", "critical": "Kritik eksik",
		"security": "Güvenlik eksik", "vulns": "Zafiyet", "kev": "KEV", "risk": "En yüksek risk",
		"reboot": "Yeniden başlatma", "state": "Durum", "state.patched": "Tam yamalı", "state.missing": "Eksik yama var",
		"state.none": "Envanter yok", "cve": "CVE", "title": "Başlık", "severity": "Önem", "cvss": "CVSS",
		"epss": "EPSS", "riskScore": "Risk", "affected": "Etkilenen makine", "kind": "Tür", "kind.os": "İşletim sistemi",
		"kind.app": "Uygulama", "kind.both": "İşletim sistemi + uygulama", "published": "Yayın", "kb": "KB / sürüm",
		"classification": "Sınıflandırma", "released": "Yayın tarihi", "cveCount": "CVE sayısı", "app": "Uygulama",
		"version": "Sürüm", "publisher": "Yayıncı", "machines": "Makine sayısı",
		"sum.machines": "Toplam makine", "sum.patched": "Tam yamalı", "sum.kevMachines": "KEV açığı olan makine",
		"sum.avgRisk": "Ortalama risk", "sum.cves": "Farklı CVE", "sum.kev": "KEV'de", "sum.urgent": "Acil (risk ≥ 80)",
		"sum.missing": "Eksik yama", "sum.affected": "Etkilenen makine", "sum.apps": "Uygulama/sürüm", "sum.installs": "Kurulum",
		"all": "Tümü", "pdfLimit": "PDF ilk %d satırı içerir; tamamı için Excel veya CSV biçimini kullanın.",
		"sev.CRITICAL": "Kritik", "sev.HIGH": "Yüksek", "sev.MEDIUM": "Orta", "sev.LOW": "Düşük",
		"sev.Critical": "Kritik", "sev.Important": "Önemli", "sev.Moderate": "Orta", "sev.Low": "Düşük",
		"short.missing": "Eksik", "short.critical": "Kritik", "short.risk": "Risk", "short.reboot": "Y. başlatma",
		"short.affected": "Makine",
	},
	"en": {
		"compliance.title": "Compliance Report", "compliance.file": "compliance-report",
		"vulnerabilities.title": "Vulnerability Report", "vulnerabilities.file": "vulnerability-report",
		"missing-patches.title": "Missing Patch Report", "missing-patches.file": "missing-patch-report",
		"apps.title": "Application Inventory Report", "apps.file": "application-report",
		"machine": "Machine", "platform": "Platform", "os": "Operating system", "build": "Build", "ou": "OU",
		"lastSeen": "Last seen", "inventory": "Last inventory", "missing": "Missing", "critical": "Critical missing",
		"security": "Security missing", "vulns": "Vulnerabilities", "kev": "KEV", "risk": "Highest risk",
		"reboot": "Reboot pending", "state": "State", "state.patched": "Fully patched", "state.missing": "Missing patches",
		"state.none": "No inventory", "cve": "CVE", "title": "Title", "severity": "Severity", "cvss": "CVSS",
		"epss": "EPSS", "riskScore": "Risk", "affected": "Affected machines", "kind": "Type", "kind.os": "Operating system",
		"kind.app": "Application", "kind.both": "Operating system + application", "published": "Published", "kb": "KB / version",
		"classification": "Classification", "released": "Released", "cveCount": "CVEs", "app": "Application",
		"version": "Version", "publisher": "Publisher", "machines": "Machines",
		"sum.machines": "Machines", "sum.patched": "Fully patched", "sum.kevMachines": "Machines with KEV",
		"sum.avgRisk": "Average risk", "sum.cves": "Distinct CVEs", "sum.kev": "In KEV", "sum.urgent": "Urgent (risk ≥ 80)",
		"sum.missing": "Missing patches", "sum.affected": "Affected machines", "sum.apps": "App/version pairs", "sum.installs": "Installs",
		"all": "All", "pdfLimit": "The PDF contains the first %d rows; use Excel or CSV for the full report.",
		"sev.CRITICAL": "Critical", "sev.HIGH": "High", "sev.MEDIUM": "Medium", "sev.LOW": "Low",
		"sev.Critical": "Critical", "sev.Important": "Important", "sev.Moderate": "Moderate", "sev.Low": "Low",
		"short.missing": "Missing", "short.critical": "Critical", "short.risk": "Risk", "short.reboot": "Reboot",
		"short.affected": "Machines",
	},
}

// decimal, ondalık sayıyı rapor diline göre biçimler (Türkçede virgül).
func decimal(lang string, v float64) string {
	s := fmt.Sprintf("%.1f", v)
	if lang == "tr" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

func rt(lang, key string) string {
	if v, ok := reportText[lang][key]; ok {
		return v
	}
	if v, ok := reportText["en"][key]; ok {
		return v
	}
	return key
}

func platformName(p string) string {
	switch p {
	case protocol.PlatformWindows:
		return "Windows"
	case protocol.PlatformDarwin:
		return "macOS"
	}
	return p
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	q := r.URL.Query()
	kind := r.PathValue("type")
	format := report.Format(q.Get("format"))
	if format == "" {
		format = report.XLSX
	}
	if format != report.CSV && format != report.XLSX && format != report.PDF {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Biçim csv, xlsx veya pdf olmalı")
		return
	}
	lang := q.Get("lang")
	if lang != "en" {
		lang = "tr"
	}
	loc := time.UTC
	if tz := q.Get("tz"); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	platform := q.Get("platform")
	if platform != "" && platform != protocol.PlatformWindows && platform != protocol.PlatformDarwin {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz platform")
		return
	}
	t := &report.Table{
		GeneratedAt: s.now(), GeneratedBy: sess.User.Username, Lang: lang, Location: loc,
		Title: rt(lang, kind+".title"),
	}
	if sess.User.DisplayName != "" {
		t.GeneratedBy = sess.User.DisplayName
	}
	var filters []string
	if platform != "" {
		filters = append(filters, rt(lang, "platform")+": "+platformName(platform))
	}

	var err error
	switch kind {
	case reportCompliance:
		err = s.buildComplianceReport(r, t, platform)
	case reportVulns:
		f, _, _, ok := vulnFilterFromQuery(r)
		if !ok {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz filtre")
			return
		}
		if f.Severity != "" {
			filters = append(filters, rt(lang, "severity")+": "+rt(lang, "sev."+f.Severity))
		}
		if f.KEV {
			filters = append(filters, rt(lang, "kev"))
		}
		err = s.buildVulnReport(r, t, f)
	case reportMissing:
		sev := q.Get("severity")
		switch sev {
		case "", "Critical", "Important", "Moderate", "Low":
		default:
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz önem derecesi")
			return
		}
		if sev != "" {
			filters = append(filters, rt(lang, "severity")+": "+rt(lang, "sev."+sev))
		}
		err = s.buildMissingReport(r, t, platform, sev)
	case reportApps:
		search := strings.TrimSpace(q.Get("q"))
		if search != "" {
			filters = append(filters, "“"+search+"”")
		}
		err = s.buildAppsReport(r, t, platform, search)
	default:
		writeError(w, http.StatusNotFound, codeNotFound, "Rapor bulunamadı")
		return
	}
	if err != nil {
		s.log.Error("rapor oluşturulamadı", "rapor", kind, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	t.Subtitle = strings.Join(filters, " · ")
	if format == report.PDF && len(t.Rows) > report.MaxPDFRows {
		t.Note = fmt.Sprintf(rt(lang, "pdfLimit"), report.MaxPDFRows)
	}

	// Önce belleğe yazılır; hata olursa yarım dosya yerine JSON hata döner.
	var buf bytes.Buffer
	if err := report.Write(&buf, format, t); err != nil {
		s.log.Error("rapor yazılamadı", "rapor", kind, "biçim", string(format), "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "report.export", TargetType: "report", TargetID: kind, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"format": string(format), "rows": len(t.Rows), "filters": q.Encode()},
	})
	name := fmt.Sprintf("%s-%s.%s", rt(lang, kind+".file"), s.now().In(loc).Format("2006-01-02"), format)
	w.Header().Set("Content-Type", format.ContentType())
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) buildComplianceReport(r *http.Request, t *report.Table, platform string) error {
	lang := t.Lang
	items, _, err := s.store.ListMachinesFiltered(r.Context(), store.MachineFilter{
		Platform: platform, Sort: "hostname", Unlimited: true, Now: s.now(), OnlineWindow: s.onlineWindow(),
	})
	if err != nil {
		return err
	}
	t.Columns = []report.Column{
		{Header: rt(lang, "machine"), Width: 17}, {Header: rt(lang, "platform"), Width: 8},
		{Header: rt(lang, "os"), Width: 21}, {Header: rt(lang, "build"), Width: 15},
		{Header: rt(lang, "lastSeen"), Width: 16, Kind: report.DateTime},
		{Header: rt(lang, "short.missing"), Width: 7, Kind: report.Number},
		{Header: rt(lang, "short.critical"), Width: 7, Kind: report.Number},
		{Header: rt(lang, "vulns"), Width: 8, Kind: report.Number}, {Header: rt(lang, "kev"), Width: 5, Kind: report.Number},
		{Header: rt(lang, "short.risk"), Width: 6, Kind: report.Decimal}, {Header: rt(lang, "short.reboot"), Width: 10},
		{Header: rt(lang, "state"), Width: 13}, {Header: rt(lang, "ou"), Width: 22},
	}
	var patched, withInv, kevMachines int
	var riskSum float64
	for _, m := range items {
		if m.Status != protocol.StatusActive && m.Status != protocol.StatusPending {
			continue
		}
		state := rt(lang, "state.none")
		var missing, critical any
		if m.InventoryAt != nil {
			withInv++
			riskSum += float64(m.MaxRisk)
			missing, critical = m.MissingCount, m.MissingCriticalCount
			state = rt(lang, "state.missing")
			if m.MissingCount == 0 {
				state = rt(lang, "state.patched")
				patched++
			}
		}
		if m.KEVCount > 0 {
			kevMachines++
		}
		t.Rows = append(t.Rows, []any{
			m.Hostname, platformName(m.OSPlatform), strings.TrimSpace(m.OSName + " " + m.OSVersion), m.OSBuild,
			m.LastSeenAt, missing, critical, m.VulnCount, m.KEVCount, m.MaxRisk, m.RebootPending, state, m.ADOU,
		})
	}
	pct := "—"
	avg := "—"
	if withInv > 0 {
		pct = fmt.Sprintf("%d / %d", patched, withInv)
		avg = decimal(lang, riskSum/float64(withInv))
	}
	t.Summary = []report.Metric{
		{Label: rt(lang, "sum.machines"), Value: fmt.Sprint(len(t.Rows))},
		{Label: rt(lang, "sum.patched"), Value: pct},
		{Label: rt(lang, "sum.kevMachines"), Value: fmt.Sprint(kevMachines)},
		{Label: rt(lang, "sum.avgRisk"), Value: avg},
	}
	return nil
}

func (s *Server) buildVulnReport(r *http.Request, t *report.Table, f store.VulnFilter) error {
	lang := t.Lang
	f.Unlimited = true
	items, _, err := s.store.ListVulnerabilities(r.Context(), f)
	if err != nil {
		return err
	}
	t.Columns = []report.Column{
		{Header: rt(lang, "cve"), Width: 16}, {Header: rt(lang, "title"), Width: 41},
		{Header: rt(lang, "severity"), Width: 9}, {Header: rt(lang, "cvss"), Width: 6, Kind: report.Decimal},
		{Header: rt(lang, "epss"), Width: 7, Kind: report.Percent}, {Header: rt(lang, "kev"), Width: 6},
		{Header: rt(lang, "riskScore"), Width: 6, Kind: report.Decimal}, {Header: rt(lang, "short.affected"), Width: 7, Kind: report.Number},
		{Header: rt(lang, "kind"), Width: 19}, {Header: rt(lang, "published"), Width: 10, Kind: report.Date},
	}
	var kev, urgent, affected int
	for _, v := range items {
		k := "kind.os"
		switch {
		case v.OS && v.App:
			k = "kind.both"
		case v.App:
			k = "kind.app"
		}
		sev := ""
		if v.Severity != "" {
			sev = rt(lang, "sev."+v.Severity)
		}
		if v.KEV {
			kev++
		}
		if cve.RiskLevel(float64(v.Risk)) == cve.RiskUrgent {
			urgent++
		}
		affected += v.AffectedMachines
		t.Rows = append(t.Rows, []any{
			v.CVE, v.Title, sev, v.CVSS, v.EPSS, v.KEV, v.Risk, v.AffectedMachines, rt(lang, k), v.PublishedAt,
		})
	}
	t.Summary = []report.Metric{
		{Label: rt(lang, "sum.cves"), Value: fmt.Sprint(len(items))},
		{Label: rt(lang, "sum.kev"), Value: fmt.Sprint(kev)},
		{Label: rt(lang, "sum.urgent"), Value: fmt.Sprint(urgent)},
	}
	return nil
}

func (s *Server) buildMissingReport(r *http.Request, t *report.Table, platform, severity string) error {
	lang := t.Lang
	rows, err := s.store.ReportMissingPatches(r.Context(), platform, severity)
	if err != nil {
		return err
	}
	t.Columns = []report.Column{
		{Header: rt(lang, "machine"), Width: 18}, {Header: rt(lang, "platform"), Width: 8},
		{Header: rt(lang, "kb"), Width: 12}, {Header: rt(lang, "title"), Width: 48},
		{Header: rt(lang, "classification"), Width: 16}, {Header: rt(lang, "severity"), Width: 9},
		{Header: rt(lang, "released"), Width: 10, Kind: report.Date}, {Header: rt(lang, "reboot"), Width: 8},
		{Header: rt(lang, "cveCount"), Width: 7, Kind: report.Number},
	}
	machines := map[string]bool{}
	for _, p := range rows {
		machines[p.Hostname] = true
		kb := p.KB
		if kb == "" {
			kb = p.Version
		}
		sev := ""
		if p.Severity != "" {
			sev = rt(lang, "sev."+p.Severity)
		}
		t.Rows = append(t.Rows, []any{
			p.Hostname, platformName(p.Platform), kb, p.Title, p.Classification, sev, p.ReleasedAt, p.RebootRequired, p.CVECount,
		})
	}
	t.Summary = []report.Metric{
		{Label: rt(lang, "sum.missing"), Value: fmt.Sprint(len(rows))},
		{Label: rt(lang, "sum.affected"), Value: fmt.Sprint(len(machines))},
	}
	return nil
}

func (s *Server) buildAppsReport(r *http.Request, t *report.Table, platform, search string) error {
	lang := t.Lang
	rows, err := s.store.ReportApps(r.Context(), platform, search)
	if err != nil {
		return err
	}
	t.Columns = []report.Column{
		{Header: rt(lang, "app"), Width: 40}, {Header: rt(lang, "version"), Width: 18},
		{Header: rt(lang, "publisher"), Width: 28}, {Header: rt(lang, "platform"), Width: 9},
		{Header: rt(lang, "machines"), Width: 9, Kind: report.Number},
	}
	installs := 0
	for _, a := range rows {
		installs += a.Machines
		t.Rows = append(t.Rows, []any{a.Name, a.Version, a.Publisher, platformName(a.Platform), a.Machines})
	}
	t.Summary = []report.Metric{
		{Label: rt(lang, "sum.apps"), Value: fmt.Sprint(len(rows))},
		{Label: rt(lang, "sum.installs"), Value: fmt.Sprint(installs)},
	}
	return nil
}
