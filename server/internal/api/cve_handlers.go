package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/cve"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

// trendDays, gösterge panelindeki uyumluluk eğiliminin gün sayısıdır.
const trendDays = 30

// RunBackground, zafiyet korelasyon kuyruğunu ve CVE kaynak zamanlayıcısını ctx kapanana
// kadar çalıştırır.
func (s *Server) RunBackground(ctx context.Context) {
	go s.vulns.Run(ctx)
	go s.runMinutely(ctx)
	// Başlangıçta envanteri olan tüm makineler bir kez hesaplanır (kural veya kod değişmiş olabilir).
	s.vulns.RecomputeAll()
	if !s.cfg.CVE.Enabled {
		s.log.Info("CVE kaynak eşitlemesi kapalı (cve.enabled: false)")
		return
	}
	go s.runCVEScheduler(ctx)
}

// runCVEScheduler, eşitleme aralığı dolan kaynakları eşitler. İlk kontrol sunucu açıldıktan
// bir dakika sonra yapılır; konsoldan "Şimdi eşitle" isteği beklemeden tetikler.
func (s *Server) runCVEScheduler(ctx context.Context) {
	first := time.NewTimer(time.Minute)
	defer first.Stop()
	tick := time.NewTicker(15 * time.Minute)
	defer tick.Stop()
	for {
		var force bool
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		case <-s.syncTrigger:
			force = true
		}
		feeds := s.dueFeeds(ctx, force)
		if len(feeds) == 0 {
			continue
		}
		err := s.cveSync.Sync(ctx, feeds...)
		if errors.Is(err, cve.ErrSyncRunning) || ctx.Err() != nil {
			continue
		}
		// Kısmi başarıda da yeni veriyle yeniden hesaplanır.
		s.vulns.RecomputeAll()
	}
}

func (s *Server) dueFeeds(ctx context.Context, force bool) []string {
	if force {
		return cve.AllFeeds
	}
	st, err := s.store.ListFeedStatus(ctx)
	if err != nil {
		s.log.Warn("CVE kaynak durumu okunamadı", "hata", err)
		return nil
	}
	var due []string
	interval := s.cfg.CVE.SyncInterval.D()
	for _, f := range st {
		// Başarısız kaynak bir saat sonra yeniden denenir.
		retry := f.LastError != "" && f.LastAttemptAt != nil && s.now().Sub(*f.LastAttemptAt) >= time.Hour
		if f.LastSuccessAt == nil || s.now().Sub(*f.LastSuccessAt) >= interval || retry {
			due = append(due, f.Feed)
		}
	}
	return due
}

func (s *Server) newSyncer() *cve.Syncer {
	return &cve.Syncer{
		Store:      s.store,
		Log:        s.log,
		Products:   s.vulns.TrackedProducts,
		NVDAPIKey:  s.cfg.CVE.NVDAPIKey,
		MSRCMonths: s.cfg.CVE.MSRCMonths,
		OfflineDir: s.cfg.CVE.OfflineDir,
		Now:        func() time.Time { return s.now() },
	}
}

// --- Konsol uç noktaları ---

func (s *Server) handleRiskSummary(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	sum, err := s.store.GetRiskSummary(r.Context(), trendDays, sess.User.Scope())
	if err != nil {
		s.log.Error("risk özeti hesaplanamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

var validSeverity = map[string]bool{"": true, "CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}

func vulnFilterFromQuery(r *http.Request) (store.VulnFilter, int, int, bool) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size < 1 || size > 500 {
		size = 50
	}
	f := store.VulnFilter{
		Search:   q.Get("q"),
		Severity: strings.ToUpper(q.Get("severity")),
		KEV:      q.Get("kev") == "true",
		Kind:     q.Get("kind"),
		Sort:     q.Get("sort"),
		Desc:     q.Get("desc") != "false",
		Limit:    size,
		Offset:   (page - 1) * size,
	}
	ok := validSeverity[f.Severity] && (f.Kind == "" || f.Kind == "os" || f.Kind == "app")
	return f, page, size, ok
}

func (s *Server) handleListVulns(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	f, page, size, ok := vulnFilterFromQuery(r)
	f.Scope = sess.User.Scope()
	if !ok {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz filtre")
		return
	}
	items, total, err := s.store.ListVulnerabilities(r.Context(), f)
	if err != nil {
		s.log.Error("zafiyetler okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) handleGetVuln(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := strings.ToUpper(r.PathValue("id"))
	if !cve.ValidCVEID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "CVE bulunamadı")
		return
	}
	d, err := s.store.GetCVEDetail(r.Context(), id, sess.User.Scope())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "CVE bulunamadı")
		return
	}
	if err != nil {
		s.log.Error("CVE okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleMachineVulns(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListMachineVulns(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type cveStatusResponse struct {
	Enabled      bool               `json:"enabled"`
	Offline      bool               `json:"offline"`
	Running      bool               `json:"running"`
	IntervalHrs  float64            `json:"sync_interval_hours"`
	NVDAPIKey    bool               `json:"nvd_api_key"`
	MSRCMonths   int                `json:"msrc_months"`
	Feeds        []store.FeedStatus `json:"feeds"`
	ProductCount int                `json:"tracked_products"`
}

func (s *Server) handleCVEStatus(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	feeds, err := s.store.ListFeedStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	keys := map[string]bool{}
	for _, rule := range s.vulns.Rules() {
		keys[rule.Key()] = true
	}
	writeJSON(w, http.StatusOK, cveStatusResponse{
		Enabled: s.cfg.CVE.Enabled, Offline: s.cfg.CVE.OfflineDir != "", Running: s.cveSync.Running(),
		IntervalHrs: s.cfg.CVE.SyncInterval.D().Hours(), NVDAPIKey: s.cfg.CVE.NVDAPIKey != "",
		MSRCMonths: s.cfg.CVE.MSRCMonths, Feeds: feeds, ProductCount: len(keys),
	})
}

func (s *Server) handleCVESync(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	if !s.cfg.CVE.Enabled {
		writeError(w, http.StatusConflict, codeConflict, "CVE eşitlemesi yapılandırmada kapalı")
		return
	}
	if s.cveSync.Running() {
		writeError(w, http.StatusConflict, codeConflict, "Eşitleme zaten çalışıyor")
		return
	}
	select {
	case s.syncTrigger <- struct{}{}:
	default:
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "cve.sync", TargetType: "settings", TargetID: "cve", Result: store.ResultSuccess, SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) handleListRules(w http.ResponseWriter, _ *http.Request, _ *store.Session) {
	writeJSON(w, http.StatusOK, map[string]any{"items": s.vulns.Rules()})
}

type ruleRequest struct {
	Name       string `json:"name"`
	Publisher  string `json:"publisher"`
	Identifier string `json:"identifier"`
	Part       string `json:"part"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req ruleRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	rule := cve.ProductRule{
		Name: strings.TrimSpace(req.Name), Publisher: strings.TrimSpace(req.Publisher),
		Identifier: strings.TrimSpace(req.Identifier), Part: req.Part,
		Vendor: strings.ToLower(strings.TrimSpace(req.Vendor)), Product: strings.ToLower(strings.TrimSpace(req.Product)),
	}
	if rule.Part == "" {
		rule.Part = "a"
	}
	if rule.Part != "a" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Özel kurallar yalnızca uygulamalar (a) içindir")
		return
	}
	if len(rule.Name)+len(rule.Publisher)+len(rule.Identifier) > 600 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kalıplar çok uzun")
		return
	}
	if err := cve.ValidateRule(rule); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	created, err := s.store.CreateAppRule(r.Context(), rule, sess.User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.afterRulesChanged(r.Context())
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "cve.rule.create", TargetType: "cve_rule", TargetID: created.ID, Result: store.ResultSuccess,
		SourceIP: clientIP(r), Params: map[string]any{"rule": created},
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kural bulunamadı")
		return
	}
	err := s.store.DeleteAppRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kural bulunamadı")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.afterRulesChanged(r.Context())
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "cve.rule.delete", TargetType: "cve_rule", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

// afterRulesChanged, eşleyiciyi yeniler; yeni ürünlerin CVE'leri sonraki eşitlemede çekilir.
func (s *Server) afterRulesChanged(ctx context.Context) {
	if err := s.vulns.ReloadRules(ctx); err != nil {
		s.log.Error("CVE kuralları yüklenemedi", "hata", err)
		return
	}
	s.vulns.RecomputeAll()
	if s.cfg.CVE.Enabled {
		select {
		case s.syncTrigger <- struct{}{}:
		default:
		}
	}
}

// runMinutely, dakikalık işleri (kademeli dağıtım, bildirimler, zamanlanmış raporlar) yürütür.
func (s *Server) runMinutely(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RunRollouts(ctx)
			s.RunNotifications(ctx)
		}
	}
}
