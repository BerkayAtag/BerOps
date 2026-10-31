package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/ad"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// maxInventoryBody, açılmış envanter gövdesinin üst sınırıdır.
const maxInventoryBody = 32 << 20

// settingsCache, her heartbeat'te veritabanına gitmemek için ajan ayarlarını kısa süre tutar.
type settingsCache struct {
	mu      sync.Mutex
	value   protocol.AgentSettings
	expires time.Time
}

const settingsCacheTTL = 30 * time.Second

func (s *Server) agentSettings(r *http.Request) (protocol.AgentSettings, error) {
	s.settings.mu.Lock()
	defer s.settings.mu.Unlock()
	now := s.now()
	if now.Before(s.settings.expires) {
		return s.settings.value, nil
	}
	v, err := s.store.GetAgentSettings(r.Context())
	if err != nil {
		return v, err
	}
	s.settings.value, s.settings.expires = v, now.Add(settingsCacheTTL)
	return v, nil
}

func (s *Server) invalidateSettings() {
	s.settings.mu.Lock()
	s.settings.expires = time.Time{}
	s.settings.mu.Unlock()
}

// inventoryInstructions, heartbeat yanıtına envanterle ilgili talimatları ekler.
func (s *Server) inventoryInstructions(r *http.Request, machineID string, agentHashes map[string]string, resp *protocol.HeartbeatResponse) error {
	st, err := s.store.GetInventoryState(r.Context(), machineID)
	if err != nil {
		return err
	}
	if len(agentHashes) > 0 {
		if !st.HasInventory {
			resp.RequestFullInventory = true
		} else {
			for sec, h := range agentHashes {
				if st.Hashes[sec] != h {
					resp.RequestFullInventory = true
					break
				}
			}
		}
	}
	if st.ScanRequestedAt != nil && (st.ReceivedAt == nil || st.ReceivedAt.Before(*st.ScanRequestedAt)) {
		resp.ScanRequestedAt = st.ScanRequestedAt
	}
	return nil
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	if m.Status != protocol.StatusActive && m.Status != protocol.StatusPending {
		writeError(w, http.StatusForbidden, codeAgentRevoked, "Ajan reddedilmiş veya iptal edilmiş")
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, codeUnsupportedMedia, "İçerik türü application/json olmalı")
		return
	}
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxInventoryBody)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "gzip gövdesi okunamadı")
			return
		}
		defer zr.Close()
		// Sıkıştırma bombasına karşı açılmış boyut da sınırlanır.
		body = io.LimitReader(zr, maxInventoryBody+1)
	}
	var rep protocol.InventoryReport
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Envanter gövdesi geçersiz: "+err.Error())
		return
	}
	if err := rep.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	now := s.now()
	if rep.CollectedAt.IsZero() || rep.CollectedAt.After(now.Add(time.Hour)) {
		rep.CollectedAt = now
	}
	if err := s.store.ApplyInventory(r.Context(), m.ID, &rep, now); err != nil {
		s.log.Error("envanter kaydedilemedi", "ajan", m.ID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.vulns.Enqueue(m.ID)
	// Log'a ajanın gönderdiği metinler değil, sabit değerlerden türetilenler yazılır (log enjeksiyonuna karşı).
	kind := "değişiklik"
	if rep.Full {
		kind = "tam"
	}
	var sections []string
	for _, sec := range protocol.AllSections {
		if rep.Has(sec) {
			sections = append(sections, sec)
		}
	}
	s.log.Info("envanter alındı", "ajan", m.ID, "tür", kind, "bölümler", strings.Join(sections, ","),
		"uygulama", len(rep.Apps), "eksik_yama", len(rep.MissingPatches))
	w.WriteHeader(http.StatusNoContent)
}

// wsusCabPath, çevrimdışı Windows Update kataloğunun sunucudaki yoludur.
func (s *Server) wsusCabPath() string {
	return filepath.Join(s.cfg.DataDir, "wsus", "wsusscn2.cab")
}

func (s *Server) handleWSUSCab(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.agentFromTLS(w, r); !ok {
		return
	}
	f, err := os.Open(s.wsusCabPath())
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, codeNotFound, "Sunucuda wsusscn2.cab bulunmuyor")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// ServeContent, Range (kaldığı yerden devam) ve If-Modified-Since isteklerini destekler.
	// İstemci başına hız sınırı paket indirmeleriyle aynıdır.
	noWriteDeadline(w)
	fileDownloadHeaders(w, "application/vnd.ms-cab-compressed")
	w.Header().Set("ETag", `"`+strconv.FormatInt(info.ModTime().Unix(), 16)+"-"+strconv.FormatInt(info.Size(), 16)+`"`)
	http.ServeContent(newThrottledWriter(r.Context(), w, s.clientRate(r, 0)), r, "wsusscn2.cab", info.ModTime(), f)
}

// --- Konsol ---

type machineListResponse struct {
	Items    []store.MachineListItem `json:"items"`
	Total    int                     `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
}

func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size < 1 || size > 500 {
		size = 50
	}
	f := store.MachineFilter{
		Search:       q.Get("q"),
		Platform:     q.Get("platform"),
		Status:       q.Get("status"),
		Sort:         q.Get("sort"),
		Desc:         q.Get("desc") == "true",
		Limit:        size,
		Offset:       (page - 1) * size,
		Now:          s.now(),
		OnlineWindow: s.onlineWindow(),
		Scope:        sess.User.Scope(),
	}
	if f.Platform != "" && f.Platform != protocol.PlatformWindows && f.Platform != protocol.PlatformDarwin {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz platform")
		return
	}
	switch f.Status {
	case "", protocol.StatusActive, protocol.StatusPending, protocol.StatusRejected, protocol.StatusRevoked:
	default:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz durum")
		return
	}
	switch q.Get("online") {
	case "true":
		v := true
		f.Online = &v
	case "false":
		v := false
		f.Online = &v
	}
	items, total, err := s.store.ListMachinesFiltered(r.Context(), f)
	if err != nil {
		s.log.Error("makineler okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, machineListResponse{Items: items, Total: total, Page: page, PageSize: size})
}

func (s *Server) handleFleetSummary(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	sum, err := s.store.GetFleetSummary(r.Context(), s.now(), s.onlineWindow(), sess.User.Scope())
	if err != nil {
		s.log.Error("filo özeti hesaplanamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

type machineDetailResponse struct {
	Machine         store.Machine           `json:"machine"`
	Online          bool                    `json:"online"`
	ScanRequestedAt *time.Time              `json:"scan_requested_at"`
	Inventory       *store.InventorySummary `json:"inventory"`
	Risk            *store.MachineRisk      `json:"risk"`
}

// machineFromPath, yoldaki makine kimliğini doğrular ve makineyi yükler.
func (s *Server) machineFromPath(w http.ResponseWriter, r *http.Request) (*store.Machine, bool) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
		return nil, false
	}
	m, err := s.store.GetMachine(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	// Kapsam dışındaki makine, varlığı da belli olmasın diye "bulunamadı" döner.
	if sess := sessionFrom(r.Context()); sess != nil && !ad.InScope(m.ADOU, sess.User.Scope()) {
		writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
		return nil, false
	}
	return m, true
}

func (s *Server) handleGetMachine(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	resp := machineDetailResponse{Machine: *m}
	resp.Online = m.LastSeenAt != nil && s.now().Sub(*m.LastSeenAt) <= s.onlineWindow() &&
		(m.Status == protocol.StatusActive || m.Status == protocol.StatusPending)
	inv, err := s.store.GetInventorySummary(r.Context(), m.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	default:
		resp.Inventory = inv
	}
	if risk, err := s.store.GetMachineRisk(r.Context(), m.ID); err == nil {
		resp.Risk = risk
	}
	st, err := s.store.GetInventoryState(r.Context(), m.ID)
	if err == nil && st.ScanRequestedAt != nil && (st.ReceivedAt == nil || st.ReceivedAt.Before(*st.ScanRequestedAt)) {
		resp.ScanRequestedAt = st.ScanRequestedAt
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMachineMissingPatches(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListMissingPatches(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleMachineInstalledPatches(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListInstalledPatches(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleMachineApps(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListApps(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type scanRequest struct {
	MachineIDs []string `json:"machine_ids"`
}

func (s *Server) handleRequestScan(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req scanRequest
	if !decodeJSON(w, r, &req, 256<<10) {
		return
	}
	if len(req.MachineIDs) == 0 || len(req.MachineIDs) > 5000 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "1-5000 makine seçilmeli")
		return
	}
	for _, id := range req.MachineIDs {
		if !validUUID(id) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz makine kimliği: "+id)
			return
		}
	}
	if scope := sess.User.Scope(); scope != nil {
		targets, err := s.store.ActiveMachines(r.Context(), req.MachineIDs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		for _, t := range targets {
			if !ad.InScope(t.OU, scope) {
				writeError(w, http.StatusForbidden, codeForbidden, "Seçilen makinelerden bazıları yetki kapsamınızın dışında")
				return
			}
		}
	}
	n, err := s.store.RequestScan(r.Context(), req.MachineIDs, s.now())
	if err != nil {
		s.log.Error("tarama isteği kaydedilemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "machine.scan_request", TargetType: "machine", Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"machine_ids": req.MachineIDs, "accepted": n},
	})
	writeJSON(w, http.StatusOK, map[string]any{"accepted": n})
}

type agentSettingsResponse struct {
	Settings protocol.AgentSettings `json:"settings"`
	WSUSCab  *wsusCabInfo           `json:"wsus_cab"`
}

type wsusCabInfo struct {
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

func (s *Server) handleGetAgentSettings(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	set, err := s.store.GetAgentSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	resp := agentSettingsResponse{Settings: set}
	if info, err := os.Stat(s.wsusCabPath()); err == nil {
		resp.WSUSCab = &wsusCabInfo{SizeBytes: info.Size(), ModifiedAt: info.ModTime()}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePutAgentSettings(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var set protocol.AgentSettings
	if !decodeJSON(w, r, &set, 8<<10) {
		return
	}
	if err := set.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	old, _ := s.store.GetAgentSettings(r.Context())
	if err := s.store.SaveAgentSettings(r.Context(), set, sess.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.invalidateSettings()
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.agent.update", TargetType: "settings", TargetID: "agent", Result: store.ResultSuccess,
		SourceIP: clientIP(r), Params: map[string]any{"old": old, "new": set},
	})
	writeJSON(w, http.StatusOK, agentSettingsResponse{Settings: set})
}
