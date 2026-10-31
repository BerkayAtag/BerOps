package api

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/BerkayAtag/BerOps/server/internal/ad"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// windowCache, her heartbeat'te pencereleri okumamak için kısa süreli önbellektir.
type windowCache struct {
	mu      sync.Mutex
	list    []store.MaintenanceWindow
	expires time.Time
}

func (s *Server) maintenanceWindows(ctx context.Context) ([]store.MaintenanceWindow, error) {
	s.windows.mu.Lock()
	defer s.windows.mu.Unlock()
	if s.now().Before(s.windows.expires) {
		return s.windows.list, nil
	}
	list, err := s.store.ListWindows(ctx)
	if err != nil {
		return nil, err
	}
	s.windows.list, s.windows.expires = list, s.now().Add(30*time.Second)
	return list, nil
}

func (s *Server) invalidateWindows() {
	s.windows.mu.Lock()
	s.windows.expires = time.Time{}
	s.windows.mu.Unlock()
}

// machineJobs, makineye şu anda verilebilecek işleri döner: "bakım penceresine uy" seçilen
// aksiyonlar yalnızca makinenin penceresi açıkken verilir.
func (s *Server) machineJobs(ctx context.Context, m *store.Machine) ([]protocol.SignedJob, error) {
	pending, err := s.store.PendingJobs(ctx, m.ID, s.now())
	if err != nil {
		return nil, err
	}
	out := make([]protocol.SignedJob, 0, len(pending))
	var open *bool
	for _, j := range pending {
		if j.RespectWindows {
			if open == nil {
				windows, err := s.maintenanceWindows(ctx)
				if err != nil {
					return nil, err
				}
				o, _ := store.OpenWindowsFor(windows, m.ADOU, s.now(), ad.InScope)
				open = &o
			}
			if !*open {
				continue
			}
		}
		out = append(out, j.SignedJob)
	}
	return out, nil
}

// --- Kademeli dağıtım ---

func validateRollout(r *store.Rollout) error {
	if r == nil {
		return nil
	}
	if len(r.Stages) < 2 || len(r.Stages) > 5 {
		return errors.New("kademeli dağıtım 2-5 aşama olmalı")
	}
	total, prevDelay := 0, -1
	for _, st := range r.Stages {
		if st.Percent < 1 || st.Percent > 99 {
			return errors.New("aşama yüzdesi 1-99 olmalı")
		}
		if st.DelayHours < 0 || st.DelayHours > 168 || st.DelayHours < prevDelay {
			return errors.New("aşama gecikmeleri 0-168 saat ve artan sırada olmalı")
		}
		total += st.Percent
		prevDelay = st.DelayHours
	}
	if total != 100 {
		return fmt.Errorf("aşama yüzdelerinin toplamı 100 olmalı (%d)", total)
	}
	if r.MinSuccessPercent < 0 || r.MinSuccessPercent > 100 {
		return errors.New("en düşük başarı oranı 0-100 olmalı")
	}
	r.Stages[0].DelayHours = 0
	return nil
}

// assignStages, hedefleri aşamalara dağıtır. Sıra aksiyon kimliğiyle karıştırılır; böylece
// pilot halka her aksiyonda aynı makinelerden oluşmaz ama aynı aksiyon için belirlenimlidir.
func assignStages(actionID string, ids []string, r *store.Rollout) map[string]int {
	out := make(map[string]int, len(ids))
	if r == nil {
		for _, id := range ids {
			out[id] = 0
		}
		return out
	}
	order := append([]string{}, ids...)
	key := func(id string) uint64 {
		h := fnv.New64a()
		h.Write([]byte(actionID + id))
		return h.Sum64()
	}
	sort.Slice(order, func(i, j int) bool { return key(order[i]) < key(order[j]) })
	idx, cum := 0, 0
	for stage, st := range r.Stages {
		cum += st.Percent
		end := (len(order)*cum + 99) / 100
		if stage == len(r.Stages)-1 {
			end = len(order)
		}
		// Her aşamada en az bir makine olur (hedef sayısı aşama sayısından azsa sonraki aşamalar boş kalır).
		end = max(end, min(idx+1, len(order)))
		for ; idx < end; idx++ {
			out[order[idx]] = stage
		}
	}
	return out
}

// RunRollouts, kademeli aksiyonların sonraki aşamalarını koşullar sağlandığında açar.
func (s *Server) RunRollouts(ctx context.Context) {
	cands, err := s.store.RolloutCandidates(ctx)
	if err != nil {
		s.log.Warn("kademeli dağıtımlar okunamadı", "hata", err)
		return
	}
	for _, c := range cands {
		if c.NextStage >= len(c.Rollout.Stages) {
			continue
		}
		due := c.CreatedAt.Add(time.Duration(c.Rollout.Stages[c.NextStage].DelayHours) * time.Hour)
		if s.now().Before(due) {
			continue
		}
		// Açılmış hedeflerin en az yarısı sonuçlanmadan karar verilmez.
		if c.Finished*2 < c.Released {
			continue
		}
		if c.Finished > 0 && c.Succeeded*100 < c.Rollout.MinSuccessPercent*c.Finished {
			reason := fmt.Sprintf("Başarı oranı %%%d, eşik %%%d; sonraki aşama durduruldu", c.Succeeded*100/c.Finished, c.Rollout.MinSuccessPercent)
			if err := s.store.PauseRollout(ctx, c.ID, reason); err != nil {
				s.log.Warn("kademeli dağıtım duraklatılamadı", "hata", err)
			}
			continue
		}
		if err := s.store.ReleaseStage(ctx, c.ID, c.NextStage); err != nil {
			s.log.Warn("aşama açılamadı", "aksiyon", c.ID, "hata", err)
			continue
		}
		s.log.Info("kademeli dağıtımda aşama açıldı", "aksiyon", c.ID, "aşama", c.NextStage+1)
		s.audit(ctx, store.AuditEntry{ActorType: store.ActorSystem, ActorName: "kademeli dağıtım", Action: "action.stage_release",
			TargetType: "action", TargetID: c.ID, Result: store.ResultSuccess,
			Params: map[string]any{"stage": c.NextStage + 1, "succeeded": c.Succeeded, "finished": c.Finished}})
	}
}

// handleReleaseNextStage, duraklatılmış veya beklemedeki sonraki aşamayı elle açar.
func (s *Server) handleReleaseNextStage(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	a, ok := s.actionFromPath(w, r)
	if !ok {
		return
	}
	if !s.requirePerm(w, r, sess, kindPermission(a.Kind)) {
		return
	}
	if a.Rollout == nil || a.Status != store.ActionActive || a.ReleasedStages >= len(a.Rollout.Stages) {
		writeError(w, http.StatusConflict, codeConflict, "Açılacak aşama yok")
		return
	}
	if err := s.store.ReleaseStage(r.Context(), a.ID, a.ReleasedStages); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "action.stage_release", TargetType: "action", TargetID: a.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"stage": a.ReleasedStages + 1, "manual": true}})
	a, _ = s.store.GetAction(r.Context(), a.ID)
	writeJSON(w, http.StatusOK, a)
}

// --- Bakım pencereleri ---

func (s *Server) handleListWindows(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	list, err := s.store.ListWindows(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	type item struct {
		store.MaintenanceWindow
		OpenNow bool `json:"open_now"`
	}
	out := make([]item, len(list))
	for i, mw := range list {
		out[i] = item{mw, mw.Enabled && mw.Contains(s.now())}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleSaveWindow(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var mw store.MaintenanceWindow
	if !decodeJSON(w, r, &mw, 16<<10) {
		return
	}
	mw.ID = r.PathValue("id")
	if mw.ID != "" && !validUUID(mw.ID) {
		writeError(w, http.StatusNotFound, codeNotFound, "Pencere bulunamadı")
		return
	}
	mw.Name = strings.TrimSpace(mw.Name)
	if mw.Timezone == "" {
		mw.Timezone = "Europe/Istanbul"
	}
	switch {
	case mw.Name == "" || utf8.RuneCountInString(mw.Name) > 100:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Ad 1-100 karakter olmalı")
		return
	case len(mw.Weekdays) == 0 || len(mw.Weekdays) > 7:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "En az bir gün seçilmeli")
		return
	case mw.StartMinute < 0 || mw.StartMinute > 1439 || mw.DurationMinutes < 15 || mw.DurationMinutes > 1440:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Başlangıç 00:00-23:59, süre 15 dk - 24 saat olmalı")
		return
	}
	for _, d := range mw.Weekdays {
		if d < 0 || d > 6 {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Gün 0-6 olmalı")
			return
		}
	}
	if _, err := time.LoadLocation(mw.Timezone); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Saat dilimi geçersiz")
		return
	}
	scope, err := cleanScope(mw.ScopeOUs)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	mw.ScopeOUs = scope
	id, err := s.store.SaveWindow(r.Context(), mw)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Pencere bulunamadı")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.invalidateWindows()
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.window.save", TargetType: "maintenance_window", TargetID: id, Result: store.ResultSuccess,
		SourceIP: clientIP(r), Params: map[string]any{"window": mw}})
	mw.ID = id
	writeJSON(w, http.StatusOK, mw)
}

func (s *Server) handleDeleteWindow(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Pencere bulunamadı")
		return
	}
	if err := s.store.DeleteWindow(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Pencere bulunamadı")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.invalidateWindows()
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.window.delete", TargetType: "maintenance_window", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
