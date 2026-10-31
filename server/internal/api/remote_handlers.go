package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/auth"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// Uzaktan yönetim zaman sınırları (testlerde kısaltılır).
var (
	remotePollWait    = 25 * time.Second // ajanın uzun yoklamada bekletildiği en uzun süre
	remoteCallWait    = 40 * time.Second // konsol isteğinin sonucu beklediği en uzun süre
	remoteConnectedIn = 35 * time.Second // son yoklama bu süre içindeyse ajan "bağlı" sayılır
)

// remoteBroker, konsol istekleriyle ajanın uzun yoklamasını eşleştiren bellek içi kuyruktur.
// Tek sunucu örneği varsayılır (docs/varsayimlar.md 6.4).
type remoteBroker struct {
	mu sync.Mutex
	m  map[string]*remoteMachine
}

type remoteMachine struct {
	wantUntil time.Time
	lastPoll  time.Time
	queue     []*remoteCall
	pending   map[string]*remoteCall
	notify    chan struct{}
}

type remoteCall struct {
	id     string
	signed protocol.SignedJob
	result chan protocol.RemoteResult
}

func (b *remoteBroker) get(id string) *remoteMachine {
	if b.m == nil {
		b.m = map[string]*remoteMachine{}
	}
	rm := b.m[id]
	if rm == nil {
		rm = &remoteMachine{pending: map[string]*remoteCall{}, notify: make(chan struct{}, 1)}
		b.m[id] = rm
	}
	return rm
}

func (b *remoteBroker) want(machineID string, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rm := b.get(machineID); until.After(rm.wantUntil) {
		rm.wantUntil = until
	}
}

func (b *remoteBroker) status(machineID string, now time.Time) (active, connected bool, until time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rm := b.get(machineID)
	return now.Before(rm.wantUntil), now.Sub(rm.lastPoll) < remoteConnectedIn, rm.wantUntil
}

func (b *remoteBroker) enqueue(machineID string, c *remoteCall) {
	b.mu.Lock()
	rm := b.get(machineID)
	rm.queue = append(rm.queue, c)
	rm.pending[c.id] = c
	b.mu.Unlock()
	select {
	case rm.notify <- struct{}{}:
	default:
	}
}

func (b *remoteBroker) cancel(machineID, callID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rm := b.get(machineID)
	delete(rm.pending, callID)
	for i, c := range rm.queue {
		if c.id == callID {
			rm.queue = append(rm.queue[:i], rm.queue[i+1:]...)
			break
		}
	}
}

// poll, ajan için sıradaki isteği döner; oturum yoksa hemen, istek yoksa beklemeden sonra nil döner.
func (b *remoteBroker) poll(ctx context.Context, machineID string, now func() time.Time) *remoteCall {
	deadline := time.NewTimer(remotePollWait)
	defer deadline.Stop()
	for {
		b.mu.Lock()
		rm := b.get(machineID)
		rm.lastPoll = now()
		if !now().Before(rm.wantUntil) && len(rm.queue) == 0 {
			b.mu.Unlock()
			return nil
		}
		if len(rm.queue) > 0 {
			c := rm.queue[0]
			rm.queue = rm.queue[1:]
			b.mu.Unlock()
			return c
		}
		notify := rm.notify
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		case <-notify:
		}
	}
}

func (b *remoteBroker) deliver(machineID, callID string, r protocol.RemoteResult) bool {
	b.mu.Lock()
	rm := b.get(machineID)
	c := rm.pending[callID]
	delete(rm.pending, callID)
	b.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case c.result <- r:
	default:
	}
	return true
}

// heartbeatRemote, heartbeat yanıtına uzaktan yönetim bayraklarını ve oturum süresini ekler.
func (s *Server) heartbeatRemote(r *http.Request, m *store.Machine, resp *protocol.HeartbeatResponse) {
	if m.Status != protocol.StatusActive {
		return
	}
	set, err := s.store.GetRemoteSettings(r.Context())
	if err != nil || !set.Enabled {
		return
	}
	flags, err := s.store.GetMachineRemote(r.Context(), m.ID)
	if err != nil || !flags.Any() {
		return
	}
	resp.Remote = &flags
	if active, _, until := s.remote.status(m.ID, s.now()); active {
		u := until.UTC()
		resp.RemoteUntil = &u
		// Oturum sürerken heartbeat sıklaştırılmaz; ajan uzun yoklamaya geçer.
	}
}

// --- Ajan uç noktaları ---

func (s *Server) handleRemotePoll(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	if m.Status != protocol.StatusActive {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	c := s.remote.poll(r.Context(), m.ID, s.now)
	if c == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, c.signed)
}

func (s *Server) handleRemoteResult(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	var res protocol.RemoteResult
	if !decodeJSON(w, r, &res, 8<<20) {
		return
	}
	if !s.remote.deliver(m.ID, r.PathValue("id"), res) {
		writeError(w, http.StatusNotFound, codeNotFound, "İstek bulunamadı veya zaman aşımına uğradı")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Konsol uç noktaları ---

type remoteStatusResponse struct {
	Enabled   bool                 `json:"enabled"`
	Flags     protocol.RemoteFlags `json:"flags"`
	Active    bool                 `json:"active"`
	Connected bool                 `json:"connected"`
	Until     *time.Time           `json:"until"`
	Platform  string               `json:"platform"`
}

func (s *Server) remoteStatus(r *http.Request, m *store.Machine) (*remoteStatusResponse, error) {
	set, err := s.store.GetRemoteSettings(r.Context())
	if err != nil {
		return nil, err
	}
	flags, err := s.store.GetMachineRemote(r.Context(), m.ID)
	if err != nil {
		return nil, err
	}
	resp := &remoteStatusResponse{Enabled: set.Enabled, Flags: flags, Platform: m.OSPlatform}
	active, connected, until := s.remote.status(m.ID, s.now())
	resp.Active, resp.Connected = active, connected && active
	if active {
		resp.Until = &until
	}
	return resp, nil
}

func (s *Server) handleGetRemote(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	st, err := s.remoteStatus(r, m)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func hasAnyRemotePerm(role string) bool {
	for _, p := range []auth.Permission{auth.PermRemotePerformance, auth.PermRemoteServices, auth.PermRemoteRegistryRead, auth.PermRemoteRegistryWrite} {
		if auth.HasPermission(auth.Role(role), p) {
			return true
		}
	}
	return false
}

// handleRemoteSession, makinede uzaktan oturum açar; ajan bir sonraki heartbeat'te
// (en fazla heartbeat aralığı kadar sonra) uzun yoklamaya geçer.
func (s *Server) handleRemoteSession(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	if !hasAnyRemotePerm(sess.User.Role) {
		s.requirePerm(w, r, sess, auth.PermRemotePerformance)
		return
	}
	set, err := s.store.GetRemoteSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	flags, err := s.store.GetMachineRemote(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if !set.Enabled || !flags.Any() || m.Status != protocol.StatusActive {
		writeError(w, http.StatusConflict, codeRemoteDisabled, "Bu makinede uzaktan yönetim kapalı")
		return
	}
	active, _, _ := s.remote.status(m.ID, s.now())
	s.remote.want(m.ID, s.now().Add(time.Duration(set.SessionMinutes)*time.Minute))
	if !active {
		s.audit(r.Context(), store.AuditEntry{
			ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "remote.session",
			TargetType: "machine", TargetID: m.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
			Params: map[string]any{"hostname": m.Hostname, "minutes": set.SessionMinutes},
		})
	}
	st, err := s.remoteStatus(r, m)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handlePutMachineRemote(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	var f protocol.RemoteFlags
	if !decodeJSON(w, r, &f, 4<<10) {
		return
	}
	if m.OSPlatform != protocol.PlatformWindows && (f.RegistryRead || f.RegistryWrite) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kayıt defteri yalnızca Windows makinelerde vardır")
		return
	}
	old, _ := s.store.GetMachineRemote(r.Context(), m.ID)
	if err := s.store.SaveMachineRemote(r.Context(), m.ID, f, sess.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "remote.settings.machine",
		TargetType: "machine", TargetID: m.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"hostname": m.Hostname, "old": old, "new": f},
	})
	st, _ := s.remoteStatus(r, m)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetRemoteSettings(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	set, err := s.store.GetRemoteSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handlePutRemoteSettings(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var set store.RemoteSettings
	if !decodeJSON(w, r, &set, 4<<10) {
		return
	}
	if set.SessionMinutes < 1 || set.SessionMinutes > 120 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Oturum süresi 1-120 dakika olmalı")
		return
	}
	old, _ := s.store.GetRemoteSettings(r.Context())
	if err := s.store.SaveRemoteSettings(r.Context(), set, sess.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.remote.update",
		TargetType: "settings", TargetID: "remote", Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"old": old, "new": set},
	})
	writeJSON(w, http.StatusOK, set)
}

type remoteCallRequest struct {
	Op     string          `json:"op"`
	Params json.RawMessage `json:"params"`
}

var remoteOpPerm = map[string]auth.Permission{
	protocol.RemotePerformance:     auth.PermRemotePerformance,
	protocol.RemoteServicesList:    auth.PermRemoteServices,
	protocol.RemoteServicesControl: auth.PermRemoteServices,
	protocol.RemoteRegistryList:    auth.PermRemoteRegistryRead,
	protocol.RemoteRegistrySet:     auth.PermRemoteRegistryWrite,
	protocol.RemoteRegistryDelete:  auth.PermRemoteRegistryWrite,
}

// remoteAudited, denetim kaydına yazılan (durum değiştiren) işlemlerdir; okuma işlemleri
// oturum açılışında bir kez kaydedilir.
var remoteAudited = map[string]bool{
	protocol.RemoteServicesControl: true, protocol.RemoteRegistrySet: true, protocol.RemoteRegistryDelete: true,
}

var registryPathRe = regexp.MustCompile(`^(?i:HKLM|HKU|HKCR|HKCC|HKEY_LOCAL_MACHINE|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG)(\\[^\x00-\x1f]{1,255})*\\?$`)

// validateRemoteParams, ajan da denetlese bile parametreleri sunucuda doğrular.
func validateRemoteParams(op string, raw json.RawMessage) error {
	switch op {
	case protocol.RemotePerformance, protocol.RemoteServicesList:
		return nil
	case protocol.RemoteServicesControl:
		var p protocol.ServiceControlParams
		if err := json.Unmarshal(raw, &p); err != nil || p.Name == "" || len(p.Name) > 256 {
			return errors.New("servis adı gerekli")
		}
		if p.Action != "start" && p.Action != "stop" && p.Action != "restart" {
			return errors.New("işlem start, stop veya restart olmalı")
		}
	case protocol.RemoteRegistryList:
		var p protocol.RegistryPathParams
		if err := json.Unmarshal(raw, &p); err != nil || !registryPathRe.MatchString(p.Path) {
			return errors.New("kayıt defteri yolu geçersiz (ör. HKLM\\SOFTWARE\\Örnek)")
		}
	case protocol.RemoteRegistrySet:
		var p protocol.RegistrySetParams
		if err := json.Unmarshal(raw, &p); err != nil || !registryPathRe.MatchString(p.Path) || !strings.Contains(p.Path, `\`) {
			return errors.New("kayıt defteri yolu geçersiz")
		}
		switch p.Value.Type {
		case "REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY":
		default:
			return errors.New("desteklenmeyen değer türü")
		}
		if len(p.Value.Name) > 16383 || len(p.Value.Data) > 1<<20 {
			return errors.New("değer çok uzun")
		}
	case protocol.RemoteRegistryDelete:
		var p protocol.RegistryDeleteParams
		if err := json.Unmarshal(raw, &p); err != nil || !registryPathRe.MatchString(p.Path) {
			return errors.New("kayıt defteri yolu geçersiz")
		}
	default:
		return errors.New("bilinmeyen işlem")
	}
	return nil
}

func (s *Server) handleRemoteCall(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	m, ok := s.machineFromPath(w, r)
	if !ok {
		return
	}
	var req remoteCallRequest
	if !decodeJSON(w, r, &req, 2<<20) {
		return
	}
	perm, known := remoteOpPerm[req.Op]
	if !known {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Bilinmeyen işlem")
		return
	}
	if !s.requirePerm(w, r, sess, perm) {
		return
	}
	if err := validateRemoteParams(req.Op, req.Params); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	set, err := s.store.GetRemoteSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	flags, err := s.store.GetMachineRemote(r.Context(), m.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if !set.Enabled || !flags.Allows(req.Op) || m.Status != protocol.StatusActive {
		writeError(w, http.StatusConflict, codeRemoteDisabled, "Bu özellik makinede kapalı")
		return
	}
	if active, _, _ := s.remote.status(m.ID, s.now()); !active {
		writeError(w, http.StatusConflict, codeRemoteNoSession, "Önce uzaktan oturum açın")
		return
	}
	id, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	signed, err := protocol.SignRemote(s.signKey, protocol.RemoteRequest{
		ID: id, MachineID: m.ID, Op: req.Op, Params: req.Params, ExpiresAt: s.now().Add(remoteCallWait).UTC(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	call := &remoteCall{id: id, signed: signed, result: make(chan protocol.RemoteResult, 1)}
	audit := store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "remote." + req.Op,
		TargetType: "machine", TargetID: m.ID, SourceIP: clientIP(r),
		Params: map[string]any{"hostname": m.Hostname, "params": json.RawMessage(req.Params)},
	}
	// Durum değiştiren işlemler önce kaydedilir; kayıt yazılamazsa işlem gönderilmez.
	if remoteAudited[req.Op] {
		audit.Result, audit.OccurredAt = store.ResultSuccess, s.now()
		audit.Detail = "gönderildi"
		if err := s.store.AppendAudit(r.Context(), audit); err != nil {
			writeError(w, http.StatusServiceUnavailable, codeInternal, "Denetim kaydı yazılamadığı için işlem gönderilmedi")
			return
		}
	}
	s.remote.enqueue(m.ID, call)
	timer := time.NewTimer(remoteCallWait)
	defer timer.Stop()
	select {
	case res := <-call.result:
		if remoteAudited[req.Op] {
			audit.Detail = "sonuç"
			audit.Result = store.ResultSuccess
			if !res.OK {
				audit.Result, audit.Detail = store.ResultFailure, res.Error
			}
			audit.Params["result"] = json.RawMessage(nonEmptyJSON(res.Data))
			s.audit(r.Context(), audit)
		}
		if !res.OK {
			writeError(w, http.StatusUnprocessableEntity, codeRemoteFailed, res.Error)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(nonEmptyJSON(res.Data))
	case <-timer.C:
		s.remote.cancel(m.ID, id)
		writeError(w, http.StatusGatewayTimeout, codeRemoteTimeout, "Ajan yanıt vermedi; çevrimdışı olabilir veya henüz bağlanmamış olabilir")
	case <-r.Context().Done():
		s.remote.cancel(m.ID, id)
	}
}

func nonEmptyJSON(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}
