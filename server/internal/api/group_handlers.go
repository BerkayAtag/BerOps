package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BerkayAtag/BerOps/server/internal/ad"
	"github.com/BerkayAtag/BerOps/server/internal/store"
)

// groupFromID, gruptaki makineleri süzmek için grubu okur; hata durumunda yanıtı yazar.
func (s *Server) groupFromID(w http.ResponseWriter, r *http.Request, id string) (*store.Group, bool) {
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return nil, false
	}
	g, err := s.store.GetGroup(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	return g, true
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	groups, err := s.store.ListGroups(r.Context(), sess.User.Scope())
	if err != nil {
		s.log.Error("gruplar okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	tags, err := s.store.AllTags(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": groups, "tags": tags})
}

type groupRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Kind        string           `json:"kind"`
	Rule        *store.GroupRule `json:"rule"`
	// MachineIDs, yeni statik grubun ilk üyeleridir.
	MachineIDs []string `json:"machine_ids"`
}

func (g *groupRequest) validate() error {
	g.Name = strings.TrimSpace(g.Name)
	g.Description = strings.TrimSpace(g.Description)
	switch {
	case g.Name == "" || utf8.RuneCountInString(g.Name) > 100:
		return errors.New("ad 1-100 karakter olmalı")
	case utf8.RuneCountInString(g.Description) > 500:
		return errors.New("açıklama en fazla 500 karakter olabilir")
	case g.Kind != "static" && g.Kind != "dynamic":
		return errors.New("tür static veya dynamic olmalı")
	case g.Kind == "dynamic" && g.Rule == nil:
		return errors.New("dinamik grup için kural gerekli")
	}
	if g.Kind == "static" {
		g.Rule = nil
		return nil
	}
	return g.Rule.Validate()
}

func (s *Server) handleSaveGroup(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req groupRequest
	if !decodeJSON(w, r, &req, 64<<10) {
		return
	}
	id := r.PathValue("id")
	if id != "" && !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	saved, err := s.store.SaveGroup(r.Context(), store.Group{ID: id, Name: req.Name, Description: req.Description,
		Kind: req.Kind, Rule: req.Rule}, sess.User.ID)
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, codeConflict, "Bu adda bir grup zaten var")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return
	case err != nil:
		s.log.Error("grup kaydedilemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if id == "" && req.Kind == "static" && len(req.MachineIDs) > 0 {
		if !s.updateMembers(w, r, sess, saved, req.MachineIDs, nil) {
			return
		}
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "group.save", TargetType: "group", TargetID: saved, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"name": req.Name, "kind": req.Kind, "rule": req.Rule}})
	g, _ := s.store.GetGroup(r.Context(), saved)
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return
	}
	if err := s.store.DeleteGroup(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Grup bulunamadı")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "group.delete", TargetType: "group", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

// handlePreviewGroup, kaydetmeden önce kuralın eşleştiği makine sayısını ve ilk 20 makineyi döner.
func (s *Server) handlePreviewGroup(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var rule store.GroupRule
	if !decodeJSON(w, r, &rule, 64<<10) {
		return
	}
	if err := rule.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	g := &store.Group{Kind: "dynamic", Rule: &rule}
	items, total, err := s.store.ListMachinesFiltered(r.Context(), store.MachineFilter{Group: g, Status: "active", Sort: "hostname",
		Limit: 20, Now: s.now(), OnlineWindow: s.onlineWindow(), Scope: sess.User.Scope()})
	if err != nil {
		s.log.Error("grup önizlemesi yapılamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

type membersRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req membersRequest
	if !decodeJSON(w, r, &req, 1<<20) {
		return
	}
	g, ok := s.groupFromID(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if g.Kind != "static" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Dinamik grubun üyeleri kuralla belirlenir")
		return
	}
	if !s.updateMembers(w, r, sess, g.ID, req.Add, req.Remove) {
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "group.members", TargetType: "group", TargetID: g.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"add": len(req.Add), "remove": len(req.Remove)}})
	w.WriteHeader(http.StatusNoContent)
}

// updateMembers, kimlikleri doğrular, kapsam dışı makineleri reddeder ve üyeliği günceller.
func (s *Server) updateMembers(w http.ResponseWriter, r *http.Request, sess *store.Session, groupID string, add, remove []string) bool {
	if len(add)+len(remove) > 10000 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "En fazla 10000 makine")
		return false
	}
	for _, id := range append(slices.Clone(add), remove...) {
		if !validUUID(id) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz makine kimliği: "+id)
			return false
		}
	}
	if !s.machinesInScope(w, r, sess, add) {
		return false
	}
	if err := s.store.UpdateGroupMembers(r.Context(), groupID, add, remove); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return false
	}
	return true
}

// machinesInScope, kapsamlı kullanıcının yalnızca kendi OU'larındaki makinelere dokunmasını sağlar.
func (s *Server) machinesInScope(w http.ResponseWriter, r *http.Request, sess *store.Session, ids []string) bool {
	scope := sess.User.Scope()
	if scope == nil || len(ids) == 0 {
		return true
	}
	platforms, err := s.store.ActiveMachines(r.Context(), ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return false
	}
	for _, t := range platforms {
		if !ad.InScope(t.OU, scope) {
			s.requirePermDenied(r, sess, "kapsam dışı makine")
			writeError(w, http.StatusForbidden, codeForbidden, "Seçilen makinelerden bazıları yetki kapsamınızın dışında")
			return false
		}
	}
	return true
}

type tagsRequest struct {
	Tags []string `json:"tags"`
}

func (s *Server) handleSetMachineTags(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req tagsRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
		return
	}
	if !s.machinesInScope(w, r, sess, []string{id}) {
		return
	}
	tags := []string{}
	for _, t := range req.Tags {
		t = strings.TrimSpace(t)
		if t == "" || slices.Contains(tags, t) {
			continue
		}
		if !store.TagPattern.MatchString(t) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz etiket: "+t+" (harf/rakam, en fazla 40 karakter)")
			return
		}
		tags = append(tags, t)
	}
	if len(tags) > 20 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Bir makinede en fazla 20 etiket olabilir")
		return
	}
	if err := s.store.SetMachineTags(r.Context(), id, tags); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "machine.tags", TargetType: "machine", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"tags": tags}})
	writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
}

func (s *Server) handleMachineTags(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
		return
	}
	if !s.machinesInScope(w, r, sess, []string{id}) {
		return
	}
	tags, err := s.store.MachineTags(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
}
