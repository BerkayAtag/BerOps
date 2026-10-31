package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/BerkayAtag/automation-ber/server/internal/ad"
	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

// adPasswordLabel, AD hizmet hesabı parolasının şifreleme etiketidir.
const adPasswordLabel = "ad_settings.bind_password"

// directory, AD işlemleridir; testlerde sahte uygulama kullanılır.
type directory struct {
	authenticate func(ctx context.Context, c ad.Config, username, password string) (*ad.User, error)
	test         func(ctx context.Context, c ad.Config) error
	computers    func(ctx context.Context, c ad.Config, limit int) ([]ad.Computer, error)
}

var ldapDirectory = directory{authenticate: ad.Authenticate, test: ad.Test, computers: ad.Computers}

// adConfig, kayıtlı ayarlardan bağlantı yapılandırmasını kurar (parola çözülür).
func (s *Server) adConfig(ctx context.Context) (*store.ADSettings, ad.Config, error) {
	st, err := s.store.GetADSettings(ctx)
	if err != nil {
		return nil, ad.Config{}, err
	}
	c := ad.Config{URL: st.URL, BaseDN: st.BaseDN, BindDN: st.BindDN, UserAttr: st.UserAttr, UserFilter: st.UserFilter,
		CACertPEM: st.CACertPEM, Timeout: time.Duration(st.TimeoutSeconds) * time.Second, ComputersBaseDN: st.ComputersBaseDN}
	if len(st.BindPasswordEnc) > 0 {
		pw, err := s.secrets.Open(st.BindPasswordEnc, adPasswordLabel)
		if err != nil {
			return st, c, err
		}
		c.BindPassword = string(pw)
	}
	return st, c, nil
}

func (s *Server) handleGetADSettings(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	st, err := s.store.GetADSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type adSettingsRequest struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"`
	BaseDN          string `json:"base_dn"`
	BindDN          string `json:"bind_dn"`
	BindPassword    string `json:"bind_password"` // boşsa mevcut parola korunur
	UserAttr        string `json:"user_attr"`
	UserFilter      string `json:"user_filter"`
	CACertPEM       string `json:"ca_cert_pem"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	ComputersBaseDN string `json:"computers_base_dn"`
}

func (req adSettingsRequest) config() ad.Config {
	return ad.Config{URL: strings.TrimSpace(req.URL), BaseDN: strings.TrimSpace(req.BaseDN), BindDN: strings.TrimSpace(req.BindDN),
		BindPassword: req.BindPassword, UserAttr: req.UserAttr, UserFilter: strings.TrimSpace(req.UserFilter),
		CACertPEM: strings.TrimSpace(req.CACertPEM), Timeout: time.Duration(req.TimeoutSeconds) * time.Second,
		ComputersBaseDN: strings.TrimSpace(req.ComputersBaseDN)}
}

func (s *Server) handlePutADSettings(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req adSettingsRequest
	if !decodeJSON(w, r, &req, 64<<10) {
		return
	}
	if req.UserAttr == "" {
		req.UserAttr = "sAMAccountName"
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 10
	}
	if req.TimeoutSeconds < 2 || req.TimeoutSeconds > 60 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Zaman aşımı 2-60 saniye olmalı")
		return
	}
	cfg := req.config()
	if req.Enabled || cfg.URL != "" {
		if err := cfg.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
			return
		}
	}
	var enc []byte
	if req.BindPassword != "" {
		var err error
		if enc, err = s.secrets.Seal([]byte(req.BindPassword), adPasswordLabel); err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
	}
	cur, err := s.store.GetADSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if req.Enabled && enc == nil && !cur.HasPassword {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Hizmet hesabı parolası gerekli")
		return
	}
	st := store.ADSettings{Enabled: req.Enabled, URL: cfg.URL, BaseDN: cfg.BaseDN, BindDN: cfg.BindDN, UserAttr: cfg.UserAttr,
		UserFilter: cfg.UserFilter, CACertPEM: cfg.CACertPEM, TimeoutSeconds: req.TimeoutSeconds, ComputersBaseDN: cfg.ComputersBaseDN}
	if err := s.store.SaveADSettings(r.Context(), st, enc, sess.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.ad.update",
		TargetType: "settings", TargetID: "ad", Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"enabled": st.Enabled, "url": st.URL, "base_dn": st.BaseDN, "bind_dn": st.BindDN,
			"password_changed": enc != nil},
	})
	out, _ := s.store.GetADSettings(r.Context())
	writeJSON(w, http.StatusOK, out)
}

type adTestRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type adTestResponse struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	User    *ad.User `json:"user,omitempty"`
	Role    string   `json:"role,omitempty"`
	Scope   []string `json:"scope_ous,omitempty"`
}

// handleTestAD, kayıtlı ayarlarla bağlantıyı dener; kullanıcı adı ve parola verilirse o
// kullanıcıyla girişi, gruplarını ve eşlenecek rolü gösterir (oturum açılmaz).
func (s *Server) handleTestAD(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req adTestRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	_, cfg, err := s.adConfig(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, adTestResponse{Message: "Hizmet hesabı parolası çözülemedi; parolayı yeniden girin"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	resp := adTestResponse{OK: true, Message: "Bağlantı ve hizmet hesabı doğrulandı"}
	if req.Username == "" {
		if err := s.dir.test(ctx, cfg); err != nil {
			resp = adTestResponse{Message: err.Error()}
		}
	} else {
		u, err := s.dir.authenticate(ctx, cfg, req.Username, req.Password)
		if err != nil {
			resp = adTestResponse{Message: err.Error()}
		} else {
			mappings, _ := s.store.ListADMappings(r.Context())
			resp.User = u
			if role, scope, ok := ad.ResolveRole(u.Groups, mappings); ok {
				resp.Role, resp.Scope = role, scope
				resp.Message = "Kullanıcı doğrulandı"
			} else {
				resp.OK, resp.Message = false, "Kullanıcı doğrulandı ama hiçbir grup eşlemesine uymuyor; giriş reddedilir"
			}
		}
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.ad.test",
		Result: map[bool]string{true: store.ResultSuccess, false: store.ResultFailure}[resp.OK], SourceIP: clientIP(r),
		Detail: resp.Message, Params: map[string]any{"username": req.Username},
	})
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListADMappings(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	items, err := s.store.ListADMappings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCreateADMapping(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var m ad.Mapping
	if !decodeJSON(w, r, &m, 16<<10) {
		return
	}
	m.GroupDN = strings.TrimSpace(m.GroupDN)
	if _, err := ldap.ParseDN(m.GroupDN); err != nil || m.GroupDN == "" || len(m.GroupDN) > 500 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Grup DN'i geçersiz (ör. CN=BER-Teknisyen,OU=Gruplar,DC=corp,DC=example)")
		return
	}
	if !auth.ValidRole(auth.Role(m.Role)) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz rol")
		return
	}
	scope, err := cleanScope(m.ScopeOUs)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	m.ScopeOUs = scope
	created, err := s.store.CreateADMapping(r.Context(), m, sess.User.ID)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, codeConflict, "Bu grup için zaten bir eşleme var")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.ad.mapping.create",
		TargetType: "ad_mapping", TargetID: created.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"group_dn": created.GroupDN, "role": created.Role, "scope_ous": created.ScopeOUs},
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeleteADMapping(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Eşleme bulunamadı")
		return
	}
	if err := s.store.DeleteADMapping(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Eşleme bulunamadı")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.ad.mapping.delete",
		TargetType: "ad_mapping", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

type adComputer struct {
	ad.Computer
	MachineID *string `json:"machine_id"`
}

// handleADComputers, AD'deki bilgisayarları ajan kurulu olup olmadığıyla birlikte listeler
// (ajansız makineleri bulmak için). Sonuç saklanmaz.
func (s *Server) handleADComputers(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	st, cfg, err := s.adConfig(r.Context())
	if err != nil || !st.Enabled {
		writeError(w, http.StatusConflict, codeConflict, "AD entegrasyonu etkin değil")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	list, err := s.dir.computers(ctx, cfg, 20000)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeDirectoryUnavailable, err.Error())
		return
	}
	names, err := s.store.MachineHostnames(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	scope := sess.User.Scope()
	out := make([]adComputer, 0, len(list))
	for _, c := range list {
		if !ad.InScope(c.OU, scope) {
			continue
		}
		item := adComputer{Computer: c}
		for _, n := range []string{strings.ToLower(c.Name), strings.ToLower(strings.SplitN(c.DNSHostName, ".", 2)[0])} {
			if id, ok := names[n]; ok && n != "" {
				item.MachineID = &id
				break
			}
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// loginWithAD, yerel hesabı olmayan kullanıcıyı AD ile doğrular, rolünü grup eşlemelerinden
// çözer ve kullanıcı kaydını oluşturur/günceller. AD kapalıysa (nil, nil) döner.
func (s *Server) loginWithAD(ctx context.Context, username, password string) (*store.User, string, error) {
	st, cfg, err := s.adConfig(ctx)
	if err != nil {
		return nil, "AD ayarları okunamadı", ad.ErrUnavailable
	}
	if !st.Enabled {
		return nil, "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout*3)
	defer cancel()
	u, err := s.dir.authenticate(ctx, cfg, username, password)
	if err != nil {
		return nil, err.Error(), err
	}
	if u.Disabled {
		return nil, "AD hesabı devre dışı", ad.ErrInvalidCredentials
	}
	mappings, err := s.store.ListADMappings(ctx)
	if err != nil {
		return nil, "eşlemeler okunamadı", ad.ErrUnavailable
	}
	role, scope, ok := ad.ResolveRole(u.Groups, mappings)
	if !ok {
		return nil, "AD grubu hiçbir role eşlenmiyor", errNoRoleMapping
	}
	user, err := s.store.UpsertADUser(ctx, store.ADUser{
		Username: strings.ToLower(u.Username), DisplayName: u.DisplayName, Email: u.Email, DN: u.DN, Role: role, ScopeOUs: scope,
	}, s.now())
	if errors.Is(err, store.ErrConflict) {
		return nil, "aynı adda yerel hesap var", ad.ErrInvalidCredentials
	}
	if err != nil {
		return nil, "kullanıcı kaydedilemedi", err
	}
	return user, "", nil
}

var errNoRoleMapping = errors.New("AD grubu eşlemesi yok")
