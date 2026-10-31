// Package api, konsol API'sini (/api/v1) ve ajan API'sini (/agent/v1) sunar.
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	_ "embed"
	"log/slog"
	"net/http"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/config"
	"github.com/BerkayAtag/automation-ber/server/internal/cve"
	"github.com/BerkayAtag/automation-ber/server/internal/pki"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/server/internal/vuln"
)

//go:embed openapi.yaml
var openAPISpec []byte

// Server, HTTP işleyicilerinin ortak bağımlılıklarını taşır.
type Server struct {
	cfg   config.Config
	store *store.Store
	ca    *pki.CA
	log   *slog.Logger
	now   func() time.Time

	settings settingsCache

	vulns       *vuln.Engine
	cveSync     *cve.Syncer
	syncTrigger chan struct{}

	// signKey, ajanlara gönderilen işleri imzalar. Varsayılan bellekte üretilir (testler);
	// sunucu açılışta kalıcı anahtarı SetSigningKey ile verir.
	signKey ed25519.PrivateKey

	loginLimiter  *auth.AttemptLimiter
	enrollLimiter *auth.AttemptLimiter
	// dummyHash, var olmayan kullanıcılar için de parola doğrulaması yapılarak yanıt
	// süresinden kullanıcı adının varlığının anlaşılmasını önler.
	dummyHash string
}

// New, API sunucusunu oluşturur.
func New(cfg config.Config, st *store.Store, ca *pki.CA, log *slog.Logger) (*Server, error) {
	dummy, err := auth.HashPassword("zamanlama-esitleme-icin-kukla-parola")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:         cfg,
		store:       st,
		ca:          ca,
		log:         log,
		now:         time.Now,
		dummyHash:   dummy,
		syncTrigger: make(chan struct{}, 1),
		signKey:     pki.NewSigningKey(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s.vulns, err = vuln.New(ctx, st, log); err != nil {
		return nil, err
	}
	s.cveSync = s.newSyncer()
	clock := func() time.Time { return s.now() }
	s.loginLimiter = auth.NewAttemptLimiter(5, 15*time.Minute).WithClock(clock)
	s.enrollLimiter = auth.NewAttemptLimiter(10, 15*time.Minute).WithClock(clock)
	return s, nil
}

// SetSigningKey, kalıcı aksiyon imza anahtarını ayarlar.
func (s *Server) SetSigningKey(k ed25519.PrivateKey) { s.signKey = k }

// actionPublicKey, ajanların sabitlediği açık anahtardır.
func (s *Server) actionPublicKey() []byte { return s.signKey.Public().(ed25519.PublicKey) }

// ConsoleHandler, konsol dinleyicisinin işleyicisidir.
func (s *Server) ConsoleHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_, _ = w.Write(openAPISpec)
	})

	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.Handle("POST /api/v1/auth/logout", s.authed("", s.handleLogout))
	mux.Handle("GET /api/v1/auth/me", s.authed("", s.handleMe))

	mux.Handle("GET /api/v1/server-info", s.authed(auth.PermMachinesRead, s.handleServerInfo))

	mux.Handle("GET /api/v1/registration-keys", s.authed(auth.PermRegKeysManage, s.handleListRegKeys))
	mux.Handle("POST /api/v1/registration-keys", s.authed(auth.PermRegKeysManage, s.handleCreateRegKey))
	mux.Handle("DELETE /api/v1/registration-keys/{id}", s.authed(auth.PermRegKeysManage, s.handleRevokeRegKey))

	mux.Handle("GET /api/v1/machines", s.authed(auth.PermMachinesRead, s.handleListMachines))
	mux.Handle("GET /api/v1/machines/summary", s.authed(auth.PermMachinesRead, s.handleFleetSummary))
	mux.Handle("POST /api/v1/machines/scan", s.authed(auth.PermMachinesManage, s.handleRequestScan))
	mux.Handle("GET /api/v1/machines/{id}", s.authed(auth.PermMachinesRead, s.handleGetMachine))
	mux.Handle("GET /api/v1/machines/{id}/missing-patches", s.authed(auth.PermMachinesRead, s.handleMachineMissingPatches))
	mux.Handle("GET /api/v1/machines/{id}/installed-patches", s.authed(auth.PermMachinesRead, s.handleMachineInstalledPatches))
	mux.Handle("GET /api/v1/machines/{id}/apps", s.authed(auth.PermMachinesRead, s.handleMachineApps))
	mux.Handle("GET /api/v1/machines/{id}/vulnerabilities", s.authed(auth.PermMachinesRead, s.handleMachineVulns))
	mux.Handle("POST /api/v1/machines/{id}/approve", s.authed(auth.PermMachinesManage, s.handleSetMachineStatus("approve")))
	mux.Handle("POST /api/v1/machines/{id}/reject", s.authed(auth.PermMachinesManage, s.handleSetMachineStatus("reject")))

	mux.Handle("GET /api/v1/packages", s.authed(auth.PermPackagesRead, s.handleListPackages))
	mux.Handle("POST /api/v1/packages", s.authed(auth.PermPackagesUpload, s.handleUploadPackage))
	mux.Handle("GET /api/v1/packages/{id}", s.authed(auth.PermPackagesRead, s.handleGetPackage))
	mux.Handle("DELETE /api/v1/packages/{id}", s.authed(auth.PermPackagesDelete, s.handleDeletePackage))

	// Aksiyon oluşturma izni türe göre (paket / komut) işleyicide denetlenir.
	mux.Handle("POST /api/v1/actions", s.authed("", s.handleCreateAction))
	mux.Handle("GET /api/v1/actions", s.authed(auth.PermMachinesRead, s.handleListActions))
	mux.Handle("GET /api/v1/actions/{id}", s.authed(auth.PermMachinesRead, s.handleGetAction))
	mux.Handle("POST /api/v1/actions/{id}/approve", s.authed("", s.handleActionTransition("approve")))
	mux.Handle("POST /api/v1/actions/{id}/reject", s.authed("", s.handleActionTransition("reject")))
	mux.Handle("POST /api/v1/actions/{id}/cancel", s.authed("", s.handleActionTransition("cancel")))

	mux.Handle("GET /api/v1/settings/transfer", s.authed(auth.PermSettingsRead, s.handleGetTransferSettings))
	mux.Handle("PUT /api/v1/settings/transfer", s.authed(auth.PermRateLimitManage, s.handlePutTransferSettings))

	mux.Handle("GET /api/v1/settings/agent", s.authed(auth.PermSettingsRead, s.handleGetAgentSettings))
	mux.Handle("PUT /api/v1/settings/agent", s.authed(auth.PermSettingsWrite, s.handlePutAgentSettings))

	mux.Handle("GET /api/v1/dashboard/risk", s.authed(auth.PermReportsRead, s.handleRiskSummary))
	mux.Handle("GET /api/v1/vulnerabilities", s.authed(auth.PermReportsRead, s.handleListVulns))
	mux.Handle("GET /api/v1/vulnerabilities/{id}", s.authed(auth.PermReportsRead, s.handleGetVuln))
	mux.Handle("GET /api/v1/reports/{type}", s.authed(auth.PermReportsExport, s.handleReport))

	mux.Handle("GET /api/v1/cve/status", s.authed(auth.PermSettingsRead, s.handleCVEStatus))
	mux.Handle("POST /api/v1/cve/sync", s.authed(auth.PermSettingsWrite, s.handleCVESync))
	mux.Handle("GET /api/v1/cve/rules", s.authed(auth.PermSettingsRead, s.handleListRules))
	mux.Handle("POST /api/v1/cve/rules", s.authed(auth.PermSettingsWrite, s.handleCreateRule))
	mux.Handle("DELETE /api/v1/cve/rules/{id}", s.authed(auth.PermSettingsWrite, s.handleDeleteRule))

	mux.Handle("GET /api/v1/audit", s.authed(auth.PermAuditRead, s.handleListAudit))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound, "Uç nokta bulunamadı")
	})
	mux.Handle("/", s.staticHandler())

	return chain(mux, s.recoverer, s.requestLogger, securityHeaders)
}

// AgentHandler, ajan dinleyicisinin işleyicisidir.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /agent/v1/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /agent/v1/inventory", s.handleInventory)
	mux.HandleFunc("GET /agent/v1/files/wsusscn2.cab", s.handleWSUSCab)
	mux.HandleFunc("GET /agent/v1/jobs", s.handleAgentJobs)
	mux.HandleFunc("POST /agent/v1/jobs/{id}/status", s.handleAgentJobStatus)
	mux.HandleFunc("GET /agent/v1/packages/{id}/file", s.handlePackageDownload)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound, "Uç nokta bulunamadı")
	})
	return chain(mux, s.recoverer, s.requestLogger)
}

// AgentTLSConfig, ajan dinleyicisinin TLS yapılandırmasıdır. İstemci sertifikası
// isteğe bağlıdır (kayıt sertifikasız yapılır) ama sunulursa iç CA'ya göre doğrulanır;
// kimlik gerektiren uç noktalar doğrulanmış zinciri ayrıca zorunlu tutar.
func (s *Server) AgentTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.ca.Pool(),
	}
}

// RunMaintenance, süresi dolmuş oturumları ve hız sınırı kayıtlarını periyodik temizler.
func (s *Server) RunMaintenance(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.store.DeleteExpiredSessions(ctx, s.now(), s.cfg.Session.IdleTimeout.D())
			if err != nil {
				s.log.Warn("süresi dolan oturumlar temizlenemedi", "hata", err)
			} else if n > 0 {
				s.log.Debug("süresi dolan oturumlar temizlendi", "adet", n)
			}
			s.loginLimiter.Sweep()
			s.enrollLimiter.Sweep()
			if n, err := s.store.ExpireActions(ctx, s.now()); err != nil {
				s.log.Warn("süresi dolan aksiyonlar kapatılamadı", "hata", err)
			} else if n > 0 {
				s.log.Info("süresi dolan aksiyon hedefleri kapatıldı", "adet", n)
			}
			// Günün uyumluluk özeti her turda güncellenir; geçmiş günler eğilim grafiğinde kalır.
			if err := s.store.SaveComplianceSnapshot(ctx, s.now()); err != nil {
				s.log.Warn("uyumluluk özeti yazılamadı", "hata", err)
			}
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "database": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}

// audit, denetim kaydı ekler. Yazılamazsa hata loglanır; Aşama 4'te komut çalıştırma gibi
// kritik aksiyonlar denetim kaydı yazılamazsa reddedilecek (fail-closed).
func (s *Server) audit(ctx context.Context, e store.AuditEntry) {
	e.OccurredAt = s.now()
	if err := s.store.AppendAudit(context.WithoutCancel(ctx), e); err != nil {
		s.log.Error("denetim kaydı yazılamadı", "eylem", e.Action, "hata", err)
	}
}
