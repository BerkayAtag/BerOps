package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BerkayAtag/automation-ber/server/internal/ad"
	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/cve"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// --- Paket deposu ---

func (s *Server) packageDir() string { return filepath.Join(s.cfg.DataDir, "packages") }

func (s *Server) packagePath(sha string) string { return filepath.Join(s.packageDir(), sha) }

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// installerRules, platform başına izin verilen yükleyici türleri, dosya uzantıları ve
// varsayılan kurulum komutlarıdır.
var installerRules = map[string]map[string]struct {
	ext     string
	command string
	shell   string
	codes   []int32
}{
	protocol.PlatformWindows: {
		protocol.InstallerMSI:  {".msi", `msiexec.exe /i "{file}" /qn /norestart`, protocol.ShellCmd, []int32{0, 1641, 3010}},
		protocol.InstallerEXE:  {".exe", "", protocol.ShellCmd, []int32{0}},
		protocol.InstallerFile: {"", "", protocol.ShellPowerShell, []int32{0}},
	},
	protocol.PlatformDarwin: {
		protocol.InstallerPKG:  {".pkg", `/usr/sbin/installer -pkg "{file}" -target /`, protocol.ShellSh, []int32{0}},
		protocol.InstallerDMG:  {".dmg", "", protocol.ShellSh, []int32{0}}, // boşsa ajan imajı bağlayıp kurar
		protocol.InstallerFile: {"", "", protocol.ShellZsh, []int32{0}},
	},
}

type packageMeta struct {
	Name           string  `json:"name"`
	Version        string  `json:"version"`
	Publisher      string  `json:"publisher"`
	Platform       string  `json:"platform"`
	Description    string  `json:"description"`
	Installer      string  `json:"installer"`
	InstallCommand string  `json:"install_command"`
	Shell          string  `json:"shell"`
	SuccessCodes   []int32 `json:"success_codes"`
	DetectName     string  `json:"detect_name"`
}

// validate, meta veriyi doğrular ve varsayılanları doldurur.
func (m *packageMeta) validate(fileName string) error {
	m.Name, m.Version = strings.TrimSpace(m.Name), strings.TrimSpace(m.Version)
	if m.Name == "" || utf8.RuneCountInString(m.Name) > 200 {
		return errors.New("paket adı 1-200 karakter olmalı")
	}
	if m.Version == "" || len(m.Version) > 100 {
		return errors.New("sürüm 1-100 karakter olmalı")
	}
	if len(m.Publisher) > 200 || len(m.Description) > 4000 || len(m.InstallCommand) > 8000 || len(m.DetectName) > 300 {
		return errors.New("alanlardan biri çok uzun")
	}
	rules, ok := installerRules[m.Platform]
	if !ok {
		return errors.New("platform windows veya darwin olmalı")
	}
	rule, ok := rules[m.Installer]
	if !ok {
		return fmt.Errorf("%s için geçersiz yükleyici türü: %s", m.Platform, m.Installer)
	}
	if rule.ext != "" && !strings.EqualFold(filepath.Ext(fileName), rule.ext) {
		return fmt.Errorf("%s paketi %s uzantılı olmalı", m.Installer, rule.ext)
	}
	m.InstallCommand = strings.TrimSpace(m.InstallCommand)
	if m.InstallCommand == "" {
		m.InstallCommand = rule.command
	}
	if m.InstallCommand == "" && m.Installer != protocol.InstallerDMG {
		return errors.New("bu yükleyici türü için kurulum komutu gerekli ({file} indirilen dosyanın yoludur)")
	}
	if m.Shell == "" {
		m.Shell = rule.shell
	}
	if !protocol.ValidShell(m.Platform, m.Shell) {
		return fmt.Errorf("%s için geçersiz kabuk: %s", m.Platform, m.Shell)
	}
	if len(m.SuccessCodes) == 0 {
		m.SuccessCodes = rule.codes
	}
	if len(m.SuccessCodes) > 20 {
		return errors.New("en fazla 20 başarı kodu")
	}
	if m.DetectName != "" {
		if _, err := regexp.Compile("(?i)" + m.DetectName); err != nil {
			return fmt.Errorf("uygulama adı kalıbı geçersiz: %w", err)
		}
	}
	return nil
}

// safeFileName, yüklenen dosyanın yalnızca adını alır ve yol/denetim karakterlerini atar.
func safeFileName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, name)
	if name == "." || name == ".." || name == "" {
		return ""
	}
	if len(name) > 255 {
		name = name[len(name)-255:]
	}
	return name
}

// handleUploadPackage, multipart isteği akış halinde işler: önce "metadata" (JSON), sonra
// "file" parçası. Dosya diske yazılırken SHA-256 hesaplanır; dosya içerik adresli saklanır.
func (s *Server) handleUploadPackage(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" {
		writeError(w, http.StatusUnsupportedMediaType, codeUnsupportedMedia, "İçerik türü multipart/form-data olmalı")
		return
	}
	set, err := s.store.GetTransferSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// Büyük yüklemeler genel okuma/yazma zaman aşımına takılmaz.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(6 * time.Hour))
	_ = rc.SetWriteDeadline(time.Now().Add(6 * time.Hour))
	maxBytes := int64(set.MaxUploadMB) << 20
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Çok parçalı gövde okunamadı")
		return
	}

	var meta *packageMeta
	var sha, fileName string
	var size int64
	tmpDir := filepath.Join(s.packageDir(), ".tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Çok parçalı gövde okunamadı")
			return
		}
		switch part.FormName() {
		case "metadata":
			var m packageMeta
			dec := json.NewDecoder(io.LimitReader(part, 64<<10))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&m); err != nil {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "Paket bilgisi geçersiz: "+err.Error())
				return
			}
			meta = &m
		case "file":
			if meta == nil {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "metadata parçası dosyadan önce gönderilmeli")
				return
			}
			fileName = safeFileName(part.FileName())
			if fileName == "" {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "Dosya adı geçersiz")
				return
			}
			if err := meta.validate(fileName); err != nil {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
				return
			}
			tmp, err := os.CreateTemp(tmpDir, "yukleme-*")
			if err != nil {
				writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
				return
			}
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(part, maxBytes+1))
			closeErr := tmp.Close()
			if err != nil || closeErr != nil {
				os.Remove(tmp.Name())
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "Dosya yüklenemedi")
				return
			}
			if n > maxBytes {
				os.Remove(tmp.Name())
				writeError(w, http.StatusRequestEntityTooLarge, codeInvalidRequest,
					fmt.Sprintf("Dosya en fazla %d MB olabilir", set.MaxUploadMB))
				return
			}
			sha, size = hex.EncodeToString(h.Sum(nil)), n
			if _, err := os.Stat(s.packagePath(sha)); err == nil {
				os.Remove(tmp.Name()) // aynı içerik zaten var
			} else if err := os.Rename(tmp.Name(), s.packagePath(sha)); err != nil {
				os.Remove(tmp.Name())
				writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
				return
			}
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, 1<<20))
		}
	}
	if meta == nil || sha == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "metadata ve file parçaları gerekli")
		return
	}
	uid := sess.User.ID
	p, err := s.store.CreatePackage(r.Context(), store.Package{
		Name: meta.Name, Version: meta.Version, Publisher: strings.TrimSpace(meta.Publisher), Platform: meta.Platform,
		Description: meta.Description, Installer: meta.Installer, InstallCommand: meta.InstallCommand, Shell: meta.Shell,
		SuccessCodes: meta.SuccessCodes, DetectName: meta.DetectName, FileName: fileName, FileSize: size,
		FileSHA256: sha, CreatedBy: &uid,
	})
	if errors.Is(err, store.ErrConflict) {
		s.removeUnusedPackageFile(r, sha)
		writeError(w, http.StatusConflict, codeConflict, "Bu platformda aynı ad ve sürümde bir paket zaten var")
		return
	}
	if err != nil {
		s.log.Error("paket kaydedilemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "package.upload",
		TargetType: "package", TargetID: p.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"name": p.Name, "version": p.Version, "platform": p.Platform, "sha256": p.FileSHA256, "size": p.FileSize},
	})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) removeUnusedPackageFile(r *http.Request, sha string) {
	if used, err := s.store.PackageFileReferenced(r.Context(), sha); err == nil && !used && sha256Hex.MatchString(sha) {
		_ = os.Remove(s.packagePath(sha))
	}
}

func (s *Server) handleListPackages(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	q := r.URL.Query()
	items, err := s.store.ListPackages(r.Context(), q.Get("platform"), q.Get("q"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) packageFromPath(w http.ResponseWriter, r *http.Request) (*store.Package, bool) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Paket bulunamadı")
		return nil, false
	}
	p, err := s.store.GetPackage(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Paket bulunamadı")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	return p, true
}

type packageDetail struct {
	store.Package
	// Outdated, uygulamanın paketten eski sürümünü çalıştıran makinelerdir.
	Outdated []store.AppInstall `json:"outdated"`
	UpToDate int                `json:"up_to_date"`
}

// outdatedInstalls, paketin tespit kalıbına uyan ve sürümü paketten eski olan kurulumları bulur.
func (s *Server) outdatedInstalls(r *http.Request, p *store.Package, scope []string) ([]store.AppInstall, int, error) {
	out := []store.AppInstall{}
	if p.DetectName == "" {
		return out, 0, nil
	}
	re, err := regexp.Compile("(?i)" + p.DetectName)
	if err != nil {
		return out, 0, nil
	}
	names, err := s.store.DistinctAppNames(r.Context(), p.Platform)
	if err != nil {
		return nil, 0, err
	}
	var hits []string
	for _, n := range names {
		if re.MatchString(n) {
			hits = append(hits, n)
		}
	}
	if len(hits) == 0 {
		return out, 0, nil
	}
	installs, err := s.store.AppInstalls(r.Context(), p.Platform, hits, scope)
	if err != nil {
		return nil, 0, err
	}
	// Makine başına en yeni kurulu sürüm esas alınır.
	newest := map[string]store.AppInstall{}
	var order []string
	for _, a := range installs {
		cur, ok := newest[a.MachineID]
		if !ok {
			order = append(order, a.MachineID)
		}
		if !ok || cve.CompareVersions(cve.NormalizeVersion(a.Version), cve.NormalizeVersion(cur.Version)) > 0 {
			newest[a.MachineID] = a
		}
	}
	upToDate := 0
	pv := cve.NormalizeVersion(p.Version)
	for _, id := range order {
		a := newest[id]
		if cve.CompareVersions(cve.NormalizeVersion(a.Version), pv) < 0 {
			out = append(out, a)
		} else {
			upToDate++
		}
	}
	return out, upToDate, nil
}

func (s *Server) handleGetPackage(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	p, ok := s.packageFromPath(w, r)
	if !ok {
		return
	}
	outdated, upToDate, err := s.outdatedInstalls(r, p, sess.User.Scope())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, packageDetail{Package: *p, Outdated: outdated, UpToDate: upToDate})
}

func (s *Server) handleDeletePackage(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	p, ok := s.packageFromPath(w, r)
	if !ok {
		return
	}
	sha, inUse, err := s.store.DeletePackage(r.Context(), p.ID, s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if !inUse && sha256Hex.MatchString(sha) {
		_ = os.Remove(s.packagePath(sha))
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "package.delete",
		TargetType: "package", TargetID: p.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"name": p.Name, "version": p.Version},
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- Aktarım ayarları ---

func (s *Server) handleGetTransferSettings(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	t, err := s.store.GetTransferSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handlePutTransferSettings(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var t store.TransferSettings
	if !decodeJSON(w, r, &t, 4<<10) {
		return
	}
	switch {
	case t.PerClientKbps < 64 || t.PerClientKbps > 10_000_000:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "İstemci başına hız 64 kbps - 10 Gbps arasında olmalı")
		return
	case t.MaxUploadMB < 1 || t.MaxUploadMB > 102_400:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Yükleme sınırı 1 MB - 100 GB arasında olmalı")
		return
	case t.DefaultExpiryHours < 1 || t.DefaultExpiryHours > 720:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Aksiyon süresi 1-720 saat arasında olmalı")
		return
	}
	old, _ := s.store.GetTransferSettings(r.Context())
	if err := s.store.SaveTransferSettings(r.Context(), t, sess.User.ID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "settings.transfer.update",
		TargetType: "settings", TargetID: "transfer", Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"old": old, "new": t},
	})
	writeJSON(w, http.StatusOK, t)
}

// --- Aksiyonlar ---

type createActionRequest struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PackageID string `json:"package_id"`
	Shell     string `json:"shell"`
	Command   string `json:"command"`
	// Patches, deploy_patch için kurulacak güncellemelerdir (Windows UpdateID / macOS etiketi).
	Patches        []string `json:"patches"`
	MachineIDs     []string `json:"machine_ids"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	BandwidthKbps  int      `json:"bandwidth_kbps"`
	ExpiresHours   int      `json:"expires_hours"`
	RespectWindows bool     `json:"respect_windows"`
	// Rollout doluysa hedefler aşamalara bölünür (pilot halka → geri kalanlar).
	Rollout *store.Rollout `json:"rollout"`
}

// requirePermDenied, kapsam reddini denetim kaydına yazar.
func (s *Server) requirePermDenied(r *http.Request, sess *store.Session, detail string) {
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "authz.denied", Result: store.ResultDenied, SourceIP: clientIP(r), Detail: detail,
		Params: map[string]any{"method": r.Method, "path": r.URL.Path},
	})
}

// requirePerm, izni denetler; yoksa reddi denetim kaydına yazıp 403 döner.
func (s *Server) requirePerm(w http.ResponseWriter, r *http.Request, sess *store.Session, perm auth.Permission) bool {
	if auth.HasPermission(auth.Role(sess.User.Role), perm) {
		return true
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "authz.denied", Result: store.ResultDenied, SourceIP: clientIP(r),
		Params: map[string]any{"method": r.Method, "path": r.URL.Path, "permission": string(perm)},
	})
	writeError(w, http.StatusForbidden, codeForbidden, "Bu işlem için yetkiniz yok")
	return false
}

func kindPermission(kind string) auth.Permission {
	switch kind {
	case protocol.JobRunCommand:
		return auth.PermActionsRunCommand
	case protocol.JobDeployPatch:
		return auth.PermActionsDeployPatch
	}
	return auth.PermActionsDeployPackage
}

func (s *Server) handleCreateAction(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createActionRequest
	if !decodeJSON(w, r, &req, 2<<20) {
		return
	}
	if req.Kind != protocol.JobDeployPackage && req.Kind != protocol.JobRunCommand && req.Kind != protocol.JobDeployPatch {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Aksiyon türü deploy_package, deploy_patch veya run_command olmalı")
		return
	}
	// Teknisyen yalnızca kütüphanedeki paketleri gönderebilir; serbest komut ayrı izindir.
	if !s.requirePerm(w, r, sess, kindPermission(req.Kind)) {
		return
	}
	set, err := s.store.GetTransferSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 3600
	}
	if req.BandwidthKbps == 0 || req.BandwidthKbps > set.PerClientKbps {
		req.BandwidthKbps = set.PerClientKbps
	}
	if req.ExpiresHours == 0 {
		req.ExpiresHours = set.DefaultExpiryHours
	}
	switch {
	case req.TimeoutSeconds < 30 || req.TimeoutSeconds > 86400:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Zaman aşımı 30 sn - 24 saat arasında olmalı")
		return
	case req.BandwidthKbps < 64:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Hız sınırı en az 64 kbps olmalı")
		return
	case req.ExpiresHours < 1 || req.ExpiresHours > 720:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçerlilik 1-720 saat arasında olmalı")
		return
	case len(req.MachineIDs) == 0 || len(req.MachineIDs) > 10000:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "1-10000 makine seçilmeli")
		return
	case utf8.RuneCountInString(req.Name) > 200:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Aksiyon adı en fazla 200 karakter olabilir")
		return
	}
	if err := validateRollout(req.Rollout); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	ids := make([]string, 0, len(req.MachineIDs))
	for _, id := range req.MachineIDs {
		id = strings.ToLower(id)
		if !validUUID(id) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz makine kimliği: "+id)
			return
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	platforms, err := s.store.ActiveMachines(r.Context(), ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if missing := len(ids) - len(platforms); missing > 0 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest,
			fmt.Sprintf("%d makine bulunamadı veya aktif değil (onay bekleyen makinelere iş gönderilmez)", missing))
		return
	}
	if scope := sess.User.Scope(); scope != nil {
		for _, t := range platforms {
			if !ad.InScope(t.OU, scope) {
				s.requirePermDenied(r, sess, "kapsam dışı makine")
				writeError(w, http.StatusForbidden, codeForbidden, "Seçilen makinelerden bazıları yetki kapsamınızın dışında")
				return
			}
		}
	}

	now := s.now()
	job := protocol.Job{
		Kind: req.Kind, IssuedAt: now.UTC(), ExpiresAt: now.Add(time.Duration(req.ExpiresHours) * time.Hour).UTC(),
		TimeoutSeconds: req.TimeoutSeconds, RescanAfter: req.Kind != protocol.JobRunCommand,
	}
	var pkg *store.Package
	switch req.Kind {
	case protocol.JobDeployPackage:
		if !validUUID(req.PackageID) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Paket seçilmeli")
			return
		}
		pkg, err = s.store.GetPackage(r.Context(), req.PackageID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Paket bulunamadı")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		for _, p := range platforms {
			if p.Platform != pkg.Platform {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "Paket yalnızca "+pkg.Platform+" makinelerine gönderilebilir")
				return
			}
		}
		job.Shell, job.Command = pkg.Shell, pkg.InstallCommand
		for _, c := range pkg.SuccessCodes {
			job.SuccessCodes = append(job.SuccessCodes, int(c))
		}
		job.Package = &protocol.JobPackage{
			ID: pkg.ID, Name: pkg.Name, Version: pkg.Version, FileName: pkg.FileName, Size: pkg.FileSize,
			SHA256: pkg.FileSHA256, Installer: pkg.Installer,
		}
		if req.Name == "" {
			req.Name = pkg.Name + " " + pkg.Version
		}
	case protocol.JobRunCommand:
		req.Command = strings.TrimSpace(req.Command)
		if req.Command == "" || len(req.Command) > 32<<10 {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Komut 1 bayt - 32 KB olmalı")
			return
		}
		for _, p := range platforms {
			if !protocol.ValidShell(p.Platform, req.Shell) {
				writeError(w, http.StatusBadRequest, codeInvalidRequest,
					fmt.Sprintf("%s kabuğu %s makinelerinde kullanılamaz; platformları ayrı aksiyonlarla hedefleyin", req.Shell, p.Platform))
				return
			}
		}
		job.Shell, job.Command, job.SuccessCodes = req.Shell, req.Command, []int{0}
		if req.Name == "" {
			req.Name = firstLineOf(req.Command, 80)
		}
	case protocol.JobDeployPatch:
		platform := platforms[ids[0]].Platform
		for _, p := range platforms {
			if p.Platform != platform {
				writeError(w, http.StatusBadRequest, codeInvalidRequest, "Yamalar tek platforma gönderilebilir; Windows ve macOS'u ayrı aksiyonlarla hedefleyin")
				return
			}
		}
		job.Shell, job.Command, job.SuccessCodes, err = patchJob(platform, req.Patches)
		if err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
			return
		}
		job.Patches = req.Patches
		// Yama kurulumu uzun sürebilir: varsayılan zaman aşımı 2 saat.
		if req.TimeoutSeconds == 3600 {
			job.TimeoutSeconds = 7200
		}
		if req.Name == "" {
			req.Name = fmt.Sprintf("Yama dağıtımı (%d güncelleme)", len(req.Patches))
		}
	}

	actionID, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	job.ID = actionID
	stages := assignStages(actionID, ids, req.Rollout)
	targets := make([]store.NewTarget, 0, len(ids))
	for _, id := range ids {
		job.MachineID = id
		sj, err := protocol.SignJob(s.signKey, job)
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		targets = append(targets, store.NewTarget{MachineID: id, Payload: sj.Payload, Signature: sj.Signature, Stage: stages[id]})
	}
	status := store.ActionActive
	if req.Kind == protocol.JobRunCommand && set.CommandApproval {
		status = store.ActionPendingApproval
	}

	// Kritik aksiyon: denetim kaydı yazılamazsa aksiyon oluşturulmaz (fail-closed).
	entry := store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "action.create",
		TargetType: "action", TargetID: actionID, Result: store.ResultSuccess, SourceIP: clientIP(r), OccurredAt: now,
		Params: map[string]any{
			"kind": req.Kind, "name": req.Name, "package_id": req.PackageID, "shell": job.Shell, "command": job.Command,
			"machine_ids": ids, "timeout_seconds": req.TimeoutSeconds, "bandwidth_kbps": req.BandwidthKbps, "status": status,
			"respect_windows": req.RespectWindows, "rollout": req.Rollout,
		},
	}
	if err := s.store.AppendAudit(r.Context(), entry); err != nil {
		s.log.Error("aksiyon denetim kaydı yazılamadı; aksiyon reddedildi", "hata", err)
		writeError(w, http.StatusServiceUnavailable, codeInternal, "Denetim kaydı yazılamadığı için aksiyon oluşturulmadı")
		return
	}
	err = s.store.CreateAction(r.Context(), store.NewAction{
		ID: actionID, Name: req.Name, Kind: req.Kind, PackageID: req.PackageID, Shell: job.Shell, Command: job.Command,
		TimeoutSeconds: job.TimeoutSeconds, BandwidthKbps: req.BandwidthKbps, Status: status, CreatedBy: sess.User.ID,
		CreatedByName: sess.User.Username, CreatedAt: now, ExpiresAt: job.ExpiresAt, Targets: targets,
		RespectWindows: req.RespectWindows, Rollout: req.Rollout, Patches: job.Patches,
	})
	if err != nil {
		s.log.Error("aksiyon kaydedilemedi", "hata", err)
		entry.Action, entry.Result, entry.Detail = "action.create", store.ResultFailure, "veritabanı hatası"
		s.audit(r.Context(), entry)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	a, err := s.store.GetAction(r.Context(), actionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func firstLineOf(s string, n int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size < 1 || size > 200 {
		size = 50
	}
	f := store.ActionFilter{Status: q.Get("status"), Kind: q.Get("kind"), MachineID: q.Get("machine_id"), Limit: size,
		Offset: (page - 1) * size, Scope: sess.User.Scope(), ViewerID: sess.User.ID}
	if f.MachineID != "" && !validUUID(f.MachineID) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz makine kimliği")
		return
	}
	items, total, err := s.store.ListActions(r.Context(), f)
	if err != nil {
		s.log.Error("aksiyonlar okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) actionFromPath(w http.ResponseWriter, r *http.Request) (*store.Action, bool) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Aksiyon bulunamadı")
		return nil, false
	}
	a, err := s.store.GetAction(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Aksiyon bulunamadı")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	return a, true
}

func (s *Server) handleGetAction(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	a, ok := s.actionFromPath(w, r)
	if !ok {
		return
	}
	targets, err := s.store.ListActionTargets(r.Context(), a.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// Kapsamlı kullanıcı yalnızca kapsamındaki hedefleri görür; hiçbiri yoksa ve aksiyonu
	// kendisi oluşturmadıysa aksiyon "bulunamadı" sayılır.
	if scope := sess.User.Scope(); scope != nil {
		visible := targets[:0]
		for _, t := range targets {
			if ad.InScope(t.OU, scope) {
				visible = append(visible, t)
			}
		}
		mine := a.CreatedBy != nil && *a.CreatedBy == sess.User.ID
		if len(visible) == 0 && !mine {
			writeError(w, http.StatusNotFound, codeNotFound, "Aksiyon bulunamadı")
			return
		}
		targets = visible
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": a, "targets": targets})
}

// handleActionTransition, onay, red ve iptal işlemleridir.
func (s *Server) handleActionTransition(op string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, sess *store.Session) {
		a, ok := s.actionFromPath(w, r)
		if !ok {
			return
		}
		var to string
		var from []string
		switch op {
		case "approve", "reject":
			if !s.requirePerm(w, r, sess, auth.PermActionsApprove) {
				return
			}
			// Dört göz ilkesi: aksiyonu oluşturan kişi kendi aksiyonunu onaylayamaz.
			if a.CreatedBy != nil && *a.CreatedBy == sess.User.ID {
				writeError(w, http.StatusForbidden, codeForbidden, "Kendi oluşturduğunuz aksiyonu onaylayamazsınız")
				return
			}
			to, from = store.ActionActive, []string{store.ActionPendingApproval}
			if op == "reject" {
				to = store.ActionRejected
			}
		case "cancel":
			if !s.requirePerm(w, r, sess, kindPermission(a.Kind)) {
				return
			}
			to, from = store.ActionCancelled, []string{store.ActionPendingApproval, store.ActionActive}
		}
		err := s.store.SetActionStatus(r.Context(), a.ID, to, from, sess.User.ID, s.now())
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, codeConflict, "Aksiyon bu işleme uygun durumda değil")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		s.audit(r.Context(), store.AuditEntry{
			ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "action." + op,
			TargetType: "action", TargetID: a.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		})
		a, _ = s.store.GetAction(r.Context(), a.ID)
		writeJSON(w, http.StatusOK, a)
	}
}

// --- Ajan uç noktaları ---

func (s *Server) handleAgentJobs(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	if m.Status != protocol.StatusActive {
		writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: []protocol.SignedJob{}})
		return
	}
	jobs, err := s.machineJobs(r.Context(), m)
	if err != nil {
		s.log.Error("işler okunamadı", "ajan", m.ID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, protocol.JobsResponse{Jobs: jobs})
}

func (s *Server) handleAgentJobStatus(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "İş bulunamadı")
		return
	}
	var req protocol.JobStatusRequest
	if !decodeJSON(w, r, &req, 512<<10) {
		return
	}
	switch req.Status {
	case protocol.TargetDownloading, protocol.TargetRunning, protocol.TargetSucceeded, protocol.TargetFailed:
	default:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz durum")
		return
	}
	err := s.store.UpdateTargetStatus(r.Context(), id, m.ID, req, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, "İş bulunamadı")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, codeConflict, "İş zaten sonuçlanmış veya iptal edilmiş")
	case err != nil:
		s.log.Error("iş durumu kaydedilemedi", "ajan", m.ID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
	default:
		if protocol.FinalTargetStatus(req.Status) {
			s.log.Info("iş sonuçlandı", "ajan", m.ID, "aksiyon", id, "durum", req.Status)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// clientRate, istemci başına uygulanacak hızdır: aksiyonun hızı ile genel sınırın küçüğü.
func (s *Server) clientRate(r *http.Request, actionKbps int) int {
	kbps := actionKbps
	if set, err := s.store.GetTransferSettings(r.Context()); err == nil && (kbps <= 0 || set.PerClientKbps < kbps) {
		kbps = set.PerClientKbps
	}
	return max(kbps, 64)
}

func (s *Server) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	pkgID, actionID := r.PathValue("id"), r.URL.Query().Get("action")
	if !validUUID(pkgID) || !validUUID(actionID) || m.Status != protocol.StatusActive {
		writeError(w, http.StatusNotFound, codeNotFound, "Paket bulunamadı")
		return
	}
	g, err := s.store.GrantDownload(r.Context(), actionID, m.ID, pkgID, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Bu makine için açık bir dağıtım yok")
		return
	}
	if err != nil || !sha256Hex.MatchString(g.SHA256) {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	f, err := os.Open(s.packagePath(g.SHA256))
	if err != nil {
		s.log.Error("paket dosyası açılamadı", "paket", pkgID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Paket dosyası sunucuda bulunamadı")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if isRelayRequest(r) && r.Header.Get(HeaderRelayProbe) != "" {
		relayProbeResponse(w, g.SHA256, info.Size(), s.clientRate(r, g.BandwidthKbps))
		return
	}
	noWriteDeadline(w)
	fileDownloadHeaders(w, "application/octet-stream")
	w.Header().Set("ETag", `"`+g.SHA256+`"`)
	w.Header().Set("X-Ber-Rate-Kbps", strconv.Itoa(s.clientRate(r, g.BandwidthKbps)))
	http.ServeContent(newThrottledWriter(r.Context(), w, s.clientRate(r, g.BandwidthKbps)), r, g.FileName, info.ModTime(), f)
}
