package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BerkayAtag/BerOps/server/internal/report"
	"github.com/BerkayAtag/BerOps/server/internal/store"
)

const channelSecretLabel = "notification_channels.secret"

// emailConfig, e-posta kanalı ayarlarıdır.
type emailConfig struct {
	Host     string   `json:"smtp_host"`
	Port     int      `json:"smtp_port"`
	Security string   `json:"security"` // starttls, tls, none
	Username string   `json:"username"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// webhookConfig, webhook kanalı ayarlarıdır.
type webhookConfig struct {
	URL    string `json:"url"`
	Format string `json:"format"` // generic, teams, slack
}

// Notification, kanala gönderilen iletidir.
type Notification struct {
	Event      string
	Title      string
	Text       string
	Payload    any
	Attachment *Attachment
}

// Attachment, e-posta ekidir (zamanlanmış raporlar).
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

func validateChannel(kind string, raw json.RawMessage) (json.RawMessage, error) {
	switch kind {
	case "email":
		var c emailConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, errors.New("e-posta ayarları geçersiz")
		}
		c.Host = strings.TrimSpace(c.Host)
		if c.Host == "" || strings.ContainsAny(c.Host, " /") {
			return nil, errors.New("SMTP sunucusu gerekli")
		}
		if c.Port == 0 {
			c.Port = 587
		}
		if c.Port < 1 || c.Port > 65535 {
			return nil, errors.New("SMTP portu geçersiz")
		}
		if c.Security == "" {
			c.Security = "starttls"
		}
		if c.Security != "starttls" && c.Security != "tls" && c.Security != "none" {
			return nil, errors.New("güvenlik starttls, tls veya none olmalı")
		}
		if _, err := mail.ParseAddress(c.From); err != nil {
			return nil, errors.New("gönderen adresi geçersiz")
		}
		if len(c.To) == 0 || len(c.To) > 50 {
			return nil, errors.New("1-50 alıcı gerekli")
		}
		for _, to := range c.To {
			if _, err := mail.ParseAddress(to); err != nil {
				return nil, fmt.Errorf("alıcı adresi geçersiz: %s", to)
			}
		}
		return json.Marshal(c)
	case "webhook":
		var c webhookConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, errors.New("webhook ayarları geçersiz")
		}
		u, err := url.Parse(strings.TrimSpace(c.URL))
		if err != nil || u.Host == "" {
			return nil, errors.New("webhook adresi geçersiz")
		}
		// Şifresiz HTTP yalnızca yerel testler için kabul edilir.
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
			return nil, errors.New("webhook adresi https olmalı")
		}
		if c.Format == "" {
			c.Format = "generic"
		}
		if c.Format != "generic" && c.Format != "teams" && c.Format != "slack" {
			return nil, errors.New("biçim generic, teams veya slack olmalı")
		}
		c.URL = u.String()
		return json.Marshal(c)
	}
	return nil, errors.New("kanal türü email veya webhook olmalı")
}

// send, iletiyi kanala gönderir.
func (s *Server) send(ctx context.Context, ch *store.Channel, n Notification) error {
	var secret string
	if len(ch.SecretEnc) > 0 {
		b, err := s.secrets.Open(ch.SecretEnc, channelSecretLabel)
		if err != nil {
			return errors.New("kanal gizli değeri çözülemedi; yeniden girin")
		}
		secret = string(b)
	}
	switch ch.Kind {
	case "email":
		var c emailConfig
		if err := json.Unmarshal(ch.Config, &c); err != nil {
			return err
		}
		return sendEmail(ctx, c, secret, n)
	case "webhook":
		if n.Attachment != nil {
			return errors.New("webhook kanalları dosya eki taşıyamaz; zamanlanmış raporlar için e-posta kanalı kullanın")
		}
		var c webhookConfig
		if err := json.Unmarshal(ch.Config, &c); err != nil {
			return err
		}
		return sendWebhook(ctx, c, secret, n, s.now())
	}
	return errors.New("bilinmeyen kanal türü")
}

func sendWebhook(ctx context.Context, c webhookConfig, secret string, n Notification, now time.Time) error {
	var body any
	switch c.Format {
	case "slack":
		body = map[string]string{"text": "*" + n.Title + "*\n" + n.Text}
	case "teams":
		body = map[string]any{"@type": "MessageCard", "@context": "https://schema.org/extensions", "themeColor": "DC0005",
			"summary": n.Title, "title": n.Title, "text": strings.ReplaceAll(n.Text, "\n", "<br>")}
	default:
		body = map[string]any{"event": n.Event, "title": n.Title, "text": n.Text, "payload": n.Payload, "occurred_at": now.UTC()}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "berops-notify")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(b)
		req.Header.Set("X-Ber-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %d döndü", resp.StatusCode)
	}
	return nil
}

// buildEmail, UTF-8 konu ve gövdeli, isteğe bağlı ekli MIME iletisi üretir.
func buildEmail(from string, to []string, n Notification, now time.Time) []byte {
	var b bytes.Buffer
	boundary := "ber-" + strconv.FormatInt(now.UnixNano(), 36)
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\n",
		from, strings.Join(to, ", "), mime.QEncoding.Encode("utf-8", n.Title), now.Format(time.RFC1123Z))
	text := base64.StdEncoding.EncodeToString([]byte(n.Text + "\n\n— BerOps\n"))
	if n.Attachment == nil {
		fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", wrap76(text))
		return b.Bytes()
	}
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", boundary, wrap76(text))
	fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=%q\r\n\r\n%s\r\n",
		boundary, n.Attachment.ContentType, n.Attachment.Name, wrap76(base64.StdEncoding.EncodeToString(n.Attachment.Data)))
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

func sendEmail(ctx context.Context, c emailConfig, password string, n Notification) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	tc := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.Security == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tc)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP sunucusuna bağlanılamadı: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.Security == "starttls" {
		if err := cl.StartTLS(tc); err != nil {
			return fmt.Errorf("STARTTLS başarısız: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); err != nil {
			return fmt.Errorf("SMTP kimlik doğrulaması başarısız: %w", err)
		}
	}
	from, _ := mail.ParseAddress(c.From)
	if err := cl.Mail(from.Address); err != nil {
		return err
	}
	var to []string
	for _, t := range c.To {
		a, _ := mail.ParseAddress(t)
		if err := cl.Rcpt(a.Address); err != nil {
			return fmt.Errorf("alıcı reddedildi (%s): %w", a.Address, err)
		}
		to = append(to, a.String())
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildEmail(from.String(), to, n, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

// dispatch, olayı abone kanallara gönderir; olay daha önce bildirildiyse hiçbir şey yapmaz.
func (s *Server) dispatch(ctx context.Context, n Notification, dedupeKey string) {
	channels, err := s.store.ListChannels(ctx)
	if err != nil {
		return
	}
	var subs []store.Channel
	for _, c := range channels {
		if c.Enabled && slices.Contains(c.Events, n.Event) {
			subs = append(subs, c)
		}
	}
	if len(subs) == 0 {
		return
	}
	if first, err := s.store.ClaimEvent(ctx, n.Event, dedupeKey, n.Payload); err != nil || !first {
		return
	}
	for i := range subs {
		err := s.send(ctx, &subs[i], n)
		_ = s.store.ChannelResult(ctx, subs[i].ID, s.now(), err)
		if err != nil {
			s.log.Warn("bildirim gönderilemedi", "kanal", subs[i].Name, "olay", n.Event, "hata", err)
		}
	}
}

// RunNotifications, olayları üretir ve zamanlanmış raporları çalıştırır.
func (s *Server) RunNotifications(ctx context.Context) {
	if acts, err := s.store.RecentlyCompletedActions(ctx, s.now()); err == nil {
		for _, a := range acts {
			failed := a.Counts["failed"] + a.Counts["expired"]
			title := fmt.Sprintf("Aksiyon tamamlandı: %s", a.Name)
			if failed > 0 {
				title = fmt.Sprintf("Aksiyon tamamlandı (%d hedef başarısız): %s", failed, a.Name)
			}
			text := fmt.Sprintf("Oluşturan: %s\nBaşarılı: %d · Başarısız: %d · Süresi dolan: %d · İptal: %d",
				a.CreatedBy, a.Counts["succeeded"], a.Counts["failed"], a.Counts["expired"], a.Counts["cancelled"])
			s.dispatch(ctx, Notification{Event: store.EventActionCompleted, Title: title, Text: text, Payload: a}, a.ID)
		}
	}
	if kevs, err := s.store.RecentKEVInFleet(ctx, s.now()); err == nil {
		for _, k := range kevs {
			text := fmt.Sprintf("%s: %s\nKEV'e eklenme: %s · Etkilenen makine: %d", k.CVE, k.Name, k.DateAdded.Format("2006-01-02"), k.Affected)
			if k.Ransom {
				text += "\nFidye yazılımı kampanyalarında kullanıldığı biliniyor."
			}
			s.dispatch(ctx, Notification{Event: store.EventKEVNew, Title: "Aktif istismar edilen yeni açık: " + k.CVE, Text: text, Payload: k}, k.CVE)
		}
	}
	if feeds, err := s.store.ListFeedStatus(ctx); err == nil {
		for _, f := range feeds {
			if f.LastError != "" && f.LastAttemptAt != nil {
				s.dispatch(ctx, Notification{Event: store.EventCVESyncFailed, Title: "CVE kaynağı eşitlenemedi: " + f.Feed,
					Text: f.LastError, Payload: f}, f.Feed+"@"+f.LastAttemptAt.UTC().Format("2006-01-02"))
			}
		}
	}
	s.runSchedules(ctx)
}

// runSchedules, vakti gelen zamanlanmış raporları üretip e-postayla gönderir.
func (s *Server) runSchedules(ctx context.Context) {
	list, err := s.store.ListSchedules(ctx)
	if err != nil {
		return
	}
	for _, sc := range list {
		if !sc.Enabled {
			continue
		}
		loc, err := time.LoadLocation(sc.Timezone)
		if err != nil {
			loc = time.UTC
		}
		now := s.now().In(loc)
		if int16(now.Hour()) != sc.Hour || (sc.Weekday != nil && int16(now.Weekday()) != *sc.Weekday) {
			continue
		}
		if sc.LastRunAt != nil && s.now().Sub(*sc.LastRunAt) < 2*time.Hour {
			continue
		}
		_ = s.store.MarkScheduleRun(ctx, sc.ID, s.now())
		ch, err := s.store.GetChannel(ctx, sc.ChannelID)
		if err != nil {
			continue
		}
		t, err := s.buildScheduledReport(ctx, sc, loc)
		if err != nil {
			s.log.Warn("zamanlanmış rapor üretilemedi", "rapor", sc.Report, "hata", err)
			continue
		}
		var buf bytes.Buffer
		if err := report.Write(&buf, report.Format(sc.Format), t); err != nil {
			continue
		}
		name := fmt.Sprintf("%s-%s.%s", rt(sc.Lang, sc.Report+".file"), now.Format("2006-01-02"), sc.Format)
		err = s.send(ctx, ch, Notification{Event: "report.scheduled", Title: t.Title + " · " + now.Format("2006-01-02"),
			Text: "Zamanlanmış rapor ektedir.", Attachment: &Attachment{Name: name, ContentType: report.Format(sc.Format).ContentType(), Data: buf.Bytes()}})
		_ = s.store.ChannelResult(ctx, ch.ID, s.now(), err)
		s.audit(ctx, store.AuditEntry{ActorType: store.ActorSystem, ActorName: "zamanlanmış rapor", Action: "report.scheduled",
			TargetType: "report", TargetID: sc.Report, Result: map[bool]string{true: store.ResultSuccess, false: store.ResultFailure}[err == nil],
			Params: map[string]any{"schedule": sc.ID, "channel": ch.Name, "format": sc.Format}})
	}
}

// buildScheduledReport, raporu kapsamsız (tüm filo) üretir.
func (s *Server) buildScheduledReport(ctx context.Context, sc store.ReportSchedule, loc *time.Location) (*report.Table, error) {
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	t := &report.Table{GeneratedAt: s.now(), GeneratedBy: "BerOps", Lang: sc.Lang, Location: loc, Title: rt(sc.Lang, sc.Report+".title")}
	var err error
	switch sc.Report {
	case reportCompliance:
		err = s.buildComplianceReport(r, t, "", nil)
	case reportVulns:
		err = s.buildVulnReport(r, t, store.VulnFilter{})
	case reportMissing:
		err = s.buildMissingReport(r, t, "", "", nil)
	case reportApps:
		err = s.buildAppsReport(r, t, "", "", nil)
	default:
		err = errors.New("bilinmeyen rapor")
	}
	return t, err
}

// --- Konsol uç noktaları ---

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	list, err := s.store.ListChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	schedules, err := s.store.ListSchedules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "events": store.AllEvents, "schedules": schedules})
}

type channelRequest struct {
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	Config  json.RawMessage `json:"config"`
	Secret  string          `json:"secret"` // boşsa mevcut değer korunur
	Events  []string        `json:"events"`
	Enabled bool            `json:"enabled"`
}

func (s *Server) handleSaveChannel(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req channelRequest
	if !decodeJSON(w, r, &req, 32<<10) {
		return
	}
	id := r.PathValue("id")
	if id != "" && !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Ad 1-100 karakter olmalı")
		return
	}
	cfg, err := validateChannel(req.Kind, req.Config)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	for _, e := range req.Events {
		if !slices.Contains(store.AllEvents, e) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Bilinmeyen olay: "+e)
			return
		}
	}
	var enc []byte
	if req.Secret != "" {
		if enc, err = s.secrets.Seal([]byte(req.Secret), channelSecretLabel); err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
	}
	ch, err := s.store.SaveChannel(r.Context(), store.Channel{ID: id, Name: req.Name, Kind: req.Kind, Config: cfg,
		Events: req.Events, Enabled: req.Enabled}, enc)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.notification.save", TargetType: "notification_channel", TargetID: ch.ID, Result: store.ResultSuccess,
		SourceIP: clientIP(r), Params: map[string]any{"name": ch.Name, "kind": ch.Kind, "events": ch.Events, "secret_changed": enc != nil}})
	writeJSON(w, http.StatusOK, ch)
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	}
	if err := s.store.DeleteChannel(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.notification.delete", TargetType: "notification_channel", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

// handleTestChannel, kanala deneme iletisi gönderir.
func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	}
	ch, err := s.store.GetChannel(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "Kanal bulunamadı")
		return
	}
	err = s.send(r.Context(), ch, Notification{Event: "test", Title: "BerOps deneme bildirimi",
		Text: "Bu kanal BerOps bildirimlerini alabiliyor.", Payload: map[string]string{"channel": ch.Name}})
	_ = s.store.ChannelResult(r.Context(), ch.ID, s.now(), err)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Deneme bildirimi gönderildi"})
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var sc store.ReportSchedule
	if !decodeJSON(w, r, &sc, 4<<10) {
		return
	}
	if sc.Timezone == "" {
		sc.Timezone = "Europe/Istanbul"
	}
	if sc.Lang == "" {
		sc.Lang = "tr"
	}
	switch {
	case !slices.Contains([]string{reportCompliance, reportVulns, reportMissing, reportApps}, sc.Report):
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Bilinmeyen rapor")
		return
	case sc.Format != "pdf" && sc.Format != "xlsx" && sc.Format != "csv":
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Biçim pdf, xlsx veya csv olmalı")
		return
	case sc.Hour < 0 || sc.Hour > 23 || (sc.Weekday != nil && (*sc.Weekday < 0 || *sc.Weekday > 6)):
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Saat 0-23, gün 0-6 olmalı")
		return
	case sc.Lang != "tr" && sc.Lang != "en":
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Dil tr veya en olmalı")
		return
	}
	if _, err := time.LoadLocation(sc.Timezone); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Saat dilimi geçersiz")
		return
	}
	ch, err := s.store.GetChannel(r.Context(), sc.ChannelID)
	if err != nil || ch.Kind != "email" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Zamanlanmış raporlar için bir e-posta kanalı seçin")
		return
	}
	sc.Enabled = true
	id, err := s.store.CreateSchedule(r.Context(), sc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	sc.ID = id
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.schedule.create", TargetType: "report_schedule", TargetID: id, Result: store.ResultSuccess,
		SourceIP: clientIP(r), Params: map[string]any{"schedule": sc}})
	writeJSON(w, http.StatusCreated, sc)
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Rapor bulunamadı")
		return
	}
	if err := s.store.DeleteSchedule(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "Rapor bulunamadı")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.schedule.delete", TargetType: "report_schedule", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
