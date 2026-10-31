package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/report"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

// auditFilterFromQuery, sorgu parametrelerinden denetim filtresi kurar. Tarihler YYYY-MM-DD
// biçimindedir; "to" günü dahildir.
func auditFilterFromQuery(r *http.Request) (store.AuditFilter, int, int, error) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size < 1 || size > 500 {
		size = 50
	}
	f := store.AuditFilter{Search: q.Get("q"), Action: q.Get("action"), Result: q.Get("result"), Actor: q.Get("actor"),
		Limit: size, Offset: (page - 1) * size}
	switch f.Result {
	case "", store.ResultSuccess, store.ResultFailure, store.ResultDenied:
	default:
		return f, 0, 0, fmt.Errorf("geçersiz sonuç")
	}
	loc := time.UTC
	if tz := q.Get("tz"); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	if v := q.Get("from"); v != "" {
		t, err := time.ParseInLocation(time.DateOnly, v, loc)
		if err != nil {
			return f, 0, 0, fmt.Errorf("from tarihi YYYY-AA-GG olmalı")
		}
		f.From = &t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.ParseInLocation(time.DateOnly, v, loc)
		if err != nil {
			return f, 0, 0, fmt.Errorf("to tarihi YYYY-AA-GG olmalı")
		}
		t = t.AddDate(0, 0, 1)
		f.To = &t
	}
	return f, page, size, nil
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	f, page, size, err := auditFilterFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	items, total, err := s.store.ListAudit(r.Context(), f)
	if err != nil {
		s.log.Error("denetim kaydı okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

// handleExportAudit, filtreye uyan kayıtları (en fazla 100 000) CSV veya Excel olarak verir.
func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	f, _, _, err := auditFilterFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	format := report.Format(r.URL.Query().Get("format"))
	if format != report.CSV && format != report.XLSX {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Biçim csv veya xlsx olmalı")
		return
	}
	f.Limit, f.Offset = 100_000, 0
	items, _, err := s.store.ListAudit(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	lang := r.URL.Query().Get("lang")
	if lang != "en" {
		lang = "tr"
	}
	loc := time.UTC
	if l, err := time.LoadLocation(r.URL.Query().Get("tz")); err == nil {
		loc = l
	}
	h := map[string][]string{
		"tr": {"Denetim Kaydı", "Zaman", "Aktör türü", "Aktör", "Eylem", "Hedef türü", "Hedef", "Sonuç", "Ayrıntı", "Kaynak IP", "Parametreler"},
		"en": {"Audit Log", "Time", "Actor type", "Actor", "Action", "Target type", "Target", "Result", "Detail", "Source IP", "Parameters"},
	}[lang]
	t := &report.Table{
		Title: h[0], GeneratedAt: s.now(), GeneratedBy: sess.User.Username, Lang: lang, Location: loc,
		Columns: []report.Column{
			{Header: h[1], Width: 17, Kind: report.DateTime}, {Header: h[2], Width: 9}, {Header: h[3], Width: 16},
			{Header: h[4], Width: 22}, {Header: h[5], Width: 12}, {Header: h[6], Width: 30}, {Header: h[7], Width: 9},
			{Header: h[8], Width: 24}, {Header: h[9], Width: 14}, {Header: h[10], Width: 60},
		},
	}
	for _, e := range items {
		params, _ := json.Marshal(e.Params)
		t.Rows = append(t.Rows, []any{e.OccurredAt, e.ActorType, e.ActorName, e.Action, e.TargetType, e.TargetID,
			e.Result, e.Detail, e.SourceIP, string(params)})
	}
	var buf bytes.Buffer
	if err := report.Write(&buf, format, t); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "audit.export",
		Result: store.ResultSuccess, SourceIP: clientIP(r), Params: map[string]any{"format": string(format), "rows": len(items)},
	})
	w.Header().Set("Content-Type", format.ContentType())
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="denetim-kaydi-%s.%s"`, s.now().In(loc).Format("2006-01-02"), format))
	_, _ = w.Write(buf.Bytes())
}
