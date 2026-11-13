package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type deadlineWriter struct {
	*httptest.ResponseRecorder
	read, write time.Time
}

func (w *deadlineWriter) SetReadDeadline(t time.Time) error  { w.read = t; return nil }
func (w *deadlineWriter) SetWriteDeadline(t time.Time) error { w.write = t; return nil }

func TestRequestLoggerPreservesDeadlines(t *testing.T) {
	w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	rc := http.NewResponseController(rec)
	deadline := time.Now().Add(time.Hour)
	if err := rc.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := rc.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if !w.read.Equal(deadline) || !w.write.Equal(deadline) {
		t.Fatal("zaman aşımı alttaki yazıcıya ulaşmadı")
	}
	noWriteDeadline(rec)
	if !w.write.IsZero() {
		t.Fatal("indirme zaman aşımı kaldırılamadı")
	}
}
