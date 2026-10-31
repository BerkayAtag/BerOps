package api

import (
	"context"
	"io"
	"net/http"
	"time"
)

// throttledWriter, yanıt gövdesini en fazla verilen hızda yazar (istemci başına bant genişliği
// sınırı). Hız, gönderilen toplam bayt ile geçen süre karşılaştırılarak uygulanır; kısa
// patlamalar en fazla bir parça (16 KiB) kadardır.
type throttledWriter struct {
	http.ResponseWriter
	// body, gövdenin yazıldığı hedeftir (ResponseWriter'ın kendisi); başlıklar gömülü
	// ResponseWriter üzerinden ayarlanır.
	body        io.Writer
	ctx         context.Context
	bytesPerSec float64
	start       time.Time
	sent        int64
	sleep       func(context.Context, time.Duration) bool
}

const throttleChunk = 16 << 10

func newThrottledWriter(ctx context.Context, w http.ResponseWriter, kbps int) *throttledWriter {
	return &throttledWriter{
		ResponseWriter: w, body: w, ctx: ctx, bytesPerSec: float64(kbps) * 1000 / 8, start: time.Now(),
		sleep: func(ctx context.Context, d time.Duration) bool {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-t.C:
				return true
			}
		},
	}
}

func (t *throttledWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), throttleChunk)
		m, err := t.body.Write(p[:n])
		written += m
		t.sent += int64(m)
		if err != nil {
			return written, err
		}
		p = p[n:]
		due := time.Duration(float64(t.sent) / t.bytesPerSec * float64(time.Second))
		if wait := due - time.Since(t.start); wait > 0 {
			if !t.sleep(t.ctx, wait) {
				return written, t.ctx.Err()
			}
		}
	}
	return written, nil
}

// Unwrap, http.ResponseController'ın alttaki yazıcıya ulaşmasını sağlar.
func (t *throttledWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// noWriteDeadline, uzun sürebilecek indirme/yüklemelerde sunucunun genel zaman aşımını
// kaldırır; bağlantı kopması bağlam üzerinden yine algılanır.
func noWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

// fileDownloadHeaders, dosya indirme yanıtlarının içerik olarak yorumlanmasını engeller
// (ajan API'si tarayıcıya hizmet etmez; savunma derinliği için).
func fileDownloadHeaders(w http.ResponseWriter, contentType string) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", "attachment")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
}
