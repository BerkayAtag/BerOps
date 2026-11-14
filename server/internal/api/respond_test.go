package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsTrailingBody(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
	}{
		{"valid", "{} \n\t", http.StatusOK},
		{"second object", "{} {}", http.StatusBadRequest},
		{"trailing null", "{} null", http.StatusBadRequest},
		{"garbage", "{} invalid", http.StatusBadRequest},
		{"oversized whitespace", "{}" + strings.Repeat(" ", 1024), http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			var body struct{}
			ok := decodeJSON(w, r, &body, 128)
			if ok != (tc.status == http.StatusOK) || w.Code != tc.status {
				t.Fatalf("ok=%v status=%d, want %d", ok, w.Code, tc.status)
			}
		})
	}
}
