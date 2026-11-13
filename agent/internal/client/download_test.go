package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestWSUSResumeValidatesCatalog(t *testing.T) {
	for _, tc := range []struct {
		name, validator string
		status          int
		wantRange       bool
	}{
		{"legacy partial restarts", "", http.StatusOK, false},
		{"unchanged resumes", `"old"`, http.StatusPartialContent, true},
		{"changed replaces", `"old"`, http.StatusOK, true},
		{"invalid range recovers", `"old"`, http.StatusRequestedRangeNotSatisfiable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "catalog.cab")
			if err := os.WriteFile(dest+".part", []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.validator != "" {
				if err := os.WriteFile(dest+".part.validator", []byte(tc.validator), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				wantRange := tc.wantRange && calls == 1
				if (r.Header.Get("Range") == "bytes=3-") != wantRange {
					t.Error("yanlış Range başlığı")
				}
				if wantRange && r.Header.Get("If-Range") != tc.validator {
					t.Error("If-Range eksik")
				}
				status := tc.status
				if calls > 1 {
					status = http.StatusOK
				}
				w.Header().Set("ETag", `"new"`)
				if status == http.StatusPartialContent {
					w.Header().Set("Content-Range", "bytes 3-5/6")
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("new"))
			}))
			defer s.Close()
			u, _ := url.Parse(s.URL)
			c := &Client{base: u, http: s.Client()}
			err := c.DownloadWSUSCab(context.Background(), dest)
			if tc.status == http.StatusRequestedRangeNotSatisfiable {
				if err == nil {
					t.Fatal("416 hata olmalı")
				}
				err = c.DownloadWSUSCab(context.Background(), dest)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(dest)
			want := "new"
			if tc.status == http.StatusPartialContent {
				want = "oldnew"
			}
			if err != nil || string(got) != want {
				t.Fatalf("got %q, err %v; want %q", got, err, want)
			}
		})
	}
}
