package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type memStore struct {
	mu      sync.Mutex
	state   map[string][]byte
	errs    map[string]string
	records map[string]Record
	kev     []KEVEntry
	epss    int
}

func newMemStore() *memStore {
	return &memStore{state: map[string][]byte{}, errs: map[string]string{}, records: map[string]Record{}}
}

func (m *memStore) LoadFeedState(_ context.Context, feed string, v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.state[feed]; ok {
		return json.Unmarshal(b, v)
	}
	return nil
}
func (m *memStore) BeginFeed(context.Context, string, time.Time) error { return nil }
func (m *memStore) FinishFeed(_ context.Context, feed string, _ time.Time, _ int, _ time.Duration, st any, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st != nil {
		m.state[feed], _ = json.Marshal(st)
	}
	m.errs[feed] = ""
	if err != nil {
		m.errs[feed] = err.Error()
	}
	return nil
}
func (m *memStore) UpsertRecords(_ context.Context, recs []Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range recs {
		m.records[r.ID+"/"+r.Source] = r
	}
	return nil
}
func (m *memStore) ExistingCVEs(_ context.Context, ids []string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, id := range ids {
		if _, ok := m.records[id+"/nvd"]; ok {
			out[id] = true
		}
	}
	return out, nil
}
func (m *memStore) ReplaceKEV(_ context.Context, e []KEVEntry) error { m.kev = e; return nil }
func (m *memStore) ReplaceEPSS(_ context.Context, _ time.Time, load func(func(EPSSScore) error) error) (int, error) {
	n := 0
	err := load(func(EPSSScore) error { n++; return nil })
	m.epss = n
	return n, err
}

func nvdPage(start, total int, ids ...string) string {
	var vs []string
	for _, id := range ids {
		vs = append(vs, fmt.Sprintf(`{"cve":{"id":%q,"published":"2026-01-01T00:00:00.000","descriptions":[{"lang":"en","value":"x"}],
			"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*","versionEndExcluding":"26.01"}]}]}]}}`, id))
	}
	return fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`, len(ids), start, total, strings.Join(vs, ","))
}

func TestSyncerOnline(t *testing.T) {
	kev, _ := os.ReadFile("testdata/kev.json")
	epss, _ := os.ReadFile("testdata/epss.csv")
	msrc, _ := os.ReadFile("testdata/msrc.json")
	var mu sync.Mutex
	var nvdQueries []string
	limited := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			_, _ = w.Write(kev)
		case "/epss.csv":
			_, _ = w.Write(epss)
		case "/msrc/updates":
			if r.Header.Get("Accept") != "application/json" {
				http.Error(w, "accept", http.StatusNotAcceptable)
				return
			}
			fmt.Fprintf(w, `{"value":[
				{"ID":"2026-Oct","InitialReleaseDate":"2026-10-13T07:00:00Z","CurrentReleaseDate":"2026-10-20T00:00:00Z","CvrfUrl":"%s/msrc/doc"},
				{"ID":"2019-Jan","InitialReleaseDate":"2019-01-08T07:00:00Z","CurrentReleaseDate":"2019-01-08T07:00:00Z","CvrfUrl":"%s/msrc/eski"}]}`,
				srv.URL, srv.URL)
		case "/msrc/doc":
			_, _ = w.Write(msrc)
		case "/msrc/eski":
			t.Error("pencere dışındaki MSRC belgesi indirilmemeli")
		case "/nvd":
			mu.Lock()
			nvdQueries = append(nvdQueries, r.URL.RawQuery)
			first := limited == 0
			limited++
			mu.Unlock()
			if first {
				http.Error(w, "hız sınırı", http.StatusForbidden) // NVD hız sınırında 403 döner
				return
			}
			q := r.URL.Query()
			switch {
			case q.Get("virtualMatchString") != "" && q.Get("startIndex") == "0":
				fmt.Fprint(w, nvdPage(0, 3, "CVE-2026-0001", "CVE-2026-0002"))
			case q.Get("virtualMatchString") != "":
				fmt.Fprint(w, nvdPage(2, 3, "CVE-2026-0003"))
			case q.Get("lastModStartDate") != "":
				// Artımlı sorgu: takip edilmeyen ürünler atlanmalı, mevcut kayıt güncellenmeli.
				fmt.Fprint(w, `{"resultsPerPage":2,"startIndex":0,"totalResults":2,"vulnerabilities":[
					{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"güncel"}]}},
					{"cve":{"id":"CVE-2026-0099","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:baska:urun:*:*:*:*:*:*:*:*"}]}]}]}}]}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	st := newMemStore()
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	var slept []time.Duration
	s := &Syncer{
		Store: st, HTTP: srv.Client(),
		Products: func(context.Context) ([]ProductRule, error) {
			return []ProductRule{{Name: "^7-zip", Vendor: "7-zip", Product: "7-zip"}}, nil
		},
		NVDURL: srv.URL + "/nvd", MSRCUpdatesURL: srv.URL + "/msrc/updates", KEVURL: srv.URL + "/kev.json",
		EPSSURL: srv.URL + "/epss.csv", MSRCMonths: 12,
		Now:   func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil },
	}
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.kev) != 3 || st.epss != 5 {
		t.Errorf("KEV %d, EPSS %d", len(st.kev), st.epss)
	}
	if _, ok := st.records["CVE-2026-100200/msrc"]; !ok {
		t.Error("MSRC kaydı yazılmadı")
	}
	for _, id := range []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"} {
		if _, ok := st.records[id+"/nvd"]; !ok {
			t.Errorf("%s yazılmadı (sayfalama)", id)
		}
	}
	// 403 sonrası yeniden deneme beklemesi + sayfalar arası anahtarsız NVD beklemesi.
	if len(slept) != 2 || slept[0] != 15*time.Second || slept[1] != 6500*time.Millisecond {
		t.Errorf("beklemeler = %v", slept)
	}

	// İkinci eşitleme artımlıdır ve ilgisiz CVE'leri saklamaz; MSRC belgesi değişmediği için tekrar indirilmez.
	now = now.Add(24 * time.Hour)
	nvdQueries = nil
	if err := s.Sync(context.Background(), FeedNVD); err != nil {
		t.Fatal(err)
	}
	if len(nvdQueries) != 1 || !strings.Contains(nvdQueries[0], "lastModStartDate=2026-10-30T23%3A00%3A00.000Z") {
		t.Errorf("artımlı sorgu = %v", nvdQueries)
	}
	if st.records["CVE-2026-0001/nvd"].Description != "güncel" {
		t.Error("mevcut kayıt güncellenmeli")
	}
	if _, ok := st.records["CVE-2026-0099/nvd"]; ok {
		t.Error("takip edilmeyen ürünün CVE'si saklanmamalı")
	}
}

func TestSyncerOfflineMissingFiles(t *testing.T) {
	st := newMemStore()
	s := &Syncer{Store: st, OfflineDir: t.TempDir(), Products: func(context.Context) ([]ProductRule, error) { return nil, nil }}
	err := s.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "kev.json") || !strings.Contains(err.Error(), "nvd/*.json") {
		t.Errorf("eksik dosyalar raporlanmalı: %v", err)
	}
	if st.errs[FeedKEV] == "" {
		t.Error("hata kaynak durumuna yazılmalı")
	}
}
