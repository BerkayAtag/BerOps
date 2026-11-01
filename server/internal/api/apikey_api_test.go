package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// bearer, API anahtarıyla (çerez ve CSRF olmadan) istek yapar.
func (e *env) bearer(key, method, path string, body any) (*http.Response, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.console.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.console.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestAPIKeys(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")
	secret := e.adminCreateKey(map[string]any{"name": "api"})
	_, ag := e.enroll(secret, "PC-001")

	resp, _ := ro.do("POST", "/api/v1/api-keys", map[string]any{"name": "x", "role": "readonly"}, true)
	expectStatus(t, resp, 403, "salt okunur anahtar üretemez")
	resp, _ = admin.do("POST", "/api/v1/api-keys", map[string]any{"name": "x", "role": "root"}, true)
	expectStatus(t, resp, 400, "geçersiz rol")

	resp, out := admin.do("POST", "/api/v1/api-keys", map[string]any{"name": "CMDB eşitleme", "role": "technician",
		"expires_in_days": 30}, true)
	expectStatus(t, resp, 201, "teknisyen anahtarı")
	techKey := out["secret"].(string)
	keyID := out["key"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(techKey, "berops_") || out["key"].(map[string]any)["expires_at"] == nil {
		t.Fatalf("anahtar = %v", out)
	}
	resp, out = admin.do("GET", "/api/v1/api-keys", nil, false)
	expectStatus(t, resp, 200, "liste")
	if strings.Contains(mustJSON(out), techKey) {
		t.Fatal("liste anahtarın kendisini içermemeli")
	}

	resp, out = e.bearer(techKey, "GET", "/api/v1/machines", nil)
	expectStatus(t, resp, 200, "anahtarla makine listesi")
	if out["total"].(float64) != 1 {
		t.Errorf("makineler = %v", out)
	}
	resp, _ = e.bearer(techKey, "POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd",
		"command": "ver", "machine_ids": []string{ag.id}})
	expectStatus(t, resp, 403, "teknisyen anahtarı komut çalıştıramaz")
	resp, _ = e.bearer(techKey, "GET", "/api/v1/api-keys", nil)
	expectStatus(t, resp, 403, "anahtar anahtarları yönetemez")

	resp, out = admin.do("POST", "/api/v1/api-keys", map[string]any{"name": "Otomasyon", "role": "admin"}, true)
	expectStatus(t, resp, 201, "admin anahtarı")
	adminKey := out["secret"].(string)
	resp, _ = admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 10000, "max_upload_mb": 100,
		"command_approval": false, "default_expiry_hours": 24}, true)
	expectStatus(t, resp, 200, "aktarım")
	resp, out = e.bearer(adminKey, "POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd",
		"command": "ver", "machine_ids": []string{ag.id}})
	expectStatus(t, resp, 201, "admin anahtarı CSRF olmadan aksiyon oluşturur")
	if out["created_by_name"] != "api:Otomasyon" {
		t.Errorf("oluşturan = %v", out["created_by_name"])
	}
	resp, _ = e.bearer(adminKey, "POST", "/api/v1/users", map[string]any{"username": "kotu", "password": "uzun-bir-parola-123",
		"role": "admin"})
	expectStatus(t, resp, 403, "anahtarla kullanıcı oluşturulamaz")

	resp, _ = admin.do("DELETE", "/api/v1/api-keys/"+keyID, nil, true)
	expectStatus(t, resp, 204, "iptal")
	resp, _ = e.bearer(techKey, "GET", "/api/v1/machines", nil)
	expectStatus(t, resp, 401, "iptal edilen anahtar")
	resp, _ = e.bearer("berops_yanlis", "GET", "/api/v1/machines", nil)
	expectStatus(t, resp, 401, "yanlış anahtar")
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
