package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/BerkayAtag/BerOps/server/internal/ad"
)

const (
	izmirOU  = "OU=İzmir,OU=Şubeler,DC=corp,DC=example"
	ankaraOU = "OU=Ankara,OU=Şubeler,DC=corp,DC=example"
	adminGrp = "CN=BerOps-Admins,OU=Gruplar,DC=corp,DC=example"
	techGrp  = "CN=BerOps-Izmir-Teknik,OU=Gruplar,DC=corp,DC=example"
)

// fakeDirectory, AD yerine kullanılan sahte dizindir.
func fakeDirectory(t *testing.T, up *bool) directory {
	users := map[string]*ad.User{
		"zeynep":  {DN: "CN=Zeynep,OU=Kullanicilar,DC=corp,DC=example", Username: "zeynep", DisplayName: "Zeynep Kaya", Groups: []string{techGrp}},
		"burak":   {DN: "CN=Burak,OU=Kullanicilar,DC=corp,DC=example", Username: "burak", Groups: []string{adminGrp}},
		"muhasip": {DN: "CN=Muhasip,OU=Kullanicilar,DC=corp,DC=example", Username: "muhasip", Groups: []string{"CN=Muhasebe,DC=corp,DC=example"}},
		"admin":   {DN: "CN=admin,DC=corp,DC=example", Username: "admin", Groups: []string{adminGrp}},
	}
	return directory{
		authenticate: func(_ context.Context, c ad.Config, username, password string) (*ad.User, error) {
			if c.BindPassword != "hizmet-parolasi" {
				t.Errorf("hizmet hesabı parolası çözülmeli, %q geldi", c.BindPassword)
			}
			if !*up {
				return nil, ad.ErrUnavailable
			}
			u, ok := users[ad.NormalizeUsername(username)]
			if !ok {
				return nil, ad.ErrUserNotFound
			}
			if password != "ad-parolasi" {
				return nil, ad.ErrInvalidCredentials
			}
			return u, nil
		},
		test: func(context.Context, ad.Config) error { return nil },
		computers: func(context.Context, ad.Config, int) ([]ad.Computer, error) {
			return []ad.Computer{
				{Name: "PC-IZMIR", DN: "CN=PC-IZMIR," + izmirOU, OU: izmirOU},
				{Name: "PC-YENI", DN: "CN=PC-YENI," + izmirOU, OU: izmirOU},
				{Name: "PC-ANKARA", DN: "CN=PC-ANKARA," + ankaraOU, OU: ankaraOU},
			}, nil
		},
	}
}

func (e *env) enrollWithOU(secret, hostname, ou string) *testAgent {
	e.t.Helper()
	_, ag := e.enroll(secret, hostname)
	c := e.agentClient(ag.tlsCert(e.t))
	rep := sampleReport(e.clock)
	rep.OS.ADDN = "CN=" + hostname + "," + ou
	expectStatus(e.t, e.postInventory(c, rep, false), 204, "envanter")
	return ag
}

func TestADLoginRolesAndScopes(t *testing.T) {
	e := newEnv(t)
	up := true
	e.srv.dir = fakeDirectory(t, &up)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "ad"})
	izmir := e.enrollWithOU(secret, "PC-IZMIR", izmirOU)
	ankara := e.enrollWithOU(secret, "PC-ANKARA", ankaraOU)

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")

	// AD kapalıyken yerel olmayan kullanıcı giremez.
	b := e.browser()
	expectStatus(t, b.login("zeynep", "ad-parolasi"), 401, "AD kapalı")

	settings := map[string]any{"enabled": true, "url": "ldap://dc01.corp.example", "base_dn": "DC=corp,DC=example",
		"bind_dn": "CN=svc-ber,OU=Hizmet,DC=corp,DC=example", "bind_password": "hizmet-parolasi"}
	resp, _ := admin.do("PUT", "/api/v1/settings/ad", settings, true)
	expectStatus(t, resp, 400, "şifresiz LDAP reddedilmeli")
	settings["url"] = "ldaps://dc01.corp.example"
	resp, out := admin.do("PUT", "/api/v1/settings/ad", settings, true)
	expectStatus(t, resp, 200, "AD ayarı")
	if out["has_password"] != true || out["bind_password"] != nil {
		t.Errorf("parola dönmemeli, varlığı belirtilmeli: %v", out)
	}
	delete(settings, "bind_password") // boş parola mevcut parolayı korur
	resp, _ = admin.do("PUT", "/api/v1/settings/ad", settings, true)
	expectStatus(t, resp, 200, "parolasız güncelleme")
	resp, _ = admin.do("POST", "/api/v1/settings/ad/mappings", map[string]any{"group_dn": adminGrp, "role": "admin"}, true)
	expectStatus(t, resp, 201, "admin eşlemesi")
	resp, _ = admin.do("POST", "/api/v1/settings/ad/mappings", map[string]any{"group_dn": techGrp, "role": "technician",
		"scope_ous": []string{izmirOU}}, true)
	expectStatus(t, resp, 201, "teknisyen eşlemesi")
	resp, _ = admin.do("POST", "/api/v1/settings/ad/mappings", map[string]any{"group_dn": "geçersiz", "role": "admin"}, true)
	expectStatus(t, resp, 400, "geçersiz DN")

	resp, out = admin.do("POST", "/api/v1/settings/ad/test", map[string]any{"username": `CORP\zeynep`, "password": "ad-parolasi"}, true)
	expectStatus(t, resp, 200, "AD testi")
	if out["ok"] != true || out["role"] != "technician" {
		t.Errorf("AD testi = %v", out)
	}

	// AD girişi: rol ve kapsam gruplardan.
	tech := e.browser()
	expectStatus(t, tech.login(`CORP\zeynep`, "ad-parolasi"), 200, "AD girişi")
	resp, out = tech.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 200, "me")
	if u := out["user"].(map[string]any); u["role"] != "technician" || u["source"] != "ad" || u["display_name"] != "Zeynep Kaya" {
		t.Errorf("AD kullanıcısı = %v", u)
	}
	expectStatus(t, e.browser().login("zeynep", "yanlis"), 401, "yanlış AD parolası")
	r, out := e.browser().do("POST", "/api/v1/auth/login", map[string]string{"username": "muhasip", "password": "ad-parolasi"}, false)
	if r.StatusCode != 403 || out["code"] != "auth.no_role_mapping" {
		t.Errorf("eşlemesiz grup: %d %v", r.StatusCode, out)
	}
	// Aynı adda yerel hesap varsa AD değil yerel parola geçerlidir.
	expectStatus(t, e.browser().login("admin", "ad-parolasi"), 401, "yerel hesap AD ile ele geçirilemez")

	// Kapsam: teknisyen yalnızca İzmir'i görür ve hedefler.
	resp, out = tech.do("GET", "/api/v1/machines", nil, false)
	expectStatus(t, resp, 200, "makineler")
	if out["total"].(float64) != 1 || out["items"].([]any)[0].(map[string]any)["hostname"] != "PC-IZMIR" {
		t.Errorf("kapsamlı liste = %v", out["items"])
	}
	resp, _ = tech.do("GET", "/api/v1/machines/"+ankara.id, nil, false)
	expectStatus(t, resp, 404, "kapsam dışı makine")
	resp, _ = tech.do("GET", "/api/v1/machines/"+izmir.id+"/apps", nil, false)
	expectStatus(t, resp, 200, "kapsam içi alt kaynak")
	resp, out = tech.do("GET", "/api/v1/machines/summary", nil, false)
	expectStatus(t, resp, 200, "özet")
	if out["total"].(float64) != 1 {
		t.Errorf("kapsamlı özet = %v", out)
	}
	resp, out = admin.do("GET", "/api/v1/machines/summary", nil, false)
	expectStatus(t, resp, 200, "özet")
	if out["total"].(float64) != 2 {
		t.Errorf("admin tüm filoyu görmeli: %v", out)
	}
	resp, _ = tech.do("POST", "/api/v1/machines/scan", map[string]any{"machine_ids": []string{ankara.id}}, true)
	expectStatus(t, resp, 403, "kapsam dışı tarama")

	resp, pkg := admin.upload(map[string]any{"name": "Araç", "version": "1.0", "platform": "windows", "installer": "msi"}, "arac.msi", []byte("msi"))
	expectStatus(t, resp, 201, "paket")
	resp, _ = tech.do("POST", "/api/v1/actions", map[string]any{"kind": "deploy_package", "package_id": pkg["id"],
		"machine_ids": []string{izmir.id, ankara.id}}, true)
	expectStatus(t, resp, 403, "kapsam dışı hedef")
	resp, act := tech.do("POST", "/api/v1/actions", map[string]any{"kind": "deploy_package", "package_id": pkg["id"],
		"machine_ids": []string{izmir.id}}, true)
	expectStatus(t, resp, 201, "kapsam içi dağıtım")
	resp, adminAct := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "deploy_package", "package_id": pkg["id"],
		"machine_ids": []string{ankara.id}}, true)
	expectStatus(t, resp, 201, "admin dağıtımı")
	resp, out = tech.do("GET", "/api/v1/actions", nil, false)
	expectStatus(t, resp, 200, "aksiyonlar")
	if out["total"].(float64) != 1 || out["items"].([]any)[0].(map[string]any)["id"] != act["id"] {
		t.Errorf("teknisyen yalnızca kapsamındaki aksiyonu görmeli: %v", out["items"])
	}
	resp, _ = tech.do("GET", "/api/v1/actions/"+adminAct["id"].(string), nil, false)
	expectStatus(t, resp, 404, "kapsam dışı aksiyon")

	resp, out = admin.do("GET", "/api/v1/ad/computers", nil, false)
	expectStatus(t, resp, 200, "AD bilgisayarları")
	agentless := 0
	for _, c := range out["items"].([]any) {
		if c.(map[string]any)["machine_id"] == nil {
			agentless++
		}
	}
	if len(out["items"].([]any)) != 3 || agentless != 1 {
		t.Errorf("ajansız bilgisayar 1 olmalı: %v", out["items"])
	}
	resp, out = tech.do("GET", "/api/v1/ad/computers", nil, false)
	expectStatus(t, resp, 200, "kapsamlı AD bilgisayarları")
	if len(out["items"].([]any)) != 2 {
		t.Errorf("teknisyen yalnızca İzmir bilgisayarlarını görmeli: %v", out["items"])
	}

	// AD erişilemezse 503 ve kurtarma önerisi; yerel hesap çalışmaya devam eder.
	up = false
	r, out = e.browser().do("POST", "/api/v1/auth/login", map[string]string{"username": "burak", "password": "ad-parolasi"}, false)
	if r.StatusCode != http.StatusServiceUnavailable || out["code"] != "auth.directory_unavailable" {
		t.Errorf("AD erişilemiyor: %d %v", r.StatusCode, out)
	}
	expectStatus(t, e.browser().login("admin", testPassword), 200, "yerel kurtarma girişi")
}

func TestUserManagementAndAudit(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")

	resp, _ := admin.do("POST", "/api/v1/users", map[string]any{"username": "kisa", "password": "kisa", "role": "readonly"}, true)
	expectStatus(t, resp, 400, "kısa parola")
	resp, u := admin.do("POST", "/api/v1/users", map[string]any{"username": "izleyici", "display_name": "İzleyici",
		"password": "uzun-bir-parola-123", "role": "readonly", "scope_ous": []string{izmirOU}}, true)
	expectStatus(t, resp, 201, "kullanıcı oluşturma")
	if u["scope_ous"].([]any)[0] != izmirOU {
		t.Errorf("kapsam = %v", u)
	}
	resp, _ = admin.do("POST", "/api/v1/users", map[string]any{"username": "IZLEYICI", "password": "uzun-bir-parola-123", "role": "readonly"}, true)
	expectStatus(t, resp, 409, "aynı ad")

	ro := e.browser()
	expectStatus(t, ro.login("izleyici", "uzun-bir-parola-123"), 200, "izleyici girişi")
	resp, _ = ro.do("GET", "/api/v1/users", nil, false)
	expectStatus(t, resp, 403, "salt okunur kullanıcıları göremez")

	me := admin.mustMe()
	resp, _ = admin.do("PATCH", "/api/v1/users/"+me, map[string]any{"role": "readonly"}, true)
	expectStatus(t, resp, 400, "kendi rolünü düşüremez")
	resp, _ = admin.do("PATCH", "/api/v1/users/"+u["id"].(string), map[string]any{"disabled": true}, true)
	expectStatus(t, resp, 200, "devre dışı")
	resp, _ = ro.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 401, "devre dışı kullanıcının oturumu kapanmalı")
	expectStatus(t, e.browser().login("izleyici", "uzun-bir-parola-123"), 401, "devre dışı giriş")

	// Kendi parolasını değiştirme: mevcut oturum açık kalır.
	resp, _ = admin.do("POST", "/api/v1/auth/password", map[string]any{"current_password": "yanlis", "new_password": "yeni-uzun-parola-456"}, true)
	expectStatus(t, resp, 400, "yanlış mevcut parola")
	resp, _ = admin.do("POST", "/api/v1/auth/password", map[string]any{"current_password": testPassword, "new_password": "yeni-uzun-parola-456"}, true)
	expectStatus(t, resp, 204, "parola değişimi")
	resp, _ = admin.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 200, "oturum açık kalmalı")
	expectStatus(t, e.browser().login("admin", "yeni-uzun-parola-456"), 200, "yeni parolayla giriş")

	// Denetim kaydı: filtre, sayfalama ve dışa aktarma.
	resp, out := admin.do("GET", "/api/v1/audit?action=user.&page_size=2", nil, false)
	expectStatus(t, resp, 200, "denetim")
	if out["total"].(float64) != 2 || len(out["items"].([]any)) != 2 {
		t.Errorf("user.* kayıtları = %v", out)
	}
	resp, out = admin.do("GET", "/api/v1/audit?result=failure&q=parola", nil, false)
	expectStatus(t, resp, 200, "denetim")
	if out["total"].(float64) != 1 {
		t.Errorf("başarısız parola değişimi kaydı = %v", out)
	}
	resp, _ = admin.do("GET", "/api/v1/audit?from=31-10-2026", nil, false)
	expectStatus(t, resp, 400, "geçersiz tarih")
	resp2, body := admin.raw("/api/v1/audit/export?format=csv&action=auth.")
	expectStatus(t, resp2, 200, "denetim dışa aktarma")
	if !strings.Contains(string(body), "auth.password_change") || !strings.HasPrefix(resp2.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("CSV = %s", body)
	}
}

func (b *browser) mustMe() string {
	b.e.t.Helper()
	resp, out := b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(b.e.t, resp, 200, "me")
	return out["user"].(map[string]any)["id"].(string)
}
