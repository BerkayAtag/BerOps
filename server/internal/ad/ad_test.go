package ad

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestResolveRole(t *testing.T) {
	maps := []Mapping{
		{GroupDN: "CN=BerOps-Admins,OU=Gruplar,DC=corp,DC=example", Role: "admin"},
		{GroupDN: "CN=BerOps-Izmir-Teknik,OU=Gruplar,DC=corp,DC=example", Role: "technician", ScopeOUs: []string{"OU=İzmir,OU=Şubeler,DC=corp,DC=example"}},
		{GroupDN: "CN=BerOps-Ankara-Teknik,OU=Gruplar,DC=corp,DC=example", Role: "technician", ScopeOUs: []string{"OU=Ankara,OU=Şubeler,DC=corp,DC=example"}},
		{GroupDN: "CN=BerOps-Izleyici,OU=Gruplar,DC=corp,DC=example", Role: "readonly"},
	}
	cases := []struct {
		groups []string
		role   string
		scope  []string
		ok     bool
	}{
		{[]string{"cn=berops-admins,ou=gruplar,dc=corp,dc=example", "CN=BerOps-Izleyici,OU=Gruplar,DC=corp,DC=example"}, "admin", []string{}, true},
		{[]string{"CN=BerOps-Izmir-Teknik,OU=Gruplar,DC=corp,DC=example", "CN=BerOps-Ankara-Teknik,OU=Gruplar,DC=corp,DC=example"}, "technician",
			[]string{"OU=Ankara,OU=Şubeler,DC=corp,DC=example", "OU=İzmir,OU=Şubeler,DC=corp,DC=example"}, true},
		{[]string{"CN=BerOps-Izmir-Teknik,OU=Gruplar,DC=corp,DC=example", "CN=BerOps-Izleyici,OU=Gruplar,DC=corp,DC=example"}, "technician",
			[]string{"OU=İzmir,OU=Şubeler,DC=corp,DC=example"}, true},
		{[]string{"CN=Muhasebe,DC=corp,DC=example"}, "", nil, false},
	}
	for i, c := range cases {
		role, scope, ok := ResolveRole(c.groups, maps)
		if role != c.role || ok != c.ok || !slices.Equal(scope, c.scope) {
			t.Errorf("#%d: %s %v %v, beklenen %s %v %v", i, role, scope, ok, c.role, c.scope, c.ok)
		}
	}
}

func TestInScope(t *testing.T) {
	scope := []string{"OU=İzmir,OU=Şubeler,DC=corp,DC=example"}
	for ou, want := range map[string]bool{
		"OU=İzmir,OU=Şubeler,DC=corp,DC=example":              true,
		"OU=Karşıyaka,OU=İzmir,OU=Şubeler,DC=corp,DC=example": true,
		"ou=izmir,ou=şubeler,dc=corp,dc=example":              true, // AD gibi büyük/küçük harf duyarsız
		"OU=Yeniİzmir,OU=Şubeler,DC=corp,DC=example":          false,
		"": false,
	} {
		if got := InScope(ou, scope); got != want {
			t.Errorf("InScope(%q) = %v, beklenen %v", ou, got, want)
		}
	}
	if !InScope("", nil) {
		t.Error("boş kapsam her şeyi kapsamalı")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{URL: "ldaps://dc01.corp.example", BaseDN: "DC=corp,DC=example", BindDN: "CN=svc-ber,OU=Hizmet,DC=corp,DC=example", UserAttr: "sAMAccountName"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Config{
		{URL: "ldap://dc01", BaseDN: ok.BaseDN, BindDN: ok.BindDN, UserAttr: "sAMAccountName"},
		{URL: ok.URL, BaseDN: "geçersiz", BindDN: ok.BindDN, UserAttr: "sAMAccountName"},
		{URL: ok.URL, BaseDN: ok.BaseDN, BindDN: ok.BindDN, UserAttr: "mail"},
		{URL: ok.URL, BaseDN: ok.BaseDN, BindDN: ok.BindDN, UserAttr: "sAMAccountName", UserFilter: "(objectClass=user"},
		{URL: ok.URL, BaseDN: ok.BaseDN, BindDN: ok.BindDN, UserAttr: "sAMAccountName", CACertPEM: "sertifika değil"},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrConfig) {
			t.Errorf("geçersiz yapılandırma kabul edildi: %+v", bad)
		}
	}
}

func TestUserFilterEscapes(t *testing.T) {
	c := Config{UserAttr: "sAMAccountName"}
	if got := c.userFilter(`ali*)(cn=*`); got != `(&(&(objectCategory=person)(objectClass=user))(sAMAccountName=ali\2a\29\28cn=\2a))` {
		t.Errorf("filtre kaçışlanmalı: %s", got)
	}
	if got := c.userFilter("ayse@corp.example"); got != `(&(&(objectCategory=person)(objectClass=user))(userPrincipalName=ayse@corp.example))` {
		t.Errorf("UPN ile arama: %s", got)
	}
	if NormalizeUsername(`CORP\ayse`) != "ayse" || NormalizeUsername(" ayse ") != "ayse" {
		t.Error("alan öneki atılmalı")
	}
}

func TestParentDNAndFileTime(t *testing.T) {
	if got := ParentDN(`CN=PC\,01,OU=İzmir,OU=Şubeler,DC=corp,DC=example`); got != "OU=İzmir,OU=Şubeler,DC=corp,DC=example" {
		t.Errorf("ParentDN = %q", got)
	}
	if got := FileTime(133000000000000000); !got.Equal(time.Date(2022, 6, 18, 4, 26, 40, 0, time.UTC)) {
		t.Errorf("FileTime = %v", got)
	}
}

func TestAuthenticateRejectsEmptyPassword(t *testing.T) {
	// Boş parola ağ bağlantısı kurulmadan reddedilir (LDAP'ta anonim bind sayılır).
	_, err := Authenticate(t.Context(), Config{URL: "ldaps://127.0.0.1:1"}, "ayse", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("boş parola: %v", err)
	}
}
