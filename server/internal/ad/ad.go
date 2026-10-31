// Package ad, Active Directory ile LDAPS üzerinden kimlik doğrulama, grup üyeliği ve
// bilgisayar listesi işlemlerini yapar.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config, AD bağlantı ayarlarıdır.
type Config struct {
	URL             string // yalnızca ldaps:// kabul edilir
	BaseDN          string
	BindDN          string
	BindPassword    string
	UserAttr        string // sAMAccountName (varsayılan) veya userPrincipalName
	UserFilter      string
	CACertPEM       string // iç CA sertifikası (boşsa sistem güven deposu)
	Timeout         time.Duration
	ComputersBaseDN string
}

// User, doğrulanan AD kullanıcısıdır.
type User struct {
	DN          string   `json:"dn"`
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"` // iç içe üyelikler dahil grup DN'leri
	Disabled    bool     `json:"disabled"`
}

// Hatalar.
var (
	ErrInvalidCredentials = errors.New("AD kullanıcı adı veya parola hatalı")
	ErrUserNotFound       = errors.New("AD kullanıcısı bulunamadı")
	ErrUnavailable        = errors.New("AD sunucusuna ulaşılamıyor")
	ErrConfig             = errors.New("AD yapılandırması geçersiz")
)

// Validate, yapılandırmayı denetler.
func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" {
		return fmt.Errorf("%w: adres ldaps://sunucu[:636] biçiminde olmalı (şifresiz LDAP desteklenmez)", ErrConfig)
	}
	if _, err := ldap.ParseDN(c.BaseDN); err != nil || c.BaseDN == "" {
		return fmt.Errorf("%w: temel DN geçersiz", ErrConfig)
	}
	if _, err := ldap.ParseDN(c.BindDN); err != nil || c.BindDN == "" {
		return fmt.Errorf("%w: hizmet hesabı DN'i geçersiz", ErrConfig)
	}
	if c.ComputersBaseDN != "" {
		if _, err := ldap.ParseDN(c.ComputersBaseDN); err != nil {
			return fmt.Errorf("%w: bilgisayar arama DN'i geçersiz", ErrConfig)
		}
	}
	if c.UserAttr != "sAMAccountName" && c.UserAttr != "userPrincipalName" && c.UserAttr != "uid" {
		return fmt.Errorf("%w: kullanıcı özniteliği sAMAccountName, userPrincipalName veya uid olmalı", ErrConfig)
	}
	if c.UserFilter != "" {
		if _, err := ldap.CompileFilter(c.UserFilter); err != nil {
			return fmt.Errorf("%w: kullanıcı filtresi geçersiz: %v", ErrConfig, err)
		}
	}
	if c.CACertPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CACertPEM)) {
		return fmt.Errorf("%w: CA sertifikası PEM biçiminde değil", ErrConfig)
	}
	return nil
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 10 * time.Second
	}
	return c.Timeout
}

func (c Config) dial(ctx context.Context) (*ldap.Conn, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.URL)
	host := u.Hostname()
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(host, "636")
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if c.CACertPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM([]byte(c.CACertPEM))
		tc.RootCAs = pool
	}
	d := &net.Dialer{Timeout: c.timeout()}
	conn, err := tls.DialWithDialer(d, "tcp", addr, tc)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			return nil, fmt.Errorf("%w: sunucu sertifikası doğrulanamadı (iç CA sertifikasını ayarlara ekleyin): %v", ErrUnavailable, certErr.Err)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	l := ldap.NewConn(conn, true)
	l.Start()
	l.SetTimeout(c.timeout())
	return l, nil
}

func (c Config) bindService(l *ldap.Conn) error {
	if c.BindPassword == "" {
		return fmt.Errorf("%w: hizmet hesabı parolası tanımlı değil", ErrConfig)
	}
	if err := l.Bind(c.BindDN, c.BindPassword); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return fmt.Errorf("%w: hizmet hesabı kimlik bilgileri hatalı", ErrConfig)
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Test, bağlantıyı ve hizmet hesabıyla bağlanmayı (bind) dener.
func Test(ctx context.Context, c Config) error {
	l, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer l.Close()
	return c.bindService(l)
}

// NormalizeUsername, "ALAN\kullanici" biçimini "kullanici" yapar; "kullanici@alan" olduğu gibi kalır.
func NormalizeUsername(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// userFilter, kullanıcı arama filtresini kaçışlanmış kullanıcı adıyla kurar.
func (c Config) userFilter(username string) string {
	attr := c.UserAttr
	if attr == "" {
		attr = "sAMAccountName"
	}
	if strings.Contains(username, "@") && attr == "sAMAccountName" {
		attr = "userPrincipalName"
	}
	base := c.UserFilter
	if base == "" {
		base = "(&(objectCategory=person)(objectClass=user))"
	}
	return fmt.Sprintf("(&%s(%s=%s))", base, attr, ldap.EscapeFilter(username))
}

// Authenticate, kullanıcıyı hizmet hesabıyla arar, kendi parolasıyla doğrular ve iç içe
// grup üyeliklerini döner. Boş parola reddedilir (LDAP'ta boş parolalı bind "anonim" sayılır).
func Authenticate(ctx context.Context, c Config, username, password string) (*User, error) {
	username = NormalizeUsername(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	l, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if err := c.bindService(l); err != nil {
		return nil, err
	}
	res, err := l.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
		int(c.timeout().Seconds()), false, c.userFilter(username),
		[]string{"sAMAccountName", "userPrincipalName", "uid", "displayName", "cn", "mail", "userAccountControl", "memberOf"}, nil))
	if err != nil {
		return nil, fmt.Errorf("%w: kullanıcı araması başarısız: %v", ErrUnavailable, err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrUserNotFound
	}
	e := res.Entries[0]
	u := &User{
		DN:          e.DN,
		Username:    firstNonEmpty(e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("uid"), username),
		DisplayName: firstNonEmpty(e.GetAttributeValue("displayName"), e.GetAttributeValue("cn")),
		Email:       e.GetAttributeValue("mail"),
	}
	if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil && uac&2 != 0 {
		u.Disabled = true
	}
	// Kullanıcının kendi parolasıyla bağlanılır; başarısızsa kimlik bilgisi hatalıdır.
	if err := l.Bind(u.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Grup araması için hizmet hesabına geri dönülür (kullanıcının okuma yetkisi kısıtlı olabilir).
	if err := c.bindService(l); err != nil {
		return nil, err
	}
	u.Groups = nestedGroups(l, c, u.DN, e.GetAttributeValues("memberOf"))
	return u, nil
}

// nestedGroups, AD'nin LDAP_MATCHING_RULE_IN_CHAIN kuralıyla iç içe grup üyeliklerini bulur.
// Kural desteklenmiyorsa (AD dışı dizinler) doğrudan memberOf değerleri kullanılır.
func nestedGroups(l *ldap.Conn, c Config, userDN string, direct []string) []string {
	res, err := l.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000,
		int(c.timeout().Seconds()), false,
		fmt.Sprintf("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(userDN)),
		[]string{"dn"}, nil))
	groups := append([]string{}, direct...)
	if err == nil {
		for _, e := range res.Entries {
			groups = append(groups, e.DN)
		}
	}
	return dedupeFold(groups)
}

func dedupeFold(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range in {
		k := strings.ToLower(g)
		if g != "" && !seen[k] {
			seen[k] = true
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Computer, AD'deki bilgisayar nesnesidir.
type Computer struct {
	Name            string     `json:"name"`
	DNSHostName     string     `json:"dns_host_name"`
	DN              string     `json:"dn"`
	OU              string     `json:"ou"`
	OperatingSystem string     `json:"operating_system"`
	LastLogon       *time.Time `json:"last_logon"`
	Disabled        bool       `json:"disabled"`
}

// Computers, bilgisayar nesnelerini sayfalı arama ile listeler (en fazla limit kadar).
func Computers(ctx context.Context, c Config, limit int) ([]Computer, error) {
	l, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if err := c.bindService(l); err != nil {
		return nil, err
	}
	base := c.ComputersBaseDN
	if base == "" {
		base = c.BaseDN
	}
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(c.timeout().Seconds()*3), false,
		"(objectCategory=computer)", []string{"cn", "dNSHostName", "operatingSystem", "lastLogonTimestamp", "userAccountControl"}, nil)
	res, err := l.SearchWithPaging(req, 500)
	if err != nil && (res == nil || len(res.Entries) == 0) {
		return nil, fmt.Errorf("%w: bilgisayar araması başarısız: %v", ErrUnavailable, err)
	}
	out := make([]Computer, 0, len(res.Entries))
	for _, e := range res.Entries {
		if limit > 0 && len(out) >= limit {
			break
		}
		cmp := Computer{
			Name: e.GetAttributeValue("cn"), DNSHostName: e.GetAttributeValue("dNSHostName"), DN: e.DN,
			OU: ParentDN(e.DN), OperatingSystem: e.GetAttributeValue("operatingSystem"),
		}
		if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil && uac&2 != 0 {
			cmp.Disabled = true
		}
		if ts, err := strconv.ParseInt(e.GetAttributeValue("lastLogonTimestamp"), 10, 64); err == nil && ts > 0 {
			t := FileTime(ts)
			cmp.LastLogon = &t
		}
		out = append(out, cmp)
	}
	return out, nil
}

// FileTime, Windows FILETIME değerini (1601'den beri 100 ns) zamana çevirir.
func FileTime(v int64) time.Time {
	const epochDiff = 116444736000000000
	return time.Unix(0, (v-epochDiff)*100).UTC()
}

// ParentDN, nesnenin bulunduğu kapsayıcının DN'ini döner ("CN=PC01,OU=İzmir,DC=x" → "OU=İzmir,DC=x").
func ParentDN(dn string) string {
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) < 2 {
		return ""
	}
	parts := make([]string, 0, len(p.RDNs)-1)
	for _, r := range p.RDNs[1:] {
		attrs := make([]string, len(r.Attributes))
		for i, a := range r.Attributes {
			attrs[i] = a.Type + "=" + escapeDNValue(a.Value)
		}
		parts = append(parts, strings.Join(attrs, "+"))
	}
	return strings.Join(parts, ",")
}

func escapeDNValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, ",", `\,`, "+", `\+`, `"`, `\"`, "<", `\<`, ">", `\>`, ";", `\;`, "=", `\=`).Replace(v)
}
