package ad

import (
	"slices"
	"strings"
)

// Mapping, AD grubu → rol ve OU kapsamı eşlemesidir.
type Mapping struct {
	ID       string   `json:"id"`
	GroupDN  string   `json:"group_dn"`
	Role     string   `json:"role"`
	ScopeOUs []string `json:"scope_ous"`
}

var rolePriority = map[string]int{"admin": 3, "technician": 2, "readonly": 1}

// ResolveRole, kullanıcının gruplarına uyan eşlemelerden en yetkili rolü seçer. Aynı role
// birden fazla eşleme uyuyorsa kapsamlar birleştirilir; bunlardan biri kapsamsızsa kullanıcı
// kapsamsızdır. Hiçbir eşleme uymazsa ok false döner (giriş reddedilir).
func ResolveRole(groups []string, mappings []Mapping) (role string, scope []string, ok bool) {
	in := map[string]bool{}
	for _, g := range groups {
		in[strings.ToLower(g)] = true
	}
	best := 0
	unrestricted := false
	for _, m := range mappings {
		p := rolePriority[m.Role]
		if p == 0 || !in[strings.ToLower(m.GroupDN)] || p < best {
			continue
		}
		if p > best {
			best, role, scope, unrestricted = p, m.Role, nil, false
		}
		if len(m.ScopeOUs) == 0 {
			unrestricted = true
		}
		scope = append(scope, m.ScopeOUs...)
	}
	if best == 0 {
		return "", nil, false
	}
	if unrestricted || role == "admin" {
		return role, []string{}, true
	}
	slices.Sort(scope)
	return role, slices.Compact(scope), true
}

// InScope, makinenin OU'sunun kapsamdaki bir OU'ya eşit veya altında olup olmadığını döner.
// Boş kapsam tüm makineleri kapsar. Karşılaştırma büyük/küçük harf duyarsızdır.
func InScope(machineOU string, scope []string) bool {
	if len(scope) == 0 {
		return true
	}
	ou := strings.ToLower(strings.TrimSpace(machineOU))
	for _, s := range scope {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && (ou == s || strings.HasSuffix(ou, ","+s)) {
			return true
		}
	}
	return false
}
