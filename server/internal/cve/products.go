package cve

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed products.json
var builtinProductsJSON []byte

// ProductRule, kurulu uygulamayı NVD CPE ürününe eşleyen kuraldır. Name, Publisher ve
// Identifier büyük/küçük harf duyarsız düzenli ifadelerdir; verilenlerin tümü eşleşmelidir
// (Name ile Identifier verilmişse ikisinden biri yeterlidir). OS doluysa kural yalnızca o
// platformun işletim sistemine uygulanır.
type ProductRule struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Publisher  string `json:"publisher,omitempty"`
	Identifier string `json:"identifier,omitempty"`
	OS         string `json:"os,omitempty"`
	Part       string `json:"part,omitempty"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	// Continue, eşleşmeden sonra sonraki kuralların da denenmesini sağlar (ürünü NVD'de birden
	// fazla adla geçen uygulamalar için).
	Continue bool `json:"continue,omitempty"`
	Builtin  bool `json:"builtin"`
}

// Key, CPE ürününün "a:vendor:product" biçimindeki anahtarıdır.
func (r ProductRule) Key() string { return ProductKey(r.part(), r.Vendor, r.Product) }

func (r ProductRule) part() string {
	if r.Part == "" {
		return "a"
	}
	return r.Part
}

// ProductKey, CPE ürün anahtarıdır.
func ProductKey(part, vendor, product string) string { return part + ":" + vendor + ":" + product }

// VirtualMatchString, NVD API'sinin virtualMatchString parametresidir.
func (r ProductRule) VirtualMatchString() string {
	return "cpe:2.3:" + r.part() + ":" + r.Vendor + ":" + r.Product
}

type compiledRule struct {
	ProductRule
	name, publisher, identifier *regexp.Regexp
}

// Matcher, uygulamaları CPE ürünlerine eşler. Kurallar sırayla denenir, ilk eşleşen kazanır;
// özel kurallar yerleşik sözlükten önce gelir.
type Matcher struct {
	rules []compiledRule
}

// BuiltinRules, ürünle gelen sözlüktür.
func BuiltinRules() []ProductRule {
	var rules []ProductRule
	if err := json.Unmarshal(builtinProductsJSON, &rules); err != nil {
		panic("products.json okunamadı: " + err.Error())
	}
	for i := range rules {
		rules[i].Builtin = true
		rules[i].ID = "builtin:" + rules[i].Key()
	}
	return rules
}

// ValidateRule, kuralın derlenebilir olduğunu ve CPE alanlarının geçerli olduğunu denetler.
func ValidateRule(r ProductRule) error {
	_, err := compile(r)
	return err
}

var cpeField = regexp.MustCompile(`^[a-z0-9][a-z0-9._\-\\+]*$`)

func compile(r ProductRule) (compiledRule, error) {
	c := compiledRule{ProductRule: r}
	if r.Name == "" && r.Identifier == "" && r.OS == "" {
		return c, fmt.Errorf("kural ad veya tanımlayıcı kalıbı içermeli")
	}
	if !cpeField.MatchString(r.Vendor) || !cpeField.MatchString(r.Product) {
		return c, fmt.Errorf("geçersiz CPE üretici/ürün adı: %s:%s", r.Vendor, r.Product)
	}
	if p := r.part(); p != "a" && p != "o" {
		return c, fmt.Errorf("geçersiz CPE türü: %s", p)
	}
	var err error
	re := func(s string) *regexp.Regexp {
		if s == "" || err != nil {
			return nil
		}
		var x *regexp.Regexp
		x, err = regexp.Compile("(?i)" + s)
		return x
	}
	c.name, c.publisher, c.identifier = re(r.Name), re(r.Publisher), re(r.Identifier)
	if err != nil {
		return c, fmt.Errorf("geçersiz düzenli ifade: %w", err)
	}
	return c, nil
}

// NewMatcher, özel kuralları yerleşik sözlüğün önüne ekleyerek eşleyici oluşturur.
func NewMatcher(custom []ProductRule) (*Matcher, error) {
	m := &Matcher{}
	for _, r := range append(append([]ProductRule{}, custom...), BuiltinRules()...) {
		c, err := compile(r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Key(), err)
		}
		m.rules = append(m.rules, c)
	}
	return m, nil
}

// Rules, eşleyicideki kuralları döner.
func (m *Matcher) Rules() []ProductRule {
	out := make([]ProductRule, len(m.rules))
	for i, r := range m.rules {
		out[i] = r.ProductRule
	}
	return out
}

// AppRef, eşlenecek kurulu uygulamadır.
type AppRef struct {
	Name       string
	Version    string
	Publisher  string
	Identifier string
	Source     string // protocol.AppSource* değerleri
}

// MatchApp, uygulamaya karşılık gelen CPE ürünlerini döner. İlk eşleşen kural kazanır;
// kuralda Continue işaretliyse sonraki kurallar da denenir.
func (m *Matcher) MatchApp(a AppRef) []ProductRule {
	name := strings.TrimSpace(a.Name)
	var out []ProductRule
	for _, r := range m.rules {
		if r.OS != "" {
			continue
		}
		hit := r.name != nil && r.name.MatchString(name)
		if !hit && r.identifier != nil && a.Identifier != "" {
			hit = r.identifier.MatchString(a.Identifier)
		}
		if !hit || (r.publisher != nil && !r.publisher.MatchString(a.Publisher)) {
			continue
		}
		out = append(out, r.ProductRule)
		if !r.Continue {
			break
		}
	}
	return out
}

// MatchOS, platformun işletim sistemi ürününü döner (macOS → apple:macos). Windows işletim
// sistemi açıkları NVD yerine MSRC yapı numaralarıyla değerlendirilir.
func (m *Matcher) MatchOS(platform string) (ProductRule, bool) {
	for _, r := range m.rules {
		if r.OS == platform {
			return r.ProductRule, true
		}
	}
	return ProductRule{}, false
}
