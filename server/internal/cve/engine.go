package cve

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Bulgu kaynakları.
const (
	SourceOSBuild      = "os_build"      // Windows yapı numarası MSRC'deki düzeltme yapısından eski
	SourceMissingPatch = "missing_patch" // eksik güncellemenin kapattığı CVE (WUA veya MSRC KB eşlemesi)
	SourceApp          = "app"           // üçüncü parti uygulama sürümü NVD aralığında
	SourceOS           = "os"            // macOS sürümü NVD aralığında
)

// BuildFix, bir Windows yapı ailesi için CVE'yi kapatan yapı ve KB'dir.
type BuildFix struct {
	CVE        string
	KB         string
	FixedBuild string
}

// CPEMatch, CVE'nin savunmasız bir ürün sürüm aralığıdır.
type CPEMatch struct {
	CVE   string
	Range VersionRange
}

// Lookup, korelasyonun ihtiyaç duyduğu CVE verisine erişimdir.
type Lookup interface {
	// BuildFixes, Windows yapı ailesi (ör. 10.0.22631) için MSRC düzeltmelerini döner.
	BuildFixes(ctx context.Context, family string) ([]BuildFix, error)
	// KBCVEs, KB numaralarının kapattığı CVE'leri döner (anahtar: KB5034441).
	KBCVEs(ctx context.Context, kbs []string) (map[string][]string, error)
	// ProductMatches, CPE ürün anahtarının ("a:google:chrome") savunmasız aralıklarını döner.
	ProductMatches(ctx context.Context, key string) ([]CPEMatch, error)
}

// MissingRef, makinedeki eksik güncellemedir.
type MissingRef struct {
	KB   string
	CVEs []string
}

// MachineInput, korelasyon girdisidir.
type MachineInput struct {
	Platform  string // windows, darwin
	OSVersion string
	OSBuild   string
	Missing   []MissingRef
	Apps      []AppRef
}

// Finding, makinedeki bir CVE bulgusudur.
type Finding struct {
	CVE     string
	Sources []string
	Refs    []string // KB5034441, "Google Chrome 120.0.6099.109", "10.0.22631.4460"
	FixedBy []string // KB5034441, 10.0.22631.4602, ">= 121.0"
}

var (
	cveIDRe  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	kbRe     = regexp.MustCompile(`^(?i:KB)?(\d{6,8})$`)
	winBuild = regexp.MustCompile(`^(\d+\.\d+\.\d+)\.(\d+)$`)
)

// ValidCVEID, CVE kimliğinin biçimini denetler.
func ValidCVEID(s string) bool { return cveIDRe.MatchString(s) }

// NormalizeKB, KB numarasını "KB1234567" biçimine getirir; geçersizse boş döner.
func NormalizeKB(s string) string {
	m := kbRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	return "KB" + m[1]
}

// BuildFamily, Windows yapı numarasının ailesini döner ("10.0.22631.4460" → "10.0.22631").
func BuildFamily(build string) string {
	m := winBuild.FindStringSubmatch(build)
	if m == nil {
		return ""
	}
	return m[1]
}

type collector map[string]*Finding

func (c collector) add(cveID, source, ref, fixedBy string) {
	if !ValidCVEID(cveID) {
		return
	}
	f := c[cveID]
	if f == nil {
		f = &Finding{CVE: cveID}
		c[cveID] = f
	}
	addUnique(&f.Sources, source)
	addUnique(&f.Refs, ref)
	addUnique(&f.FixedBy, fixedBy)
}

func addUnique(s *[]string, v string) {
	if v != "" && !slices.Contains(*s, v) && len(*s) < 20 {
		*s = append(*s, v)
	}
}

// actionable, sürüm bilgisi taşıyan eşleşmeleri seçer. NVD'de sürüm sınırı olmayan ("tüm
// sürümler") kayıtlar çoğunlukla protokol düzeyindeki eski açıklardır (ör. TLS BEAST); düzeltme
// sürümü olmadığından yama yönetiminde aksiyon alınamaz ve gürültü oluşturur.
func actionable(r VersionRange) bool { return r != (VersionRange{}) }

// Correlate, makinenin envanterini CVE verisiyle eşleştirir. Sonuç CVE kimliğine göre sıralıdır.
func Correlate(ctx context.Context, in MachineInput, m *Matcher, lk Lookup) ([]Finding, error) {
	c := collector{}

	// Windows: yapı numarası, MSRC'deki düzeltme yapısından küçükse işletim sistemi savunmasızdır.
	// Toplu güncellemeler kümülatif olduğundan bu karşılaştırma, eksik toplu güncellemenin
	// kapattığı ve WUA'nın CVE listesinde göstermediği açıkları da yakalar.
	if in.Platform == "windows" {
		if fam := BuildFamily(in.OSBuild); fam != "" {
			fixes, err := lk.BuildFixes(ctx, fam)
			if err != nil {
				return nil, err
			}
			for _, f := range fixes {
				if CompareVersions(in.OSBuild, f.FixedBuild) < 0 {
					c.add(f.CVE, SourceOSBuild, in.OSBuild, f.KB)
					c.add(f.CVE, SourceOSBuild, "", f.FixedBuild)
				}
			}
		}
	}

	// Eksik güncellemeler: WUA'nın bildirdiği CVE'ler ve MSRC'nin KB → CVE eşlemesi.
	var kbs []string
	for _, mp := range in.Missing {
		kb := NormalizeKB(mp.KB)
		for _, id := range mp.CVEs {
			c.add(strings.ToUpper(strings.TrimSpace(id)), SourceMissingPatch, kb, kb)
		}
		if kb != "" {
			kbs = append(kbs, kb)
		}
	}
	if len(kbs) > 0 {
		byKB, err := lk.KBCVEs(ctx, kbs)
		if err != nil {
			return nil, err
		}
		for kb, ids := range byKB {
			for _, id := range ids {
				c.add(id, SourceMissingPatch, kb, kb)
			}
		}
	}

	// macOS sürümü.
	if rule, ok := m.MatchOS(in.Platform); ok && in.OSVersion != "" {
		matches, err := lk.ProductMatches(ctx, rule.Key())
		if err != nil {
			return nil, err
		}
		v := NormalizeVersion(in.OSVersion)
		for _, cm := range matches {
			if actionable(cm.Range) && cm.Range.Contains(v) {
				c.add(cm.CVE, SourceOS, "macOS "+in.OSVersion, cm.Range.FixedIn())
			}
		}
	}

	// Üçüncü parti uygulamalar.
	for _, a := range in.Apps {
		// macOS paket makbuzları (pkgutil) kurulum anındaki sürümü tutar; kendini güncelleyen
		// uygulamalarda (Firefox, Chrome) eski kalır. Gerçek sürüm .app paketinden okunduğundan
		// makbuzlar CVE eşleştirmesine katılmaz.
		if a.Source == "pkg" {
			continue
		}
		v := NormalizeVersion(a.Version)
		if v == "" {
			continue
		}
		ref := strings.TrimSpace(a.Name + " " + a.Version)
		for _, rule := range m.MatchApp(a) {
			matches, err := lk.ProductMatches(ctx, rule.Key())
			if err != nil {
				return nil, err
			}
			for _, cm := range matches {
				if actionable(cm.Range) && cm.Range.Contains(v) {
					c.add(cm.CVE, SourceApp, ref, cm.Range.FixedIn())
				}
			}
		}
	}

	out := make([]Finding, 0, len(c))
	for _, f := range c {
		slices.Sort(f.Sources)
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b Finding) int { return strings.Compare(a.CVE, b.CVE) })
	return out, nil
}

// CachedLookup, toplu yeniden hesaplamada aynı yapı ailesi ve ürün için veritabanına tekrar
// gitmemek amacıyla sonuçları bellekte tutar. KB sorguları makineye özgü olduğundan önbelleğe
// alınmaz.
type CachedLookup struct {
	Lookup
	mu       sync.Mutex
	builds   map[string][]BuildFix
	products map[string][]CPEMatch
}

// NewCachedLookup, önbellekli erişim oluşturur.
func NewCachedLookup(lk Lookup) *CachedLookup {
	return &CachedLookup{Lookup: lk, builds: map[string][]BuildFix{}, products: map[string][]CPEMatch{}}
}

// BuildFixes, önbellekten veya alttaki erişimden döner.
func (c *CachedLookup) BuildFixes(ctx context.Context, family string) ([]BuildFix, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.builds[family]; ok {
		return v, nil
	}
	v, err := c.Lookup.BuildFixes(ctx, family)
	if err == nil {
		c.builds[family] = v
	}
	return v, err
}

// ProductMatches, önbellekten veya alttaki erişimden döner.
func (c *CachedLookup) ProductMatches(ctx context.Context, key string) ([]CPEMatch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.products[key]; ok {
		return v, nil
	}
	v, err := c.Lookup.ProductMatches(ctx, key)
	if err == nil {
		c.products[key] = v
	}
	return v, err
}
