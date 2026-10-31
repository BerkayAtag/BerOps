package cve

import (
	"regexp"
	"strconv"
	"strings"
)

// versionPrefix, sürüm metninin karşılaştırılabilir baş kısmıdır ("v1.2.3-beta" → "1.2.3-beta").
var versionPrefix = regexp.MustCompile(`[0-9][0-9A-Za-z.\-_+]*`)

// NormalizeVersion, uygulama sürümünü karşılaştırmaya hazırlar: baştaki "v" ve sürüm dışı
// metinler atılır, Homebrew revizyonu ("3.4.0_1") kaldırılır.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	m := versionPrefix.FindString(v)
	if m == "" {
		return ""
	}
	if i := strings.IndexByte(m, '_'); i > 0 {
		m = m[:i]
	}
	return strings.TrimRight(m, ".-+")
}

// splitVersion, sürümü nokta, tire ve artı işaretlerinden, ayrıca rakam/harf geçişlerinden böler
// ("1.2rc3" → 1, 2, rc, 3).
func splitVersion(v string) []string {
	var parts []string
	cur := strings.Builder{}
	kind := 0 // 1 rakam, 2 harf
	flush := func() {
		if cur.Len() > 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			if kind == 2 {
				flush()
			}
			kind = 1
			cur.WriteRune(r)
		case r == '.' || r == '-' || r == '+' || r == '_':
			flush()
			kind = 0
		default:
			if kind == 1 {
				flush()
			}
			kind = 2
			cur.WriteRune(r)
		}
	}
	flush()
	return parts
}

// CompareVersions, iki sürümü karşılaştırır (a<b: -1, a==b: 0, a>b: 1). Sayısal parçalar sayı
// olarak, diğerleri harf sırasıyla karşılaştırılır. Eksik parçalar sıfır sayılır ("1.2" == "1.2.0");
// sayısal parça harf parçasından büyüktür ("1.0.1" > "1.0rc1").
func CompareVersions(a, b string) int {
	pa, pb := splitVersion(strings.ToLower(a)), splitVersion(strings.ToLower(b))
	n := max(len(pa), len(pb))
	for i := range n {
		x, y := "0", "0"
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		xi, xerr := strconv.ParseUint(x, 10, 64)
		yi, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xi != yi {
				if xi < yi {
					return -1
				}
				return 1
			}
		case xerr == nil:
			// Ön sürüm etiketi (rc, beta) sayısal parçadan küçüktür; eksik parça "0" sayıldığından
			// "1.0" ile "1.0rc1" karşılaştırmasında harf tarafı küçük kalır.
			return 1
		case yerr == nil:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

// VersionRange, NVD CPE eşleşmesinin sürüm koşuludur. Exact doluysa yalnızca o sürüm,
// değilse sınırlar uygulanır; hiçbir sınır yoksa tüm sürümler eşleşir.
type VersionRange struct {
	Exact          string `json:"version,omitempty"`
	StartIncluding string `json:"start_including,omitempty"`
	StartExcluding string `json:"start_excluding,omitempty"`
	EndIncluding   string `json:"end_including,omitempty"`
	EndExcluding   string `json:"end_excluding,omitempty"`
}

// Contains, sürümün aralıkta olup olmadığını döner. Boş sürüm hiçbir aralıkta değildir.
func (r VersionRange) Contains(v string) bool {
	if v == "" {
		return false
	}
	if r.Exact != "" {
		return CompareVersions(v, r.Exact) == 0
	}
	if r.StartIncluding != "" && CompareVersions(v, r.StartIncluding) < 0 {
		return false
	}
	if r.StartExcluding != "" && CompareVersions(v, r.StartExcluding) <= 0 {
		return false
	}
	if r.EndIncluding != "" && CompareVersions(v, r.EndIncluding) > 0 {
		return false
	}
	if r.EndExcluding != "" && CompareVersions(v, r.EndExcluding) >= 0 {
		return false
	}
	return true
}

// FixedIn, aralığın üst sınırından türetilen düzeltme sürümüdür (konsolda "≥ 121.0" olarak gösterilir).
func (r VersionRange) FixedIn() string {
	switch {
	case r.EndExcluding != "":
		return ">= " + r.EndExcluding
	case r.EndIncluding != "":
		return "> " + r.EndIncluding
	}
	return ""
}
