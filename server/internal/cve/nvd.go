package cve

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Record, kaynaktan bağımsız CVE kaydıdır.
type Record struct {
	ID          string
	Source      string // nvd, msrc
	Title       string
	Description string
	Published   *time.Time
	Modified    *time.Time
	CVSS        *float64
	CVSSVector  string
	CVSSVersion string
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW, NONE
	CWEs        []string
	Refs        []string
	Exploited   bool
	// Matches, NVD yapılandırmalarındaki savunmasız ürün aralıklarıdır.
	Matches []ProductMatch
	// Remediations, MSRC'deki Windows düzeltmeleridir.
	Remediations []Remediation
}

// ProductMatch, kayda ait CPE ürün aralığıdır.
type ProductMatch struct {
	Part    string
	Vendor  string
	Product string
	Range   VersionRange
}

// Key, ürün anahtarıdır.
func (p ProductMatch) Key() string { return ProductKey(p.Part, p.Vendor, p.Product) }

// NVDPage, NVD CVE API 2.0 yanıtıdır (veri akışı dosyaları da aynı biçimdedir).
type NVDPage struct {
	ResultsPerPage  int    `json:"resultsPerPage"`
	StartIndex      int    `json:"startIndex"`
	TotalResults    int    `json:"totalResults"`
	Timestamp       string `json:"timestamp"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			Negate   bool `json:"negate"`
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	CISAVulnerabilityName string `json:"cisaVulnerabilityName"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2'de cvssData dışında
}

// ParseNVD, NVD API yanıtını veya JSON 2.0 veri akışı dosyasını okur.
func ParseNVD(r io.Reader) (*NVDPage, []Record, error) {
	var page NVDPage
	if err := json.NewDecoder(r).Decode(&page); err != nil {
		return nil, nil, err
	}
	out := make([]Record, 0, len(page.Vulnerabilities))
	for _, v := range page.Vulnerabilities {
		if rec, ok := v.CVE.record(); ok {
			out = append(out, rec)
		}
	}
	return &page, out, nil
}

// nvdTime, NVD'nin saat dilimi içermeyen (UTC) zaman damgasını ayrıştırır.
func nvdTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return &t
		}
	}
	return nil
}

func (c nvdCVE) record() (Record, bool) {
	if !ValidCVEID(c.ID) || c.VulnStatus == "Rejected" {
		return Record{}, false
	}
	rec := Record{
		ID:        c.ID,
		Source:    "nvd",
		Title:     c.CISAVulnerabilityName,
		Published: nvdTime(c.Published),
		Modified:  nvdTime(c.LastModified),
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			rec.Description = d.Value
			break
		}
	}
	// CVSS: v3.1 > v3.0 > v4.0 > v2; birincil (NVD) ölçüm ikincilden önce gelir.
	for _, set := range [][]nvdMetric{c.Metrics.V31, c.Metrics.V30, c.Metrics.V40, c.Metrics.V2} {
		if m, ok := pickMetric(set); ok {
			score := m.CVSSData.BaseScore
			rec.CVSS = &score
			rec.CVSSVector = m.CVSSData.VectorString
			rec.CVSSVersion = m.CVSSData.Version
			rec.Severity = NormalizeSeverity(firstNonEmpty(m.CVSSData.BaseSeverity, m.BaseSeverity))
			if rec.Severity == "" {
				rec.Severity = SeverityFromCVSS(score)
			}
			break
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				addUnique(&rec.CWEs, d.Value)
			}
		}
	}
	for _, ref := range c.References {
		if len(rec.Refs) >= 10 {
			break
		}
		if strings.HasPrefix(ref.URL, "https://") || strings.HasPrefix(ref.URL, "http://") {
			rec.Refs = append(rec.Refs, ref.URL)
		}
	}
	seen := map[ProductMatch]bool{}
	for _, cfg := range c.Configurations {
		for _, n := range cfg.Nodes {
			if n.Negate {
				continue
			}
			for _, cm := range n.CPEMatch {
				if !cm.Vulnerable {
					continue
				}
				pm, ok := parseCPE(cm.Criteria)
				if !ok {
					continue
				}
				bounds := VersionRange{
					StartIncluding: cm.VersionStartIncluding, StartExcluding: cm.VersionStartExcluding,
					EndIncluding: cm.VersionEndIncluding, EndExcluding: cm.VersionEndExcluding,
				}
				// Sınır verilmişse CPE'deki sürüm "*" olur; tam sürüm yalnızca sınırsız eşleşmede anlamlıdır.
				if bounds != (VersionRange{}) {
					pm.Range = bounds
				}
				if !seen[pm] {
					seen[pm] = true
					rec.Matches = append(rec.Matches, pm)
				}
			}
		}
	}
	return rec, true
}

func pickMetric(set []nvdMetric) (nvdMetric, bool) {
	for _, m := range set {
		if m.Type == "Primary" {
			return m, true
		}
	}
	if len(set) > 0 {
		return set[0], true
	}
	return nvdMetric{}, false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// parseCPE, "cpe:2.3:a:google:chrome:120.0:*:*:*:*:*:*:*" ifadesini çözer. Güncelleme alanı
// belirli bir değer taşıyan tam sürümler (ör. macOS "security_update_2021-001") sürüm
// karşılaştırmasıyla değerlendirilemeyeceği için atlanır.
func parseCPE(s string) (ProductMatch, bool) {
	f := splitCPE(s)
	if len(f) < 7 || f[0] != "cpe" || f[1] != "2.3" {
		return ProductMatch{}, false
	}
	pm := ProductMatch{Part: f[2], Vendor: f[3], Product: f[4]}
	if pm.Part != "a" && pm.Part != "o" {
		return ProductMatch{}, false
	}
	switch v := f[5]; v {
	case "*", "-":
	default:
		if u := f[6]; u != "*" && u != "-" {
			return ProductMatch{}, false
		}
		pm.Range.Exact = strings.ReplaceAll(v, `\`, "")
	}
	return pm, true
}

// splitCPE, CPE 2.3 biçimli adı ters eğik çizgiyle kaçışlanmış iki noktaları koruyarak böler.
func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune('\\')
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

// nvdQueryTime, NVD API tarih parametresi biçimidir.
func nvdQueryTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func itoa(i int) string { return strconv.Itoa(i) }
