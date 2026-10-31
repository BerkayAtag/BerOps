package cve

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KEVEntry, CISA KEV kataloğundaki bir kayıttır.
type KEVEntry struct {
	CVE            string
	Vendor         string
	Product        string
	Name           string
	DateAdded      time.Time
	DueDate        *time.Time
	Ransomware     bool
	RequiredAction string
}

// ParseKEV, CISA known_exploited_vulnerabilities.json dosyasını okur.
func ParseKEV(r io.Reader) ([]KEVEntry, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			RequiredAction             string `json:"requiredAction"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("KEV kataloğu boş")
	}
	out := make([]KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		added, err := time.Parse(time.DateOnly, v.DateAdded)
		if err != nil || !ValidCVEID(v.CVEID) {
			continue
		}
		e := KEVEntry{
			CVE: v.CVEID, Vendor: v.VendorProject, Product: v.Product, Name: v.VulnerabilityName,
			DateAdded: added, Ransomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "Known"),
			RequiredAction: v.RequiredAction,
		}
		if due, err := time.Parse(time.DateOnly, v.DueDate); err == nil {
			e.DueDate = &due
		}
		out = append(out, e)
	}
	return out, nil
}

// EPSSScore, bir CVE'nin EPSS skorudur.
type EPSSScore struct {
	CVE        string
	Score      float64
	Percentile float64
}

var epssDate = regexp.MustCompile(`score_date:(\d{4}-\d{2}-\d{2})`)

// ParseEPSS, FIRST EPSS CSV dosyasını (açılmış) okur ve her kaydı fn'e verir. İlk satırdaki
// "#model_version:...,score_date:..." yorumundan skor tarihi okunur.
func ParseEPSS(r io.Reader, fn func(EPSSScore) error) (time.Time, int, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	scored := time.Time{}
	if peek, err := br.Peek(1); err == nil && peek[0] == '#' {
		line, err := br.ReadString('\n')
		if err != nil {
			return scored, 0, err
		}
		if m := epssDate.FindStringSubmatch(line); m != nil {
			scored, _ = time.Parse(time.DateOnly, m[1])
		}
	}
	cr := csv.NewReader(br)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return scored, 0, err
	}
	if len(header) < 3 || header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return scored, 0, fmt.Errorf("EPSS başlığı beklenmiyor: %v", header)
	}
	n := 0
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return scored, n, err
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil || !ValidCVEID(rec[0]) {
			continue
		}
		if err := fn(EPSSScore{CVE: rec[0], Score: score, Percentile: pct}); err != nil {
			return scored, n, err
		}
		n++
	}
	if n == 0 {
		return scored, 0, errors.New("EPSS dosyası boş")
	}
	return scored, n, nil
}

// Remediation, MSRC'deki bir Windows düzeltmesidir.
type Remediation struct {
	KB          string
	BuildFamily string
	FixedBuild  string
	Severity    string // Critical, Important, Moderate, Low
}

// MSRCUpdate, MSRC güncelleme listesindeki bir aylık belgedir.
type MSRCUpdate struct {
	ID                 string    `json:"ID"`
	InitialReleaseDate time.Time `json:"InitialReleaseDate"`
	CurrentReleaseDate time.Time `json:"CurrentReleaseDate"`
	CvrfURL            string    `json:"CvrfUrl"`
}

// ParseMSRCUpdates, https://api.msrc.microsoft.com/cvrf/v3.0/updates yanıtını okur.
func ParseMSRCUpdates(r io.Reader) ([]MSRCUpdate, error) {
	var doc struct {
		Value []MSRCUpdate `json:"value"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	return doc.Value, nil
}

type msrcValue struct {
	Value string `json:"Value"`
}

// ParseMSRC, aylık CVRF belgesini (JSON) okur. Yalnızca Windows ürünlerine ait, yapı numarası
// veya KB içeren düzeltmeler alınır; Azure Linux gibi ürünler atlanır.
func ParseMSRC(r io.Reader) ([]Record, error) {
	var doc struct {
		DocumentTracking struct {
			InitialReleaseDate string `json:"InitialReleaseDate"` // saat dilimi olmadan (UTC)
		} `json:"DocumentTracking"`
		ProductTree struct {
			FullProductName []struct {
				ProductID string `json:"ProductID"`
				Value     string `json:"Value"`
			} `json:"FullProductName"`
		} `json:"ProductTree"`
		Vulnerability []struct {
			Title   msrcValue `json:"Title"`
			CVE     string    `json:"CVE"`
			Threats []struct {
				Description msrcValue `json:"Description"`
				ProductID   []string  `json:"ProductID"`
				Type        int       `json:"Type"`
			} `json:"Threats"`
			CVSSScoreSets []struct {
				BaseScore float64  `json:"BaseScore"`
				Vector    string   `json:"Vector"`
				ProductID []string `json:"ProductID"`
			} `json:"CVSSScoreSets"`
			Remediations []struct {
				Description msrcValue `json:"Description"`
				ProductID   []string  `json:"ProductID"`
				Type        int       `json:"Type"`
				FixedBuild  string    `json:"FixedBuild"`
			} `json:"Remediations"`
		} `json:"Vulnerability"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	windows := map[string]bool{}
	for _, p := range doc.ProductTree.FullProductName {
		if strings.HasPrefix(p.Value, "Windows") {
			windows[p.ProductID] = true
		}
	}
	published := nvdTime(doc.DocumentTracking.InitialReleaseDate)
	var out []Record
	for _, v := range doc.Vulnerability {
		if !ValidCVEID(v.CVE) {
			continue
		}
		sevByProduct := map[string]string{}
		exploited := false
		for _, t := range v.Threats {
			switch t.Type {
			case 3: // önem derecesi
				for _, p := range t.ProductID {
					sevByProduct[p] = t.Description.Value
				}
			case 1: // istismar durumu: "Publicly Disclosed:No;Exploited:Yes;..."
				if strings.Contains(t.Description.Value, "Exploited:Yes") {
					exploited = true
				}
			}
		}
		rec := Record{ID: v.CVE, Source: "msrc", Title: v.Title.Value, Exploited: exploited}
		rec.Published = published
		var best float64
		for _, s := range v.CVSSScoreSets {
			if s.BaseScore > best {
				best = s.BaseScore
				rec.CVSSVector = s.Vector
			}
		}
		if best > 0 {
			rec.CVSS = &best
			rec.CVSSVersion = "3.1"
			rec.Severity = SeverityFromCVSS(best)
		}
		seen := map[Remediation]bool{}
		for _, rm := range v.Remediations {
			if rm.Type != 2 { // 2: Vendor Fix
				continue
			}
			kb := NormalizeKB(rm.Description.Value)
			for _, pid := range rm.ProductID {
				if !windows[pid] {
					continue
				}
				x := Remediation{KB: kb, Severity: sevByProduct[pid]}
				if fam := BuildFamily(rm.FixedBuild); fam != "" {
					x.BuildFamily, x.FixedBuild = fam, rm.FixedBuild
				}
				if x.KB == "" && x.BuildFamily == "" {
					continue
				}
				if !seen[x] {
					seen[x] = true
					rec.Remediations = append(rec.Remediations, x)
				}
			}
		}
		if rec.Severity == "" {
			for _, s := range sevByProduct {
				if sv := NormalizeSeverity(s); severityScore(sv) > severityScore(rec.Severity) || rec.Severity == "" {
					rec.Severity = sv
				}
			}
		}
		// Windows'a dokunmayan kayıtlar (Azure Linux paketleri vb.) saklanmaz.
		if len(rec.Remediations) == 0 {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}
